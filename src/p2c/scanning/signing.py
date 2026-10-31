"""ATLAS nuclei-template signing gate (Stage 3): run only SIGNED templates.

Each template is signed with an HMAC-SHA256 over its exact bytes (key from
``ATLAS_TEMPLATE_SIGNING_KEY``); the runner verifies every template against a
signature manifest before handing it to nuclei, so an **unsigned or tampered**
template is rejected (acceptance-gate item). Phase 6 upgrades this to ECDSA/Sigstore.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from p2c.config import Settings

MANIFEST_NAME = "_signatures.json"
# The built-in dev key — must never sign production templates (see signer_from_settings).
DEV_TEMPLATE_SIGNING_KEY = "atlas-dev-template-key-change-me"


def sign_bytes(content: bytes, key: bytes) -> str:
    """HMAC-SHA256 hex signature over ``content``."""
    return hmac.new(key, content, hashlib.sha256).hexdigest()


def verify_bytes(content: bytes, signature: str, key: bytes) -> bool:
    """Constant-time verification of an HMAC signature."""
    return hmac.compare_digest(sign_bytes(content, key), signature)


def signer_from_settings(settings: Settings) -> TemplateSigner:
    """Build a :class:`TemplateSigner`, refusing the built-in dev key when it matters.

    Under ``SOVEREIGN_MODE`` the dev default is rejected (unless
    ``ATLAS_ALLOW_DEV_TEMPLATE_KEY`` is set) — a source-committed signing key would
    let anyone forge template signatures, hollowing out the signed-only gate.
    """
    key = settings.template_signing_key
    if settings.sovereign_mode and key == DEV_TEMPLATE_SIGNING_KEY and not settings.allow_dev_template_key:
        raise ValueError(
            "refusing the built-in dev template-signing key under SOVEREIGN_MODE; "
            "set ATLAS_TEMPLATE_SIGNING_KEY to a real secret and re-run `make sign-templates`"
        )
    return TemplateSigner(key.encode())


class TemplateSigner:
    """Signs / verifies a directory of ``*.yaml`` nuclei templates."""

    def __init__(self, key: bytes) -> None:
        if not key:
            raise ValueError("template signing key must not be empty")
        self._key = key

    def sign_dir(self, template_dir: Path) -> dict[str, str]:
        """Return ``{filename: signature}`` for every template in the directory."""
        return {p.name: sign_bytes(p.read_bytes(), self._key) for p in sorted(template_dir.glob("*.yaml"))}

    def write_manifest(self, template_dir: Path) -> Path:
        """Sign the directory and write the signature manifest; return its path."""
        manifest = self.sign_dir(template_dir)
        path = template_dir / MANIFEST_NAME
        path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return path

    def load_manifest(self, template_dir: Path) -> dict[str, str]:
        path = template_dir / MANIFEST_NAME
        if not path.exists():
            return {}
        loaded = json.loads(path.read_text(encoding="utf-8"))
        return {str(k): str(v) for k, v in loaded.items()}

    def verified_templates(self, template_dir: Path, manifest: dict[str, str] | None = None) -> list[Path]:
        """Return only the templates whose signature verifies; reject unsigned/tampered."""
        sigs = manifest if manifest is not None else self.load_manifest(template_dir)
        verified: list[Path] = []
        for path in sorted(template_dir.glob("*.yaml")):
            signature = sigs.get(path.name)
            if signature and verify_bytes(path.read_bytes(), signature, self._key):
                verified.append(path)
        return verified
