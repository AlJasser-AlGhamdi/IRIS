"""Provenance helpers — deterministic hashing for content-addressed artifacts.

Every evidence item, attestation, and audit entry is content-hashed so it can be
traced and tamper-checked (spec §2.5). Hashing is canonical (sorted keys, no
whitespace drift) so the same input always yields the same digest.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from p2c._embed import normalize_text


def canonical_json(payload: Any) -> str:
    """Serialize ``payload`` to a canonical JSON string (stable across runs)."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def sha256_hex(data: str | bytes) -> str:
    """Return the hex SHA-256 digest of ``data`` (utf-8 if str)."""
    raw = data.encode("utf-8") if isinstance(data, str) else data
    return hashlib.sha256(raw).hexdigest()


def content_hash(payload: Any) -> str:
    """Canonical-JSON then SHA-256: the digest used for all ATLAS artifacts."""
    return sha256_hex(canonical_json(payload))


# Arabic letters and digits (Arabic-Indic and Western) only: what survives every way of copying the
# text out of a PDF or a web page. Punctuation, diacritics, tatweel and spacing do not.
_NOT_KEPT = re.compile(r"[^\u0621-\u064a\u0660-\u06690-9]+")


def canonical_arabic(text: str) -> str:
    """Arabic control text reduced to what a faithful copy cannot change: the normalised letters and
    digits, one space between words."""
    return " ".join(part for part in _NOT_KEPT.split(normalize_text(text)) if part)


def text_fingerprint(text: str) -> str:
    """SHA-256 of :func:`canonical_arabic`: lets anyone holding the official text check a row of the
    encoding without the text being redistributed."""
    return sha256_hex(canonical_arabic(text))
