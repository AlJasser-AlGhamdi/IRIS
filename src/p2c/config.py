"""Central configuration + determinism spine for ATLAS.

Everything reproducible flows from here: ``GLOBAL_SEED`` seeds every RNG,
``RUN_MODE`` selects synthetic vs. (test-target-only) live execution, and
``SOVEREIGN_MODE`` + ``ALLOWLISTED_HOSTS`` parameterize the egress guard that
makes data sovereignty a *tested* runtime property (spec §2, Phase 0).
"""

from __future__ import annotations

import os
import random
from functools import lru_cache
from typing import Annotated, Any

import numpy as np
from pydantic import field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

from p2c.schemas.enums import RunMode


class Settings(BaseSettings):
    """Process configuration, populated from ``ATLAS_*`` env vars / ``.env``.

    Defaults are the *safe* posture: synthetic mode + sovereignty on.
    """

    model_config = SettingsConfigDict(
        env_prefix="ATLAS_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
        frozen=True,
    )

    # --- run + reproducibility -------------------------------------------
    run_mode: RunMode = RunMode.SYNTHETIC
    sovereign_mode: bool = True
    global_seed: int = 1337

    # --- sovereignty ------------------------------------------------------
    # NoDecode: hand the raw env string to _parse_hosts (avoid JSON-decoding it).
    allowlisted_hosts: Annotated[frozenset[str], NoDecode] = frozenset()
    # Escape hatch: permit a non-guard-visible loop (uvloop) ONLY when egress is
    # enforced at the OS/network layer instead. Default off = fail closed.
    allow_unguarded_loop: bool = False

    # --- services (all localhost; never OpenClaw's ports) -----------------
    database_url: str = "postgresql+psycopg://atlas:atlas@127.0.0.1:5432/atlas"
    api_host: str = "127.0.0.1"
    api_port: int = 8000
    ollama_url: str = "http://127.0.0.1:11434"

    # Server-side base URL for HTTP ownership verification. When set (LIVE mode),
    # ALL verification fetches go here (the local test-target) instead of
    # https://<domain> — enforces the test-target-only scope + prevents SSRF.
    test_target_base_url: str | None = None

    # HMAC key that signs ATLAS nuclei templates (Stage 3). Dev default; OVERRIDE in
    # production via a secret. Only signed templates run; under SOVEREIGN_MODE the
    # runtime refuses this dev default unless allow_dev_template_key is set.
    template_signing_key: str = "atlas-dev-template-key-change-me"
    allow_dev_template_key: bool = False

    # --- logging ----------------------------------------------------------
    log_level: str = "INFO"
    log_json: bool = True

    @field_validator("allowlisted_hosts", mode="before")
    @classmethod
    def _parse_hosts(cls, value: Any) -> Any:
        """Accept a comma-separated string (env) or any iterable of hostnames."""
        if value is None or value == "":
            return frozenset()
        if isinstance(value, str):
            return frozenset(h.strip().lower() for h in value.split(",") if h.strip())
        if isinstance(value, (list, tuple, set, frozenset)):
            return frozenset(str(h).strip().lower() for h in value if str(h).strip())
        return value


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide, cached :class:`Settings` singleton."""
    return Settings()


def seed_everything(seed: int | None = None) -> int:
    """Seed every RNG deterministically and return the seed used.

    Seeds :mod:`random` and :mod:`numpy`, and exports ``PYTHONHASHSEED`` /
    ``ATLAS_SEED`` so subprocess-based tools (Go scanners) inherit the seed.
    ``PYTHONHASHSEED`` only affects *newly spawned* interpreters — the CI/Make
    harness also sets it in the environment before launch (see ``REPRODUCE.md``).
    """
    resolved = get_settings().global_seed if seed is None else seed
    os.environ["PYTHONHASHSEED"] = str(resolved)
    os.environ["ATLAS_SEED"] = str(resolved)
    random.seed(resolved)
    np.random.seed(resolved % (2**32))
    return resolved
