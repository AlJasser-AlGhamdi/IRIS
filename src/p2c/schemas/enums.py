"""Shared enumerations for the ATLAS pipeline (Stage-agnostic value types).

These types are imported across every pipeline stage; keep them free of heavy
dependencies so the schema layer stays cheap to import.
"""

from __future__ import annotations

from enum import IntEnum, StrEnum


class RunMode(StrEnum):
    """Pipeline execution mode. Synthetic + live share the *same* schemas.

    In this deployment ``LIVE`` may only ever be pointed at the local
    ``test-target`` container — never a real external domain (owner decision).
    """

    LIVE = "LIVE"
    SYNTHETIC = "SYNTHETIC"


class Severity(StrEnum):
    """CVSS v3.1 qualitative severity rating bands."""

    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class EvidenceTier(IntEnum):
    """Three-tier evidence model.

    Tier 1 = externally observable (scanner) · Tier 2 = questionnaire/upload ·
    Tier 3 = attestation. ``assessed_score`` is computed over Tier-1 only;
    ``documented_score`` over all tiers.
    """

    TIER_1 = 1
    TIER_2 = 2
    TIER_3 = 3


class ScanIntensity(StrEnum):
    """Allowed scan intensity captured in a consent record (fail-safe default)."""

    PASSIVE = "PASSIVE"
    SAFE_ACTIVE = "SAFE_ACTIVE"
    FULL_ACTIVE = "FULL_ACTIVE"


class Framework(StrEnum):
    """Saudi control frameworks encoded by ATLAS."""

    ECC_2_2024 = "ECC-2:2024"
    NCNICC_1_2025 = "NCNICC-1:2025"


class ChallengeType(StrEnum):
    """Domain-ownership challenge mechanisms (Stage 1). Mirrors ACME/Search-Console."""

    DNS_TXT = "dns-txt"
    HTML_FILE = "html-file"
    META_TAG = "meta-tag"


class VerificationStatus(StrEnum):
    """Lifecycle of an ownership verification (Stage 1)."""

    PENDING = "PENDING"
    VERIFIED = "VERIFIED"
    FAILED = "FAILED"
    EXPIRED = "EXPIRED"


class AuditEventType(StrEnum):
    """Event kinds recorded in the tamper-evident audit chain (Stage 1)."""

    CHALLENGE_ISSUED = "challenge_issued"
    OWNERSHIP_VERIFIED = "ownership_verified"
    OWNERSHIP_FAILED = "ownership_failed"
    CONSENT_GRANTED = "consent_granted"
    CONSENT_REVOKED = "consent_revoked"
    SCAN_AUTHORIZED = "scan_authorized"
    SCAN_BLOCKED = "scan_blocked"
    ATTESTATION_ISSUED = "attestation_issued"
    ATTESTATION_RENEWED = "attestation_renewed"


class AssetType(StrEnum):
    """Kind of externally observable asset (Stage 2 discovery)."""

    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP = "ip"
    URL = "url"
    SERVICE = "service"


class DiscoveryMethod(StrEnum):
    """How an asset was discovered (Stage 2). Also the canonical ``source_tool`` set."""

    SUBFINDER = "subfinder"
    AMASS_PASSIVE = "amass-passive"
    CRTSH = "crt.sh"
    DNSX = "dnsx"
    SYNTHETIC = "synthetic"
