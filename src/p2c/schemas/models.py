"""Shared Pydantic v2 schemas for every ATLAS pipeline stage.

Synthetic and live data share these exact models (spec §1). Every artifact
carries provenance (``source_tool`` / ``tool_version`` / ``timestamp`` /
``consent_ref``) so a reviewer can trace any finding, score, or report back to
the tool and consent record that produced it (spec §2.5).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Any

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, model_validator

from p2c.schemas.enums import EvidenceTier, Framework, ScanIntensity, Severity


def _ensure_utc(value: datetime) -> datetime:
    """Normalize any datetime to timezone-aware UTC (naive input is assumed UTC).

    Guarantees every timestamp in every schema is aware + UTC, so comparisons
    (e.g. ``Consent.is_active``) never raise on naive/aware mixing and reproduced
    outputs are timezone-stable.
    """
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


UtcDateTime = Annotated[datetime, AfterValidator(_ensure_utc)]

# --- CVSS v3.1 qualitative severity bands (spec §Phase 0 test target) --------
# https://www.first.org/cvss/v3.1/specification-document#Qualitative-Severity-Rating-Scale
_CVSS_MIN = 0.0
_CVSS_MAX = 10.0
_BAND_LOW_MAX = 4.0  # scores < 4.0 (and > 0) are LOW
_BAND_MEDIUM_MAX = 7.0  # scores < 7.0 are MEDIUM
_BAND_HIGH_MAX = 9.0  # scores < 9.0 are HIGH


def severity_from_cvss(score: float) -> Severity:
    """Map a CVSS v3.1 base score in ``[0.0, 10.0]`` to its qualitative band.

    Bands: 0.0 -> NONE, 0.1-3.9 -> LOW, 4.0-6.9 -> MEDIUM, 7.0-8.9 -> HIGH,
    9.0-10.0 -> CRITICAL. Raises ``ValueError`` outside ``[0, 10]``.
    """
    if not _CVSS_MIN <= score <= _CVSS_MAX:
        raise ValueError(f"CVSS base score {score!r} outside [0.0, 10.0]")
    if score == _CVSS_MIN:
        return Severity.NONE
    if score < _BAND_LOW_MAX:
        return Severity.LOW
    if score < _BAND_MEDIUM_MAX:
        return Severity.MEDIUM
    if score < _BAND_HIGH_MAX:
        return Severity.HIGH
    return Severity.CRITICAL


def _utcnow() -> datetime:
    return datetime.now(UTC)


class AtlasModel(BaseModel):
    """Base for all ATLAS schemas: strict, forbid unknown fields."""

    model_config = ConfigDict(
        extra="forbid",
        validate_assignment=True,
        use_enum_values=False,
        ser_json_timedelta="iso8601",
    )


class Asset(AtlasModel):
    """An externally observable asset discovered in Stage 2 (EASM)."""

    asset_id: str
    value: str = Field(description="domain, subdomain, IP, or URL")
    asset_type: str = Field(description="e.g. domain|subdomain|ip|url|service")
    source_tool: str
    tool_version: str
    discovery_method: str = Field(description="e.g. subfinder|amass|crt.sh|dnsx|synthetic")
    consent_ref: str
    first_seen: UtcDateTime = Field(default_factory=_utcnow)
    attributes: dict[str, Any] = Field(default_factory=dict)


class Finding(AtlasModel):
    """A machine-readable, CVSS-normalized observation about an asset (Stage 3).

    Field set is spec-exact (§Phase 0 Build). ``control_ids`` are populated by
    the Stage-4 mapping engine; a raw Stage-3 finding may have none yet.
    """

    finding_id: str
    asset: str = Field(description="reference to Asset.asset_id (or asset value)")
    source_tool: str
    tool_version: str
    raw_evidence: dict[str, Any] = Field(default_factory=dict)
    observed_state: str
    cvss_v3_1_vector: str | None = None
    cvss_base_score: float | None = Field(default=None, ge=_CVSS_MIN, le=_CVSS_MAX)
    severity: Severity
    control_ids: list[str] = Field(default_factory=list)
    evidence_tier: EvidenceTier
    timestamp: UtcDateTime = Field(default_factory=_utcnow)
    consent_ref: str

    @model_validator(mode="after")
    def _severity_matches_score(self) -> Finding:
        """If a CVSS score is present, severity must equal its qualitative band."""
        if self.cvss_base_score is not None:
            expected = severity_from_cvss(self.cvss_base_score)
            if self.severity is not expected:
                raise ValueError(
                    f"severity {self.severity} inconsistent with CVSS "
                    f"{self.cvss_base_score} (expected {expected})"
                )
        return self


class Control(AtlasModel):
    """A single control from a Saudi framework (OSCAL-backed catalog in Phase 4).

    Full OSCAL ``catalog`` encoding lives in ``catalogs/``; this is the runtime
    projection the pipeline maps findings onto.
    """

    control_id: str = Field(description="native scheme, e.g. 2-5-3-1")
    framework: Framework
    title_en: str
    title_ar: str
    domain: str
    subdomain: str
    evidence_tier: EvidenceTier
    class_a_applicable: bool = True
    class_b_applicable: bool = False


class Evidence(AtlasModel):
    """A tier-tagged piece of evidence supporting a control assessment (Stage 5)."""

    evidence_id: str
    control_id: str
    evidence_tier: EvidenceTier
    content_hash: str = Field(description="sha256 hex of the canonical content")
    source: str
    finding_ids: list[str] = Field(default_factory=list)
    timestamp: UtcDateTime = Field(default_factory=_utcnow)
    consent_ref: str


class Consent(AtlasModel):
    """Authorization record proving a target may be assessed (Stage 1).

    Active scanning is hard-blocked until a valid, unexpired consent exists.
    """

    consent_id: str
    verified_apex: str
    in_scope_subdomains: list[str] = Field(default_factory=list)
    in_scope_ip_ranges: list[str] = Field(default_factory=list)
    time_window_start: UtcDateTime
    time_window_end: UtcDateTime
    allowed_intensity: ScanIntensity = ScanIntensity.PASSIVE
    verification_method: str = Field(description="dns-txt|html-file|meta-tag")
    verified_at: UtcDateTime = Field(default_factory=_utcnow)
    content_hash: str | None = None

    @model_validator(mode="after")
    def _window_ordered(self) -> Consent:
        if self.time_window_end <= self.time_window_start:
            raise ValueError("time_window_end must be after time_window_start")
        return self

    def is_active(self, at: datetime | None = None) -> bool:
        """True if ``at`` (default now, normalized to UTC) is within the window."""
        now = _ensure_utc(at) if at is not None else _utcnow()
        return self.time_window_start <= now <= self.time_window_end


class Attestation(AtlasModel):
    """A signed, timestamped Tier-3 attestation for a control (Stage 6)."""

    attestation_id: str
    control_id: str
    statement: str
    signer_identity: str
    payload_hash: str
    valid_from: UtcDateTime
    valid_until: UtcDateTime
    signature: str | None = None
    timestamp_token: str | None = Field(default=None, description="RFC-3161 TSA token (base64)")
    timestamp: UtcDateTime = Field(default_factory=_utcnow)

    @model_validator(mode="after")
    def _validity_ordered(self) -> Attestation:
        if self.valid_until <= self.valid_from:
            raise ValueError("valid_until must be after valid_from")
        return self


class Score(AtlasModel):
    """Dual compliance score for a subject; the two scores are never merged.

    ``assessed_score`` covers externally-verifiable Tier-1 controls;
    ``documented_score`` covers the full Tier 1+2+3 set. ``gap`` is the
    externally-attributable gap ``G = 1 - assessed_score``.
    """

    subject_id: str
    assessed_score: float = Field(ge=0.0, le=1.0)
    documented_score: float = Field(ge=0.0, le=1.0)
    gap: float = Field(default=0.0, ge=0.0, le=1.0)
    tier1_controls: int = Field(default=0, ge=0)
    total_controls: int = Field(default=0, ge=0)
    contradiction_count: int = Field(default=0, ge=0)
    timestamp: UtcDateTime = Field(default_factory=_utcnow)

    @model_validator(mode="after")
    def _derive_gap(self) -> Score:
        object.__setattr__(self, "gap", round(1.0 - self.assessed_score, 12))
        return self
