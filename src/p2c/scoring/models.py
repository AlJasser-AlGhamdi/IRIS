"""Stage-5 scoring contracts: per-control assessment, dual scores, contradictions.

The dual scores are **never merged** (spec §4): ``assessed_score`` is computed over
externally-verifiable **Tier-1** controls only; ``documented_score`` over the full
Tier 1+2+3 set. The externally-attributable gap ``G = 1 - assessed`` quantifies what
the scan alone can attribute. A :class:`Contradiction` records where a Tier-3
attestation claims a control that Tier-1 evidence refutes (the overstatement adversary).
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import Field, computed_field, model_validator

from p2c.schemas.enums import EvidenceTier
from p2c.schemas.models import AtlasModel, UtcDateTime, _utcnow


class ComplianceStatus(StrEnum):
    """A control's assessed compliance state (kept separate from its evidence tier)."""

    COMPLIANT = "compliant"  # satisfied: Tier-1 pass / Tier-2 evidence ok / Tier-3 attested
    NON_COMPLIANT = "non_compliant"  # a failing finding or a negative questionnaire answer
    NOT_ASSESSED = "not_assessed"  # no evidence of any tier


class ObservationState(StrEnum):
    """What the scan established about one externally testable (Tier-1) control.

    The scan can show a violation, and it can show that it read the control and found none; it can
    never show compliance. A control it could not read (a blocked host, an origin hidden behind a
    CDN, a suppressed banner, an apex domain left out of scope) is NOT_OBSERVED, which never passes.
    A subdomain left out of scope cannot be detected this way: the scorer never learns of it.
    """

    VIOLATION_OBSERVED = "violation_observed"
    NO_VIOLATION_OBSERVED = "no_violation_observed"
    NOT_OBSERVED = "not_observed"


_OBSERVATION_OF: dict[ComplianceStatus, ObservationState] = {
    ComplianceStatus.NON_COMPLIANT: ObservationState.VIOLATION_OBSERVED,
    ComplianceStatus.COMPLIANT: ObservationState.NO_VIOLATION_OBSERVED,
    ComplianceStatus.NOT_ASSESSED: ObservationState.NOT_OBSERVED,
}


class ControlAssessment(AtlasModel):
    """One control's compliance state + weight for scoring."""

    control_id: str
    tier: EvidenceTier
    status: ComplianceStatus
    weight: float = Field(default=1.0, gt=0.0)
    evidence_ids: list[str] = Field(default_factory=list)
    source: str = Field(default="", description="finding | questionnaire | attestation")

    @model_validator(mode="before")
    @classmethod
    def _drop_derived_observation(cls, data: object) -> object:
        """Accept a serialised record back: ``observation`` is derived, never an input."""
        if isinstance(data, dict) and "observation" in data:
            data = {k: v for k, v in data.items() if k != "observation"}
        return data

    @property
    def satisfied(self) -> bool:
        return self.status is ComplianceStatus.COMPLIANT

    @computed_field  # type: ignore[prop-decorator]
    @property
    def observation(self) -> ObservationState | None:
        """The observation state of a Tier-1 record, the label the scorer reports for it.

        A Tier-1 COMPLIANT record means no violation observed, never compliant; the status enum is
        shared with Tier 2 and 3, so the scan-specific reading is exposed here. ``None`` off Tier 1.
        """
        return _OBSERVATION_OF[self.status] if self.tier == EvidenceTier.TIER_1 else None


class DualScore(AtlasModel):
    """Assessed (Tier-1) and documented (all-tier) scores — never merged."""

    assessed_score: float = Field(ge=0.0, le=1.0, description="weighted Tier-1 compliance")
    documented_score: float = Field(ge=0.0, le=1.0, description="weighted all-tier compliance")
    gap: float = Field(
        ge=0.0, le=1.0, description="1 - assessed: the Tier-1 share not observed clean (violated or unread)"
    )
    tier1_total_weight: float = Field(ge=0.0)
    tier1_compliant_weight: float = Field(ge=0.0)
    documented_total_weight: float = Field(ge=0.0)
    documented_satisfied_weight: float = Field(ge=0.0)
    coverage: float = Field(ge=0.0, le=1.0, description="share of the Tier-1 weight the scan observed")
    evidence_coverage: float = Field(
        ge=0.0, le=1.0, description="share of the documented set that carries assessed evidence"
    )
    weights_source: str = "uniform"
    computed_at: UtcDateTime = Field(default_factory=_utcnow)


class Contradiction(AtlasModel):
    """A Tier-2 or Tier-3 compliance claim refuted by externally-observed Tier-1 evidence."""

    control_id: str
    attestation_id: str
    finding_id: str
    attested_claim: str
    observed_state: str
    tier: int = Field(default=3, ge=2, le=3, description="evidence tier of the refuted claim")
    detail: str = ""
