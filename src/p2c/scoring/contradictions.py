"""Contradiction detection: Tier-2 and Tier-3 self-reports vs Tier-1 evidence (Stage 5).

The overstatement adversary signs a Tier-3 attestation ("email security is
implemented") that externally-observed Tier-1 evidence refutes (no DMARC record), or
files the same claim as a Tier-2 internal-assessment record. This module flags exactly
those conflicts: a self-report asserting compliance for a control on which the toolkit
holds a **non-compliant Tier-1 finding**. Surfacing the conflict (rather than letting the
claim quietly raise ``documented_score``) is what keeps the two scores honest.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime

import structlog

from p2c.mapping.models import ControlMapping
from p2c.schemas.enums import Severity
from p2c.schemas.models import Attestation
from p2c.scoring.models import ComplianceStatus, Contradiction, ControlAssessment

log = structlog.get_logger("p2c.scoring.contradictions")

_TIER2_CLAIM = "internal assessment record: compliant"

# Most-severe-first ordering (CRITICAL=0 .. NONE=4) for picking the refuting finding to report.
_SEVERITY_RANK = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.NONE: 4,
}


# The evidence-tier rubric's fourth decision rule: a control that only requires the requirements
# another control lists to be implemented ("Cybersecurity requirements for X shall be implemented",
# beside the control that lists them). A claim on it asserts every listed requirement is in place.
# These are the seven such controls whose list holds an externally testable subcontrol (2-2-2 left on
# 2026-10-20, when no subcontrol of 2-2-3 stayed in Tier 1). 2-7-2 implements the requirements 2-7-1
# identifies, among them the NCNICC printer control 2-7-1-3 (added 2026-10-22, full review round 10).
IMPLEMENTS: dict[str, str] = {
    "2-3-2": "2-3-3",
    "2-4-2": "2-4-3",
    "2-5-2": "2-5-3",
    "2-7-2": "2-7-1",
    "2-8-2": "2-8-3",
    "2-10-2": "2-10-3",
    "2-15-2": "2-15-3",
}


def hierarchy_related(attested: str, finding: str) -> bool:
    """True if ``finding`` is ``attested`` itself or one of its descendants in the control tree."""
    return attested == finding or finding.startswith(f"{attested}-")


def control_related(attested: str, finding: str) -> bool:
    """True if a compliance claim on ``attested`` is contradicted by a finding on ``finding``.

    Direction-sensitive: a claim on a control asserts every requirement beneath it, so a
    finding on the same control or on any **descendant** contradicts it (``2-4-3`` covers
    ``2-4-3-5``; attesting at a parent does not escape a finding on one of its subcontrols).
    A claim that a list of requirements is implemented (:data:`IMPLEMENTS`) asserts every
    requirement of that list, so a finding on any of them contradicts it too (``2-5-2``
    against a finding on ``2-5-3-1``). A finding on an **ancestor** does not say which child
    failed, so it never contradicts a claim on a child: failure of one child requirement does
    not invalidate a sibling. The scorer (:func:`p2c.scoring.assemble.merge_assessments`) uses
    the same relation to neutralize a refuted self-report, so a flagged contradiction can never
    still inflate the score.
    """
    listed = IMPLEMENTS.get(attested)
    return hierarchy_related(attested, finding) or (listed is not None and hierarchy_related(listed, finding))


def detect_contradictions(
    attestations: Sequence[Attestation],
    tier1_findings: Sequence[ControlMapping],
    *,
    now: datetime | None = None,
    tier2: Sequence[ControlAssessment] = (),
) -> list[Contradiction]:
    """Flag self-reports of compliance that a Tier-1 finding contradicts.

    A Tier-1 ``ControlMapping`` *is* a detected problem for that control (a finding means
    non-compliance), so any claim of compliance for the same control, or for an ancestor of
    it, is a contradiction (:func:`control_related`). Tier-3 attestations are checked, and so
    are Tier-2 internal-assessment records claiming compliance (``tier2``): an overstatement
    filed as a Tier-2 record instead of a declaration is flagged the same way, so relabelling
    the claim does not escape the check. A Tier-2 record that already reports a gap overstates
    nothing and is left alone. Results are sorted for deterministic output. When ``now`` is
    given, attestations outside their ``[valid_from, valid_until]`` window are skipped,
    matching :func:`p2c.scoring.assemble.attestation_assessments`; by default (``now=None``)
    every overstatement is surfaced, including lapsed ones.
    """
    tier1 = [m for m in tier1_findings if m.tier == 1]  # only externally-verifiable evidence refutes
    considered = (
        [a for a in attestations if a.valid_from <= now <= a.valid_until]
        if now is not None
        else list(attestations)
    )
    claims: list[tuple[str, str, str, int]] = [
        (a.control_id, a.attestation_id, a.statement, 3) for a in considered
    ]
    claims += [
        (r.control_id, r.evidence_ids[0] if r.evidence_ids else f"tier2:{r.control_id}", _TIER2_CLAIM, 2)
        for r in tier2
        if r.status is ComplianceStatus.COMPLIANT
    ]

    contradictions: list[Contradiction] = []
    for control_id, claim_id, statement, tier in claims:
        refuting = [m for m in tier1 if control_related(control_id, m.control_id)]
        if not refuting:
            continue
        # Pair the claim with its most severe refuting finding (tie-break by id for determinism).
        finding = min(refuting, key=lambda m: (_SEVERITY_RANK[m.severity], m.finding_id))
        contradictions.append(
            Contradiction(
                control_id=control_id,
                attestation_id=claim_id,
                finding_id=finding.finding_id,
                attested_claim=statement,
                observed_state=f"Tier-1 finding {finding.finding_id} ({finding.severity.value})",
                tier=tier,
                detail=(
                    f"Tier-{tier} claim of compliance for {control_id}, but a Tier-1 scan finding refutes it"
                ),
            )
        )
        log.warning(
            "attestation_contradicts_evidence",
            control_id=control_id,
            attestation_id=claim_id,
            finding_id=finding.finding_id,
            tier=tier,
        )
    contradictions.sort(key=lambda c: (c.control_id, c.tier, c.attestation_id))
    return contradictions
