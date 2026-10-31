"""Correctness fixes from the 2026-07 adversarial review of tier scoring.

- A refuted higher-tier self-report at a *different granularity* than the finding must be
  neutralized so it cannot inflate ``documented_score`` (the exact-id case is handled by
  ``reconcile``; the parent/child case was not).
- A questionnaire may never carry Tier-1 authority.
- Contradiction detection can optionally honor the attestation validity window.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from p2c.mapping.rules import MappingEngine
from p2c.scanning.catalog import CheckId, build_finding
from p2c.schemas.enums import EvidenceTier
from p2c.schemas.models import Attestation
from p2c.scoring.assemble import merge_assessments
from p2c.scoring.contradictions import detect_contradictions
from p2c.scoring.dual_score import compute_dual_score
from p2c.scoring.models import ComplianceStatus, ControlAssessment
from p2c.scoring.questionnaire import Question, Questionnaire

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def _mk(cid: str, tier: EvidenceTier, status: ComplianceStatus) -> ControlAssessment:
    return ControlAssessment(control_id=cid, tier=tier, status=status, weight=1.0)


def test_parent_attestation_refuted_by_child_finding_cannot_inflate_documented() -> None:
    # Coarse Tier-3 attestation on the parent 2-4-3, refuted by a Tier-1 finding on the
    # subcontrol 2-4-3-5. Different exact ids, so reconcile alone would let it survive.
    merged = merge_assessments(
        [_mk("2-4-3-5", EvidenceTier.TIER_1, ComplianceStatus.NON_COMPLIANT)],
        [_mk("2-4-3", EvidenceTier.TIER_3, ComplianceStatus.COMPLIANT)],
    )
    parent = next(a for a in merged if a.control_id == "2-4-3")
    assert parent.status == ComplianceStatus.NON_COMPLIANT  # neutralized, not satisfied
    assert compute_dual_score(merged).documented_score == 0.0  # no inflation


def test_child_attestation_is_not_neutralized_by_a_parent_finding() -> None:
    # Array R2-7: a parent-level finding does not say which child failed, so a declaration on
    # one child stays as declared (mixed-compliance siblings). Only the reverse direction refutes.
    merged = merge_assessments(
        [_mk("2-4-3", EvidenceTier.TIER_1, ComplianceStatus.NON_COMPLIANT)],
        [_mk("2-4-3-5", EvidenceTier.TIER_3, ComplianceStatus.COMPLIANT)],
    )
    child = next(a for a in merged if a.control_id == "2-4-3-5")
    assert child.status == ComplianceStatus.COMPLIANT
    assert compute_dual_score(merged).documented_score == 0.5


def test_unrelated_attestation_still_lifts_documented() -> None:
    # An attestation on an UNrelated control is untouched and lifts documented above assessed.
    merged = merge_assessments(
        [_mk("2-4-3-5", EvidenceTier.TIER_1, ComplianceStatus.NON_COMPLIANT)],
        [_mk("1-3-2", EvidenceTier.TIER_3, ComplianceStatus.COMPLIANT)],
    )
    assert next(a for a in merged if a.control_id == "1-3-2").status == ComplianceStatus.COMPLIANT
    score = compute_dual_score(merged)
    assert score.documented_score == 0.5
    assert score.assessed_score == 0.0


def test_questionnaire_rejects_tier1() -> None:
    with pytest.raises(ValueError, match="TIER_2 or TIER_3"):
        Questionnaire(
            questionnaire_id="q",
            title="t",
            tier=EvidenceTier.TIER_1,
            questions=[Question(question_id="a", control_id="1-3-2", prompt_en="x")],
        )


def test_detect_contradictions_respects_validity_window_when_now_given() -> None:
    findings = MappingEngine().map_findings(
        [
            build_finding(
                CheckId.SPF_MISSING,
                asset="x.sa",
                observed_state="o",
                consent_ref="C",
                source_tool="s",
                tool_version="0",
                now=NOW,
            )
        ]
    )
    expired = Attestation(
        attestation_id="A",
        control_id="2-4-3-5",
        statement="done",
        signer_identity="ciso",
        payload_hash="h",
        valid_from=datetime(2024, 1, 1, tzinfo=UTC),
        valid_until=datetime(2024, 6, 1, tzinfo=UTC),
    )
    # Default: every overstatement is surfaced, including the lapsed one.
    assert len(detect_contradictions([expired], findings)) == 1
    # With now after expiry: the lapsed attestation is skipped, matching the scorer.
    assert detect_contradictions([expired], findings, now=NOW) == []
