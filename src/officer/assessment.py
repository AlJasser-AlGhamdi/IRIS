"""From typed observations and the owner's answers to control states and both scores.

Mirrors the engine's own assessment step (the private pilot runner's ``assess``) on the public scoring API,
so the agent's numbers are the engine's. A parity test on the lab worker compares the two on the same input.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from functools import cache

from officer import taxonomy
from officer.questions import Declaration
from p2c.mapping.models import ControlMapping
from p2c.mapping.rules import MappingEngine
from p2c.scanning.catalog import CATALOG, CheckId, build_finding
from p2c.schemas.enums import EvidenceTier
from p2c.schemas.models import Attestation
from p2c.scoring.assemble import attestation_assessments, merge_assessments, tier1_assessments
from p2c.scoring.contradictions import detect_contradictions
from p2c.scoring.dual_score import compute_dual_score
from p2c.scoring.models import ComplianceStatus, Contradiction, ControlAssessment, DualScore, ObservationState
from p2c.sovereignty.provenance import sha256_hex

Observation = tuple[str, CheckId]  # (host, detector)


class Tile(StrEnum):
    UNKNOWN = "unknown"  # nothing known yet
    NEEDS_ANSWER = "needs_answer"  # the scan cannot see it; the interview has not covered it
    CLEAN = "clean"  # no violation observed from outside (never "compliant")
    VIOLATION = "violation"  # a violation observed from outside
    NOT_OBSERVABLE = "not_observable"  # testable in principle, but this read did not complete
    CONTRADICTED = "contradicted"  # the owner's claim meets a finding
    DECLARED = "declared"  # the owner declared it in place (Tier 3)
    DECLARED_EVIDENCE = "declared_evidence"  # declared with evidence offered (Tier 2)
    SELF_GAP = "self_gap"  # the owner said it is not in place


@dataclass(frozen=True)
class Assessed:
    mappings: list[ControlMapping]
    tier1: list[ControlAssessment]
    merged: list[ControlAssessment]
    score: DualScore
    contradictions: list[Contradiction]
    tiles: dict[str, Tile]

    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for tile in self.tiles.values():
            out[tile.value] = out.get(tile.value, 0) + 1
        return out


@cache
def documented_universe() -> frozenset[str]:
    from p2c.evaluation.harness import _documented_universe  # noqa: PLC0415 - heavy import, once

    return _documented_universe()


def assess(
    findings: Iterable[Observation],
    unread: Iterable[Observation],
    declarations: Sequence[Declaration],
    *,
    now: datetime,
    interview_open: bool = False,
    signer: str = "owner",
) -> Assessed:
    findings = sorted(set(findings), key=lambda o: (o[0], o[1].value))
    unread_set = set(unread)
    built = [
        build_finding(check, asset=host, observed_state=f"{check.value} on {host}", consent_ref="agent",
                      source_tool="officer", tool_version="1", now=now)
        for host, check in findings
    ]
    mappings = MappingEngine().map_findings(built)
    unobserved = frozenset(c for _host, check in unread_set for c in CATALOG[check].control_ids)
    tier1 = tier1_assessments(mappings, unobserved=unobserved)
    status = {"compliant": ComplianceStatus.COMPLIANT, "non_compliant": ComplianceStatus.NON_COMPLIANT}
    tier2 = [
        ControlAssessment(control_id=d.control_id, tier=EvidenceTier.TIER_2, status=status[d.claim],
                          evidence_ids=[f"tier2:{d.question}:{d.control_id}"], source="questionnaire")
        for d in declarations
        if d.tier == 2  # noqa: PLR2004
    ]
    declared = [
        Attestation(
            attestation_id=f"decl-{d.question}-{d.control_id}",
            control_id=d.control_id,
            statement=f"{d.control_id} declared compliant",
            signer_identity=signer,
            payload_hash=sha256_hex(f"{d.control_id}|{signer}"),
            valid_from=now - timedelta(minutes=1),
            valid_until=now + timedelta(days=365),
        )
        for d in declarations
        if d.tier == 3 and d.claim == "compliant"  # noqa: PLR2004
    ]
    self_reported_gaps = [
        ControlAssessment(control_id=d.control_id, tier=EvidenceTier.TIER_3,
                          status=ComplianceStatus.NON_COMPLIANT, source="attestation")
        for d in declarations
        if d.tier == 3 and d.claim == "non_compliant"  # noqa: PLR2004
    ]
    merged = merge_assessments(tier1, tier2, attestation_assessments(declared, now=now), self_reported_gaps)
    score = compute_dual_score(merged, universe=documented_universe())
    flags = detect_contradictions(declared, mappings, now=now, tier2=tier2)
    return Assessed(mappings, tier1, merged, score, flags,
                    _tiles(merged, flags, declarations, interview_open=interview_open))


def _tiles(
    merged: Sequence[ControlAssessment],
    flags: Sequence[Contradiction],
    declarations: Sequence[Declaration],
    *,
    interview_open: bool,
) -> dict[str, Tile]:
    by_control = {a.control_id: a for a in merged}
    contradicted = {f.control_id for f in flags}
    evidence = {d.control_id for d in declarations if d.tier == 2}  # noqa: PLR2004
    out: dict[str, Tile] = {}
    for row in taxonomy.rows():
        a = by_control.get(row.id)
        if row.id in contradicted:
            out[row.id] = Tile.CONTRADICTED
        elif a is not None and a.tier == EvidenceTier.TIER_1:
            out[row.id] = {
                ObservationState.VIOLATION_OBSERVED: Tile.VIOLATION,
                ObservationState.NO_VIOLATION_OBSERVED: Tile.CLEAN,
            }.get(a.observation, Tile.NOT_OBSERVABLE) if a.observation is not None else Tile.NOT_OBSERVABLE
        elif a is not None and a.status is ComplianceStatus.COMPLIANT:
            out[row.id] = Tile.DECLARED_EVIDENCE if row.id in evidence else Tile.DECLARED
        elif a is not None and a.status is ComplianceStatus.NON_COMPLIANT:
            out[row.id] = Tile.SELF_GAP
        elif interview_open and row.in_class_b and row.tier != 1:
            out[row.id] = Tile.NEEDS_ANSWER
        else:
            out[row.id] = Tile.UNKNOWN
    # A Tier-1 parent with no detectors of its own shows its children (display only, never scored).
    for row in taxonomy.rows():
        if row.tier == 1 and not row.scanner_checks and out[row.id] is Tile.UNKNOWN:
            children = [out[r.id] for r in taxonomy.rows() if r.id.startswith(f"{row.id}-") and r.tier == 1]
            if Tile.VIOLATION in children or Tile.CONTRADICTED in children:
                out[row.id] = Tile.VIOLATION
            elif children and all(c is Tile.CLEAN for c in children):
                out[row.id] = Tile.CLEAN
            elif children and any(c is not Tile.UNKNOWN for c in children):
                out[row.id] = Tile.NOT_OBSERVABLE
    return out
