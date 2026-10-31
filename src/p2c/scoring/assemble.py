"""Assemble the per-control assessment set from all evidence tiers (Stage 5).

Bridges Phase 4 (control mappings) and the Tier-2/3 evidence into the unified
:class:`ControlAssessment` list the dual score consumes. Crucially, when a control
carries evidence at more than one tier, **the lowest tier wins** — externally-observed
Tier-1 evidence overrides a Tier-2 questionnaire answer or a Tier-3 attestation, so a
self-report can never overwrite a scan finding (the overstatement is instead surfaced
by :mod:`p2c.scoring.contradictions`).
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime

from p2c.mapping.models import ControlMapping
from p2c.scanning.catalog import CATALOG as _CHECK_CATALOG
from p2c.schemas.enums import EvidenceTier
from p2c.schemas.models import Attestation
from p2c.scoring.contradictions import control_related
from p2c.scoring.dual_score import reconcile
from p2c.scoring.models import ComplianceStatus, ControlAssessment

# The externally-observable Tier-1 controls ATLAS actually scans (from the Phase-3
# check catalog) — the universe over which `assessed_score` is meaningful.
TIER1_CHECKABLE: frozenset[str] = frozenset(
    cid for spec in _CHECK_CATALOG.values() for cid in spec.control_ids
)


def tier1_assessments(
    mappings: Sequence[ControlMapping],
    *,
    checkable: frozenset[str] = TIER1_CHECKABLE,
    unobserved: frozenset[str],
) -> list[ControlAssessment]:
    """Assess Tier-1 controls: a finding => violation observed; read and clean => no violation
    observed; not read => not observed.

    The assessed set is **every checkable control plus every control that actually has a Tier-1
    finding**, even one outside the checkable list (e.g. an extra control tag on a nuclei template),
    so a real non-compliance is never dropped. A checkable control in ``unobserved`` (one the scan
    could not read on every in-scope host) is NOT_ASSESSED unless a finding was still observed on it:
    missing evidence never scores as a pass, and an observed violation is never hidden by it. A
    COMPLIANT Tier-1 record means no violation observed, never compliant (the one-direction rule).
    ``unobserved`` has no default on purpose: a caller must state what the scan could not read, so
    a blind scan can never score as a clean one by omission (pass ``frozenset()`` only when every
    read succeeded).
    """
    non_compliant = {m.control_id for m in mappings if m.tier == 1}
    out: list[ControlAssessment] = []
    for cid in sorted(checkable | non_compliant):
        if cid in non_compliant:
            status = ComplianceStatus.NON_COMPLIANT
        elif cid in unobserved:
            status = ComplianceStatus.NOT_ASSESSED
        else:
            status = ComplianceStatus.COMPLIANT
        out.append(
            ControlAssessment(control_id=cid, tier=EvidenceTier.TIER_1, status=status, source="finding")
        )
    return out


def attestation_assessments(
    attestations: Sequence[Attestation], *, now: datetime | None = None
) -> list[ControlAssessment]:
    """Each **currently-valid** attestation is a Tier-3 compliant assessment for its control.

    An attestation outside its ``[valid_from, valid_until]`` window is dropped, not counted as
    compliant Tier-3 evidence: a lapsed (or not-yet-valid) self-report must not inflate the
    documented score while :mod:`p2c.attestation.renewal` simultaneously flags it as expired.
    ``now`` is injectable so scoring stays deterministic (defaults to the current UTC time).
    """
    at = now or datetime.now(UTC)
    return [
        ControlAssessment(
            control_id=a.control_id,
            tier=EvidenceTier.TIER_3,
            status=ComplianceStatus.COMPLIANT,
            evidence_ids=[a.attestation_id],
            source="attestation",
        )
        for a in attestations
        if a.valid_from <= at <= a.valid_until
    ]


def _neutralize_refuted(assessments: list[ControlAssessment]) -> list[ControlAssessment]:
    """Flip a Tier-2/Tier-3 COMPLIANT record to NON_COMPLIANT when a Tier-1 non-compliant
    finding on a hierarchically related control refutes it, and to NOT_ASSESSED when it claims a
    control above a Tier-1 control the scan could not read.

    :func:`reconcile` resolves conflicts on the *exact* same control id (lowest tier wins),
    but a coarse (parent-level) attestation refuted by a finding on one of its subcontrols
    carries a different id and would otherwise survive as a satisfied control and inflate
    ``documented_score`` even though
    :func:`p2c.scoring.contradictions.detect_contradictions` flags it. Using the same
    :func:`control_related` relation keeps the two consistent: a flagged self-report can
    never still raise the score.
    """
    tier1_nc = [
        a.control_id
        for a in assessments
        if a.tier == EvidenceTier.TIER_1 and a.status == ComplianceStatus.NON_COMPLIANT
    ]
    tier1_unread = [
        a.control_id
        for a in assessments
        if a.tier == EvidenceTier.TIER_1 and a.status == ComplianceStatus.NOT_ASSESSED
    ]
    if not tier1_nc and not tier1_unread:
        return assessments
    out: list[ControlAssessment] = []
    for a in assessments:
        claim = a.tier != EvidenceTier.TIER_1 and a.status == ComplianceStatus.COMPLIANT
        if claim and any(control_related(a.control_id, nc) for nc in tier1_nc):
            out.append(a.model_copy(update={"status": ComplianceStatus.NON_COMPLIANT}))
        elif claim and any(control_related(a.control_id, cid) for cid in tier1_unread):
            # A claim above a control the scan could not read vouches for something unobserved, so it
            # passes no more than the unread control itself does (block, then claim the parent).
            out.append(a.model_copy(update={"status": ComplianceStatus.NOT_ASSESSED}))
        else:
            out.append(a)
    return out


def merge_assessments(*groups: Sequence[ControlAssessment]) -> list[ControlAssessment]:
    """Merge assessment groups into one per-control set (lowest tier / non-compliant wins).

    Delegates to :func:`p2c.scoring.dual_score.reconcile`, so a tie on tier prefers the
    **non-compliant** assessment (a failure is never hidden by a duplicate compliant one)
    and cross-tier precedence keeps Tier-1 above Tier-2/3. A refuted higher-tier self-report
    at a *different granularity* than the finding is then neutralized (see
    :func:`_neutralize_refuted`). Output is sorted by control id.
    """
    return _neutralize_refuted(reconcile([assessment for group in groups for assessment in group]))
