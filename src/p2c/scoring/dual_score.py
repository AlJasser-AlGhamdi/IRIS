"""Dual scoring: assessed (Tier-1) vs documented (all-tier) — never merged (Stage 5).

``assessed_score`` is the weighted fraction of **externally-verifiable Tier-1** controls
observed with no violation (an unread control never counts); ``documented_score`` is the
weighted fraction of the **full** control set that is satisfied by evidence of any tier.
The two are reported side by side (never collapsed into one number) so a Tier-3
self-attestation can never inflate the externally-attributable picture.
``gap = 1 - assessed_score`` is the share of the assessed surface not observed clean:
observed violated, or not read at all.

Design invariants (enforced as property tests, spec §Phase 5):
- both scores are always in [0, 1];
- a Tier-1 control flipping compliant→non-compliant never *increases* ``assessed_score``;
- marking a control satisfied (adding consistent evidence) never *decreases*
  ``documented_score``.
"""

from __future__ import annotations

from collections.abc import Collection, Iterable, Mapping, Sequence

from p2c.scoring.models import ComplianceStatus, ControlAssessment, DualScore


def _supersedes(new: ControlAssessment, current: ControlAssessment) -> bool:
    """True if ``new`` is more authoritative than ``current`` for the same control.

    **Lowest evidence tier always wins** (external Tier-1 overrides a self-report) — this is the
    load-bearing rule: a higher-tier record (e.g. a Tier-3 attestation) must NEVER evict a
    lower-tier one, because doing so would drop a Tier-1-classified control out of the
    ``assessed_score`` universe and let the attestation inflate the externally-attributable score.
    On a **tie**: an assessed record (compliant/non-compliant) beats a ``NOT_ASSESSED`` one (real
    evidence over absence of evidence); among two assessed records, non-compliant wins over
    compliant (a compliance tool must never hide a detected failure behind a satisfied duplicate).
    """
    if new.tier != current.tier:
        return new.tier < current.tier  # lower tier is more authoritative, regardless of status
    new_unassessed = new.status is ComplianceStatus.NOT_ASSESSED
    current_unassessed = current.status is ComplianceStatus.NOT_ASSESSED
    if new_unassessed != current_unassessed:
        return current_unassessed  # same tier: the assessed record wins over NOT_ASSESSED
    return current.satisfied and not new.satisfied


def reconcile(assessments: Iterable[ControlAssessment]) -> list[ControlAssessment]:
    """Collapse to one assessment per control (lowest tier / non-compliant wins).

    The scorer operates on a per-control set; duplicate control ids (a control assessed
    at several tiers) are reconciled here so ``documented_score`` is a true set fraction
    and a Tier-3 self-report can never double-count or mask a Tier-1 finding. Output is
    sorted by control id (deterministic).
    """
    best: dict[str, ControlAssessment] = {}
    for a in assessments:
        current = best.get(a.control_id)
        if current is None or _supersedes(a, current):
            best[a.control_id] = a
    return [best[cid] for cid in sorted(best)]


def _weighted(assessments: Iterable[ControlAssessment]) -> tuple[float, float]:
    """Return (satisfied_weight, total_weight) over the given assessments."""
    total = 0.0
    satisfied = 0.0
    for a in assessments:
        total += a.weight
        if a.satisfied:
            satisfied += a.weight
    return satisfied, total


def compute_dual_score(
    assessments: Sequence[ControlAssessment],
    *,
    weights_source: str = "uniform",
    universe: Collection[str] | None = None,
) -> DualScore:
    """Compute the assessed (Tier-1) and documented (all-tier) scores.

    Each assessment carries its own ``weight`` (uniform by default; set via AHP/BWM
    domain weights, see :func:`apply_weights`). Input is **reconciled to one assessment
    per control** first (so a control at multiple tiers is never double-counted). A
    control counts toward ``assessed`` only if its tier is Tier-1; toward ``documented``
    regardless of tier. A Tier-1 control that is ``NOT_ASSESSED`` (not observed) never passes,
    and ``coverage`` reports the share of the Tier-1 weight the scan did observe, separately.

    ``universe`` fixes the documented set: the score is taken over exactly those rows, a row with
    no assessed evidence counts as not passing, and a record on a row outside the set is ignored,
    so neither withholding nor filing a record outside it can raise the score, and withholding one
    inside it never scores better than submitting a failing one. ``evidence_coverage`` is the share
    of the set with assessed evidence. A universe requires uniform weights (``ValueError``
    otherwise). Without a universe the documented score is over the records given.
    """
    # A recorded gap stands in the documented score over a scan that observed none: no violation
    # observed says nothing of the requirements the scan cannot see. The assessed score stays the scan's.
    recorded_gap = {a.control_id for a in assessments if a.tier > 1 and a.status is ComplianceStatus.NON_COMPLIANT}
    assessments = reconcile(assessments)

    def passes(a: ControlAssessment) -> bool:
        return a.satisfied and not (a.tier == 1 and a.control_id in recorded_gap)

    tier1 = [a for a in assessments if a.tier == 1]
    tier1_compliant, tier1_total = _weighted(tier1)
    # Accumulated exactly like _weighted's total (a plain loop, not sum(), which compensates), so a
    # fully observed estate gives coverage exactly 1.0.
    tier1_observed = 0.0
    for a in tier1:
        if a.status is not ComplianceStatus.NOT_ASSESSED:
            tier1_observed += a.weight

    if universe is not None:
        if any(a.weight != 1.0 for a in assessments):
            raise ValueError(
                "a fixed documented set needs uniform weights: an unevidenced row has no group to take "
                "a share from, so weighted scoring over a universe could reward withholding evidence"
            )
        rows = set(universe)
        in_set = [a for a in assessments if a.control_id in rows]  # records outside the set are ignored
        documented_satisfied = float(sum(1 for a in in_set if passes(a)))
        documented_total = float(len(rows))
        evidenced = float(sum(1 for a in in_set if a.status is not ComplianceStatus.NOT_ASSESSED))
    else:
        documented_total = 0.0
        documented_satisfied = 0.0
        for a in assessments:  # a plain loop, as in _weighted
            documented_total += a.weight
            if passes(a):
                documented_satisfied += a.weight
        evidenced = 0.0
        for a in assessments:
            if a.status is not ComplianceStatus.NOT_ASSESSED:
                evidenced += a.weight

    assessed = tier1_compliant / tier1_total if tier1_total > 0 else 0.0
    documented = documented_satisfied / documented_total if documented_total > 0 else 0.0
    return DualScore(
        assessed_score=assessed,
        documented_score=documented,
        gap=1.0 - assessed,
        tier1_total_weight=tier1_total,
        tier1_compliant_weight=tier1_compliant,
        documented_total_weight=documented_total,
        documented_satisfied_weight=documented_satisfied,
        coverage=tier1_observed / tier1_total if tier1_total > 0 else 0.0,
        evidence_coverage=evidenced / documented_total if documented_total > 0 else 0.0,
        weights_source=weights_source,
    )


def apply_weights(
    assessments: Sequence[ControlAssessment], group_weights: Mapping[str, float], *, key: str = "domain"
) -> list[ControlAssessment]:
    """Distribute group weights (e.g. AHP domain weights) across each group's controls.

    ``group_weights`` maps a group id (the control's domain ``2`` or subdomain ``2-5``)
    to that group's weight; each control in the group gets an equal share, so the group's
    controls sum to the group weight. Controls whose group is absent keep weight 1.0.
    A non-positive group weight is rejected (weights are positive by construction — AHP/BWM
    weights sum to 1) rather than silently clamped. Returns new assessments (not mutated).

    The share denominator counts **distinct control ids**, not assessments: a control carrying
    evidence at multiple tiers (a Tier-1 scan + a Tier-3 attestation) must count once, so that
    after :func:`reconcile` collapses it to one record the group still sums to the group weight.
    Counting assessments would understate the group's weight for any multi-tier control.
    """
    bad = {g: w for g, w in group_weights.items() if w <= 0}
    if bad:
        raise ValueError(f"group weights must be positive, got {bad}")

    group_ids: dict[str, set[str]] = {}
    for a in assessments:
        group_ids.setdefault(_group_of(a.control_id, key), set()).add(a.control_id)

    out: list[ControlAssessment] = []
    for a in assessments:  # original order preserved
        group = _group_of(a.control_id, key)
        share = group_weights.get(group)
        weight = (share / len(group_ids[group])) if share is not None else 1.0
        out.append(a.model_copy(update={"weight": weight}))
    return out


def _group_of(control_id: str, key: str) -> str:
    parts = control_id.split("-")
    if key == "domain":
        return parts[0]
    if key == "subdomain":
        return "-".join(parts[:2])
    raise ValueError(f"unknown group key {key!r} (want 'domain' or 'subdomain')")
