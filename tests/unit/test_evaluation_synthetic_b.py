"""Cohort B (R2): a second, structurally independent generator on the same schema.

Mirrors the cohort-A generator tests (determinism, leakage guard, schema, findings) and adds the
structural-difference checks that make cohort B a genuine second population rather than a reskin of
cohort A. Cohort B is never tuned against cohort A; these tests assert its structure, not a target
number (the transfer numbers are gated in verify_numbers.py against the artifact)."""

from __future__ import annotations

import json

import pytest

from p2c.evaluation.synthetic import (
    _APEX_ONLY_CHECKS,
    CATEGORIES,
    expert_key,
    off_surface_pools,
)
from p2c.evaluation.synthetic import (
    _SUBDOMAIN_POOLS as COHORT_A_POOLS,
)
from p2c.evaluation.synthetic_b import (
    BASE_PREVALENCE,
    SECTORS_B,
    EvalCase,
    generate_cases_b,
)
from p2c.mapping.rules import check_id_from_finding
from p2c.scanning.catalog import CheckId
from p2c.scoring.assemble import TIER1_CHECKABLE
from p2c.scoring.contradictions import control_related


def test_generate_b_is_deterministic() -> None:
    a = generate_cases_b(50)
    b = generate_cases_b(50)
    assert len(a) == 50
    assert [c.case_id for c in a] == [c.case_id for c in b]
    assert [c.profile.apex for c in a] == [c.profile.apex for c in b]
    assert [sorted(c.ground_truth.control_ids) for c in a] == [sorted(c.ground_truth.control_ids) for c in b]


def test_seed_changes_the_b_corpus() -> None:
    a = generate_cases_b(20, seed=1)
    b = generate_cases_b(20, seed=2)
    assert [c.profile.apex for c in a] != [c.profile.apex for c in b]


def test_b_does_not_alias_cohort_a_domains() -> None:
    # The seed offset must keep the two corpora on disjoint apex domains, so a cross-generator run is a
    # genuinely different population and not the same firms relabelled.
    from p2c.evaluation.synthetic import generate_cases  # noqa: PLC0415 - only needed here

    apex_a = {c.profile.apex for c in generate_cases(100)}
    apex_b = {c.profile.apex for c in generate_cases_b(100)}
    assert apex_a.isdisjoint(apex_b)


def test_b_case_matches_the_shared_schema() -> None:
    case = generate_cases_b(1)[0]
    assert isinstance(case, EvalCase)
    assert case.case_id.startswith("evalb-")
    assert case.profile.apex == case.profile.assets[0].value
    # Findings recover their check id so the shared mapping engine can consume them unchanged.
    for finding, inj in zip(case.findings(), case.injected, strict=True):
        assert check_id_from_finding(finding) == inj.check
    with pytest.raises(AttributeError):
        case.sector = "hacked"  # type: ignore[misc]


def test_b_uses_a_different_subdomain_naming_convention() -> None:
    # Structural difference 1: cohort B uses flat indexed functional hostnames (svcN) plus a single
    # positional dev token, NOT cohort A's sector-keyed semantic pools. So cohort B must emit svc-indexed
    # labels, which cohort A never does, and must not emit cohort A's characteristic semantic labels.
    labels: set[str] = set()
    for c in generate_cases_b(100):
        for asset in c.profile.assets[1:]:  # skip the apex
            labels.add(asset.value.split(".", 1)[0])
    assert any(label.startswith("svc") for label in labels), "cohort B did not emit indexed svc hostnames"
    cohort_a_labels = {label for pool in COHORT_A_POOLS.values() for label in pool}
    distinctive_a = cohort_a_labels - {"dev", "staging", "uat", "test", "sandbox"}  # dev tokens are shared
    assert labels.isdisjoint(distinctive_a), "cohort B leaked cohort A's semantic pool labels"
    # No cohort-B label is a sector-keyed pool name; every non-dev label is svc-indexed.
    assert all(label.startswith("svc") or label == "sandbox" for label in labels)


def test_b_posture_is_continuous_not_three_bands() -> None:
    # Structural difference 3: cohort B's posture is a continuous per-firm neglect, so the corpus is not
    # confined to cohort A's three discrete bands. The schema field is a coarse label, but the underlying
    # true-issue counts should spread more finely than three values would allow.
    cases = generate_cases_b(100)
    distinct_true_counts = {len(c.true_injected) for c in cases}
    assert len(distinct_true_counts) > 10  # a continuum, not a handful of banded levels
    assert {c.sector for c in cases} <= {s.name for s in SECTORS_B}
    assert len({c.sector for c in cases}) >= 3  # multiple B sectors are exercised


def test_b_ground_truth_never_leaks_into_pipeline_input() -> None:
    # The leakage guard must hold for cohort B exactly as for cohort A: no gold control id may appear in
    # the pipeline-visible profile or in the pre-map findings.
    for case in generate_cases_b(50):
        visible = json.dumps(case.pipeline_input().model_dump(mode="json"))
        assert not any(cid in visible for cid in case.ground_truth.control_ids)
        for finding in case.findings():
            assert finding.control_ids == []
            dumped = json.dumps(finding.model_dump(mode="json"), default=str)
            assert not any(cid in dumped for cid in case.ground_truth.control_ids)


def test_b_observed_state_differs_from_truth() -> None:
    # The SHARED detection model must actually perturb cohort B's truth too: both missed detections and
    # false alarms appear across the corpus (the same two error modes that bound recovery on cohort A).
    missed = false_alarm = 0
    for c in generate_cases_b(50):
        true = {(i.asset, i.check) for i in c.true_injected}
        observed = {(i.asset, i.check) for i in c.injected}
        missed += len(true - observed)
        false_alarm += len(observed - true)
    assert missed > 0 and false_alarm > 0


def test_b_corpus_is_non_degenerate_and_exercises_every_control() -> None:
    cases = generate_cases_b(100)
    assert all(c.injected for c in cases)  # every profile carries at least one observed finding
    true = set().union(*(set(c.ground_truth.control_ids) for c in cases))
    assert len(true) == 11  # all 11 covered controls are truly present somewhere in the corpus
    # The never-empty-organization guard is a safety net; on the reported corpus it may fire on a
    # genuinely near-clean firm under the continuous posture, but only rarely (disclosed in DECISIONS).
    assert sum(c.forced_true_fallback for c in cases) <= 2


def test_b_base_prevalence_covers_every_non_role_check() -> None:
    # The per-host neglect model must define a base prevalence for every host- and apex-observable check;
    # only the two role checks (login panel, dev environment) are placed by role instead.
    all_checks = {c for checks in CATEGORIES.values() for c in checks}
    role_checks = {CheckId.EXPOSED_LOGIN_PANEL, CheckId.EXPOSED_DEV_ENVIRONMENT}
    assert set(BASE_PREVALENCE) == all_checks - role_checks
    assert all(0.0 <= v <= 1.0 for v in BASE_PREVALENCE.values())


def test_b_shares_the_expert_key_and_apex_placement() -> None:
    # Cohort B must reuse the SHARED mapping (expert_key) and keep apex-only checks at the apex, so the
    # identical harness scores it. Every apex-only true issue in cohort B sits on the apex domain.
    key = expert_key()
    for c in generate_cases_b(50):
        for inj in c.true_injected:
            assert inj.check in key
            if inj.check in _APEX_ONLY_CHECKS:
                assert inj.asset == c.profile.apex


def test_generate_b_rejects_nonpositive_n() -> None:
    with pytest.raises(ValueError, match="positive"):
        generate_cases_b(0)


def test_b_carries_the_same_off_surface_evidence_stream() -> None:
    """Cohort B runs the identical three-tier evidence model, drawn last.

    Cohort B reports recovery and contradiction only, neither of which the off-surface stream can
    touch, so extending it changes none of its gated numbers. It is extended anyway: running one
    cohort two-tier and the other three-tier would make the two populations differ in the pipeline
    they exercise as well as in their structure, and the comparison isolates structure alone.
    """
    internal_pool, declaration_pool = off_surface_pools()
    cases = generate_cases_b(50)
    assert any(c.internal_evidence for c in cases)
    for case in cases:
        assert all(r.control_id in set(internal_pool) for r in case.internal_evidence)
        off_surface = [a for a in case.attestations if a.control_id not in TIER1_CHECKABLE]
        assert all(a.control_id in set(declaration_pool) for a in off_surface)
        # Unrefutable by construction, so cohort B's contradiction numbers cannot move.
        for cid in {a.control_id for a in off_surface}:
            assert not any(control_related(cid, checkable) for checkable in TIER1_CHECKABLE)
            assert not any(control_related(checkable, cid) for checkable in TIER1_CHECKABLE)
    assert [c.internal_evidence for c in cases] == [c.internal_evidence for c in generate_cases_b(50)]
