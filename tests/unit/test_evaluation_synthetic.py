"""Phase-8 synthetic generator: determinism, leakage guard, realism, findings."""

from __future__ import annotations

import json

import pytest

from p2c.evaluation.synthetic import (
    _APEX_ONLY_CHECKS,
    _FALSE_ALARM_CHECKS,
    _HOST_FETCHED_CHECKS,
    CATEGORIES,
    CONDITION_FACTOR_EDGE,
    CONDITION_FACTOR_ORIGIN,
    FALSE_ALARM,
    OFF_SURFACE_COVERAGE,
    SCAN_CONDITIONS,
    SECTORS,
    SENSITIVITY,
    SIZE_BANDS,
    EvalCase,
    expert_key,
    generate_cases,
    off_surface_pools,
)
from p2c.mapping.rules import check_id_from_finding
from p2c.scanning.catalog import CATALOG, CheckId
from p2c.scoring.assemble import TIER1_CHECKABLE
from p2c.scoring.contradictions import control_related


def test_generate_is_deterministic() -> None:
    a = generate_cases(50)
    b = generate_cases(50)
    assert len(a) == 50
    assert [c.case_id for c in a] == [c.case_id for c in b]
    assert [c.profile.apex for c in a] == [c.profile.apex for c in b]
    assert [sorted(c.ground_truth.control_ids) for c in a] == [sorted(c.ground_truth.control_ids) for c in b]


def test_seed_changes_the_corpus() -> None:
    a = generate_cases(20, seed=1)
    b = generate_cases(20, seed=2)
    assert [c.profile.apex for c in a] != [c.profile.apex for c in b]


def test_no_empty_profiles_and_all_sectors_reachable() -> None:
    cases = generate_cases(50)
    assert all(c.injected for c in cases)  # every profile has >=1 finding
    assert all(c.ground_truth.control_ids for c in cases)
    # The corpus draws from multiple sectors (threat-intel weighting is exercised).
    assert len({c.sector for c in cases}) >= 4
    assert {c.sector for c in cases} <= {s.name for s in SECTORS}


def test_size_bands_are_drawn_and_condition_the_estate() -> None:
    # Each profile draws a Class-B firm-size band; the band is a plumbed field on the case, the
    # corpus is small-dominant per the SOURCED Monsha'at split (small 0.89 / medium 0.11), and
    # the estate host count is band-conditioned (small apex+1..4, medium apex+3..8; SOURCES.md §2).
    cases = generate_cases(100)
    bands = {c.size_band for c in cases}
    assert bands <= {b.name for b in SIZE_BANDS}
    assert bands == {"small", "medium"}  # both bands appear on the reported corpus
    n_small = sum(c.size_band == "small" for c in cases)
    assert n_small > sum(c.size_band == "medium" for c in cases)  # small dominates the population
    for c in cases:
        n_hosts = len(c.profile.assets)
        if c.size_band == "small":
            assert 2 <= n_hosts <= 5, (c.case_id, n_hosts)  # apex + 1..4 subdomains
        else:
            assert 4 <= n_hosts <= 9, (c.case_id, n_hosts)  # apex + 3..8 subdomains


def test_ground_truth_never_leaks_into_pipeline_input() -> None:
    # The answer key must be invisible to the pipeline: no gold control id may appear in
    # the profile the pipeline receives, nor in the findings fed to the mapper (pre-map).
    for case in generate_cases(50):
        visible = json.dumps(case.pipeline_input().model_dump(mode="json"))
        assert not any(cid in visible for cid in case.ground_truth.control_ids)
        for finding in case.findings():
            assert finding.control_ids == []  # scanner findings carry no mapping yet
            dumped = json.dumps(finding.model_dump(mode="json"), default=str)
            assert not any(cid in dumped for cid in case.ground_truth.control_ids)


def test_profiles_span_postures_and_include_overstatements() -> None:
    cases = generate_cases(50)
    assert {c.posture for c in cases} <= {"strong", "moderate", "weak"}
    assert len({c.posture for c in cases}) >= 2  # the corpus spans more than one maturity level
    # At least one profile self-attests a control it truly violates (an overstatement to catch).
    overstated = sum(len({a.control_id for a in c.attestations} & c.ground_truth.control_ids) for c in cases)
    assert overstated > 0


def test_observed_state_differs_from_truth() -> None:
    # The scanner detection model must actually perturb the truth: across the corpus there
    # are both missed detections (truly present, not observed) and false alarms (observed,
    # not truly present). Each case's observed set drives findings(); the true set is hidden.
    cases = generate_cases(50)
    missed = false_alarm = 0
    for c in cases:
        true = {(i.asset, i.check) for i in c.true_injected}
        observed = {(i.asset, i.check) for i in c.injected}
        missed += len(true - observed)
        false_alarm += len(observed - true)
    assert missed > 0, "detection model never misses a truly-present issue"
    assert false_alarm > 0, "detection model never raises a false alarm"


def test_findings_recover_their_check_id() -> None:
    # finding_id must start with the check value so the mapping engine can recover it.
    case = generate_cases(5)[0]
    for finding, inj in zip(case.findings(), case.injected, strict=True):
        assert check_id_from_finding(finding) == inj.check


def test_expert_key_covers_all_checks_and_is_catalog_valid() -> None:
    key = expert_key()
    all_checks = {c for checks in CATEGORIES.values() for c in checks}
    assert set(key) == all_checks
    # The key is the catalog's links; the hardening detectors map to none (2026-10-20 recode).
    assert all(key[c] == frozenset(CATALOG[c].control_ids) for c in key)
    assert sum(1 for ids in key.values() if ids) == 17


def test_generate_rejects_nonpositive_n() -> None:
    with pytest.raises(ValueError, match="positive"):
        generate_cases(0)


def test_case_is_frozen_dataclass() -> None:
    case = generate_cases(1)[0]
    assert isinstance(case, EvalCase)
    with pytest.raises(AttributeError):
        case.sector = "hacked"  # type: ignore[misc]


def test_false_alarm_model_has_no_dead_entries() -> None:
    # The detection model must not document a false-alarm rate it never applies: the set of checks
    # with a nonzero FALSE_ALARM is exactly the set the observer draws spurious detections for.
    nonzero = {c for c, v in FALSE_ALARM.items() if v > 0.0}
    assert set(_FALSE_ALARM_CHECKS) == nonzero
    assert len(_FALSE_ALARM_CHECKS) == len(set(_FALSE_ALARM_CHECKS))  # no duplicates in the ordered tuple
    # Deterministic reads (headers, DNS records, cert validity) carry a 0.0 rate, by design.
    assert FALSE_ALARM[CheckId.MISSING_HSTS] == 0.0
    assert FALSE_ALARM[CheckId.SPF_MISSING] == 0.0
    # Every check still has both a sensitivity and a false-alarm entry (full coverage).
    all_checks = {c for checks in CATEGORIES.values() for c in checks}
    assert set(SENSITIVITY) == all_checks and set(FALSE_ALARM) == all_checks


def test_scan_conditions_are_drawn_and_deterministic() -> None:
    cases = generate_cases(50)
    for c in cases:
        # Every host has a condition, drawn from the defined set; competence is in its band.
        assert set(c.scan_conditions.values()) <= set(SCAN_CONDITIONS)
        assert len(c.scan_conditions) == len(c.profile.assets)
        assert 0.97 <= c.scanner_competence <= 1.0
    # Deterministic across regeneration.
    again = generate_cases(50)
    assert [c.scan_conditions for c in cases] == [c.scan_conditions for c in again]
    assert [c.scanner_competence for c in cases] == [c.scanner_competence for c in again]
    # A CDN hides origin checks far more than edge checks (origin factor < edge factor when fronted).
    assert CONDITION_FACTOR_ORIGIN["cdn_fronted"] < CONDITION_FACTOR_EDGE["cdn_fronted"]
    assert CONDITION_FACTOR_ORIGIN["reachable"] == CONDITION_FACTOR_EDGE["reachable"] == 1.0


def test_obstruction_reduces_detection_but_dns_signals_are_exempt() -> None:
    # Correlated obstruction must actually cost some detections (blocked/CDN hosts miss more), while
    # DNS-observable apex signals (email/DNS/DDoS) are not gated by a host's HTTP reachability.
    assert _HOST_FETCHED_CHECKS.isdisjoint(_APEX_ONLY_CHECKS)  # exempt sets do not overlap
    cases = generate_cases(80)
    # There is at least one obstructed host in the corpus (the model is actually exercised).
    obstructed = sum(1 for c in cases for cond in c.scan_conditions.values() if cond != "reachable")
    assert obstructed > 0


def test_forced_fallback_never_fires_on_the_reported_corpus() -> None:
    # The never-empty-org fallback exists only as a safety net; on the reported corpus (n=100,
    # default seed) it does not fire, so no profile's truth is synthesized outside the prior model.
    # If a future prior change makes it fire, this fails loudly rather than silently biasing a category.
    cases = generate_cases(100)
    assert sum(c.forced_true_fallback for c in cases) == 0


def test_a_scan_that_detects_nothing_keeps_an_empty_finding_set() -> None:
    # Leakage control: no true issue is ever copied into the observation, even when the detection
    # draw misses every one of them (a scan with no findings is a valid outcome).
    import random  # noqa: PLC0415

    from p2c.evaluation.synthetic import InjectedFinding, _observe  # noqa: PLC0415

    class _Never(random.Random):
        def random(self) -> float:  # every draw fails: no detection, no false positive
            return 1.0

    true = [InjectedFinding(asset="example.sa", check=next(iter(expert_key())))]
    assert _observe(_Never(0), true, ["example.sa"], "example.sa", {"example.sa": "reachable"}, 1.0) == []


# ---- Off-surface evidence (Tier 2 and Tier 3 beyond the scan's reach) ----


def test_off_surface_pools_come_from_the_overlay_and_are_unreachable_by_a_scan() -> None:
    # The pools are exactly the tracked overlay's internal-assessment and declaration rows, and no
    # control in either can be reached by a Tier-1 finding. That second property is what makes an
    # off-surface declaration unrefutable by construction, so it is asserted, not assumed.
    from p2c.scoring.contradictions import IMPLEMENTS, hierarchy_related  # noqa: PLC0415

    internal, declarable = off_surface_pools()
    assert (len(internal), len(declarable)) == (127, 59)  # Table 2 (2026-10-21: NCNICC 2-7-1-1 added, Tier 2)
    assert not set(internal) & set(declarable)
    for cid in (*internal, *declarable):
        assert not any(hierarchy_related(cid, checkable) for checkable in TIER1_CHECKABLE)
        # Nor below one: the guard keeps both directions of the hierarchy off surface.
        assert not any(hierarchy_related(checkable, cid) for checkable in TIER1_CHECKABLE)
        # A finding reaches a pool row only through rule 4 (a list implemented), on purpose.
        reached = any(control_related(cid, checkable) for checkable in TIER1_CHECKABLE)
        assert reached == (cid in IMPLEMENTS), cid
    assert list(internal) == sorted(internal) and list(declarable) == sorted(declarable)


def test_off_surface_evidence_is_present_schema_valid_and_deterministic() -> None:
    cases = generate_cases(50)
    internal_pool, declaration_pool = set(off_surface_pools()[0]), set(off_surface_pools()[1])
    assert any(c.internal_evidence for c in cases)
    for case in cases:
        for record in case.internal_evidence:
            assert record.control_id in internal_pool
            assert isinstance(record.compliant, bool)
        # A firm assesses a control at most once internally.
        ids = [r.control_id for r in case.internal_evidence]
        assert len(ids) == len(set(ids))
        off_surface = [a for a in case.attestations if a.control_id not in TIER1_CHECKABLE]
        assert all(a.control_id in declaration_pool for a in off_surface)
    again = generate_cases(50)
    assert [c.internal_evidence for c in cases] == [c.internal_evidence for c in again]
    assert [[a.control_id for a in c.attestations] for c in cases] == [
        [a.control_id for a in c.attestations] for c in again
    ]
    # An internal assessment returns some gaps as well as some implemented controls.
    readings = {r.compliant for c in cases for r in c.internal_evidence}
    assert readings == {True, False}


def test_off_surface_coverage_rises_with_posture() -> None:
    # The declared prior is posture-correlated; the realized corpus must show it, so a future
    # reordering of the priors cannot pass unnoticed.
    assert OFF_SURFACE_COVERAGE["strong"] > OFF_SURFACE_COVERAGE["moderate"] > OFF_SURFACE_COVERAGE["weak"]
    per_posture: dict[str, list[int]] = {"strong": [], "moderate": [], "weak": []}
    for case in generate_cases(100):
        off = len(case.internal_evidence) + sum(
            1 for a in case.attestations if a.control_id not in TIER1_CHECKABLE
        )
        per_posture[case.posture].append(off)
    means = {p: sum(v) / len(v) for p, v in per_posture.items() if v}
    assert means["strong"] > means["moderate"] > means["weak"]


def test_off_surface_evidence_is_drawn_last_and_moves_no_earlier_draw(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The containment invariant: the off-surface stream is the LAST draw of a case.

    Changing it must leave the estate, the true issues, the observed findings, and the on-surface
    declarations byte-identical, because every one of those draws already happened. If it ever
    moves earlier in the sequence, every recovery and contradiction number in the toolkit shifts,
    which is exactly the silent failure this pins down.
    """

    def fingerprint(case: EvalCase) -> tuple[object, ...]:
        return (
            case.case_id,
            case.sector,
            case.size_band,
            case.posture,
            case.profile.apex,
            tuple(a.value for a in case.profile.assets),
            tuple(sorted(case.scan_conditions.items())),
            case.scanner_competence,
            case.true_injected,
            case.injected,
            tuple(sorted(case.ground_truth.control_ids)),
            tuple(
                (a.attestation_id, a.valid_from, a.valid_until)
                for a in case.attestations
                if a.control_id in TIER1_CHECKABLE
            ),
        )

    before = [fingerprint(c) for c in generate_cases(40)]
    off_before = [c.internal_evidence for c in generate_cases(40)]
    for posture, share in (("strong", 0.5), ("moderate", 0.4), ("weak", 0.3)):
        monkeypatch.setitem(OFF_SURFACE_COVERAGE, posture, share)
    after_cases = generate_cases(40)
    assert [fingerprint(c) for c in after_cases] == before
    assert [c.internal_evidence for c in after_cases] != off_before  # the stream itself did move
