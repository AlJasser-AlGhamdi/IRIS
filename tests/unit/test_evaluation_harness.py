"""Phase-8 harness: reproduce determinism, correct metrics, regenerable outputs."""

from __future__ import annotations

import dataclasses
import inspect
import json
from pathlib import Path

import pytest

from p2c.evaluation import synthetic as syn
from p2c.evaluation.ablation import naive_keyword_baseline
from p2c.evaluation.baselines import embedding_cosine_baseline, hermetic_baselines
from p2c.evaluation.harness import (
    _all_tier_assessments,
    _predict,
    cross_generator_report,
    measure_wall_clock,
    reproduce,
    robustness_report,
    run_evaluation,
    sensitivity_to_attestation_rate,
    sensitivity_to_corpus_priors,
    sensitivity_to_detection_assumptions,
    sensitivity_to_scan_conditions,
    sensitivity_to_weighting,
    stability_across_seeds,
    write_outputs,
)
from p2c.evaluation.synthetic import generate_cases
from p2c.mapping.rules import MappingEngine
from p2c.scoring.assemble import TIER1_CHECKABLE
from p2c.scoring.contradictions import detect_contradictions
from p2c.scoring.dual_score import compute_dual_score


def test_run_is_fully_deterministic() -> None:
    a = run_evaluation(50)
    b = run_evaluation(50)
    assert dataclasses.asdict(a) == dataclasses.asdict(b)


def test_reproduce_writes_byte_identical_outputs(tmp_path: Path) -> None:
    reproduce(tmp_path / "a", n=30)
    reproduce(tmp_path / "b", n=30)
    # EVERY written table must be byte-identical across runs, not just a subset.
    files_a = sorted(p.name for p in (tmp_path / "a").glob("*.json"))
    files_b = sorted(p.name for p in (tmp_path / "b").glob("*.json"))
    assert files_a == files_b and files_a, "reproduce wrote a different set of files"
    for name in files_a:
        first = (tmp_path / "a" / name).read_text(encoding="utf-8")
        second = (tmp_path / "b" / name).read_text(encoding="utf-8")
        assert first == second, f"{name} is not reproducible"


def test_outputs_regenerate_from_scratch(tmp_path: Path) -> None:
    report = run_evaluation(20)
    paths = write_outputs(report, tmp_path)
    assert (tmp_path / "report.json").exists()
    # Every table is valid JSON and non-empty.
    for p in paths:
        assert json.loads(p.read_text(encoding="utf-8"))


def test_mapping_metrics_are_correct_on_the_deterministic_corpus() -> None:
    # The deterministic rule path is correct-by-construction, so the pipeline reproduces
    # the expert mapping exactly: exact-micro P/R/F1 == 1.0 (pipeline-integrity result).
    report = run_evaluation(50)
    exact = report.mapping["exact_micro"]
    assert exact["precision"] == 1.0 and exact["recall"] == 1.0 and exact["f1"] == 1.0
    # Fuzzy is at least as good as exact.
    assert report.mapping["fuzzy70_micro"]["f1"] >= exact["f1"]
    # Macro-F1 CI is well-formed.
    ci = report.mapping["macro_f1"]
    assert ci["ci_low"] <= ci["point"] <= ci["ci_high"]


def test_mapping_integrity_is_perfect_but_end_to_end_is_not() -> None:
    # Integrity (vs what the scanner observed) is correct by construction; end-to-end (vs the
    # TRUE control state) loses precision/recall to the modelled scanner detection error.
    report = run_evaluation(50)
    integ = report.mapping["exact_micro"]["f1"]
    e2e = report.end_to_end["exact_micro"]["f1"]
    assert integ == 1.0
    assert 0.80 < e2e < 1.0, f"end-to-end F1 {e2e} should be realistic, below 1.0"
    conf = report.end_to_end["confusion"]
    assert conf["fp"] > 0 and conf["fn"] > 0  # both false alarms and missed detections appear


def test_decision_universe_reconciles_with_the_confusion_counts() -> None:
    # The recovery universe is one binary decision per organization per reached control, so the
    # four cells must sum to it and the reported F1 must recompute from three of them. Without
    # that reconciliation the MCC and balanced accuracy would be measuring a different table.
    report = run_evaluation(50)
    conf, uni = report.end_to_end["confusion"], report.end_to_end["decision_universe"]
    assert uni["n_decisions"] == 50 * uni["n_controls"]
    assert conf["tp"] + conf["fp"] + conf["fn"] + uni["tn"] == uni["n_decisions"]
    tp, fp, fn = conf["tp"], conf["fp"], conf["fn"]
    assert report.end_to_end["exact_micro"]["f1"] == pytest.approx(2 * tp / (2 * tp + fp + fn))
    # Both whole-table measures beat the predict-all floor, which sits at 0.0 and 0.5 whatever
    # the base rate is, so the margin does not depend on how rich the corpus is.
    floor = report.trivial_floor["corpus"]
    assert floor["mcc"] == 0.0 and floor["balanced_accuracy"] == pytest.approx(0.5)
    assert uni["mcc"] > 0.5 and uni["balanced_accuracy"] > 0.5


def test_detection_model_misses_and_false_alarms() -> None:
    d = run_evaluation(50).detection
    assert d["n_missed"] > 0 and d["n_false_alarm"] > 0
    assert d["recall"] < 1.0  # finite scanner sensitivity
    # Software (banner-based) and ports are the weakest sensing categories.
    assert d["per_category"]["software"]["missed"] > 0


def test_contradiction_detection_is_measured_and_imperfect() -> None:
    # ATLAS's differentiator: catch a Tier-3 attestation that a Tier-1 finding refutes.
    c = run_evaluation(50).contradictions
    assert c["n_attestations"] > 0 and c["true_contradictions"] > 0
    assert 0.5 < c["f1"] <= 1.0
    # Detection error makes it imperfect: a missed overstatement or a false accusation appears.
    assert c["fp"] > 0 or c["fn"] > 0


def test_naive_keyword_baseline_is_far_below_the_curated_rules() -> None:
    # The curated mapping is not lexically recoverable: a naive keyword baseline scores far
    # below the curated rules (which are 1.000 by construction), so the cross-walk adds value.
    b = naive_keyword_baseline(50)
    assert b["curated_f1"] == 1.0
    assert b["micro_f1"] < 0.4


def test_contradiction_f1_carries_a_confidence_interval() -> None:
    ci = run_evaluation(50).contradictions["f1_ci"]
    assert ci["ci_low"] <= ci["point"] <= ci["ci_high"]
    assert ci["ci_low"] >= 0.0 and ci["ci_high"] <= 1.0


def test_per_control_covers_eleven_with_support() -> None:
    pc = run_evaluation(100).per_control
    assert len(pc) == 11
    assert all(v["support"] > 0 for v in pc.values())


def test_contradiction_recall_is_stable_across_overstatement_rates() -> None:
    # Catching an overstatement depends on the scanner, not on how often orgs overstate, so
    # recall is near-constant across the modelled rate (precision rises with the rate).
    sweep = sensitivity_to_attestation_rate(40, rates=(0.3, 0.7))
    recalls = [v["recall"] for v in sweep.values()]
    assert max(recalls) - min(recalls) < 0.1


def test_per_posture_shows_the_base_rate_effect() -> None:
    # The base-rate effect, demonstrated: precision climbs strong -> moderate -> weak as the
    # true gaps come to outnumber the scanner's false alarms. Recall stays high throughout;
    # the strong stratum is thin (n=13 firms, few true issues), so its recall wobbles with
    # the draw (0.887 on the incident-informed corpus) and the bound sits below that noise.
    pp = run_evaluation(100).per_posture
    assert set(pp) == {"strong", "moderate", "weak"}
    assert pp["strong"]["precision"] < pp["moderate"]["precision"] < pp["weak"]["precision"]
    assert all(pp[lv]["recall"] > 0.85 for lv in pp)


def test_per_size_stratifies_small_and_medium() -> None:
    # The size-band stratification mirrors per_sector/per_posture: each band carries its n, an
    # F1 CI, and an underpowered flag; empty strata are skipped, not averaged into a spurious
    # point. Small firms dominate the Class-B population, so the small slice is always present.
    r = run_evaluation(100)
    ps = r.per_size
    assert set(ps) <= {"small", "medium"}
    assert "small" in ps
    assert sum(v["n"] for v in ps.values()) == 100
    assert {b: v["n"] for b, v in ps.items()} == r.size_band_counts
    for v in ps.values():
        assert v["n"] > 0
        assert v["f1_ci"]["ci_low"] <= v["f1"] <= v["f1_ci"]["ci_high"]
        assert isinstance(v["underpowered"], bool)


def test_posture_spans_a_spectrum() -> None:
    p = run_evaluation(50).posture
    assert p["true_assessed_max"] > p["true_assessed_min"]  # orgs are not all equally (in)secure
    assert 0.0 <= p["assessed_mae"] < 0.5  # ATLAS tracks the true posture within a sane band


def test_perfect_sensing_recovers_the_truth_exactly() -> None:
    # Metamorphic property: with a perfect scanner (signal reliability 1, no false alarms, every host
    # reachable, full competence) the observed state equals the true state, so end-to-end recovery
    # must be exactly 1.000. This proves the modelled detection error and the acquisition condition
    # are the SOLE sources of the end-to-end gap from 1.0.
    base_s, base_f = dict(syn.SENSITIVITY), dict(syn.FALSE_ALARM)
    base_shares = dict(syn.CONDITION_SHARES)
    base_comp = (syn.COMPETENCE_MIN, syn.COMPETENCE_MAX)
    try:
        for cid in base_s:
            syn.SENSITIVITY[cid] = 1.0
            syn.FALSE_ALARM[cid] = 0.0
        # A perfect scan reaches every host with full competence, so no acquisition loss remains.
        syn.CONDITION_SHARES.update({"reachable": 1.0, "throttled": 0.0, "cdn_fronted": 0.0, "blocked": 0.0})
        syn.COMPETENCE_MIN = syn.COMPETENCE_MAX = 1.0
        e = run_evaluation(50).end_to_end["exact_micro"]
        assert e["precision"] == 1.0 and e["recall"] == 1.0 and e["f1"] == 1.0
    finally:
        syn.SENSITIVITY.update(base_s)
        syn.FALSE_ALARM.update(base_f)
        syn.CONDITION_SHARES.update(base_shares)
        syn.COMPETENCE_MIN, syn.COMPETENCE_MAX = base_comp


def test_robustness_helpers_report_a_tight_band() -> None:
    s = stability_across_seeds(30, seeds=(1, 31, 61))
    assert s["stdev"] < 0.1 and 0.6 < s["mean"] < 1.0
    z = sensitivity_to_detection_assumptions(30, shifts=(-0.10, 0.10))
    assert z["max"] - z["min"] < 0.25  # results are not knife-edge on the detection assumptions


def test_stability_seeds_never_share_a_firm() -> None:
    # Firm i of seed s is drawn from random.Random(s + i), so seeds closer than n share firms and
    # their cohorts are not independent samples.
    with pytest.raises(ValueError, match="share firms"):
        stability_across_seeds(30, seeds=(1, 2, 3))
    default = inspect.signature(stability_across_seeds).parameters["seeds"].default
    assert len(default) == 30
    assert all(abs(a - b) >= 100 for i, a in enumerate(default) for b in default[i + 1 :])


def test_all_eleven_controls_are_exercised() -> None:
    # The corpus must actually drive every one of the 11 covered controls, both truly
    # present and recovered by the pipeline (a coverage-completeness guard).
    preds = _predict(generate_cases(100))
    predicted = set().union(*(p.predicted for p in preds))
    true = set().union(*(p.true_gold for p in preds))
    assert len(true) == 11
    assert predicted == true


def test_agreement_is_flagged_simulated_and_in_range() -> None:
    a = run_evaluation(50).agreement
    assert a["simulated"] is True
    assert 0.0 <= a["cohen_kappa"] <= 1.0
    # Ordinal alpha credits near-misses, so it should not be below nominal here.
    assert a["krippendorff_alpha_ordinal"] >= a["krippendorff_alpha_nominal"]


# test_faithfulness_gate_passes was dropped with p2c.evaluation.faithfulness: the RAG
# grounding stack it scored is out of scope for this toolkit, so the
# harness no longer carries a `faithfulness` field. The Wilson interval it also exercised
# is still covered directly by test_evaluation_metrics.py.


def test_latency_speedup_positive() -> None:
    lat = run_evaluation(10).latency
    assert lat["speedup_mean"]["point"] > 1.0  # ATLAS is faster than manual annotation


def test_wall_clock_is_measurable() -> None:
    assert measure_wall_clock(5) >= 0.0


def test_hermetic_baselines_stay_far_below_the_curated_rules() -> None:
    # Neither a naive keyword mapper nor a lexical embedding mapper recovers the curated
    # cross-walk, so the finding-to-control link is not recoverable without expert curation.
    # The claim holds whether the mapper sees a title or the full public control statement.
    b = hermetic_baselines(50)
    assert b["curated_f1"] == 1.0
    for key in ("naive_keyword", "keyword_fulltext", "embedding_hashing", "embedding_hashing_fulltext"):
        assert b[key]["micro_f1"] < 0.4, key
    assert embedding_cosine_baseline(50)["micro_f1"] < 0.4


def test_report_carries_the_baselines_block() -> None:
    baselines = run_evaluation(30).baselines
    assert {"naive_keyword", "embedding_hashing"} <= set(baselines)
    assert baselines["naive_keyword"]["micro_f1"] < 0.4


def test_fuzzy_threshold_sweep_is_monotone() -> None:
    # A stricter threshold can only lower (or hold) the fuzzy F1, so 0.90 <= 0.70 <= 0.50, and the
    # 70% headline is bracketed rather than cherry-picked.
    ft = run_evaluation(50).end_to_end["fuzzy_by_threshold"]
    assert set(ft) == {"0.50", "0.70", "0.90"}
    assert ft["0.90"]["f1"] <= ft["0.70"]["f1"] <= ft["0.50"]["f1"]


def test_weighting_sensitivity_uses_a_consistent_ahp_matrix() -> None:
    w = sensitivity_to_weighting(50)
    assert w["ahp_consistent"] and w["ahp_consistency_ratio"] <= 0.10  # spec fail-safe
    assert abs(sum(w["subdomain_weights"].values()) - 1.0) < 1e-9  # AHP weights sum to 1
    assert 0.0 <= w["assessed_mean_abs_delta"] <= w["assessed_max_abs_delta"]
    assert -1.0 <= w["assessed_rank_spearman"] <= 1.0


def test_robustness_bundle_has_every_analysis() -> None:
    # A cheap ensemble on purpose: this test asserts on the other analyses and never looks at
    # detection_uncertainty_ensemble, so paying for the toolkit's 2,000 draws here bought nothing
    # and made the suite unable to finish on a four core host.
    r = robustness_report(20, ensemble_draws=25)
    expected = {
        "stability_across_seeds",
        "detection_sensitivity",
        "precision_stress",
        "worst_case_corner",
        "scan_conditions",
        "attestation_sensitivity",
        "corpus_priors",
        "weighting",
    }
    assert expected <= set(r)
    assert r["weighting"]["ahp_consistent"]
    # the false-alarm-only stress must cut precision (sensitivity held), the point of the decoupled sweep
    assert r["precision_stress"]["fa_scaled"]["2.0x"]["precision"] < r["worst_case_corner"]["corner"]["f1"]


def test_corroborated_recovery_trades_recall_for_precision() -> None:
    # The corroboration operating point (require a deterministic or second signal for a low-confidence
    # gap) buys precision at some cost to recall, a valid higher-precision mode reported alongside.
    r = run_evaluation(100)
    default = r.end_to_end["exact_micro"]
    corro = r.end_to_end_corroborated["exact_micro"]
    assert corro["precision"] > default["precision"]
    assert corro["recall"] <= default["recall"]


def test_specificity_reports_clean_org_behavior() -> None:
    sp = run_evaluation(100).specificity
    assert sp["n_clean_orgs"] > 0
    # Corroboration leaves fewer spurious controls on a clean org than the default recovery.
    assert sp["corroborated"]["mean_false_controls_per_org"] <= sp["default"]["mean_false_controls_per_org"]


def test_lapsed_attestations_are_never_flagged() -> None:
    # Temporal integrity: expired or not-yet-effective attestations exist in the corpus but are never
    # counted as a live contradiction (ground truth and detector both honor the validity window).
    c = run_evaluation(100).contradictions
    assert c["n_lapsed_attestations"] > 0  # the corpus actually carries lapsed attestations
    assert c["lapsed_wrongly_flagged"] == 0


def test_tier2_precedence_is_always_enforced() -> None:
    # Three-tier assembly at scale: a Tier-2 compliant self-report never overrides a Tier-1 finding.
    t = run_evaluation(100).tier2_integrity
    assert t["precedence_checks"] > 0
    assert t["precedence_rate"] == 1.0
    assert t["precedence_correct"] == t["precedence_checks"]
    # Relabelling (evasion 5): the same overstatement filed as a Tier-2 record is flagged, not only
    # outranked, so moving the claim from a declaration to a Tier-2 record does not escape the check.
    assert t["tier2_flagged"] == t["precedence_checks"]


def test_rate_class_slice_drops_judgement_detectors_from_both_sides() -> None:
    from p2c.evaluation.appendix_tables import provenance  # noqa: PLC0415
    from p2c.evaluation.harness import _rate_class_slice  # noqa: PLC0415

    cases = generate_cases(60, seed=7)
    s = _rate_class_slice(cases)
    judged = {
        c for c in syn.SENSITIVITY if provenance(syn.SENSITIVITY[c], syn.FALSE_ALARM[c]) == "author judgment"
    }
    kept = set(syn.SENSITIVITY) - judged
    key = syn.expert_key()
    assert set(s["controls"]) == {cid for c in kept for cid in key[c]}
    assert s["n_dropped_detectors"] == len(judged)
    assert 0.0 < s["f1"] <= 1.0 and 0.0 < s["trivial_floor_f1"] < s["f1"]
    assert s["n_decisions"] == len(cases) * len(s["controls"])
    # Perfect sensing on the kept detectors gives a perfect slice: nothing the dropped detectors
    # carried can leak into either side.
    perfect = [dataclasses.replace(c, injected=c.true_injected) for c in cases]
    assert _rate_class_slice(perfect)["f1"] == 1.0


def test_scan_realism_shows_obstruction_clustering() -> None:
    # The correlated acquisition model's payoff: host-fetched detection recall is ordered
    # reachable > throttled > cdn_fronted > blocked, so misses cluster on obstructed hosts, while
    # control-level recovery stays high via cross-host co-evidence.
    sr = run_evaluation(100).scan_realism
    by_cond = sr["host_fetched_detection_by_condition"]
    assert {"reachable", "throttled", "cdn_fronted", "blocked"} <= set(by_cond)
    assert by_cond["reachable"]["recall"] > by_cond["cdn_fronted"]["recall"] > by_cond["blocked"]["recall"]
    assert 0.97 <= sr["mean_competence"] <= 1.0


def test_scan_condition_sensitivity_is_bounded() -> None:
    # Scaling the obstructed-host share 0.5x..2x moves end-to-end F1 only within a modest band, so the
    # headline is not knife-edge on the obstruction assumption.
    z = sensitivity_to_scan_conditions(30, obstruction_scales=(0.5, 2.0))
    assert z["max"] - z["min"] < 0.15
    assert run_evaluation(30).end_to_end["exact_micro"]["f1"] == z["baseline_f1"]  # restores shares


def _assert_well_formed_ci(ci: dict[str, float] | None) -> None:
    assert ci is not None
    assert 0.0 <= ci["ci_low"] <= ci["ci_high"] <= 1.0


def test_headline_and_stratum_metrics_carry_confidence_intervals() -> None:
    report = run_evaluation(50)
    # The pooled headline micro F1 now carries its own bootstrap CI.
    mci = report.end_to_end["exact_micro_f1_ci"]
    assert mci["ci_low"] <= report.end_to_end["exact_micro"]["f1"] <= mci["ci_high"]
    # Every sector and posture stratum carries an F1 CI, precision/recall CIs, an n, and a power flag.
    for block in (report.per_sector, report.per_posture):
        for stratum in block.values():
            assert stratum["f1_ci"]["ci_low"] <= stratum["f1"] <= stratum["f1_ci"]["ci_high"]
            _assert_well_formed_ci(stratum["precision_ci"])
            _assert_well_formed_ci(stratum["recall_ci"])
            assert isinstance(stratum["underpowered"], bool) and stratum["n"] > 0
    # Per-control precision/recall carry well-formed Wilson intervals. (A Wilson interval can sit
    # just below a boundary proportion of 1.0, which is correct, so assert well-formedness not
    # containment of the point.)
    for v in report.per_control.values():
        _assert_well_formed_ci(v["precision_ci"])
        _assert_well_formed_ci(v["recall_ci"])


def test_effect_size_quantifies_the_base_rate_effect() -> None:
    e = run_evaluation(100).effect_size
    # Weak estates are recovered better than strong ones (base-rate effect), a large positive d.
    assert e["cohen_d"] > 0.5 and e["n_strong"] > 0 and e["n_weak"] > 0


def test_cross_generator_report_is_deterministic_and_self_consistent() -> None:
    # R2: the cross-generator transfer must be deterministic, and its cohort-A block must equal the
    # headline the full run produces (so the toolkit's A|B table cannot drift from the headline it sits
    # beside). Cohort B runs through the identical metric code path and lands in the same ballpark.
    a = cross_generator_report(60)
    b = cross_generator_report(60)
    assert a == b  # fully deterministic
    full = run_evaluation(60)
    assert a["cohort_a"]["recovery"]["f1"] == full.end_to_end["exact_micro"]["f1"]
    assert a["cohort_a"]["recovery"]["precision"] == full.end_to_end["exact_micro"]["precision"]
    assert a["cohort_a"]["contradiction"]["f1"] == full.contradictions["f1"]
    # Cohort B is a real second population: a different finding count, yet recovery in the same regime.
    assert a["cohort_b"]["n_true_findings"] != a["cohort_a"]["n_true_findings"]
    assert 0.80 < a["cohort_b"]["recovery"]["f1"] < 1.0
    assert 0.70 < a["cohort_b"]["contradiction"]["f1"] < 1.0


def test_reproduce_writes_the_cross_generator_artifact(tmp_path: Path) -> None:
    # make reproduce must emit cross_generator.json in the reproduce path, byte-stable across runs.
    reproduce(tmp_path / "a", n=30)
    reproduce(tmp_path / "b", n=30)
    for sub in ("a", "b"):
        assert (tmp_path / sub / "cross_generator.json").is_file()
    first = (tmp_path / "a" / "cross_generator.json").read_text(encoding="utf-8")
    second = (tmp_path / "b" / "cross_generator.json").read_text(encoding="utf-8")
    assert first == second
    payload = json.loads(first)
    assert {"cohort_a", "cohort_b"} <= set(payload)


def test_corpus_prior_sensitivity_is_bounded() -> None:
    # Scaling the uncited true-issue priors by +-20% leaves end-to-end F1 in a tight band, so the
    # result does not hinge on the exact sector/propensity assumptions.
    z = sensitivity_to_corpus_priors(30, factors=(0.8, 1.2))
    assert z["max"] - z["min"] < 0.15
    # The sweep restores the priors, so a following run reproduces the untouched baseline.
    assert run_evaluation(30).end_to_end["exact_micro"]["f1"] == z["baseline_f1"]


def test_documented_score_exceeds_assessed_only_through_off_surface_evidence() -> None:
    """The three-tier scoring path is genuinely exercised: the two scores diverge, and the
    divergence is entirely the firm's off-surface Tier-2 and Tier-3 evidence.

    Stripping that evidence must collapse the documented score back onto the assessed one (every
    remaining declaration is on a Tier-1 checkable control, which lowest-tier-wins resolves), and
    must leave the assessed score untouched, since assessed reads Tier-1 records only.
    """
    engine = MappingEngine()
    diverged = 0
    for case in generate_cases(25):
        mappings = engine.map_findings(case.findings())
        full = compute_dual_score(_all_tier_assessments(case, mappings))
        stripped_case = dataclasses.replace(
            case,
            internal_evidence=(),
            attestations=tuple(a for a in case.attestations if a.control_id in TIER1_CHECKABLE),
        )
        stripped = compute_dual_score(_all_tier_assessments(stripped_case, mappings))
        assert full.assessed_score == stripped.assessed_score  # off-surface evidence cannot reach it
        assert stripped.documented_score == stripped.assessed_score  # two-tier corpus coincided
        assert full.gap == 1.0 - full.assessed_score  # the reported gap is over the assessed score
        if abs(full.documented_score - full.assessed_score) > 1e-9:
            diverged += 1
    assert diverged == 25  # every firm carries some off-surface evidence


def test_off_surface_declarations_are_never_flagged_as_contradictions() -> None:
    # An off-surface declaration is unrefutable by construction. The detector is handed every
    # declaration, on and off surface alike, and must leave the off-surface ones alone on its own
    # rather than by a filter upstream of it.
    engine = MappingEngine()
    seen_off_surface = 0
    for case in generate_cases(25):
        mappings = engine.map_findings(case.findings())
        off_surface = {a.control_id for a in case.attestations if a.control_id not in TIER1_CHECKABLE}
        seen_off_surface += len(off_surface)
        found = detect_contradictions(case.attestations, mappings, now=syn.EVAL_EPOCH)
        assert not {c.control_id for c in found} & off_surface
    assert seen_off_surface > 0


def test_cohort_firms_sum_to_the_cohort_artifacts() -> None:
    """The per-firm records behind Fig. cohort are the terms of the totals the report states."""
    report = run_evaluation(20)
    firms = report.cohort_firms["firms"]
    assert len(firms) == report.n_profiles
    assert sum(f["n_findings"] for f in firms) == report.n_findings
    assert sum(f["n_true_issues"] for f in firms) == report.n_true_findings
    assert sum(f["n_false_positives"] for f in firms) == report.detection["n_false_alarm"]
    assert sum(f["n_declarations"] for f in firms) == report.contradictions["n_attestations"]
    assert sum(f["n_overstated"] for f in firms) == report.contradictions["true_contradictions"]
    assert [f["case_id"] for f in firms] == sorted(f["case_id"] for f in firms)


# --- Observation states in the evaluation (Array R2-6) ----------------------------------------


def _with_conditions(case, condition: str):
    return dataclasses.replace(case, scan_conditions=dict.fromkeys(case.scan_conditions, condition))


def test_a_fully_reachable_estate_is_fully_observed() -> None:
    from p2c.evaluation.harness import _unobserved  # noqa: PLC0415

    case = _with_conditions(generate_cases(1, seed=3)[0], "reachable")
    assert _unobserved(case) == frozenset()


def test_blocking_every_host_leaves_only_the_apex_read_controls_observed() -> None:
    from p2c.evaluation.harness import _unobserved  # noqa: PLC0415

    case = _with_conditions(generate_cases(1, seed=3)[0], "blocked")
    # Hard-coded from the detector table, not derived from the code under test: every subcontrol a
    # host-read detector reaches is lost; the two read only from DNS at the apex (2-4-3-5, 2-5-3-7)
    # stay observed.
    assert _unobserved(case) == frozenset(
        {
            "2-3-3-3",
            "2-5-3-1",
            "2-5-3-5",
            "2-7-1-3",
            "2-8-3-1",
            "2-8-3-2",
            "2-8-3-3",
            "2-10-3-4",
            "2-15-3-3",
        }
    )


def test_a_cdn_hides_origin_reads_but_not_edge_reads() -> None:
    from p2c.evaluation.harness import _unobserved  # noqa: PLC0415

    case = _with_conditions(generate_cases(1, seed=3)[0], "cdn_fronted")
    unobserved = _unobserved(case)
    assert {"2-5-3-5", "2-7-1-3", "2-3-3-3", "2-10-3-4"} <= unobserved  # ports and banners read the origin
    assert not {"2-8-3-1", "2-8-3-2", "2-8-3-3", "2-15-3-3"} & unobserved  # TLS and edge reads succeed


def test_an_unknown_scan_condition_fails_closed() -> None:
    from p2c.evaluation.harness import _unobserved  # noqa: PLC0415

    case = _with_conditions(generate_cases(1, seed=3)[0], "something_new")
    assert _unobserved(case) == _unobserved(_with_conditions(case, "blocked"))


def test_blocking_a_firm_never_raises_its_own_assessed_score() -> None:
    from p2c.evaluation.harness import _block_hosts  # noqa: PLC0415

    engine = MappingEngine()
    for case in generate_cases(60, seed=13):
        open_score = compute_dual_score(_all_tier_assessments(case, engine.map_findings(case.findings())))
        blocked = _block_hosts(case, set(case.scan_conditions))
        blocked_score = compute_dual_score(
            _all_tier_assessments(blocked, engine.map_findings(blocked.findings()))
        )
        assert blocked_score.assessed_score <= open_score.assessed_score + 1e-12


def test_blocking_the_scan_cannot_buy_a_high_assessed_score() -> None:
    # The flaw R2 named: under "absent finding = pass", a blocked estate with no findings scored
    # 1.0. Now only the controls read from DNS at the apex can still pass, so the score is capped by
    # their share, and coverage reports how little the scan saw.
    from p2c.evaluation.synthetic import _APEX_ONLY_CHECKS  # noqa: PLC0415

    key = syn.expert_key()
    host_controls = {c for chk, cs in key.items() if chk not in _APEX_ONLY_CHECKS for c in cs}
    apex_only = {c for chk in _APEX_ONLY_CHECKS for c in key[chk]} - host_controls
    cap = len(apex_only & TIER1_CHECKABLE) / len(TIER1_CHECKABLE)
    for case in generate_cases(40, seed=11):
        blocked = dataclasses.replace(_with_conditions(case, "blocked"), injected=())
        score = compute_dual_score(_all_tier_assessments(blocked, []))
        assert score.assessed_score <= cap + 1e-12
        assert score.coverage == cap


def test_unscoped_estate_scores_zero_with_zero_coverage() -> None:
    case = dataclasses.replace(generate_cases(1, seed=5)[0], scan_conditions={}, injected=())
    score = compute_dual_score(_all_tier_assessments(case, []))
    assert score.assessed_score == 0.0
    assert score.coverage == 0.0


# --- Evasions tested directly (Array R1, R2-6) ------------------------------------------------


@pytest.fixture(scope="module")
def evasions() -> dict:
    from p2c.evaluation.harness import evasion_report  # noqa: PLC0415

    return evasion_report(40, seed=21)


def test_evasion_report_is_deterministic(evasions: dict) -> None:
    from p2c.evaluation.harness import evasion_report  # noqa: PLC0415

    assert evasion_report(40, seed=21) == evasions


def test_the_evasion_baseline_is_the_headline_contradiction_result(evasions: dict) -> None:
    con = run_evaluation(40, seed=21).contradictions
    base = evasions["scenarios"]["baseline"]
    # The evasions concern declarations: their baseline is the headline result over declarations alone.
    declared = con["declarations_only"]
    assert base["n_overstated"] == declared["true_contradictions"]
    assert base["contradiction_recall"] == round(declared["recall"], 6)


def test_deliberate_blocking_leaves_no_host_read_finding() -> None:
    from p2c.evaluation.harness import _block_hosts  # noqa: PLC0415
    from p2c.evaluation.synthetic import _HOST_FETCHED_CHECKS  # noqa: PLC0415

    for case in generate_cases(20, seed=4):
        blocked = _block_hosts(case, set(case.scan_conditions))
        assert not any(i.check in _HOST_FETCHED_CHECKS for i in blocked.injected)
        assert set(blocked.scan_conditions.values()) <= {"blocked"}


def test_blocking_raised_the_old_score_and_lowers_the_new_one(evasions: dict) -> None:
    s = evasions["scenarios"]
    base, blocked = s["baseline"], s["block_all_hosts"]
    assert blocked["assessed_absent_is_pass"] > base["assessed_absent_is_pass"]  # the flaw R2 named
    assert blocked["assessed"] < base["assessed"]  # now blocking only costs score
    assert blocked["coverage"] < base["coverage"]
    assert blocked["contradiction_recall"] < base["contradiction_recall"]  # but it does hide flags
    # Partial blocking buys nothing either: the ALL rule loses every host-read control.
    assert s["block_half_subdomains"]["assessed"] <= base["assessed"]


def test_omitting_the_apex_scores_zero_where_it_used_to_score_one(evasions: dict) -> None:
    omit = evasions["scenarios"]["omit_apex"]
    assert omit["assessed_absent_is_pass"] == 1.0
    assert omit["assessed"] == 0.0 and omit["coverage"] == 0.0
    assert omit["contradiction_recall"] == 0.0


def test_omitting_subdomains_goes_undetected(evasions: dict) -> None:
    # The open evasion: coverage stays high and the score rises, because the scorer never learns
    # of the omitted hosts; only the contradiction recall shows the loss.
    s = evasions["scenarios"]
    omit, base = s["omit_subdomains"], s["baseline"]
    assert omit["coverage"] >= 0.9
    assert omit["assessed"] > base["assessed"]
    assert omit["contradiction_recall"] < base["contradiction_recall"]


def test_throttling_buys_a_little_score_without_losing_coverage(evasions: dict) -> None:
    s = evasions["scenarios"]
    throttle, base = s["throttle_all_hosts"], s["baseline"]
    assert throttle["assessed"] >= base["assessed"]
    assert throttle["coverage"] >= base["coverage"] - 0.02
    assert throttle["contradiction_recall"] <= base["contradiction_recall"]


def test_suppression_is_not_observed_but_spoofing_reads_clean(evasions: dict) -> None:
    s = evasions["scenarios"]
    assert s["banner_suppression"]["coverage"] < s["string_spoofing"]["coverage"]
    assert s["banner_suppression"]["coverage"] < s["baseline"]["coverage"]
    assert s["banner_suppression"]["assessed"] < s["baseline"]["assessed"] < s["string_spoofing"]["assessed"]
    # Both remove every banner finding, so the flags they cost are the same; spoofing only reads clean.
    assert s["string_spoofing"]["contradiction_recall"] <= s["banner_suppression"]["contradiction_recall"]


def test_relabelling_runs_through_the_shipped_tier2_path(evasions: dict) -> None:
    # By construction the check applies one rule to both tiers, so the relabelled claims are flagged
    # exactly as the declarations were; the run confirms the shipped Tier-2 path does so.
    r = evasions["scenarios"]["relabel_tier2"]
    assert r["contradiction_recall_old_check"] == 0.0
    assert r["contradiction_recall"] == evasions["scenarios"]["baseline"]["contradiction_recall"]


def test_an_oracle_declarer_is_the_floor_below_the_heuristic(evasions: dict) -> None:
    s = evasions["scenarios"]
    oracle, heuristic = (
        s["oracle_declarer"]["contradiction_recall"],
        s["adaptive_declarer"]["contradiction_recall"],
    )
    # The oracle is a bound on both (it knows which violations the scan misses); the heuristic beats
    # the drawn declarer only on average, not on every small cohort (on this one it does not).
    assert 0.0 < oracle <= min(heuristic, s["baseline"]["contradiction_recall"])
    assert (
        s["oracle_declarer"]["n_overstated"]
        == s["adaptive_declarer"]["n_overstated"]
        == s["baseline"]["n_overstated"]
    )
    assert 0 < s["oracle_declarer"]["violations_missed"] < s["oracle_declarer"]["violations_total"]


# --- Smaller analyses for the Array reviewers (R1) ---------------------------------------------


def test_cohort_firms_carry_flag_counts_that_sum_to_the_headline() -> None:
    report = run_evaluation(60)
    firms = report.cohort_firms["firms"]
    con = report.contradictions
    assert sum(f["n_flags"] for f in firms) == con["flagged"]
    assert sum(f["n_flags_true"] for f in firms) == con["tp"]
    assert sum(f["n_flags_false"] for f in firms) == con["fp"]


def test_exposure_sweep_moves_toward_the_anchors_and_reports_all_four_measures() -> None:
    from p2c.evaluation.harness import exposure_toward_anchors  # noqa: PLC0415

    before = ({s.name: dict(s.weights) for s in syn.SECTORS}, dict(syn._SUBSET_PROB))
    sweep = exposure_toward_anchors(40, seed=9, factors=(1.0, 2.0))
    assert ({s.name: dict(s.weights) for s in syn.SECTORS}, dict(syn._SUBSET_PROB)) == before  # restored
    lo, hi = sweep["by_factor"]["1.00"], sweep["by_factor"]["2.00"]
    assert hi["precision"] > lo["precision"]
    assert hi["realized_missing_csp_per_host"] > lo["realized_missing_csp_per_host"]
    assert hi["base_rate"] > lo["base_rate"]
    assert hi["predict_all_f1"] > lo["predict_all_f1"]  # the floor rises with exposure (R1)
    for row in (lo, hi):
        assert row["predict_all_mcc"] == 0.0 and row["predict_all_balanced_accuracy"] == 0.5
        assert 0.0 < row["mcc"] <= 1.0 and 0.5 < row["balanced_accuracy"] <= 1.0


def test_mapper_disagreement_audit_covers_every_detector() -> None:
    from p2c.evaluation.harness import mapper_disagreement_audit  # noqa: PLC0415

    audit = mapper_disagreement_audit()
    assert audit["model"] == "gemma3:12b" and audit["condition"] == "title"
    # It audits the best run of the ladder (a tie on titles goes to the first model by name).
    root = Path(__file__).resolve().parents[2]
    ladder = json.loads((root / "evaluation" / "baseline_ladder_results.json").read_text(encoding="utf-8"))
    best = max(s[c]["micro_f1"] for s in ladder.values() for c in ("title", "full_text") if s.get(c))
    assert ladder["gemma3:12b"]["title"]["micro_f1"] == best
    assert len(audit["detectors"]) == 31
    n_dis = sum(1 for d in audit["detectors"] if not d["agrees"])
    assert n_dis == audit["n_disagreements"]
    assert sum(audit["disagreement_kinds"].values()) == n_dis
