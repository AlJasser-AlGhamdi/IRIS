"""Evaluations E1, E5, ablations and baselines on synthetic firms; every number on the slides comes from here.

    uv run python -m evals.run e1 --split dev --model ollama:qwen3:8b
    uv run python -m evals.run e1 --split held_out --model ollama:qwen3:8b      # once, at the end
    uv run python -m evals.run e5 --model ollama:qwen3:8b
    uv run python -m evals.run ablations --model ollama:qwen3:8b
    uv run python -m evals.run summary          # rebuilds results/summary.json

Sessions are logged (hash-chained) under evals/cache/sessions/ and per-session results are kept, so
`summary` recomputes everything without calling a model.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from pathlib import Path
from typing import Any

import yaml

from officer.cli import sim_session
from officer.contract import FixId, Group
from officer.questions import AnswerClass, bank
from officer.session import Config, Scope, in_scope

HERE = Path(__file__).resolve().parent
CACHE = HERE / "cache" / "sessions"
RESULTS = HERE / "results"
SPLITS = yaml.safe_load((HERE / "splits.yaml").read_text(encoding="utf-8"))


def _slug(text: str) -> str:
    return text.replace(":", "_").replace("/", "_")


def score_session(metrics: dict[str, Any], agent: Any, worker: Any, owner: Any) -> dict[str, Any]:
    """Compare one session with the synthetic firm's hidden truth."""
    case = worker.case
    truth_violated = set(case.ground_truth.control_ids)
    first = [e for e in agent.log.events if e["type"] == "assessment"]
    # the assessment published when the scan completes, before any answer or fix
    post_scan = next((e for e in first if e["data"].get("stage") == "post_scan"), None)
    tiles = post_scan["data"]["tiles"] if post_scan else {}
    tier1 = set(truth_violated) | {c for c, s in tiles.items() if s in ("violation", "contradicted")}
    tier1 = {c for c in tier1 if c in _tier1_checkable()}
    predicted = {
        c for c, s in tiles.items() if c in _tier1_checkable() and s in ("violation", "contradicted")
    }
    tp = len(predicted & truth_violated)
    # contradictions: an overstated answer on an area the scan can see and where the truth is violated
    observed = {c.value for _h, c in agent.state.findings} | {
        c for e in agent.log.events if e["type"] == "tool_result" for c in e["data"]["findings"]
    }
    # flags raised at reconciliation, before any fix clears the finding behind them
    flagged_qids = {e["data"]["qid"] for e in agent.log.events if e["type"] == "contradiction"}
    true_pos = pred_pos = hits = 0
    false_alarm_flags = 0
    for q in bank():
        overstated_visible = q.qid in owner.overstated and bool(set(q.contradictable_by) & observed)
        flagged = q.qid in flagged_qids
        false_alarm_flags += flagged and not overstated_visible and owner.truth(q) is AnswerClass.YES
        true_pos += overstated_visible
        pred_pos += flagged
        hits += overstated_visible and flagged
    # understanding: the first reading of each question's first reply (not follow-ups or buttons)
    # against what the simulated owner meant; a vague first reply means "unknown"
    said = owner.truth_said
    first_parse: dict[str, str] = {}
    for e in agent.log.events:
        if (
            e["type"] == "model_call"
            and e["data"].get("role") == "parse"
            and e["data"].get("qid") not in first_parse
        ):
            first_parse[e["data"]["qid"]] = e["data"]["answer"]
    vague_first = getattr(owner, "vague_first", set())
    understood = sum(
        first_parse[q] == ("unknown" if q in vague_first else said[q].value) for q in first_parse if q in said
    )
    answer_events = [e for e in agent.log.events if e["type"] == "answer"]
    buttons = sum(e["data"]["source"] == "buttons" for e in answer_events)
    # documented-score honesty: of the in-scope rows the final assessment counts as satisfied, the share
    # that is not really in place (Tier-1 rows: the hidden truth; others: the owner's real practice)
    scope = in_scope(agent.state.scope or Scope.CLASS_B)
    question_of = {c: q for q in bank() for c in q.controls}
    satisfied = [a for a in agent.assessment().merged if a.satisfied and a.control_id in scope]

    def really_in_place(control: str) -> bool:
        if control in _tier1_checkable():
            return control not in truth_violated
        q = question_of.get(control)
        return q is not None and owner.truth(q) is AnswerClass.YES

    credited = len(satisfied)
    overcredited = sum(not really_in_place(a.control_id) for a in satisfied)
    final_tiles = first[-1]["data"]["tiles"] if first else {}
    scope_now = in_scope(agent.state.scope or Scope.CLASS_B)
    determined = sum(
        final_tiles.get(c)
        in ("clean", "violation", "contradicted", "declared", "declared_evidence", "self_gap")
        for c in scope_now
    )
    return {
        "rows_in_scope": len(scope_now),
        "rows_determined": determined,
        "halted": metrics["halted"],
        "case": case.case_id,
        "persona": owner.persona,
        "completed": metrics["halted"] is None,
        "violation_tp": tp,
        "violation_pred": len(predicted),
        "violation_true": len(truth_violated & _tier1_checkable()),
        "contra_tp": hits,
        "contra_pred": pred_pos,
        "contra_true": true_pos,
        "contra_from_scanner_false_alarm": false_alarm_flags,
        "understood": understood,
        "answers": len([q for q in first_parse if q in said]),
        "button_answers": buttons,
        "answer_events": len(answer_events),
        "decisions": metrics.get("decisions", 0),
        "credited": credited,
        "overcredited": overcredited,
        "human_touches": metrics["human_touches"],
        "questions": metrics["questions_asked"],
        "followups": metrics["followups"],
        "model_calls": metrics["model_calls"],
        "fallbacks": metrics["fallbacks"],
        "illegal": metrics["illegal_choices"],
        "fixes_verified": len(metrics["fixes_verified"]),
        "fixes_failed": len(metrics["fixes_failed"]),
        "escalations": metrics["escalations"],
        "assessed_before": metrics["assessed_before"],
        "assessed_after": metrics["assessed_after"],
        "documented": metrics["documented"],
        "seconds": metrics["seconds"],
        "scope": metrics["scope"],
        "_tier1": sorted(tier1),
    }


def _last_seq(agent: Any, type_: str, before: str) -> int:
    phase, value = before.split(":")
    stop = next(
        (e["seq"] for e in agent.log.events if e["type"] == phase and e["data"].get("phase") == value), None
    )
    seqs = [e["seq"] for e in agent.log.events if e["type"] == type_ and (stop is None or e["seq"] < stop)]
    return max(seqs, default=-1)


def _tier1_checkable() -> set[str]:
    from p2c.scoring.assemble import TIER1_CHECKABLE  # noqa: PLC0415

    return set(TIER1_CHECKABLE)


def run_e1(split: str, model: str, limit: int | None = None) -> list[dict[str, Any]]:
    seeds = SPLITS["synthetic"]["dev_seeds" if split == "dev" else "held_out_seeds"][: limit or None]
    rows = []
    for seed in seeds:
        for persona in SPLITS["synthetic"]["personas"]:
            out = CACHE / f"e1-{split}-{_slug(model)}" / f"seed{seed}-{persona}.jsonl"
            start = time.perf_counter()
            metrics, agent, worker, owner = sim_session(seed, persona, model, out)
            row = score_session(metrics, agent, worker, owner) | {"seed": seed}
            row["wall_seconds"] = round(time.perf_counter() - start, 1)
            rows.append(row)
            print(
                f"e1 {split} seed{seed} {persona}: completed={row['completed']} "
                f"contra {row['contra_tp']}/{row['contra_true']} "
                f"understood {row['understood']}/{row['answers']} {row['wall_seconds']}s",
                flush=True,
            )
    _save(f"e1-{split}-{_slug(model)}", rows)
    return rows


SCENARIOS: dict[str, dict[str, Any]] = {
    "baseline": {},
    "blocked_ports": {"blocked": {Group.PORTS}},
    "blocked_web_tls": {"blocked": {Group.WEB, Group.TLS}},
    "ownership_lost": {"lose_txt": True},
    "fixes_fail": {"failing_fixes": set(FixId)},
    "scope_to_ecc": {"scope_update_at": 3, "scope_update": {"supplies_government": True}},
    "scope_to_class_a": {"scope_update_at": 2, "scope_update": {"staff": 300}},
}


def run_e5(model: str) -> list[dict[str, Any]]:
    rows = []
    models = {"main": model, "model_down": "down"}
    for seed in SPLITS["robustness_seeds"]:
        for name, scenario in SCENARIOS.items():
            out = CACHE / f"e5-{_slug(model)}" / f"{name}-seed{seed}.jsonl"
            metrics, agent, worker, owner = sim_session(seed, "overstating", model, out, **scenario)
            row = score_session(metrics, agent, worker, owner) | {"scenario": name, "seed": seed}
            row["behaved"] = expected_behaviour(name, row)
            rows.append(row)
        for name, spec in models.items():
            if name == "main":
                continue
            out = CACHE / f"e5-{_slug(model)}" / f"{name}-seed{seed}.jsonl"
            metrics, agent, worker, owner = sim_session(seed, "overstating", spec, out)
            row = score_session(metrics, agent, worker, owner) | {"scenario": name, "seed": seed}
            row["behaved"] = expected_behaviour(name, row)
            rows.append(row)
        print(f"e5 seed {seed} done", flush=True)
    _save(f"e5-{_slug(model)}", rows)
    return rows


def expected_behaviour(scenario: str, row: dict[str, Any]) -> bool:
    """What correct looks like under each change of conditions or requirements."""
    if scenario == "ownership_lost":
        return row["halted"] == "ownership_lost" and row["fixes_verified"] == 0
    if scenario == "fixes_fail":
        return (
            row["completed"]
            and row["fixes_verified"] == 0
            and (
                row["fixes_failed"] == 0 or any(e.startswith("fix_not_verified") for e in row["escalations"])
            )
        )
    if scenario == "scope_to_ecc":
        return row["completed"] and row["scope"] == "ecc"
    if scenario == "scope_to_class_a":
        return row["completed"] and row["scope"] == "class_a"
    return bool(row["completed"])


ABLATIONS: dict[str, Config] = {
    "full": Config(),
    "no_scan": Config(scan=False),
    "no_interview": Config(interview=False),
    "no_action_gate": Config(action_gate=False),
    "no_rescan_verification": Config(verify_rescan=False),
}


def run_ablations(model: str) -> list[dict[str, Any]]:
    rows = []
    for seed in SPLITS["ablation_seeds"]:
        for name, config in ABLATIONS.items():
            out = CACHE / f"ablation-{_slug(model)}" / f"{name}-seed{seed}.jsonl"
            # a third of fixes apply but do not take effect, the same ones in every row
            metrics, agent, worker, owner = sim_session(
                seed, "overstating", model, out, config, fail_rate=1 / 3
            )
            row = score_session(metrics, agent, worker, owner) | {"ablation": name, "seed": seed}
            # a "fixed" claim the simulated estate does not bear out
            open_checks = {c for _h, c in worker._open}
            from officer.fixes import FIXES  # noqa: PLC0415

            row["false_fixed"] = sum(
                bool(set(FIXES[FixId(f)].clears) & open_checks) for f in metrics["fixes_verified"]
            )
            rows.append(row)
        print(f"ablations seed {seed} done", flush=True)
    _save(f"ablations-{_slug(model)}", rows)
    return rows


def _save(name: str, rows: list[dict[str, Any]]) -> None:
    RESULTS.mkdir(parents=True, exist_ok=True)
    (RESULTS / f"{name}.json").write_text(
        json.dumps(rows, ensure_ascii=False, indent=1, default=str) + "\n", encoding="utf-8"
    )


def _f1(tp: int, pred: int, true: int) -> dict[str, float | None]:
    p = tp / pred if pred else None
    r = tp / true if true else None
    f = 2 * p * r / (p + r) if p and r else (0.0 if pred or true else None)
    return {"precision": _r(p), "recall": _r(r), "f1": _r(f)}


def _r(x: float | None) -> float | None:
    return None if x is None else round(x, 3)


def aggregate(rows: list[dict[str, Any]]) -> dict[str, Any]:
    if not rows:
        return {}
    s = lambda k: sum(r[k] for r in rows)  # noqa: E731
    return {
        "sessions": len(rows),
        "behaved": _r(sum(r.get("behaved", r["completed"]) for r in rows) / len(rows)),
        "mean_rows_determined": _r(statistics.mean(r.get("rows_determined", 0) for r in rows)),
        "mean_rows_in_scope": _r(statistics.mean(r.get("rows_in_scope", 0) for r in rows)),
        "completion": _r(s("completed") / len(rows)),
        "violation_detection": _f1(s("violation_tp"), s("violation_pred"), s("violation_true")),
        "contradiction_detection": _f1(s("contra_tp"), s("contra_pred"), s("contra_true")),
        "answer_understanding": _r(s("understood") / s("answers")) if s("answers") else None,
        "overcredit_rate": _r(s("overcredited") / s("credited")) if s("credited") else None,
        "median_human_touches": statistics.median(r["human_touches"] for r in rows),
        "median_questions": statistics.median(r["questions"] for r in rows),
        "median_model_calls": statistics.median(r["model_calls"] for r in rows),
        "button_share": _r(s("button_answers") / max(1, s("answer_events")))
        if all("answer_events" in r for r in rows) else None,  # rows recorded before the field existed
        # parse and choose only; explanations are templates (ITERATIONS #9)
        "fallback_rate": _r(
            sum(r["fallbacks"]["parse"] + r["fallbacks"]["choose"] for r in rows)
            / max(1, sum(r.get("decisions", 0) - r["fallbacks"].get("explain", 0) for r in rows))
        ),
        "illegal_choices": s("illegal"),
        "fixes_verified": s("fixes_verified"),
        "fixes_failed": s("fixes_failed"),
        "median_seconds": statistics.median(r["seconds"] for r in rows),
        "mean_assessed_before": _r(statistics.mean(r["assessed_before"] or 0 for r in rows)),
        "mean_assessed_after": _r(statistics.mean(r["assessed_after"] or 0 for r in rows)),
        "mean_documented": _r(statistics.mean(r["documented"] for r in rows)),
    }


def summary() -> dict[str, Any]:
    out: dict[str, Any] = {}
    for f in sorted(RESULTS.glob("*.json")):
        if f.name in ("summary.json", "g0.json") or f.name.startswith("e6-"):
            continue
        rows = json.loads(f.read_text(encoding="utf-8"))
        if f.name.startswith("e1-"):
            out[f.stem] = {"all": aggregate(rows)} | {
                p: aggregate([r for r in rows if r["persona"] == p]) for p in SPLITS["synthetic"]["personas"]
            }
        elif f.name.startswith("e5-"):
            out[f.stem] = {
                sc: aggregate([r for r in rows if r["scenario"] == sc])
                for sc in dict.fromkeys(r["scenario"] for r in rows)
            }
        elif f.name.startswith("ablations-"):
            out[f.stem] = {}
            for ab in dict.fromkeys(r["ablation"] for r in rows):
                sub = [r for r in rows if r["ablation"] == ab]
                out[f.stem][ab] = aggregate(sub) | {"false_fixed": sum(r["false_fixed"] for r in sub)}
    for f in sorted(RESULTS.glob("e6-*.json")):
        rows = json.loads(f.read_text(encoding="utf-8"))
        planted = sum(len(r["planted_detectors"]) for r in rows)
        fixable_defects = [(r, d) for r in rows for d in r["defects"] if d != "ssh_22"]
        removed = sum(d not in r["remaining_defects"] for r, d in fixable_defects)
        out[f.stem] = {
            "estates": len(rows),
            "completion": _r(sum(r["completed"] for r in rows) / len(rows)),
            "planted_found": f"{sum(len(r['found']) for r in rows)}/{planted}",
            "unexpected_findings": sum(len(r["unexpected"]) for r in rows),
            "fixable_defects_removed": f"{removed}/{len(fixable_defects)}",
            "ssh_escalated": sum(any(e.startswith("risky_fix") for e in r["escalations"]) for r in rows),
            "false_fixed": sum(len(r["false_fixed"]) for r in rows),
            "escalations": sum(len(r["escalations"]) for r in rows),
            "median_seconds": statistics.median(r["seconds"] for r in rows),
            "median_human_touches": statistics.median(r["human_touches"] for r in rows),
        }
    ladder = json.loads(
        (HERE.parent / "evaluation" / "baseline_ladder_results.json").read_text(encoding="utf-8")
    )
    out["e3_ladder"] = {
        m: max(v[k]["micro_f1"] for k in v if isinstance(v[k], dict) and "micro_f1" in v[k])
        for m, v in ladder.items()
        if isinstance(v, dict)
    }
    for extra in ("g0.json", "e2.json", "e4.json", "e4_live.json"):
        if (RESULTS / extra).exists():
            out[extra.removesuffix(".json")] = json.loads((RESULTS / extra).read_text(encoding="utf-8"))
    for f in sorted(RESULTS.glob("e7-*.json")):
        out[f.stem] = json.loads(f.read_text(encoding="utf-8"))["summary"]
    (RESULTS / "summary.json").write_text(
        json.dumps(out, ensure_ascii=False, indent=1) + "\n", encoding="utf-8"
    )
    print(json.dumps(out, ensure_ascii=False, indent=1)[:6000])
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="evals.run")
    parser.add_argument("what", choices=["e1", "e5", "ablations", "summary"])
    parser.add_argument("--split", default="dev", choices=["dev", "held_out"])
    parser.add_argument("--model", default="scripted")
    parser.add_argument("--limit", type=int)
    args = parser.parse_args(argv)
    if args.what == "e1":
        aggregate_rows = run_e1(args.split, args.model, args.limit)
        print(json.dumps(aggregate(aggregate_rows), indent=1))
    elif args.what == "e5":
        run_e5(args.model)
    elif args.what == "ablations":
        run_ablations(args.model)
    else:
        summary()
    return 0


if __name__ == "__main__":
    sys.exit(main())
