"""E2: does the model understand owners' answers? The parse role alone, on three labelled sets.

    uv run python -m evals.e2 run --sets dev test ood --models qwen3:8b gemma3:12b ...  # calls models, caches
    uv run python -m evals.e2 score                                                    # from the cache only

dev tunes the prompt, test is held out (labelled before any model ran on it), and ood holds the owner's 20
replies in ten styles the templates never use. Accuracy is also reported on
confident labels (c >= 8 of 10, in the notes); replies judged not applicable are not scored.
"""

from __future__ import annotations

import argparse
import csv
import json
import statistics
import sys
from pathlib import Path
from typing import Any

from evals.g0 import _record, _slug, _warm, labelled
from officer import brain
from officer.llm import ModelDown, OllamaProvider, provider_from_spec
from officer.questions import AnswerClass, by_qid

EVALS = Path(__file__).resolve().parent
SETS = {"dev": EVALS / "g0" / "answers_dev.csv", "test": EVALS / "e2" / "answers_test.csv",
        "ood": EVALS / "e2" / "answers_ood.csv"}
CACHE = EVALS / "cache" / "e2"
RESULTS = EVALS / "results"
LABEL = "label (yes/no/partial/unknown)"
CONFIDENT = 8


def _rows(name: str) -> list[dict[str, str]]:
    with labelled(SETS[name]).open(encoding="utf-8-sig", newline="") as fh:
        rows = list(csv.DictReader(fh))
    for r in rows:
        r["reply"] = next(v for k, v in r.items() if k.startswith("reply"))
    return rows


def run(sets: list[str], models: list[str]) -> None:
    for model in models:
        provider = provider_from_spec(f"ollama:{model}")
        if isinstance(provider, OllamaProvider):
            provider.timeout = 600.0
        try:
            _warm(provider)
            for name in sets:
                records = [
                    _record("parse", r["id"], provider, brain.PARSE_SYSTEM,
                            brain.parse_user_prompt(by_qid()[r["qid"]], r["reply"]), brain.PARSE_SCHEMA)
                    for r in _rows(name)
                    if r["reply"].strip()
                ]
                out = CACHE / name / f"{_slug(model)}.jsonl"
                out.parent.mkdir(parents=True, exist_ok=True)
                lines = "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in records)
                out.write_text(lines, encoding="utf-8")
                print(f"{model} {name}: {len(records)} replies -> {out.relative_to(EVALS)}", flush=True)
        except ModelDown as exc:
            print(f"{model}: model down ({exc})", file=sys.stderr)


def _confidence(row: dict[str, str]) -> int:
    head = row.get("notes", "").split("|")[0].strip()
    return int(head[2:]) if head.startswith("c=") and head[2:].isdigit() else 10


def _macro_f1(pairs: list[tuple[str, str]]) -> float:
    f1s = []
    for cls in (a.value for a in AnswerClass):
        tp = sum(g == p == cls for g, p in pairs)
        fp = sum(p == cls != g for g, p in pairs)
        fn = sum(g == cls != p for g, p in pairs)
        f1s.append(2 * tp / (2 * tp + fp + fn) if tp else 0.0)
    return round(sum(f1s) / len(f1s), 3)


def _score_set(preds: dict[str, str], rows: list[dict[str, str]]) -> dict[str, Any]:
    gold = [r for r in rows if r[LABEL].strip() and r["id"] in preds]
    pairs = [(r[LABEL].strip().lower(), preds[r["id"]]) for r in gold]
    confident = [(g, p) for r, (g, p) in zip(gold, pairs, strict=True) if _confidence(r) >= CONFIDENT]
    return {
        "n": len(pairs),
        "accuracy": round(sum(g == p for g, p in pairs) / len(pairs), 3) if pairs else None,
        "macro_f1": _macro_f1(pairs) if pairs else None,
        "n_confident": len(confident),
        "accuracy_confident": (
            round(sum(g == p for g, p in confident) / len(confident), 3) if confident else None
        ),
        "errors": sorted(f"{r['id']}: {g}->{p}" for r, (g, p) in zip(gold, pairs, strict=True) if g != p),
    }


def score() -> dict[str, Any]:
    report: dict[str, Any] = {"confident_threshold": CONFIDENT, "sets": {}}
    for name in SETS:
        rows = _rows(name)
        if not any(r[LABEL].strip() for r in rows):
            continue
        per: dict[str, Any] = {}
        lex = {r["id"]: brain.lexicon_parse(r["reply"]).answer.value for r in rows if r["reply"].strip()}
        per["lexicon (no model)"] = _score_set(lex, rows)
        replies = {r["id"]: r["reply"] for r in rows}
        for f in sorted((CACHE / name).glob("*.jsonl")):
            recs = [json.loads(line) for line in f.read_text(encoding="utf-8").splitlines() if line.strip()]
            preds, valid = {}, 0
            for r in recs:
                v = brain._valid_parse(r["parsed"])
                valid += v is not None
                # what the agent acts on: the model's reading, or the lexicon's when the JSON is invalid
                preds[r["item"]] = v[0].value if v else brain.lexicon_parse(replies[r["item"]]).answer.value
            row = _score_set(preds, rows)
            row["valid_json"] = round(valid / len(recs), 3) if recs else None
            row["p50_s"] = round(statistics.median(r["ms"] for r in recs) / 1000, 2) if recs else None
            per[recs[0]["model"] if recs else f.stem] = row
        report["sets"][name] = per
    RESULTS.mkdir(exist_ok=True)
    text = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
    (RESULTS / "e2.json").write_text(text, encoding="utf-8")
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="E2: answer understanding on dev, test and ood.")
    sub = parser.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--sets", nargs="+", default=list(SETS), choices=list(SETS))
    r.add_argument("--models", nargs="+", required=True)
    sub.add_parser("score")
    args = parser.parse_args(argv)
    if args.cmd == "run":
        run(args.sets, args.models)
    report = score()
    for name, per in report["sets"].items():
        for model, row in per.items():
            print(f"{name:5} {model[:40]:40} acc {row['accuracy']}  confident {row['accuracy_confident']} "
                  f"(n={row['n_confident']})  macroF1 {row['macro_f1']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
