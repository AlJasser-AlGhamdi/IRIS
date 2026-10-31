"""Gate G0: which local model earns each of the model's three jobs, measured on our own tasks.

    uv run python -m evals.g0 run --models qwen3:8b gemma3:12b gpt-oss:20b <allam>   # calls models, caches
    uv run python -m evals.g0 score                                                  # from the cache only

Parse accuracy needs evals/g0/answers_dev.csv labelled by a native speaker. Explanations are rated
blind from evals/g0/explain_rating.csv (model names hidden behind codes until scoring).
"""

from __future__ import annotations

import argparse
import csv
import json
import random
import statistics
import sys
from pathlib import Path
from typing import Any

from officer import brain
from officer.llm import ModelDown, OllamaProvider, Provider, provider_from_spec
from officer.questions import AnswerClass, by_qid

HERE = Path(__file__).resolve().parent / "g0"
CACHE = Path(__file__).resolve().parent / "cache" / "g0"
RESULTS = Path(__file__).resolve().parent / "results"

THRESHOLDS = {
    "parse_accuracy": 0.85,
    "valid_json": 0.98,
    "parse_p50_s": 4.0,
    "choose_acceptable": 0.80,
    "choose_p50_s": 3.0,
    "explain_mean": 3.5,
    "explain_clean": 0.90,
}


def _slug(model: str) -> str:
    return model.replace("/", "_").replace(":", "_")


LABELS = Path(__file__).resolve().parent / "labels"  # what the labelling page saved


def labelled(path: Path) -> Path:
    """The labelling page's saved copy of a sheet if there is one, else the sheet itself."""
    saved = LABELS / path.name
    return saved if saved.exists() else path


def _answers() -> list[dict[str, str]]:
    with labelled(HERE / "answers_dev.csv").open(encoding="utf-8-sig") as fh:
        return list(csv.DictReader(fh))


def run(models: list[str]) -> None:
    CACHE.mkdir(parents=True, exist_ok=True)
    states = json.loads((HERE / "states.json").read_text(encoding="utf-8"))["states"]
    facts = json.loads((HERE / "facts.json").read_text(encoding="utf-8"))["sets"]
    for model in models:
        provider = provider_from_spec(f"ollama:{model}")
        if isinstance(provider, OllamaProvider):
            provider.timeout = 600.0  # first load from the HDD and CPU offload can be slow
        records: list[dict[str, Any]] = []
        try:
            _warm(provider)
            for row in _answers():
                q = by_qid()[row["qid"]]
                records.append(
                    _record(
                        "parse",
                        row["id"],
                        provider,
                        brain.PARSE_SYSTEM,
                        brain.parse_user_prompt(q, row["reply"]),
                        brain.PARSE_SCHEMA,
                    )
                )
            for s in states:
                menu = [(a, d) for a, d in s["menu"]]
                records.append(
                    _record(
                        "choose",
                        s["id"],
                        provider,
                        brain.CHOOSE_SYSTEM,
                        brain.choose_user_prompt(s["phase"], s["facts"], menu),
                        brain.choose_schema([a for a, _ in menu]),
                    )
                )
            for f in facts:
                user = "Facts:\n" + "\n".join(f"- {k}: {v}" for k, v in f["facts"].items())
                records.append(
                    _record("explain", f["id"], provider, brain.EXPLAIN_SYSTEM, user, brain.EXPLAIN_SCHEMA)
                )
        except ModelDown as exc:
            print(f"{model}: model down ({exc})", file=sys.stderr)
        out = CACHE / f"{_slug(model)}.jsonl"
        out.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in records) + "\n", encoding="utf-8")
        print(f"{model}: {len(records)} calls cached -> {out.name}")


def _warm(provider: Provider) -> None:
    """Load the model once so the first measured call is not a disk load (the models sit on an HDD)."""
    if isinstance(provider, OllamaProvider):
        provider.complete("warm", "Reply with JSON.", "{}", {"type": "object"})


def _record(
    role: str, item: str, provider: Provider, system: str, user: str, schema: dict[str, Any]
) -> dict[str, Any]:
    call = provider.complete(role, system, user, schema)
    return {
        "role": role,
        "item": item,
        "model": call.model,
        "raw": call.raw,
        "parsed": call.parsed,
        "ms": call.ms,
        "prompt_tokens": call.prompt_tokens,
        "output_tokens": call.output_tokens,
    }


def _load(model_file: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in model_file.read_text(encoding="utf-8").splitlines() if line.strip()]


def score() -> dict[str, Any]:
    labels = {r["id"]: r for r in _answers()}
    labelled = {k: v for k, v in labels.items() if v["label (yes/no/partial/unknown)"].strip()}
    states = {s["id"]: s for s in json.loads((HERE / "states.json").read_text(encoding="utf-8"))["states"]}
    facts = {f["id"]: f for f in json.loads((HERE / "facts.json").read_text(encoding="utf-8"))["sets"]}
    ratings = _ratings()
    report: dict[str, Any] = {"labelled_answers": len(labelled), "thresholds": THRESHOLDS, "models": {}}
    for model_file in sorted(CACHE.glob("*.jsonl")):
        recs = _load(model_file)
        model = recs[0]["model"] if recs else model_file.stem
        parse = [r for r in recs if r["role"] == "parse"]
        choose = [r for r in recs if r["role"] == "choose"]
        explain = [r for r in recs if r["role"] == "explain"]
        row: dict[str, Any] = {}
        valid = [r for r in parse + choose + explain if r["parsed"] is not None]
        row["valid_json"] = round(len(valid) / max(1, len(parse) + len(choose) + len(explain)), 3)
        correct = 0
        for r in parse:
            if r["item"] in labelled:
                gold = labelled[r["item"]]["label (yes/no/partial/unknown)"].strip().lower()
                v = brain._valid_parse(r["parsed"])
                agent = v[0].value if v else brain.lexicon_parse(labels[r["item"]]["reply"]).answer.value
                correct += agent == gold
        row["parse_accuracy"] = round(correct / len(labelled), 3) if labelled else None
        row["parse_p50_s"] = round(statistics.median(r["ms"] for r in parse) / 1000, 2) if parse else None
        ok = sum((r["parsed"] or {}).get("action_id") in states[r["item"]]["acceptable"] for r in choose)
        row["choose_acceptable"] = round(ok / len(choose), 3) if choose else None
        row["choose_p50_s"] = round(statistics.median(r["ms"] for r in choose) / 1000, 2) if choose else None
        clean = 0
        for r in explain:
            text = str((r["parsed"] or {}).get("text_ar", ""))
            clean += bool(text) and not brain.unsupported_tokens(text, facts[r["item"]]["facts"])
        row["explain_clean"] = round(clean / len(explain), 3) if explain else None
        row["explain_mean"] = ratings.get(model)
        row["max_prompt_tokens"] = max((r["prompt_tokens"] for r in recs), default=0)
        row["passes"] = {
            k: (row.get(k) is not None and (row[k] <= v if k.endswith("_s") else row[k] >= v))
            for k, v in THRESHOLDS.items()
            if k in row
        }
        report["models"][model] = row
    # The deterministic fallback, for comparison.
    if labelled:
        lex = sum(
            brain.lexicon_parse(v["reply"]).answer.value
            == v["label (yes/no/partial/unknown)"].strip().lower()
            for v in labelled.values()
        )
        report["lexicon_parse_accuracy"] = round(lex / len(labelled), 3)
    RESULTS.mkdir(parents=True, exist_ok=True)
    (RESULTS / "g0.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    _write_rating_sheet()
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return report


def _write_rating_sheet() -> None:
    """Shuffle every model's explanations behind codes, for a blind 1-5 rating."""
    sheet = HERE / "explain_rating.csv"
    if sheet.exists():
        return
    facts = {f["id"]: f for f in json.loads((HERE / "facts.json").read_text(encoding="utf-8"))["sets"]}
    rows, key = [], {}
    rng = random.Random(20261030)
    codes = rng.sample(range(100, 1000), 200)
    for model_file in sorted(CACHE.glob("*.jsonl")):
        for r in _load(model_file):
            if r["role"] == "explain":
                code = f"X{codes[len(key)]}"
                key[code] = r["model"]
                text = str((r["parsed"] or {}).get("text_ar", ""))
                rows.append(
                    [code, r["item"], json.dumps(facts[r["item"]]["facts"], ensure_ascii=False), text, ""]
                )
    random.Random(7).shuffle(rows)
    with sheet.open("w", encoding="utf-8-sig", newline="") as fh:
        w = csv.writer(fh, lineterminator="\n")
        w.writerow(["code", "fact_set", "facts", "arabic_text", "rating_1_to_5"])
        w.writerows(rows)
    (CACHE / "rating_key.json").write_text(json.dumps(key, indent=2) + "\n", encoding="utf-8")


def _ratings() -> dict[str, float]:
    sheet, key_file = labelled(HERE / "explain_rating.csv"), CACHE / "rating_key.json"
    if not sheet.exists() or not key_file.exists():
        return {}
    key = json.loads(key_file.read_text(encoding="utf-8"))
    per: dict[str, list[int]] = {}
    with sheet.open(encoding="utf-8-sig") as fh:
        for row in csv.DictReader(fh):
            if row["rating_1_to_5"].strip().isdigit():
                per.setdefault(key[row["code"]], []).append(int(row["rating_1_to_5"]))
    return {m: round(statistics.mean(v), 2) for m, v in per.items() if v}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="evals.g0")
    sub = parser.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--models", nargs="+", required=True)
    sub.add_parser("score")
    args = parser.parse_args(argv)
    if args.cmd == "run":
        run(args.models)
    else:
        score()
    _ = AnswerClass  # the label vocabulary is the parse enum
    return 0


if __name__ == "__main__":
    sys.exit(main())
