"""E6: the full loop on the live lab (real DNS, web, TLS and services in Jeddah), on held-out estates.

    uv run python -m evals.e6 --split dev --model ollama:qwen3:8b
    uv run python -m evals.e6 --split held_out --model ollama:qwen3:8b        # once, at the end

Each estate plants a seeded mix of defects and the agent runs end to end with the scripted demo owner.
Scores what the first full scan found against what was planted, and whether each fix reported as verified
really cleared its defect (from the worker's truth endpoint, which the agent never sees).
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

import yaml
from dotenv import load_dotenv

from officer.cli import ROOT, lab_session
from officer.server import SITE, ScriptedOwner
from officer.worker import connect_worker

HERE = Path(__file__).resolve().parent
SPLITS = yaml.safe_load((HERE / "splits.yaml").read_text(encoding="utf-8"))
FIXABLE = {
    "spf_missing": "publish_spf",
    "dmarc_none": "set_dmarc_reject",
    "dmarc_missing": "set_dmarc_reject",
    "mysql_3306": "close_db_port",
    "redis_6379": "close_cache_port",
    "ipp_631": "close_printer_ports",
    "lpd_515": "close_printer_ports",
    "ftp_21": "close_ftp_port",
    "no_redirect": "enable_https_redirect",
}


def run(split: str, model: str) -> list[dict[str, Any]]:
    load_dotenv(ROOT / ".env")
    worker = connect_worker()
    estates = SPLITS["lab"]["dev_estates" if split == "dev" else "held_out_estates"]
    script = json.loads((SITE / "demo_owner.json").read_text(encoding="utf-8"))
    rows = []
    for estate in estates:
        out = HERE / "cache" / "e6" / f"{split}-{model.replace(':', '_')}" / f"{estate}.jsonl"
        worker.estate(estate)
        before = worker.truth()
        start = time.perf_counter()
        metrics = lab_session(model, out, ScriptedOwner(script, pause=0.0), estate)
        after = worker.truth()  # what is still planted once the agent is done
        events = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines()]
        first_scan: set[str] = set()
        for e in events:
            if e["type"] == "phase" and e["data"]["phase"] in ("interview", "fix"):
                break
            if e["type"] == "tool_result":
                first_scan |= set(e["data"]["findings"])
        planted = set(before["planted"])
        baseline = set(before["baseline"])
        remaining = set(after["defects"])
        fixed_claims = metrics["fixes_verified"]
        false_fixed = [f for f in fixed_claims if any(FIXABLE.get(d) == f for d in remaining)]
        rows.append(
            {
                "estate": estate,
                "completed": metrics["halted"] is None,
                "defects": before["defects"],
                "planted_detectors": sorted(planted),
                "found": sorted(first_scan & planted),
                "missed": sorted(planted - first_scan),
                "unexpected": sorted(first_scan - planted - baseline),
                "fixes_verified": fixed_claims,
                "false_fixed": false_fixed,
                "fixes_failed": metrics["fixes_failed"],
                "fixable": sorted({FIXABLE[d] for d in before["defects"] if d in FIXABLE}),
                "remaining_defects": sorted(remaining),
                "escalations": metrics["escalations"],
                "seconds": round(time.perf_counter() - start, 1),
                "human_touches": metrics["human_touches"],
                "questions": metrics["questions_asked"],
                "contradiction_qids": sorted(
                    {e["data"]["qid"] for e in events if e["type"] == "contradiction"}
                ),
            }
        )
        print(json.dumps(rows[-1], ensure_ascii=False), flush=True)
        out_file = HERE / "results" / f"e6-{split}-{model.replace(':', '_')}.json"
        out_file.write_text(json.dumps(rows, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    return rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="evals.e6")
    parser.add_argument("--split", default="dev", choices=["dev", "held_out"])
    parser.add_argument("--model", default="scripted")
    args = parser.parse_args(argv)
    run(args.split, args.model)
    return 0


if __name__ == "__main__":
    sys.exit(main())
