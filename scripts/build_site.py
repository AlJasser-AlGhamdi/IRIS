"""Build the static replay site: the interface plus recorded runs, no server needed.

    uv run python scripts/build_site.py                         # writes dist/
    uv run python -m http.server 8793 --directory dist          # local presenter

Each run copied in must have an intact hash chain and pass the publish gate's rules.
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from public_check import RULES  # noqa: E402

from officer.events import verify  # noqa: E402

DIST = ROOT / "dist"
RUN_DIRS = ("featured",)  # synthetic-firm runs use generated .sa-style names: kept out of the public site
RESULT_KEYS = (
    "e1-held_out-ollama_qwen3_8b",
    "e6-held_out-ollama_qwen3_8b",
    "e4",
    "e7-ollama_qwen3_8b",
    "ablations-ollama_qwen3_8b",
)


def main() -> int:
    if DIST.exists():
        shutil.rmtree(DIST)
    shutil.copytree(
        ROOT / "site",
        DIST,
        ignore=shutil.ignore_patterns("demo_owner.json", "label.html", "node_modules", "*.test.mjs"),
    )
    runs: list[str] = []
    for sub in RUN_DIRS:
        for path in sorted((ROOT / "runs" / sub).glob("*.jsonl")) if (ROOT / "runs" / sub).is_dir() else []:
            ok, events, _head = verify(path)
            text = path.read_text(encoding="utf-8")
            leaks = [name for name, rule in RULES.items() if name != "email address" and rule.search(text)]
            if not ok or leaks:
                print(f"skip {path.name}: intact={ok} leaks={leaks}")
                continue
            target = DIST / "runs" / sub / path.name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, target)
            for report_suffix in (".report.html", ".report.en.html"):
                report = path.with_suffix(report_suffix)
                report_text = report.read_text(encoding="utf-8") if report.exists() else ""
                if any(rule.search(report_text) for name, rule in RULES.items() if name != "email address"):
                    print(f"skip report {report.name}: publish-gate rule matched")
                elif report.exists():
                    shutil.copy2(report, target.with_suffix(report_suffix))
            calendar = path.with_suffix(".calendar.ics")
            if calendar.exists():
                shutil.copy2(calendar, target.with_suffix(".calendar.ics"))
            runs.append(f"{sub}/{path.name}")
            print(f"run {sub}/{path.name}: {events} events")
    (DIST / "runs").mkdir(exist_ok=True)
    (DIST / "runs" / "index.json").write_text(json.dumps(runs, indent=1) + "\n", encoding="utf-8")
    summary = json.loads((ROOT / "evals" / "results" / "summary.json").read_text(encoding="utf-8"))
    results = {key: summary[key] for key in RESULT_KEYS}
    (DIST / "results.json").write_text(json.dumps(results, indent=1) + "\n", encoding="utf-8")
    for qr_name in ("qr-code.png",):
        qr_source = ROOT / "slides" / "img" / qr_name
        if qr_source.exists():
            qr_target = DIST / "img" / qr_name
            qr_target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(qr_source, qr_target)
    print(f"dist/: {len(runs)} runs")
    return 0


if __name__ == "__main__":
    sys.exit(main())
