"""Command-line entry point.

    officer run --sim --seed 7 --persona overstating --model scripted      # synthetic firm, offline
    officer run --lab --model ollama:qwen3:8b                               # the live Jeddah lab
    officer demo                                                            # offline demo, ~1 minute
    officer audit-verify runs/<file>.jsonl
    officer serve                                                           # the interface (live + replay)
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import re
import sys
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

from officer import brain
from officer.events import EventLog, verify
from officer.llm import Provider, provider_from_spec
from officer.session import Agent, Company, Config, Owner
from officer.sovereignty import guarded
from officer.worker import SimWorker, Worker, connect_worker

ROOT = Path(__file__).resolve().parents[2]


def scripted(role: str, user: str) -> dict[str, Any] | str:
    """The deterministic stand-in model: lexicon parsing, first legal action, template explanations."""
    if role == "parse":
        reply = user.split("Owner's reply:", 1)[-1]
        p = brain.lexicon_parse(reply)
        return {"answer": p.answer.value, "evidence_offered": p.evidence_offered,
                "needs_followup": p.needs_followup, "confidence": "low"}
    if role == "choose":
        first = re.search(r"^- ([A-Za-z0-9_.-]+):", user.split("Allowed actions", 1)[-1], re.MULTILINE)
        return {"action_id": first.group(1) if first else "", "reason_ar": "حسب الأولوية"}
    return {"text_ar": ""}  # the agent falls back to its template


def make_provider(spec: str) -> Provider | None:
    if spec == "none":
        return None
    return provider_from_spec(spec, scripted if spec == "scripted" else None)


def sim_session(seed: int, persona: str, model: str, out: Path | None, config: Config | None = None,
                log: EventLog | None = None, **scenario: Any) -> tuple[dict[str, Any], Agent, SimWorker, Any]:
    from officer.owner_sim import SimOwner  # noqa: PLC0415
    from p2c.evaluation.synthetic import generate_cases  # noqa: PLC0415 - heavy import

    case = dataclasses.replace(generate_cases(1, seed=seed)[0], case_id=f"seed{seed}")
    sim_keys = {"blocked", "lose_txt", "failing_fixes", "fail_rate"}
    worker = SimWorker(case, **{k: v for k, v in scenario.items() if k in sim_keys})
    owner = SimOwner(case, persona=persona, seed=seed,
                     **{k: v for k, v in scenario.items() if k not in sim_keys})
    company = Company(name_ar="منشأة تجريبية", name_en=f"Synthetic firm {case.case_id}", apex=worker.apex,
                      hosts=[h for h in worker.hosts if h != worker.apex])
    agent = Agent(company, worker, owner, make_provider(model), log or EventLog(out), config)
    with guarded():
        metrics = agent.run()
    return metrics, agent, worker, owner


DRIFT_NOTE = ("محاكاة في المختبر: تغيّرت إعدادات المنشأة كما يحدث في الواقع، فأعاد أحدهم فتح منفذ وأضاف خدمة جديدة.",
              "Lab simulation: the estate changed the way real ones do; someone re-opened a port and added a service.")


def lab_session(model: str, out: Path, owner: Owner, estate: str = "demo",
                config: Config | None = None, payload: dict[str, str] | None = None,
                monitor: int = 0, drift: str | None = None) -> dict[str, Any]:
    load_dotenv(ROOT / ".env")
    worker: Worker = connect_worker()
    info = worker.estate(estate)
    if payload:
        worker.payload(payload)
    company = Company(name_ar="مؤسسة واحة الرمال للتجارة", name_en="Wahat Al-Ramal Trading (fictional)",
                      apex=info.apex, hosts=info.hosts)
    agent = Agent(company, worker, owner, make_provider(model), EventLog(out), config)

    def before_round(n: int) -> None:
        if n == 1 and drift:
            worker.drift_estate(drift)  # type: ignore[attr-defined]
            agent.log.emit("lab_note", text_ar=DRIFT_NOTE[0], text_en=DRIFT_NOTE[1], estate=drift)

    with guarded():
        metrics = agent.run()
        if monitor and not agent.state.halted:
            from officer.watch import watch  # noqa: PLC0415

            metrics = {**metrics, "monitor": watch(agent, monitor, before_round)}
    return metrics


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="officer")
    sub = parser.add_subparsers(dest="cmd", required=True)
    run = sub.add_parser("run")
    run.add_argument("--sim", action="store_true")
    run.add_argument("--seed", type=int, default=7)
    run.add_argument("--persona", default="overstating", choices=["honest", "overstating", "vague"])
    run.add_argument("--model", default="scripted")
    run.add_argument("--out", type=Path)
    run.add_argument("--lab", action="store_true", help="the live lab through the private worker")
    run.add_argument("--estate", default="demo")
    run.add_argument("--monitor", type=int, default=0, help="monitoring rounds after the assessment (lab)")
    run.add_argument("--drift", help="lab estate to switch to before the first monitoring round")
    demo = sub.add_parser("demo")
    demo.add_argument("--model", default="scripted")
    verify_p = sub.add_parser("audit-verify")
    verify_p.add_argument("path", type=Path)
    serve = sub.add_parser("serve")
    serve.add_argument("--port", type=int, default=8000)
    args = parser.parse_args(argv)

    if args.cmd == "audit-verify":
        ok, count, head = verify(args.path)
        print(json.dumps({"intact": ok, "events": count, "head": head}))
        return 0 if ok else 1
    if args.cmd == "serve":
        from officer.server import serve as run_server  # noqa: PLC0415

        run_server(port=args.port)
        return 0
    if args.cmd == "demo" or (args.cmd == "run" and args.sim):
        seed = getattr(args, "seed", 7)
        persona = getattr(args, "persona", "overstating")
        out = getattr(args, "out", None) or ROOT / "runs" / "sim" / f"seed{seed}-{persona}.jsonl"
        metrics, *_ = sim_session(seed, persona, args.model, out)
        print(json.dumps(metrics, ensure_ascii=False, indent=2))
        print(f"events: {out}")
        return 0
    if args.cmd == "run" and args.lab:
        from officer.server import SITE, ScriptedOwner  # noqa: PLC0415

        owner = ScriptedOwner(json.loads((SITE / "demo_owner.json").read_text(encoding="utf-8")), pause=0.0)
        out = args.out or ROOT / "runs" / "lab" / f"{args.estate}-{args.model.replace(':', '_')}.jsonl"
        metrics = lab_session(args.model, out, owner, args.estate, monitor=args.monitor, drift=args.drift)
        print(json.dumps(metrics, ensure_ascii=False, indent=2))
        print(f"events: {out}")
        return 0
    print("choose --sim or --lab", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
