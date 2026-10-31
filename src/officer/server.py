"""The interface server: live sessions over SSE, owner replies, and recorded runs for replay.

Binds to loopback only. The same page plays a live session (``/api/session/<id>/events``) or a recorded
run (``/runs/<file>.jsonl``), so the static replay site and the live demo share one renderer.
"""

from __future__ import annotations

import csv
import json
import queue
import re
import secrets
import threading
import time
from collections.abc import Awaitable, Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import uvicorn
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from officer.events import EventLog
from officer.questions import bank
from officer.session import Agent, Company, Config, OwnerReply, OwnerRequest
from officer.sovereignty import install_for_process

ROOT = Path(__file__).resolve().parents[2]
SITE = ROOT / "site"
RUNS = ROOT / "runs"


@dataclass
class UiOwner:
    """The owner is the person at the screen: each request waits for their reply from the page."""

    replies: queue.Queue[tuple[int, OwnerReply]] = field(default_factory=queue.Queue)
    pending: OwnerRequest | None = None

    def reply(self, request: OwnerRequest) -> OwnerReply:
        """Wait for the reply to this request; a stale or duplicate reply (another seq) is dropped."""
        self.pending = request
        while True:
            seq, answer = self.replies.get()
            if seq == request.seq:
                self.pending = None
                return answer


@dataclass
class ScriptedOwner:
    """A pre-written owner for recordings: replies from a script, with a short typing pause."""

    script: dict[str, Any]
    pause: float = 1.2

    def reply(self, request: OwnerRequest) -> OwnerReply:
        time.sleep(self.pause)
        if request.kind == "approve_fixes":
            allowed = set(self.script.get("approve", request.options))
            return OwnerReply(choices=tuple(o for o in request.options if o in allowed))
        if request.kind == "staff_band":
            return OwnerReply(choices=("6_to_249",))
        if request.kind in ("staff_count", "publish_txt"):
            return OwnerReply(text=str(self.script[request.kind]))
        qid = str(request.payload.get("qid", ""))
        entry = self.script["answers"].get(qid, {"text": "مدري"})
        if request.kind == "buttons":
            return OwnerReply(choices=(str(entry.get("button", "unknown")),))
        key = "followup" if request.payload.get("followup") and "followup" in entry else "text"
        update = entry.get("scope_update")
        return OwnerReply(text=str(entry[key]), scope_update=update if key == "text" else None)


@dataclass
class Live:
    log: EventLog
    owner: UiOwner | ScriptedOwner
    thread: threading.Thread
    metrics: dict[str, Any] = field(default_factory=dict)


SESSIONS: dict[str, Live] = {}


class StartIn(BaseModel):
    mode: str = "lab"  # lab | sim
    model: str = "ollama:qwen3:8b"
    owner: str = "ui"  # ui | script
    estate: str = "demo"
    seed: int = 7
    persona: str = "overstating"


LABEL_SETS = {
    "dev": ROOT / "evals" / "g0" / "answers_dev.csv",
    "test": ROOT / "evals" / "e2" / "answers_test.csv",
    "ood": ROOT / "evals" / "e2" / "answers_ood.csv",
    "rating": ROOT / "evals" / "g0" / "explain_rating.csv",
}


LABELS = ROOT / "evals" / "labels"  # where the labelling page saves; a sheet open in Excel cannot block it


def _label_path(name: str) -> Path:
    if name not in LABEL_SETS:
        raise HTTPException(404)
    return LABEL_SETS[name]


def labelled_path(name: str) -> Path:
    """The saved labels if the page has saved any, else the original sheet."""
    saved = LABELS / LABEL_SETS[name].name
    return saved if saved.exists() else LABEL_SETS[name]


class LabelIn(BaseModel):
    header: list[str]
    rows: list[list[str]]


class ReplyIn(BaseModel):
    seq: int
    text: str = ""
    choices: list[str] = []
    scope_update: dict[str, Any] | None = None


def add_label_routes(app: FastAPI) -> None:
    @app.get("/api/label/{name}")
    def label_get(name: str) -> dict[str, Any]:
        _label_path(name)
        with labelled_path(name).open(encoding="utf-8-sig", newline="") as fh:
            rows = list(csv.reader(fh))
        questions = {q.qid: {"ar": q.prompt_ar, "en": q.prompt_en} for q in bank()}
        return {"header": rows[0], "rows": rows[1:], "questions": questions}

    @app.post("/api/label/{name}")
    def label_put(name: str, body: LabelIn) -> dict[str, bool]:
        target = LABELS / _label_path(name).name
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp = target.with_suffix(".tmp")
        with tmp.open("w", encoding="utf-8-sig", newline="") as fh:
            writer = csv.writer(fh, lineterminator="\n")
            writer.writerow(body.header)
            writer.writerows(body.rows)
        tmp.replace(target)  # atomic: a half-written sheet never replaces a good one
        return {"ok": True}


LOCAL_HOSTS = ["localhost", "127.0.0.1"]
LOCAL_ORIGIN = re.compile(r"^https?://(localhost|127\.0\.0\.1)(:\d+)?$")


def create_app() -> FastAPI:
    load_dotenv(ROOT / ".env")
    install_for_process()
    app = FastAPI(title="compliance-officer", docs_url=None, redoc_url=None)
    # A page on another site must not start a session or answer for the owner: the Host check stops
    # DNS rebinding, the Origin check stops CSRF.
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=LOCAL_HOSTS)

    @app.middleware("http")
    async def same_origin(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        origin = request.headers.get("origin")
        if request.method != "GET" and origin is not None and not LOCAL_ORIGIN.match(origin):
            return JSONResponse({"error": "cross-origin request refused"}, status_code=403)
        return await call_next(request)

    @app.get("/api/ping")
    def ping() -> dict[str, bool]:
        return {"ok": True}

    add_label_routes(app)

    @app.get("/runs/index.json")
    def runs() -> list[str]:
        return sorted(str(p.relative_to(RUNS).as_posix()) for p in RUNS.rglob("*.jsonl"))

    @app.get("/runs/{path:path}")
    def run_file(path: str) -> FileResponse:
        target = (RUNS / path).resolve()
        if RUNS.resolve() not in target.parents or not target.is_file():
            raise HTTPException(404)
        return FileResponse(target, media_type="application/x-ndjson")

    @app.post("/api/session")
    def start(body: StartIn) -> dict[str, str]:
        from officer.cli import make_provider  # noqa: PLC0415

        sid = secrets.token_hex(6)
        out = RUNS / "live" / f"{time.strftime('%Y%m%d-%H%M%S')}-{body.mode}-{sid}.jsonl"
        log = EventLog(out)
        owner: UiOwner | ScriptedOwner = UiOwner()
        if body.owner == "script":
            owner = ScriptedOwner(json.loads((SITE / "demo_owner.json").read_text(encoding="utf-8")))
        provider = make_provider(body.model)

        def work() -> None:
            try:
                if body.mode == "sim":
                    from officer.cli import sim_session  # noqa: PLC0415

                    metrics, *_ = sim_session(body.seed, body.persona, body.model, None, log=log)
                    live.metrics = metrics
                    return
                from officer.worker import connect_worker  # noqa: PLC0415

                worker = connect_worker()
                info = worker.estate(body.estate)
                company = Company(name_ar="مؤسسة واحة الرمال للتجارة", name_en="Wahat Al-Ramal Trading (fictional)",
                                  apex=info.apex, hosts=info.hosts)
                live.metrics = Agent(company, worker, owner, provider, log, Config()).run()
            except Exception as exc:
                log.emit("error", kind=type(exc).__name__)

        live = Live(log, owner, threading.Thread(target=work, daemon=True))
        SESSIONS[sid] = live
        live.thread.start()
        return {"session": sid, "file": out.relative_to(RUNS).as_posix()}

    @app.get("/api/session/{sid}/events")
    def events(sid: str) -> StreamingResponse:
        live = SESSIONS.get(sid)
        if live is None:
            raise HTTPException(404)

        def stream() -> Iterator[str]:
            for event in live.log.subscribe(keepalive=15.0):
                yield ": keepalive\n\n" if event is None else f"data: {json.dumps(event, ensure_ascii=False)}\n\n"

        return StreamingResponse(stream(), media_type="text/event-stream")

    @app.post("/api/session/{sid}/reply")
    def reply(sid: str, body: ReplyIn) -> dict[str, bool]:
        live = SESSIONS.get(sid)
        if live is None or not isinstance(live.owner, UiOwner):
            raise HTTPException(404)
        pending = live.owner.pending
        if pending is None or pending.seq != body.seq:
            raise HTTPException(409, "no such pending request")
        live.owner.replies.put((body.seq, OwnerReply(text=body.text[:2000], choices=tuple(body.choices[:20]),
                                                     scope_update=body.scope_update)))
        return {"ok": True}

    if SITE.is_dir():
        app.mount("/", StaticFiles(directory=SITE, html=True), name="site")
    return app


def serve(port: int = 8000) -> None:
    uvicorn.run(create_app(), host="127.0.0.1", port=port, loop="asyncio", log_level="warning")
