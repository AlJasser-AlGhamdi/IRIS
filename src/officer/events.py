"""The run's event stream, which the interface draws, replays play and the audit verifies.

Each event is hash-chained to the one before, so a recorded run cannot be edited unnoticed. Each scan
result carries the worker's own audit-chain head, which links the two logs.
"""

from __future__ import annotations

import hashlib
import json
import queue
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

GENESIS = "0" * 64


def _digest(prev: str, body: dict[str, Any]) -> str:
    canonical = json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256((prev + canonical).encode("utf-8")).hexdigest()


@dataclass
class EventLog:
    path: Path | None = None
    clock: Any = time.time
    events: list[dict[str, Any]] = field(default_factory=list)
    _head: str = field(default=GENESIS, init=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False)
    _subscribers: list[queue.Queue[dict[str, Any]]] = field(default_factory=list, init=False)
    _t0: float = field(default=0.0, init=False)

    def __post_init__(self) -> None:
        self._t0 = self.clock()
        if self.path is not None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text("", encoding="utf-8")

    @property
    def head(self) -> str:
        return self._head

    def emit(self, type_: str, **data: Any) -> dict[str, Any]:
        with self._lock:
            body = {"seq": len(self.events), "t": round(self.clock() - self._t0, 3), "type": type_, "data": data}
            event = {**body, "prev": self._head, "hash": _digest(self._head, body)}
            self._head = event["hash"]
            self.events.append(event)
            if self.path is not None:
                with self.path.open("a", encoding="utf-8", newline="\n") as fh:
                    fh.write(json.dumps(event, ensure_ascii=False) + "\n")
            for sub in list(self._subscribers):
                sub.put(event)
        return event

    def subscribe(self, keepalive: float | None = None) -> Iterator[dict[str, Any] | None]:
        """Replay everything so far, then follow live events (one SSE client). With ``keepalive``, yield
        ``None`` after that many idle seconds so a disconnected client is noticed and released."""
        q: queue.Queue[dict[str, Any]] = queue.Queue()
        with self._lock:
            backlog = list(self.events)
            self._subscribers.append(q)
        try:
            yield from backlog
            while True:
                try:
                    yield q.get(timeout=keepalive)
                except queue.Empty:
                    yield None
        finally:
            with self._lock:
                self._subscribers.remove(q)


def verify(path: Path) -> tuple[bool, int, str]:
    """Recompute the chain of a recorded run: (intact, events, head)."""
    head = GENESIS
    count = 0
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        event = json.loads(line)
        body = {k: event[k] for k in ("seq", "t", "type", "data")}
        if event["prev"] != head or event["hash"] != _digest(head, body) or event["seq"] != count:
            return False, count, head
        head = event["hash"]
        count += 1
    return True, count, head
