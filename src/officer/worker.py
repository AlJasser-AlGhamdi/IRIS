"""Where observations come from: the private lab worker over the tailnet, or a simulated estate.

Both speak only the typed contract. The simulated worker replays what a scan of one of the engine's synthetic
firms observes, so evaluations run without the lab, the network or a GPU.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import subprocess
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Protocol

import httpx

from officer.contract import (
    ChallengeOut,
    EstateOut,
    FixId,
    FixOut,
    Group,
    GroupResult,
    ScanIn,
    ScanOut,
    StopReason,
    VerifyOut,
)
from officer.fixes import FIXES, GROUP_OF
from p2c.evaluation.synthetic import EvalCase
from p2c.scanning.catalog import CheckId


class WorkerError(Exception):
    """The worker refused or failed; the message is a code, never target text."""


class Worker(Protocol):
    def estate(self, name: str) -> EstateOut: ...
    def challenge(self, apex: str, hosts: Sequence[str]) -> list[ChallengeOut]: ...
    def owner_publish(self, challenge_ids: Sequence[str]) -> None: ...
    def owner_unpublish(self, challenge_ids: Sequence[str]) -> None: ...
    def verify(self, challenge_id: str) -> VerifyOut: ...
    def scan(self, request: ScanIn) -> ScanOut: ...
    def fix(self, fix_id: FixId) -> FixOut: ...
    def payload(self, slots: dict[str, str]) -> None: ...


@dataclass
class HttpWorker:
    """The private worker next to the lab (Jeddah), reached over the tailnet with a bearer token."""

    url: str = field(default_factory=lambda: os.environ.get("OFFICER_WORKER_URL", ""))
    token: str = field(default_factory=lambda: os.environ.get("OFFICER_WORKER_TOKEN", ""))
    timeout: float = 180.0

    def _post(self, path: str, body: dict[str, object]) -> object:
        return self._call("POST", path, body)

    def payload(self, slots: dict[str, str]) -> None:
        """Plant text where a scan reads (evaluation only): page title, a header, a TXT record, a service reply."""
        self._post("/lab/payload", dict(slots))

    def truth(self) -> dict[str, object]:
        """What the lab really planted (evaluation only; the agent never calls this)."""
        data = self._call("GET", "/lab/truth", {})
        assert isinstance(data, dict)
        return data

    def _call(self, method: str, path: str, body: dict[str, object]) -> object:
        if not self.url or not self.token:
            raise WorkerError("worker_not_configured")
        try:
            response = httpx.request(method, f"{self.url}{path}", json=body if method == "POST" else None,
                                     timeout=self.timeout, trust_env=False,
                                     headers={"Authorization": f"Bearer {self.token}"})
        except httpx.HTTPError as exc:
            raise WorkerError(f"worker_unreachable:{type(exc).__name__}") from exc
        if response.status_code == 403:  # noqa: PLR2004
            raise WorkerError("refused_not_verified")
        if response.status_code >= 400:  # noqa: PLR2004
            raise WorkerError(f"worker_http_{response.status_code}")
        return response.json()

    def estate(self, name: str) -> EstateOut:
        return EstateOut.model_validate(self._post("/lab/estate", {"estate": name}))

    def drift_estate(self, name: str) -> EstateOut:
        """Lab only: switch the planted defects to another estate's, keeping ownership proofs."""
        return EstateOut.model_validate(self._post("/lab/drift", {"estate": name}))

    def challenge(self, apex: str, hosts: Sequence[str]) -> list[ChallengeOut]:
        data = self._post("/ownership/challenge", {"apex": apex, "hosts": list(hosts)})
        assert isinstance(data, list)
        return [ChallengeOut.model_validate(c) for c in data]

    def owner_publish(self, challenge_ids: Sequence[str]) -> None:
        self._post("/lab/owner/publish_txt", {"challenge_ids": list(challenge_ids)})

    def owner_unpublish(self, challenge_ids: Sequence[str]) -> None:
        self._post("/lab/owner/unpublish_txt", {"challenge_ids": list(challenge_ids)})

    def verify(self, challenge_id: str) -> VerifyOut:
        return VerifyOut.model_validate(self._post("/ownership/verify", {"challenge_id": challenge_id}))

    def scan(self, request: ScanIn) -> ScanOut:
        return ScanOut.model_validate(self._post("/scan", request.model_dump(mode="json")))

    def fix(self, fix_id: FixId) -> FixOut:
        return FixOut.model_validate(self._post("/lab/fix", {"fix_id": fix_id.value}))


@dataclass
class SshRelayWorker(HttpWorker):
    """The worker API through a relay script over SSH, for when a firewall closes the tailnet port. The relay
    runs on the worker host, adds the token there, and returns ``{"status", "body"}``."""

    host: str = field(default_factory=lambda: os.environ.get("OFFICER_SSH_HOST", ""))
    key: str = field(default_factory=lambda: os.environ.get("OFFICER_SSH_KEY", ""))
    relay: str = "~/officer-worker/.venv/bin/python ~/officer-worker/relay.py"

    def _call(self, method: str, path: str, body: dict[str, object]) -> object:
        if not self.host or not self.key:
            raise WorkerError("relay_not_configured")
        command = ["ssh", "-i", self.key, "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", self.host,
                   f"{self.relay} {method} {path}"]
        try:
            done = subprocess.run(command, input=json.dumps(body), capture_output=True, text=True,
                                  timeout=self.timeout, check=False)
        except subprocess.TimeoutExpired as exc:
            raise WorkerError("relay_timeout") from exc
        if done.returncode != 0:
            raise WorkerError(f"relay_exit_{done.returncode}")
        reply = json.loads(done.stdout)
        status = int(reply.get("status", 0))
        if status == 403:  # noqa: PLR2004
            raise WorkerError("refused_not_verified")
        if status >= 400:  # noqa: PLR2004
            raise WorkerError(f"worker_http_{status}")
        return reply.get("body")


def connect_worker() -> Worker:
    """The lab worker: direct over the tailnet, or through the SSH relay when OFFICER_WORKER_MODE=ssh."""
    return SshRelayWorker() if os.environ.get("OFFICER_WORKER_MODE") == "ssh" else HttpWorker()


def _hex(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


@dataclass
class SimWorker:
    """A synthetic firm whose scan observes ``case.injected``; fixes remove what they clear.

    Switches for the robustness evals: ``blocked`` groups come back unread, ``lose_txt`` makes the ownership
    record vanish before the next scan, and ``failing_fixes`` apply but do not clear.
    """

    case: EvalCase
    blocked: set[Group] = field(default_factory=set)
    lose_txt: bool = False
    failing_fixes: set[FixId] = field(default_factory=set)
    fail_rate: float = 0.0  # share of fixes that apply but do not take effect, chosen by hash (deterministic)
    _open: set[tuple[str, CheckId]] = field(init=False)
    _challenges: dict[str, str] = field(init=False, default_factory=dict)  # id -> name
    _published: set[str] = field(init=False, default_factory=set)
    _verified: set[str] = field(init=False, default_factory=set)
    _audit: str = field(init=False, default="0" * 64)
    scans: int = field(init=False, default=0)

    def __post_init__(self) -> None:
        self._open = {(i.asset, i.check) for i in self.case.injected}

    @property
    def apex(self) -> str:
        return self.case.profile.apex

    @property
    def hosts(self) -> list[str]:
        return sorted({a.value for a in self.case.profile.assets} | {self.apex})

    def _chain(self, event: str) -> str:
        self._audit = _hex(self._audit + event)
        return self._audit

    def estate(self, name: str) -> EstateOut:
        return EstateOut(estate=name, apex=self.apex, hosts=[h for h in self.hosts if h != self.apex])

    def challenge(self, apex: str, hosts: Sequence[str]) -> list[ChallengeOut]:
        out = []
        for name in [apex, *hosts]:
            cid = secrets.token_hex(8)
            self._challenges[cid] = name
            out.append(ChallengeOut(challenge_id=cid, record_name=f"_officer-challenge.{name}",
                                    token=secrets.token_urlsafe(24)))
        self._chain("challenge")
        return out

    def owner_publish(self, challenge_ids: Sequence[str]) -> None:
        self._published |= set(challenge_ids)

    def owner_unpublish(self, challenge_ids: Sequence[str]) -> None:
        self._published -= set(challenge_ids)

    def verify(self, challenge_id: str) -> VerifyOut:
        ok = challenge_id in self._published
        if ok:
            self._verified.add(challenge_id)
        self._chain(f"verify:{ok}")
        return VerifyOut(verified=ok, verification_id=f"v-{challenge_id}" if ok else None)

    def scan(self, request: ScanIn) -> ScanOut:
        start = time.perf_counter()
        verified_names = {self._challenges[c.removeprefix("v-")] for c in request.verification_ids
                          if c.removeprefix("v-") in self._verified}
        if not {request.apex, *request.hosts} <= verified_names:
            raise WorkerError("refused_not_verified")
        self.scans += 1
        if self.lose_txt:
            return ScanOut(scan_id=secrets.token_hex(8), results=[], stopped=True,
                           stop_reason=StopReason.OWNERSHIP_LOST, audit_head=self._chain("stopped"),
                           duration_ms=0)
        results = []
        for group in request.groups:
            hosts = [request.apex] if group is Group.DNS else [request.apex, *request.hosts]
            for host in hosts:
                checks = [c for c, g in GROUP_OF.items() if g is group]
                readable = [c for c in checks if group not in self.blocked and self._readable(host, c)]
                found = [c.value for (h, c) in self._open if h == host and c in readable]
                unread = [c.value for c in checks if c not in readable]
                results.append(GroupResult(group=group, host=host, findings=found, unread=unread))
        return ScanOut(scan_id=secrets.token_hex(8), results=results, audit_head=self._chain("scan"),
                       duration_ms=int((time.perf_counter() - start) * 1000))

    def drift(self, opens: set[tuple[str, CheckId]]) -> None:
        """Problems that appear or come back between monitoring rounds."""
        self._open |= opens

    def payload(self, slots: dict[str, str]) -> None:
        """Synthetic firms have no text to plant; the typed contract would drop it anyway."""

    def _readable(self, host: str, check: CheckId) -> bool:
        """The engine's read rule (``harness._unobserved``): fail closed on the host's scan condition."""
        from p2c.evaluation.synthetic import _APEX_ONLY_CHECKS, _ORIGIN_CHECKS  # noqa: PLC0415

        conditions = self.case.scan_conditions
        if check in _APEX_ONLY_CHECKS:
            return self.apex in conditions
        cond = conditions.get(host)
        return cond in ("reachable", "throttled") or (cond == "cdn_fronted" and check not in _ORIGIN_CHECKS)

    def fix(self, fix_id: FixId) -> FixOut:
        spec = FIXES[fix_id]
        bucket = int(_hex(f"{self.case.case_id}:{fix_id.value}")[:8], 16) / 0xFFFFFFFF
        if fix_id not in self.failing_fixes and bucket >= self.fail_rate:
            self._open = {(h, c) for (h, c) in self._open if c not in spec.clears}
        self._chain(f"fix:{fix_id.value}")
        return FixOut(fix_id=fix_id, applied=True)
