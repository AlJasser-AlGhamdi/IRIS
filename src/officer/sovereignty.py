"""The engine's egress guard, with a count of blocked attempts for the interface.

Allows loopback (the local model server), private ranges (the lab) and the lab worker's tailnet address.
Anything else raises before a packet leaves and is counted, so the number on screen is the guard's own.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from urllib.parse import urlparse

from p2c.sovereignty.egress_guard import EgressBlocked, EgressPolicy, egress_guard, install

BLOCKED: list[str] = []


@dataclass(frozen=True)
class CountingPolicy(EgressPolicy):
    def assert_allowed(self, host: str | None) -> None:
        try:
            super().assert_allowed(host)
        except EgressBlocked:
            BLOCKED.append(host or "<unknown>")
            raise


def allowlist() -> frozenset[str]:
    names = set()
    worker = urlparse(os.environ.get("OFFICER_WORKER_URL", "")).hostname
    if worker:
        names.add(worker)
    return frozenset(names)


@contextmanager
def guarded() -> Iterator[CountingPolicy]:
    policy = CountingPolicy(sovereign=True, allowlist=allowlist(), allow_loopback=True, allow_private=True)
    with egress_guard(policy):
        yield policy


def install_for_process() -> CountingPolicy:
    """Install the guard for the life of the process: sessions run on threads, and one that ends must not
    lift the guard from another still running."""
    policy = CountingPolicy(sovereign=True, allowlist=allowlist(), allow_loopback=True, allow_private=True)
    install(policy)
    return policy
