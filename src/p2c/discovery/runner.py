"""Thin, injectable subprocess runner for the Go discovery tools (Stage 2).

Sources shell out through this so tests substitute a fake runner returning
**recorded fixture output** — no tools, no network. Real runs execute in the
network-isolated ``scanner`` image (see ``scanner/Dockerfile``, ADR-0003).
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class CommandResult:
    """Captured result of a subprocess invocation."""

    argv: list[str]
    returncode: int
    stdout: str
    stderr: str


class CommandRunner(Protocol):
    """Runs an argv and returns its captured output."""

    def run(self, argv: list[str], *, stdin: str | None = None, timeout: float = 120.0) -> CommandResult: ...


class SubprocessRunner:
    """Default :class:`CommandRunner` using :mod:`subprocess` (no shell)."""

    def run(self, argv: list[str], *, stdin: str | None = None, timeout: float = 120.0) -> CommandResult:
        proc = subprocess.run(
            argv,
            input=stdin,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return CommandResult(list(argv), proc.returncode, proc.stdout, proc.stderr)
