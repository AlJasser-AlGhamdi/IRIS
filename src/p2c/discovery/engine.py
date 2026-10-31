"""DiscoveryEngine — run sources, merge, resolve, honoring sovereignty (Stage 2).

Each source is isolated: a per-source failure is recorded in ``result.errors``
rather than aborting the whole run — **except** a sovereignty egress block, which
propagates loudly (a non-allowlisted outbound must never be silently swallowed).
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from datetime import UTC, datetime

import structlog

from p2c.discovery.base import DiscoveryResult, DiscoverySource
from p2c.discovery.dnsx import DnsxResolver
from p2c.discovery.merge import merge_assets
from p2c.discovery.synthetic import SyntheticProfile, SyntheticSource
from p2c.schemas.models import Asset
from p2c.sovereignty.egress_guard import caused_by_egress_block as _caused_by_egress_block

log = structlog.get_logger("p2c.discovery")


def _utcnow() -> datetime:
    return datetime.now(UTC)


# Fixed epoch for SYNTHETIC discovery so `first_seen` (and thus the whole inventory)
# is bit-reproducible across runs — synthetic data is deterministic (spec §6).
SYNTHETIC_EPOCH = datetime(2026, 1, 1, tzinfo=UTC)


class DiscoveryEngine:
    """Runs configured sources for a target and returns a merged asset inventory."""

    def __init__(
        self,
        sources: Sequence[DiscoverySource],
        *,
        resolver: DnsxResolver | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._sources = list(sources)
        self._resolver = resolver
        self._clock = clock or _utcnow

    def discover(self, target: str, *, consent_ref: str) -> DiscoveryResult:
        now = self._clock()
        collected: list[Asset] = []
        errors: list[str] = []
        for source in self._sources:
            try:
                collected.extend(source.discover(target, consent_ref=consent_ref, now=now))
            except Exception as exc:  # isolate per source (except sovereignty blocks)
                if _caused_by_egress_block(exc):
                    log.error("discovery_egress_blocked", source=source.source_tool)
                    raise
                log.warning("discovery_source_failed", source=source.source_tool, error=str(exc))
                errors.append(f"{source.source_tool}: {exc}")

        merged = merge_assets(collected)
        if self._resolver is not None:
            try:
                merged = self._resolver.resolve(merged)
            except Exception as exc:
                if _caused_by_egress_block(exc):
                    raise
                errors.append(f"dnsx: {exc}")

        return DiscoveryResult(
            target=target,
            assets=merged,
            sources=[s.source_tool for s in self._sources],
            errors=errors,
        )


def synthetic_engine(
    profile: SyntheticProfile, *, clock: Callable[[], datetime] | None = None
) -> DiscoveryEngine:
    """A deterministic engine that discovers straight from a synthetic profile.

    Defaults to :data:`SYNTHETIC_EPOCH` (not wall-clock) so results are reproducible.
    """
    return DiscoveryEngine([SyntheticSource(profile)], clock=clock or (lambda: SYNTHETIC_EPOCH))
