"""Stage-2 discovery contracts: the source interface and the result model."""

from __future__ import annotations

from datetime import datetime
from typing import Protocol

from pydantic import Field, computed_field

from p2c.schemas.models import Asset, AtlasModel


class DiscoveryError(RuntimeError):
    """A source failed (HTTP error, tool non-zero exit, unparseable output).

    Raised so a *failed* source is distinguishable from a legitimately *empty*
    one: the engine records it in ``DiscoveryResult.errors`` instead of it
    silently looking like "no assets found".
    """


class DiscoverySource(Protocol):
    """A passive discovery source. ``discover`` returns provenance-tagged assets."""

    source_tool: str

    def discover(self, target: str, *, consent_ref: str, now: datetime | None = None) -> list[Asset]: ...


class DiscoveryResult(AtlasModel):
    """The merged, deduped asset inventory for a target, with per-source errors."""

    target: str
    assets: list[Asset]
    sources: list[str] = Field(description="source_tools that were run")
    errors: list[str] = Field(default_factory=list)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def asset_count(self) -> int:
        return len(self.assets)
