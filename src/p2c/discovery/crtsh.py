"""crt.sh Certificate Transparency source (Stage 2).

Queries the crt.sh HTTPS JSON endpoint (no binary). The request goes through the
sovereignty egress guard, so under ``SOVEREIGN_MODE`` crt.sh must be allowlisted
or the call is blocked — that is the enforced "no non-allowlisted egress" property.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import datetime

import httpx

from p2c.discovery.base import DiscoveryError
from p2c.discovery.normalize import assets_from_hosts, require_hostname
from p2c.hosts import is_ip
from p2c.schemas.enums import DiscoveryMethod
from p2c.schemas.models import Asset

CRTSH_HOST = "crt.sh"
CRTSH_VERSION = "crt.sh-json"
_TIMEOUT = 30.0


def parse_crtsh(output: str) -> list[str]:
    """Parse crt.sh JSON: flatten ``name_value`` (newline-separated) + ``common_name``.

    Only DNS names are returned. An IP literal in a certificate SAN is dropped: a shared
    certificate (common on CT) routinely lists unrelated third-party IPs, and unlike a
    hostname an IP SAN is not filtered by the apex scope check downstream — so admitting it
    would pull an out-of-scope third party into the inventory (the scope-confinement invariant
    in docs/threats-to-validity.md). Legitimately in-scope IPs still arrive via dnsx resolution
    of an in-scope hostname.

    Raises :class:`DiscoveryError` on a non-JSON / non-list body (a failed fetch
    that returned an error page must not masquerade as an empty result).
    """
    try:
        data = json.loads(output)
    except json.JSONDecodeError as exc:
        raise DiscoveryError(f"crt.sh response was not JSON: {output[:80]!r}") from exc
    if not isinstance(data, list):
        raise DiscoveryError(f"crt.sh JSON was not a list: {type(data).__name__}")
    hosts: list[str] = []
    for entry in data:
        if not isinstance(entry, dict):
            continue
        names = str(entry.get("name_value", "")).split("\n")
        names.append(str(entry.get("common_name", "")))
        hosts.extend(name.strip() for name in names if name.strip() and not is_ip(name.strip()))
    return hosts


class CrtshSource:
    """Fetches ``https://crt.sh/?q=%25.<target>&output=json`` and normalizes to Assets."""

    source_tool = DiscoveryMethod.CRTSH.value

    def __init__(
        self,
        *,
        client_factory: Callable[[], httpx.Client] = httpx.Client,
        base_url: str = "https://crt.sh",
        version: str = CRTSH_VERSION,
        timeout: float = _TIMEOUT,
    ) -> None:
        self._client_factory = client_factory
        self._base_url = base_url.rstrip("/")
        self.version = version
        self._timeout = timeout

    def discover(self, target: str, *, consent_ref: str, now: datetime | None = None) -> list[Asset]:
        # '%.<apex>' (SQL wildcard) → all names under the apex. Pass via params so
        # httpx URL-encodes the target (no query-parameter injection). EgressBlocked
        # (sovereign + not allowlisted) propagates; other HTTP errors yield no assets.
        target = require_hostname(target)
        with self._client_factory() as client:
            response = client.get(
                f"{self._base_url}/",
                params={"q": f"%.{target}", "output": "json"},
                timeout=self._timeout,
            )
        if response.status_code != httpx.codes.OK:
            # Surface the failure (rate-limited/5xx) — do NOT return an empty list,
            # which would be indistinguishable from a domain with no certificates.
            raise DiscoveryError(f"crt.sh returned HTTP {response.status_code} for {target!r}")
        return assets_from_hosts(
            parse_crtsh(response.text),
            apex=target,
            source_tool=self.source_tool,
            tool_version=self.version,
            method=DiscoveryMethod.CRTSH,
            consent_ref=consent_ref,
            now=now,
        )
