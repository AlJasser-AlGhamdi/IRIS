"""Protective-service fingerprints (Stage 3, Tier-1): WAF and DDoS protection absent.

Both detectors infer the absence of a protective control from the absence of a recognisable
fingerprint, which is why the sensing model gives each a 0.20 false-positive rate: a transparent
or custom deployment leaves no fingerprint, and a white-box adversary can serve one it does not
have (string spoofing in the adversary model). The fingerprint tables are small, public and
attributed: the WAF signatures follow those wafw00f (EnableSecurity, BSD licence) matches on, and
the provider suffixes are the providers' documented edge and name-server domains.

**Detector contract, ``waf_absent``.**
*Observable*: the headers and cookies of a response the scanner received, from one plain request
(no attack payload is sent, so a WAF that answers ordinary requests silently is missed, the
documented false-positive case). *Positive*: no WAF signature in the headers or cookies.
*Negative*: a signature (for example ``cf-ray``, ``x-sucuri-id``, an ``incap_ses_`` cookie).
*Inconclusive*: no response. *Evidence*: the signature matched.

**Detector contract, ``no_ddos_protection``.**
*Observable*: the apex's ``NS`` records, the ``CNAME`` of the apex and of ``www``, and, when
given, the headers of a response from the apex. *Positive*: those reads completed and none shows a
DDoS-mitigating provider (a provider's name servers, an edge ``CNAME`` such as ``*.cloudfront.net``
or ``*.edgekey.net``, or a provider header, including the WAF signature of a provider whose edge
also mitigates DDoS: Cloudflare, Sucuri, Imperva and Akamai). *Negative*: a provider signature.
*Inconclusive*: the ``NS`` read did not complete, or a ``CNAME`` read did not complete and nothing matched. A
``NoAnswer`` for ``CNAME`` is a definitive "no alias", not an unread record. Alias chains are followed
up to five hops. *Evidence*: the signature matched. *Known false negative*: a provider's name servers
show where the zone is hosted, not that traffic is proxied; a Cloudflare zone whose records are set
to DNS only passes through unprotected and still reads as protected.

*Test oracle*: fixture headers and resolvers in the unit tests; planted headers and zones in the
integration matrix.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

import structlog

from p2c.scanning.catalog import CheckId
from p2c.scanning.dns_sec import RecordResolver, _is_definitive_absence
from p2c.scanning.httpx_probe import HttpProbe, response_received
from p2c.sovereignty.egress_guard import caused_by_egress_block

log = structlog.get_logger("p2c.scanning.fingerprints")

# Header names whose presence identifies a WAF in front of the origin.
_WAF_HEADERS: dict[str, str] = {
    "cf-ray": "Cloudflare",
    "x-sucuri-id": "Sucuri",
    "x-sucuri-cache": "Sucuri",
    "x-iinfo": "Imperva Incapsula",
    "x-amzn-waf-action": "AWS WAF",
}
# Header names that identify a WAF only with a particular value (wafw00f checks the value too).
_WAF_HEADER_VALUES: dict[str, tuple[str, str]] = {"x-cdn": ("incapsula", "Imperva Incapsula")}
# Server header values that name a WAF or WAF-fronting edge.
_WAF_SERVERS: dict[str, str] = {
    "cloudflare": "Cloudflare",
    "sucuri/cloudproxy": "Sucuri",
    "mod_security": "ModSecurity",
    "barracuda": "Barracuda",
}
# Cookie name prefixes WAFs set on every response.
_WAF_COOKIES: dict[str, str] = {
    "__cf_bm": "Cloudflare",
    "incap_ses_": "Imperva Incapsula",
    "visid_incap_": "Imperva Incapsula",
    "ts01": "F5 BIG-IP ASM",
    "fortiwafsid": "Fortinet FortiWeb",
    "barra_counter_session": "Barracuda",
    "aws-waf-token": "AWS WAF",
}
# A CDN edge or load balancer that may run with or without a WAF: neither WAF evidence nor its absence.
_EDGE_SERVERS: dict[str, str] = {
    "akamaighost": "Akamai",
    "bigip": "F5 BIG-IP",
    "cloudfront": "AWS CloudFront",
    "awselb": "AWS load balancer",
    "microsoft-azure-application-gateway": "Azure Application Gateway",
    "google frontend": "Google Cloud",
}
# A load balancer that may carry a WAF of its own (AWS WAF on an ALB): its presence leaves the WAF read open.
_EDGE_COOKIES: dict[str, str] = {
    "bigipserver": "F5 BIG-IP",
    "awsalb": "AWS load balancer",
    "awselb": "AWS load balancer",
}
# Cookies a CDN, WAF or load balancer sets for itself (beside the WAF and edge ones above).
_INFRASTRUCTURE_COOKIES = (
    "awsalb",
    "awselb",
    "__cflb",
    "__cfruid",
    "_cfuvid",
    "cf_clearance",
    "arraffinity",  # Azure App Service affinity
    "ak_bmsc",  # Akamai Bot Manager
    "bm_sz",
    "bm_sv",
    "_abck",
    "nlbi_",  # Imperva load balancer
    "nsc_",  # Citrix NetScaler
    "gclb",  # Google Cloud load balancer
    "bni_",  # Barracuda load balancer
)
# F5 BIG-IP ASM's TS<hex> cookies: by pattern, since a site's own cookie may start with "ts".
_F5_TS_COOKIE = re.compile(r"(?i)^ts[0-9a-f]{6,}$")
_EDGE_HEADERS: dict[str, str] = {"x-amz-cf-id": "AWS CloudFront", "x-azure-ref": "Azure Front Door"}
# DDoS-mitigating providers, by their edge alias and name-server domains.
_DDOS_SUFFIXES: dict[str, str] = {
    ".cloudflare.com": "Cloudflare",
    ".cloudflare.net": "Cloudflare",
    ".cloudfront.net": "AWS CloudFront and Shield",
    ".edgekey.net": "Akamai",
    ".akamaiedge.net": "Akamai",
    ".akamai.net": "Akamai",
    ".incapdns.net": "Imperva",
    ".azurefd.net": "Azure Front Door",
    ".fastly.net": "Fastly",
    ".sucuri.net": "Sucuri",
}
_MAX_ALIAS_HOPS = 5
# The WAF providers whose edge also absorbs DDoS traffic, so their WAF signature is a DDoS one too.
_DDOS_CAPABLE = frozenset({"Cloudflare", "Sucuri", "Imperva Incapsula", "Akamai"})
_DDOS_HEADERS: dict[str, str] = {
    "cf-ray": "Cloudflare",
    "x-amz-cf-id": "AWS CloudFront",
    "x-azure-ref": "Azure Front Door",
}


def waf_signature(headers: dict[str, str], set_cookie: tuple[str, ...] = ()) -> str | None:
    """The WAF a response identifies, as ``provider (evidence)``, or ``None``."""
    for name, value in headers.items():
        lowered = name.lower()
        if lowered in _WAF_HEADERS:
            return f"{_WAF_HEADERS[lowered]} ({name})"
        if lowered in _WAF_HEADER_VALUES and _WAF_HEADER_VALUES[lowered][0] in value.lower():
            return f"{_WAF_HEADER_VALUES[lowered][1]} ({name}: {value})"
        if lowered == "server":
            server = value.lower()
            for marker, provider in _WAF_SERVERS.items():
                if marker in server:
                    return f"{provider} (Server: {value})"
    for cookie in set_cookie:
        cookie_name = cookie.split("=", 1)[0].strip().lower()
        for prefix, provider in _WAF_COOKIES.items():
            if cookie_name.startswith(prefix):
                return f"{provider} (cookie {cookie_name})"
    return None


def edge_signature(headers: dict[str, str], set_cookie: tuple[str, ...] = ()) -> str | None:
    """A CDN edge or load balancer a response identifies, as ``provider (evidence)``, or ``None``."""
    for name, value in headers.items():
        if name.lower() in _EDGE_HEADERS:
            return f"{_EDGE_HEADERS[name.lower()]} ({name})"
        if name.lower() == "server":
            for marker, provider in _EDGE_SERVERS.items():
                if marker in value.lower():
                    return f"{provider} (Server: {value})"
    for cookie in set_cookie:
        cookie_name = cookie.split("=", 1)[0].strip().lower()
        for prefix, provider in _EDGE_COOKIES.items():
            if cookie_name.startswith(prefix):
                return f"{provider} (cookie {cookie_name})"
    return None


def waf_undecided(probe: HttpProbe) -> bool:
    """A received response behind an edge that may or may not filter it: the WAF read stays unread."""
    if not response_received(probe) or waf_signature(probe.headers, probe.set_cookie) is not None:
        return False
    return edge_signature(probe.headers, probe.set_cookie) is not None


def waf_checks(probe: HttpProbe) -> list[CheckId]:
    """``waf_absent`` for one received response; nothing for an unreceived one."""
    if not response_received(probe):
        log.warning("waf_read_indeterminate", url=probe.url, status_code=probe.status_code)
        return []
    if waf_signature(probe.headers, probe.set_cookie) or edge_signature(probe.headers, probe.set_cookie):
        return []  # a WAF, or an edge that may be one (see waf_undecided)
    return [CheckId.WAF_ABSENT]


def _ddos_match(value: str) -> str | None:
    host = value.strip().rstrip(".").lower()
    for suffix, provider in _DDOS_SUFFIXES.items():
        if host.endswith(suffix) or host == suffix.lstrip("."):
            return f"{provider} ({host})"
    return None


@dataclass(frozen=True)
class DdosResult:
    checks: tuple[CheckId, ...] = ()
    read: bool = False
    evidence: str | None = None


class DdosInspector:
    """Reads the apex's name servers and edge aliases for a DDoS-mitigating provider."""

    def __init__(self, resolver: RecordResolver) -> None:
        self._resolver = resolver

    def _records(self, name: str, rdtype: str) -> tuple[list[str], bool]:
        """(records, completed). A definitive negative is an empty, completed read."""
        try:
            return list(self._resolver.resolve(name, rdtype)), True
        except Exception as exc:
            if caused_by_egress_block(exc):
                raise
            if _is_definitive_absence(exc):
                return [], True
            log.warning("ddos_read_indeterminate", name=name, rdtype=rdtype, error=type(exc).__name__)
            return [], False

    def inspect_detailed(self, domain: str, headers: dict[str, str] | None = None) -> DdosResult:
        for name in headers or {}:
            if name.lower() in _DDOS_HEADERS:
                return DdosResult(read=True, evidence=f"{_DDOS_HEADERS[name.lower()]} ({name})")
        proxy = waf_signature(headers or {}) or edge_signature(headers or {})
        if proxy is not None and proxy.split(" (")[0] in _DDOS_CAPABLE:
            return DdosResult(read=True, evidence=proxy)  # a WAF that is also a DDoS-mitigating edge
        ns, ns_read = self._records(domain, "NS")
        aliases: list[str] = []
        aliases_read = True
        for start in (domain, f"www.{domain}"):
            name = start
            for _ in range(_MAX_ALIAS_HOPS):  # follow the alias chain, not only its first hop
                records, completed = self._records(name, "CNAME")
                aliases_read = aliases_read and completed
                if not records:
                    break
                aliases += records
                name = records[0].rstrip(".")
        for record in aliases:
            evidence = _ddos_match(record)
            if evidence is not None:
                return DdosResult(read=True, evidence=evidence)
        # A provider's name servers alone do not show that traffic passes its edge (DNS-only hosting is
        # common, with the origin exposed), so they leave the read open rather than clean.
        on_ns = next((e for record in ns if (e := _ddos_match(record)) is not None), None)
        if on_ns is not None or not (ns_read and aliases_read):
            return DdosResult(read=False, evidence=f"name servers only: {on_ns}" if on_ns else None)
        return DdosResult(checks=(CheckId.NO_DDOS_PROTECTION,), read=True)

    def inspect(self, domain: str, headers: dict[str, str] | None = None) -> list[CheckId]:
        return list(self.inspect_detailed(domain, headers).checks)


def infrastructure_cookie(set_cookie: str) -> bool:
    """True for a cookie a CDN, WAF or load balancer sets for itself: it says nothing of the cookies
    the site sets for its own sessions."""
    name = set_cookie.split("=", 1)[0].strip().lower()
    known = name.startswith((*_WAF_COOKIES, *_EDGE_COOKIES, *_INFRASTRUCTURE_COOKIES))
    return known or bool(_F5_TS_COOKIE.match(name))
