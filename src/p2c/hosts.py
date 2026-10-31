"""Canonical host normalization — one source of truth for every stage.

Phase 1 (authz), Phase 2 (discovery), and Phase 3 (scanning) all canonicalize
hosts through :func:`canonical_host` so a domain verified/consented in one stage
matches the same domain discovered/scanned in another — including IDN (Arabic
etc.) domains, which are IDNA/punycode-encoded to their ``xn--`` A-label.
"""

from __future__ import annotations

import ipaddress
import re

import idna

# RFC-1123 A-label hostname (ASCII / punycode; IDN is IDNA-encoded to this form).
_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$")

_ASCII_SPACE = 0x20  # ASCII control chars are < 0x20 ...
_ASCII_DEL = 0x7F  # ... plus DEL (0x7F)


def _is_ascii_control(ch: str) -> bool:
    return ch.isascii() and (ord(ch) < _ASCII_SPACE or ord(ch) == _ASCII_DEL)


def _clean(value: str) -> str:
    """Trim/lower/de-dot/de-wildcard a host, keeping any Unicode (IDN) intact.

    Returns ``""`` for values with internal whitespace or ASCII control chars.
    """
    host = value.strip().lower()
    if any(ch.isspace() or _is_ascii_control(ch) for ch in host):
        return ""
    host = host.rstrip(".")
    while host.startswith("*."):
        host = host[2:]
    return host


def to_ascii(host: str) -> str:
    """IDNA/punycode-encode a cleaned host to its ASCII A-label (``""`` if invalid)."""
    if host.isascii():
        return host
    try:
        return idna.encode(host, uts46=True).decode("ascii")
    except (idna.IDNAError, UnicodeError):
        return ""


def to_unicode(host: str) -> str:
    """Decode an A-label back to its Unicode U-label for display (bilingual reports)."""
    try:
        return idna.decode(host)
    except (idna.IDNAError, UnicodeError):
        return host


def canonical_host(value: str) -> str:
    """Canonical A-label host: cleaned + IDNA-encoded. Idempotent. ``""`` if invalid."""
    return to_ascii(_clean(value))


# Back-compat name used across stages.
normalize_host = canonical_host


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip())
    except ValueError:
        return False
    return True


def is_valid_hostname(value: str) -> bool:
    """True if ``value`` normalizes to a syntactically valid RFC-1123 hostname."""
    return bool(_HOSTNAME_RE.match(canonical_host(value)))


def require_hostname(target: str) -> str:
    """Return the canonical target or raise ``ValueError`` (rejects injection/garbage)."""
    normalized = canonical_host(target)
    if not is_valid_hostname(normalized):
        raise ValueError(f"invalid target hostname: {target!r}")
    return normalized


def in_scope_of(host: str, apex: str) -> bool:
    """True if ``host`` is the apex or a subdomain of it (IPs are always in scope)."""
    if is_ip(host):
        return True
    normalized, apex_norm = canonical_host(host), canonical_host(apex)
    return bool(normalized) and (normalized == apex_norm or normalized.endswith(f".{apex_norm}"))


def candidate_apexes(host: str) -> list[str]:
    """Canonical host plus each parent domain, most-specific first.

    ``www.example.com`` -> ``["www.example.com", "example.com", "com"]``. Used to
    resolve which registered-apex consent governs a (possibly subdomain) target
    without a public-suffix list: a consent registered at ``example.com`` is found
    when scanning ``www.example.com``. IPs have no parents (single-element list).
    Returns ``[]`` for an invalid host.
    """
    normalized = canonical_host(host)
    if not normalized:
        return []
    if is_ip(normalized):
        return [normalized]
    labels = normalized.split(".")
    return [".".join(labels[i:]) for i in range(len(labels))]
