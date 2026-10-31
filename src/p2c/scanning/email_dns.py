"""Email-DNS checks: SPF / DKIM / DMARC via dnspython (Stage 3, Tier-1, ADR-0004).

In-process (egress-guard-covered), no ``checkdmarc`` dependency. The resolver is
injected so unit tests use recorded fixtures, never live DNS (spec §Phase 3).
DKIM probes a fixed selector catalog and its finding is labelled *selector-limited*.

**Absence contract.** A ``*_MISSING`` finding is raised only on a *definitive* read: the
resolver answered and no matching record was in the answer, or the name provably does not
exist (``NXDOMAIN`` / ``NoAnswer``). A read that did not complete (timeout, ``SERVFAIL``
via ``NoNameservers``, resolver misconfiguration, transport failure) is *indeterminate*:
unknown is not absent, so it yields **no finding at all** and is logged and reported in
:attr:`EmailDnsResult.indeterminate` so an operator sees the coverage gap rather than a
fabricated missing record. This is what makes the zero false-alarm rate a property of the
inspector rather than an assumption about the network. Sovereignty blocks still propagate.

dnspython is never imported here (the resolver arrives through :class:`TxtResolver`), so a
raised exception is classified by its class-name lineage: dnspython's ``NXDOMAIN`` and
``NoAnswer`` read as definitive absence, everything else as indeterminate. An adapter that
does not use dnspython signals the two cases with :class:`DnsRecordAbsent` and
:class:`DnsReadIndeterminate`, or simply returns ``[]`` for a definitive empty answer.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Protocol

import structlog

from p2c.scanning.catalog import CheckId
from p2c.sovereignty.egress_guard import caused_by_egress_block

log = structlog.get_logger("p2c.scanning.email_dns")

# Common DKIM selectors probed when onboarding does not supply known ones.
DKIM_SELECTORS = ("default", "google", "selector1", "selector2", "k1", "mail", "dkim", "s1", "s2")

# Resolver exceptions that mean the record set DEFINITIVELY does not exist. Matched by name
# across the exception's class lineage so dnspython's own types classify without importing it.
# Anything else (Timeout, NoNameservers/SERVFAIL, NoResolverConfiguration, OSError, ...) is an
# incomplete read and must never become a "missing record" finding.
_DEFINITIVE_ABSENCE = frozenset({"NXDOMAIN", "NoAnswer", "NoData", "DnsRecordAbsent"})


class DnsRecordAbsent(Exception):
    """Definitive negative answer: the name, or its TXT record set, does not exist."""


class DnsReadIndeterminate(Exception):
    """The lookup did not complete: timeout, SERVFAIL, no nameservers, transport failure."""


class TxtResolver(Protocol):
    def resolve_txt(self, name: str) -> list[str]:
        """Return the TXT records for ``name``.

        ``[]`` means a definitive empty answer. Raise :class:`DnsRecordAbsent` (or
        dnspython's ``NXDOMAIN``/``NoAnswer``) for a definitive negative, and any other
        exception, conventionally :class:`DnsReadIndeterminate`, when the read failed.
        """
        ...


@dataclass(frozen=True)
class TxtRead:
    """One TXT lookup. ``resolved=False`` marks an indeterminate read: unknown, not absent."""

    records: tuple[str, ...] = ()
    resolved: bool = True


@dataclass(frozen=True)
class EmailDnsResult:
    """Findings for a domain, plus every name whose read did not complete (coverage)."""

    checks: tuple[CheckId, ...] = ()
    indeterminate: tuple[str, ...] = ()
    dkim_found: bool = False  # a key was read at some selector: the DKIM read is settled whatever else


def _is_definitive_absence(exc: BaseException) -> bool:
    return any(cls.__name__ in _DEFINITIVE_ABSENCE for cls in type(exc).__mro__)


def _dmarc_policy(records: tuple[str, ...]) -> str | None:
    """The policy of the one DMARC record; ``None`` when there is none, or more than one, which a
    receiver treats as no DMARC record at all (RFC 7489, 6.6.3)."""
    found = [r for r in records if r.strip().lower().replace(" ", "").startswith("v=dmarc1")]
    if len(found) != 1:
        return None
    for part in found[0].split(";"):
        key, _, value = part.strip().partition("=")
        if key.strip().lower() == "p":
            return value.strip().lower()
    return None


def _spf_usable(records: tuple[str, ...]) -> bool:
    """Exactly one SPF record (any other number is a permanent error, RFC 7208, 4.5) that ends by
    failing or soft-failing other senders (``-all`` or ``~all``) or hands over with ``redirect=``: one
    ending in ``+all``, ``all`` or ``?all``, or with no ``all`` at all, lets every sender pass or stay
    neutral. Whether its include chain stays within the ten-lookup limit is not evaluated."""
    found = [r.strip() for r in records if re.match(r"(?i)v=spf1(?:\s|$)", r.strip())]
    if len(found) != 1:
        return False
    return bool(re.search(r"(?i)(?:^|\s)[-~]all(?:\s|$)|(?:^|\s)redirect=", found[0]))


# A key record carries a public key in ``p=``; an empty ``p=`` is a revoked key (RFC 6376, 3.6.1).
_DKIM_KEY = re.compile(r"(?i)(?:^|;)\s*p\s*=\s*[^;\s]")


def _has_dkim_key(records: tuple[str, ...]) -> bool:
    return any(_DKIM_KEY.search(r) for r in records)


class EmailDnsInspector:
    """Evaluates SPF/DKIM/DMARC posture for a domain via an injected resolver."""

    def __init__(self, resolver: TxtResolver, *, selectors: tuple[str, ...] = DKIM_SELECTORS) -> None:
        self._resolver = resolver
        self._selectors = selectors

    def _txt(self, name: str) -> TxtRead:
        try:
            return TxtRead(tuple(self._resolver.resolve_txt(name)))
        except Exception as exc:
            # A sovereignty block is NOT "record absent" — never let it become a
            # fabricated "missing" finding; propagate it (spec §2 sovereignty).
            if caused_by_egress_block(exc):
                raise
            if _is_definitive_absence(exc):
                return TxtRead()  # NXDOMAIN / no-answer: the record provably is not published
            log.warning("dns_read_indeterminate", name=name, error=type(exc).__name__)
            return TxtRead(resolved=False)  # could not read -> unknown, report nothing

    def inspect(self, domain: str) -> list[CheckId]:
        """Tier-1 email-authentication checks for ``domain`` (indeterminate reads yield none)."""
        return list(self.inspect_detailed(domain).checks)

    def inspect_detailed(self, domain: str) -> EmailDnsResult:
        """As :meth:`inspect`, also returning the names whose read did not complete."""
        indeterminate: list[str] = []

        def read(name: str) -> TxtRead:
            result = self._txt(name)
            if not result.resolved:
                indeterminate.append(name)
            return result

        checks: list[CheckId] = []
        spf = read(domain)
        if spf.resolved and not _spf_usable(spf.records):
            checks.append(CheckId.SPF_MISSING)  # none, several, or one passing every sender

        dmarc = read(f"_dmarc.{domain}")
        if dmarc.resolved:
            policy = _dmarc_policy(dmarc.records)
            if policy is None or policy == "none":
                checks.append(CheckId.DMARC_MISSING_OR_NONE)

        # DKIM absence needs every selector in the catalog to have been read definitively:
        # one unread selector could be the one carrying the key, so the probe is inconclusive.
        dkim_found = False
        dkim_fully_read = True
        for selector in self._selectors:
            probe = read(f"{selector}._domainkey.{domain}")
            dkim_fully_read = dkim_fully_read and probe.resolved
            if _has_dkim_key(probe.records):
                dkim_found = True
                break
        if not dkim_found and dkim_fully_read:
            checks.append(CheckId.DKIM_MISSING)  # selector-limited (see catalog)
        return EmailDnsResult(checks=tuple(checks), indeterminate=tuple(indeterminate), dkim_found=dkim_found)
