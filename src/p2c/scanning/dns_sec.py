"""DNSSEC inspection (Stage 3, Tier-1): is the zone provably unsigned?

**Detector contract, ``dnssec_missing``.**

*Observable*
    The delegation signer (DS) record published for the zone by its parent, and the zone's own
    DNSKEY set.

*Positive*
    Both reads completed and both are definitively empty: the parent publishes no DS and the zone
    publishes no DNSKEY. That is an unsigned zone, and it is the only state that raises a finding.

*Negative*
    A DS record exists, or a DNSKEY exists. The zone is signed, or is in the middle of being
    signed, and the control is not violated in the way this detector tests.

*Inconclusive, and it raises nothing*
    Any read that did not complete: timeout, refused, no nameservers, transport failure. And,
    deliberately, ``SERVFAIL``. A validating resolver answers ``SERVFAIL`` for a **bogus** zone,
    one that is signed but whose chain does not verify. Reporting that as "DNSSEC missing" would
    be wrong twice over: the zone is signed, and a broken chain is a worse condition than an
    unsigned one, not the same condition. The catalogue has no detector for it, so it is reported
    as unread rather than folded into this one.

*Evidence retained*
    The DS and DNSKEY reads, each flagged with whether it resolved, on
    :class:`DnssecResult`.

*Test oracle*
    Fixture resolvers in the unit tests, and a signed-zone container in the integration matrix.

The resolver is injected through :class:`RecordResolver` for the same reason ``email_dns`` injects
its own: the classification of an exception as definitive or indeterminate is done by class-name
lineage, so the tests exercise the real classification path without a live resolver being involved.
:class:`DnspythonResolver` is the concrete adapter the released toolkit uses.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Protocol

import structlog

from p2c.scanning.catalog import CheckId
from p2c.sovereignty.egress_guard import caused_by_egress_block

log = structlog.get_logger("p2c.scanning.dns_sec")

# A definitive negative answer: the name resolves and provably carries no such record set. Anything
# else (Timeout, SERVFAIL/NoNameservers, NoResolverConfiguration, OSError, ...) is an incomplete read
# and must never become a "not signed" finding. SERVFAIL is excluded on purpose: see the contract.
_DEFINITIVE_ABSENCE = frozenset({"NXDOMAIN", "NoAnswer", "NoData", "DnsRecordAbsent"})


class RecordResolver(Protocol):
    def resolve(self, name: str, rdtype: str) -> list[str]:
        """Return the records of ``rdtype`` at ``name``.

        ``[]`` means a definitive empty answer. Raise ``NXDOMAIN``/``NoAnswer`` (or anything whose
        class name is in the definitive set) for a definitive negative, and any other exception for
        a read that did not complete.
        """
        ...


@dataclass(frozen=True)
class RecordRead:
    """One lookup. ``resolved=False`` marks an indeterminate read: unknown, not absent."""

    records: tuple[str, ...] = ()
    resolved: bool = True


class DnspythonResolver:
    """The concrete :class:`RecordResolver` the released toolkit runs.

    dnspython raises ``NXDOMAIN`` and ``NoAnswer`` for definitive negatives and ``Timeout`` or
    ``NoNameservers`` otherwise, and the classifier reads those class names, so nothing here has to
    translate them. Imported lazily so that the pure inspectors, and their tests, never require the
    package to be installed.
    """

    def __init__(self, *, timeout: float = 5.0, nameservers: list[str] | None = None, port: int = 53) -> None:
        self._timeout = timeout
        self._nameservers = nameservers
        self._port = port

    def resolve(self, name: str, rdtype: str) -> list[str]:
        import dns.resolver  # noqa: PLC0415 - keeps the dependency off the pure import path

        # A named server (the integration matrix's authoritative one) instead of the system's.
        resolver = dns.resolver.Resolver(configure=self._nameservers is None)
        if self._nameservers is not None:
            resolver.nameservers = self._nameservers
            resolver.port = self._port
        resolver.lifetime = self._timeout
        answer = resolver.resolve(name, rdtype)
        return [record.to_text() for record in answer]

    def resolve_txt(self, name: str) -> list[str]:
        """The TXT records of ``name`` as text, for the email inspector (:class:`TxtResolver`).

        ``to_text()`` keeps a record's quotes and the seams between its strings, so each record is
        rebuilt from its strings instead: a long DKIM key split into 255-byte strings is one key."""
        import dns.resolver  # noqa: PLC0415 - keeps the dependency off the pure import path

        resolver = dns.resolver.Resolver(configure=self._nameservers is None)
        if self._nameservers is not None:
            resolver.nameservers = self._nameservers
            resolver.port = self._port
        resolver.lifetime = self._timeout
        answer = resolver.resolve(name, "TXT")
        return [b"".join(record.strings).decode("utf-8", "replace") for record in answer]

    def dnskey_rrsets(self, name: str) -> tuple[Any, Any]:
        """The DNSKEY RRset at ``name`` and the RRSIG RRset over it (:meth:`signed_rrset`)."""
        return self.signed_rrset(name, "DNSKEY")

    def signed_rrset(self, name: str, rdtype: str) -> tuple[Any, Any]:
        """The ``rdtype`` RRset at ``name`` and the RRSIG RRset over it (``None`` if the answer carries
        none), asked with the DNSSEC OK bit so that even a non-validating resolver returns them."""
        import dns.flags  # noqa: PLC0415 - keeps the dependency off the pure import path
        import dns.rdataclass  # noqa: PLC0415
        import dns.rdatatype  # noqa: PLC0415
        import dns.resolver  # noqa: PLC0415

        resolver = dns.resolver.Resolver(configure=self._nameservers is None)
        if self._nameservers is not None:
            resolver.nameservers = self._nameservers
            resolver.port = self._port
        resolver.lifetime = self._timeout
        resolver.use_edns(0, dns.flags.DO, 1232)
        answer = resolver.resolve(name, rdtype)
        records = answer.rrset
        covered = dns.rdatatype.from_text(rdtype)
        sigs = answer.response.get_rrset(
            answer.response.answer, records.name, dns.rdataclass.IN, dns.rdatatype.RRSIG, covered
        )
        return records, sigs


def chain_verifies(
    ds_records: Sequence[str],
    keys: Any,
    sigs: Any,
    *,
    soa: Any = None,
    soa_sigs: Any = None,
    now: float | None = None,
) -> bool:
    """True when a DS record at the parent matches a key of the zone, that key's signature over the
    zone's DNSKEY set verifies and has not expired (the link a validator follows into the zone), and,
    given the zone's SOA, its signature by the zone's keys verifies too (a zone whose data signatures
    have lapsed fails validation as surely as a broken link). Any
    other state (a DS matching no key, a missing, invalid or expired signature, an algorithm the
    library will not validate) is a broken chain. The scanner checks it itself, because a resolver
    that does not validate (most cloud ones) passes a broken chain's records on unchanged."""
    import dns.dnssec  # noqa: PLC0415 - keeps the dependency off the pure import path
    import dns.exception  # noqa: PLC0415
    import dns.rdata  # noqa: PLC0415
    import dns.rdataclass  # noqa: PLC0415
    import dns.rdatatype  # noqa: PLC0415
    import dns.rrset  # noqa: PLC0415

    if keys is None or sigs is None:
        return False
    try:
        delegated = [dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.DS, t) for t in ds_records]
    except dns.exception.DNSException:
        return False
    matched = []
    for key in keys:
        for ds in delegated:
            try:
                # validating: a SHA-1 DS a parent publishes is still checked, as a validator does.
                if dns.dnssec.make_ds(keys.name, key, ds.digest_type, validating=True) == ds:
                    matched.append(key)
                    break
            except (dns.exception.DNSException, ValueError):
                continue  # a digest type the library does not make: that DS cannot be checked
    if not matched:
        return False
    trusted = dns.rrset.from_rdata_list(keys.name, keys.ttl, matched)
    try:
        dns.dnssec.validate(keys, sigs, {keys.name: trusted}, now=now)
        if soa is not None:
            if soa_sigs is None:
                return False
            dns.dnssec.validate(soa, soa_sigs, {keys.name: keys}, now=now)
    except (dns.exception.DNSException, ValueError):
        return False  # ValidationFailure, an unsupported or denied algorithm, an expired signature
    return True


@dataclass(frozen=True)
class DnssecResult:
    """The evidence behind the verdict, so a reviewer can see which read produced it."""

    checks: tuple[CheckId, ...] = ()
    ds: RecordRead = RecordRead(resolved=False)
    dnskey: RecordRead = RecordRead(resolved=False)
    broken: bool = False  # a DS at the parent, no keys in the zone: unread, not a verdict

    @property
    def fully_read(self) -> bool:
        return self.ds.resolved and self.dnskey.resolved


def _is_definitive_absence(exc: BaseException) -> bool:
    return any(cls.__name__ in _DEFINITIVE_ABSENCE for cls in type(exc).__mro__)


class DnssecInspector:
    """Reports whether a zone is provably unsigned, via an injected resolver."""

    def __init__(self, resolver: RecordResolver) -> None:
        self._resolver = resolver

    def inspect(self, domain: str) -> list[CheckId]:
        return list(self.inspect_detailed(domain).checks)

    def inspect_detailed(self, domain: str) -> DnssecResult:
        ds = self._read(domain, "DS")
        dnskey = self._read(domain, "DNSKEY")
        # Absence is claimed only when both reads completed. One unread lookup could be the one
        # carrying the material, exactly as an unread DKIM selector blocks a DKIM absence.
        signed = bool(ds.records) or bool(dnskey.records)
        unsigned = ds.resolved and dnskey.resolved and not signed
        checks = (CheckId.DNSSEC_MISSING,) if unsigned else ()
        # A DS at the parent with no keys in the zone is a broken chain: neither signed nor unsigned.
        broken = bool(ds.records) and dnskey.resolved and not dnskey.records
        return DnssecResult(checks=checks, ds=ds, dnskey=dnskey, broken=broken)

    def _read(self, name: str, rdtype: str) -> RecordRead:
        try:
            return RecordRead(tuple(self._resolver.resolve(name, rdtype)))
        except Exception as exc:
            if caused_by_egress_block(exc):
                raise
            if _is_definitive_absence(exc):
                return RecordRead()
            log.warning("dns_read_indeterminate", name=name, rdtype=rdtype, error=type(exc).__name__)
            return RecordRead(resolved=False)
