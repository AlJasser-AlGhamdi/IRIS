"""Zone-transfer inspection (Stage 3, Tier-1): does an authoritative server hand out the zone?

**Detector contract, ``dns_zone_transfer_open``.**

*Observable*
    The domain's ``NS`` records, each name server's address, and the answer each server gives to
    one ``AXFR`` request for the domain over TCP.

*Positive*
    Some authoritative server returns the zone: a transfer that yields records beyond the ``SOA``.
    That is a full copy of every published name, which the control set requires to be refused to
    outsiders.

*Negative*
    Every listed server definitively refused: the transfer was answered with a refusal code
    (``REFUSED``, ``NOTAUTH``), or the server closed the TCP connection on the request. Each server
    is judged at its first address that answers (IPv4 first), so an IPv6 address the scanning
    network cannot route to does not leave a refusing server unread.

*Inconclusive, and it raises nothing*
    The ``NS`` read did not complete; a server's address could not be resolved, or is a loopback,
    private or link-local address the scanner will not connect to; or a server timed out without
    refusing at any of its addresses and no other server returned the zone. Silence is not refusal.

*Evidence retained*
    The server that answered and how many names the transfer showed, on :class:`AxfrResult`. The
    transfer is read only until a name beyond the apex arrives, or :data:`_MAX_NAMES` names, so
    the scanner never holds a whole zone (whose host names may be personal data) and keeps no name.

The request is a single read-only zone-transfer query per listed server; nothing is written and
no other record type is enumerated.

*Test oracle*
    A fake transfer function in the unit tests; an authoritative server with one open and one
    closed zone in the integration matrix.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable
from dataclasses import dataclass

import structlog

from p2c.scanning.catalog import CheckId
from p2c.scanning.dns_sec import RecordResolver, _is_definitive_absence
from p2c.sovereignty.egress_guard import caused_by_egress_block

log = structlog.get_logger("p2c.scanning.dns_axfr")

# A transfer function returns the record names of the zone it received, or raises.
Transfer = Callable[[str, str, int], list[str]]
# Exception class names that mean "this server refused", as opposed to "it did not answer".
_REFUSALS = frozenset({"TransferError", "ConnectionRefusedError", "ConnectionResetError", "EOFError"})


_MAX_NAMES = 2  # the apex and one name beyond it show the zone is handed out; nothing more is read


def dnspython_transfer(address: str, zone: str, port: int, *, timeout: float = 10.0) -> list[str]:
    """One ``AXFR`` with dnspython: the record names it shows, relative to the zone (``@`` for the
    apex), read only until :data:`_MAX_NAMES` distinct names have arrived. Imported lazily."""
    import dns.name  # noqa: PLC0415 - keeps the dependency off the pure import path
    import dns.query  # noqa: PLC0415

    origin = dns.name.from_text(zone)
    names: dict[str, None] = {}
    for message in dns.query.xfr(address, zone, port=port, timeout=timeout, lifetime=timeout):
        for rrset in message.answer:
            names[rrset.name.relativize(origin).to_text()] = None
            if len(names) >= _MAX_NAMES:
                return list(names)  # the generator is closed here, and with it the connection
    return list(names)


_EMBEDDED_V4 = (ipaddress.ip_network("64:ff9b::/96"), ipaddress.ip_network("::/96"))


def _internal(address: str) -> bool:
    """True for an address the scanner must not be steered to by a published record."""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return True  # not an address at all: refuse rather than guess
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if isinstance(ip, ipaddress.IPv6Address) and any(ip in net for net in _EMBEDDED_V4):
        return True  # NAT64 or IPv4-compatible: it carries an IPv4 address the record could steer to
    # An allowlist, not a blocklist: only a global unicast address is contacted.
    return not ip.is_global or ip.is_multicast


def _refused(exc: BaseException) -> bool:
    return any(cls.__name__ in _REFUSALS for cls in type(exc).__mro__)


@dataclass(frozen=True)
class AxfrResult:
    checks: tuple[CheckId, ...] = ()
    read: bool = False
    server: str | None = None
    n_names: int = 0  # names in the transferred zone, not resource records


class ZoneTransferInspector:
    """Asks each authoritative server of a domain for the zone, once."""

    def __init__(
        self,
        resolver: RecordResolver,
        transfer: Transfer | None = None,
        *,
        port: int = 53,
        allow_internal: bool = False,
        address_types: tuple[str, ...] = ("A", "AAAA"),
    ) -> None:
        self._resolver = resolver
        self._address_types = address_types  # ("A",) when the scan uses IPv4 alone
        self._transfer = transfer or dnspython_transfer
        self._port = port
        # A published NS record can name any address. Connecting to a loopback, private or
        # link-local one would reach the scanner's own network, not the target's, so those are
        # skipped and the read stays open, unless the scan target is itself internal (the matrix).
        self._allow_internal = allow_internal

    def inspect_detailed(self, domain: str) -> AxfrResult:
        try:
            servers = [s.rstrip(".") for s in self._resolver.resolve(domain, "NS")]
        except Exception as exc:
            if caused_by_egress_block(exc):
                raise
            if _is_definitive_absence(exc):
                return AxfrResult(read=True)  # no name servers: nothing that could hand out a zone
            log.warning("axfr_ns_read_indeterminate", domain=domain, error=type(exc).__name__)
            return AxfrResult()
        refused_all = bool(servers)
        for server in servers:
            refused = False  # judged at the server's first address that answers either way
            for address in self._addresses(server):
                if not self._allow_internal and _internal(address):
                    log.warning("axfr_internal_address_skipped", server=server, address=address)
                    continue
                try:
                    names = self._transfer(address, domain, self._port)
                except Exception as exc:
                    if caused_by_egress_block(exc):
                        raise
                    if _refused(exc):
                        refused = True
                        break
                    log.warning("axfr_read_indeterminate", server=server, error=type(exc).__name__)
                    continue  # no answer here: the server's next address may give one
                beyond_apex = [n for n in names if n not in ("@", "")]
                if beyond_apex:
                    return AxfrResult(
                        checks=(CheckId.DNS_ZONE_TRANSFER_OPEN,),
                        read=True,
                        server=server,
                        n_names=len(names),
                    )
                break  # a completed transfer of the apex alone is not a refusal: the server answered
            # An unresolvable server, one that answered nowhere, or one that sent the apex alone.
            refused_all = refused_all and refused
        return AxfrResult(read=True) if refused_all else AxfrResult()

    def _addresses(self, server: str) -> list[str]:
        """The server's IPv4 and IPv6 addresses; an unread lookup contributes none."""
        found: list[str] = []
        for rdtype in self._address_types:
            try:
                found += self._resolver.resolve(server, rdtype)
            except Exception as exc:
                if caused_by_egress_block(exc):
                    raise
        return found

    def inspect(self, domain: str) -> list[CheckId]:
        return list(self.inspect_detailed(domain).checks)
