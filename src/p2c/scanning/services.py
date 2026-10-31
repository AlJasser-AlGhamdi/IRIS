"""Service identification on a reachable TCP port (Stage 3, Tier-1).

**Detector contract, ``exposed_database_port``.**

*Observable*
    The bytes a reachable TCP service sends on connect, and, for protocols whose client speaks
    first, the reply to one minimal, read-only opening message.

*Positive*
    The exchange identifies a database service. A port number is never sufficient and never
    necessary: a database on 8306 is still a database, and a web server on 3306 is not one. This
    is the whole point of the detector, and the reason it is a probe rather than a read.

*Negative*
    The service answered and is identifiably not a database: it opened with the greeting of SSH,
    SMTP or FTP, HTTP, POP3, IMAP or VNC (:func:`database_read`).

*Inconclusive, and it raises nothing*
    The connection failed or timed out, the service sent nothing and did not answer the opening
    message, or the answer matches no known signature. An unidentified service is unknown, never
    "not a database".

*Evidence retained*
    The identified protocol and the bytes that identified it, on :class:`ServiceProbe`.

*Coverage, stated plainly*
    MySQL and MariaDB are identified from the greeting they send unprompted. PostgreSQL and Redis
    are identified from the reply to one opening message: an ``SSLRequest`` and a ``PING``
    respectively, both read-only and neither an authentication attempt. MongoDB and SQL Server
    need a longer handshake and are not covered, so a reachable instance of either is reported as
    unidentified rather than guessed at. The detector therefore under-reports by construction,
    which is the safe direction: it can miss an exposed database, and it will not invent one.
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass

import structlog

from p2c.scanning.catalog import CheckId

log = structlog.get_logger("p2c.scanning.services")

# PostgreSQL SSLRequest: length 8, request code 80877103 (RFC-less, but fixed by the wire protocol).
_PG_SSL_REQUEST = struct.pack("!ii", 8, 80877103)
_REDIS_PING = b"PING\r\n"
_MYSQL_PROTOCOL_VERSION = 0x0A
_MIN_MYSQL_GREETING = 5


@dataclass(frozen=True)
class ServiceProbe:
    """What one port yielded. ``protocol`` is ``None`` when nothing identified it."""

    host: str
    port: int
    protocol: str | None = None
    evidence: bytes = b""
    # False when the exchange never completed. Without it a refused connection and an answered but
    # unrecognised service are the same object, and the contract's inconclusive state would exist
    # only in prose. The other two new modules carry the same distinction on their results.
    read: bool = True


def _mysql_greeting(banner: bytes) -> bool:
    """A MySQL handshake: a 3-byte little-endian length matching what follows, sequence id 0, the
    protocol version, then a NUL-terminated version string. A bare FTP or SMTP greeting has none of it."""
    if len(banner) < _MIN_MYSQL_GREETING or banner[3] != 0 or banner[4] != _MYSQL_PROTOCOL_VERSION:
        return False
    length = int.from_bytes(banner[:3], "little")
    return length + 4 >= len(banner) >= min(length + 4, _MIN_MYSQL_GREETING) and b"\x00" in banner[5:]


def identify_database(banner: bytes, pg_reply: bytes = b"", redis_reply: bytes = b"") -> str | None:
    """Classify one exchange. Pure, so the signatures are unit-tested without a socket."""
    if _mysql_greeting(banner):
        # MariaDB announces itself inside the version string, so both land here.
        return "mariadb" if b"MariaDB" in banner else "mysql"
    if pg_reply in (b"S", b"N"):
        # PostgreSQL answers an SSLRequest with exactly one byte, S or N. That is a thin signature,
        # and it is all the protocol offers before a startup packet, which would be an
        # authentication attempt. A service whose first byte happens to be S or N is misread here,
        # which is why the contract calls this identification rather than proof.
        return "postgresql"
    if redis_reply.startswith((b"+PONG", b"-NOAUTH", b"-ERR operation not permitted", b"-DENIED")):
        # A Redis that demands auth is still an exposed Redis, and says so in its error.
        return "redis"
    return None


class ServiceInspector:
    """Identifies the service behind a reachable port with a minimal, read-only exchange."""

    def __init__(self, *, timeout: float = 5.0) -> None:
        self._timeout = timeout

    def inspect(self, host: str, port: int) -> ServiceProbe:
        try:
            banner, pg_reply, redis_reply = self._exchange(host, port)
        except OSError as exc:
            log.warning("service_read_indeterminate", host=host, port=port, error=type(exc).__name__)
            return ServiceProbe(host=host, port=port, read=False)
        protocol = identify_database(banner, pg_reply, redis_reply)
        # An HTTP service answers the one-byte PostgreSQL probe with "H" and the PING with "HTTP/":
        # the reply that names another service is the evidence, so it reads as "not a database".
        named = [r for r in (pg_reply, redis_reply) if r.startswith(_OTHER_SERVICES)]
        evidence = banner or (named[0] if named else pg_reply or redis_reply)
        return ServiceProbe(host=host, port=port, protocol=protocol, evidence=evidence)

    def _exchange(self, host: str, port: int) -> tuple[bytes, bytes, bytes]:
        banner = b""
        with socket.create_connection((host, port), timeout=self._timeout) as sock:
            sock.settimeout(self._timeout)
            try:
                banner = sock.recv(256)
            except TimeoutError:
                banner = b""
        if banner:
            return banner, b"", b""
        # Client-speaks-first protocols. Each opening message is read-only and separately
        # connected, so a service that rejects one is still offered the other.
        return b"", self._ask(host, port, _PG_SSL_REQUEST, 1), self._ask(host, port, _REDIS_PING, 64)

    def _ask(self, host: str, port: int, message: bytes, size: int) -> bytes:
        try:
            with socket.create_connection((host, port), timeout=self._timeout) as sock:
                sock.settimeout(self._timeout)
                sock.sendall(message)
                return sock.recv(size)
        except OSError:
            return b""


# Greetings that identify a service as something other than a database (the contract's negative).
_OTHER_SERVICES = (b"SSH-", b"220", b"HTTP/", b"+OK", b"* OK", b"RFB ")


def database_read(probe: ServiceProbe) -> bool:
    """Whether the exchange settled the question: a database identified, or another service identified.

    Anything else, a failed exchange or an answer matching no signature, is inconclusive."""
    return probe.read and (probe.protocol is not None or probe.evidence.startswith(_OTHER_SERVICES))


def checks_for_service(probe: ServiceProbe) -> list[CheckId]:
    """``EXPOSED_DATABASE_PORT`` only when a database protocol was actually identified."""
    return [CheckId.EXPOSED_DATABASE_PORT] if probe.protocol else []
