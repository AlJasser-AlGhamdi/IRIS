"""Sovereignty egress guard — makes "zero non-allowlisted egress" a runtime test.

When ``SOVEREIGN_MODE`` is on, any outbound connection to a host that is not
loopback/private and not on ``ALLOWLISTED_HOSTS`` **raises** :class:`EgressBlocked`
*before* any packet (including DNS) leaves the box. We patch the Python ``socket``
chokepoints every client funnels through:

* :func:`socket.getaddrinfo` + the legacy resolver family
  (:func:`~socket.gethostbyname`, ``gethostbyname_ex``, ``gethostbyaddr``,
  :func:`~socket.getnameinfo`) — name resolution (blocks the DNS lookup itself),
* :meth:`socket.socket.connect` / :meth:`~socket.socket.connect_ex` — TCP connects,
* :meth:`~socket.socket.sendto` / :meth:`~socket.socket.sendmsg` — UDP datagrams
  (e.g. dnspython's default UDP DNS path).

**Coverage boundary (important, honest).** This is an *in-interpreter* guard. It
covers synchronous clients (httpx-sync, psycopg, dnspython) and asyncio's
**selector** event loop (whose ``sock_connect`` uses ``socket.connect``). It does
**not** see traffic that bypasses Python sockets: **uvloop** resolves/connects in
libuv (C), and **subprocess** scanners (Go tools) egress on their own. Therefore
``SOVEREIGN_MODE`` requires a *guard-visible* loop — the app runs uvicorn with
``--loop asyncio`` and refuses to start under uvloop unless
``ATLAS_ALLOW_UNGUARDED_LOOP`` is set (see :func:`running_loop_is_guarded` and
``api.main``). Subprocess egress is enforced at the OS/network layer in later
phases (documented in ``docs/threats-to-validity.md``). The patch is scoped to
*this* interpreter only; it never touches other host processes (e.g. OpenClaw).

The guard is the enforced form of spec §2's data-sovereignty property: CI runs a
sovereignty gate with ``SOVEREIGN_MODE=True`` — sync, async (selector loop), and
UDP paths — and asserts nothing escaped.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import structlog

if TYPE_CHECKING:
    from p2c.config import Settings

log = structlog.get_logger("p2c.sovereignty")

_LOOPBACK_NAMES = frozenset({"localhost", "localhost.localdomain", "", "ip6-localhost"})
# sendmsg(buffers, ancdata, flags, address): address is the 4th positional (index 3).
_SENDMSG_ADDR_INDEX = 3


def _normalize_host_name(host: str) -> str:
    """Canonicalize a host for allowlist comparison: strip, lowercase, drop a trailing dot.

    A trailing-dot FQDN (``crt.sh.``) is DNS-equivalent to the bare name, so both must map to
    the same allowlist key; without this an allowlisted host is silently never matched.
    """
    return host.strip().rstrip(".").lower()


def _is_dangerous_ip(host: str | None) -> bool:
    """True if ``host`` is an IP literal in a range that must NEVER be reachable.

    Link-local / cloud-metadata (169.254.169.254) / unspecified / multicast / reserved — the
    same ranges :meth:`EgressPolicy.is_allowed` rejects up front. Applied to IPs an allowlisted
    hostname resolves to, so DNS-rebinding (or a malicious allowlisted domain) to the metadata
    IP cannot slip past the connect layer. Non-IP inputs return False (the hostname path handles
    them). ``ip_address`` classifies IPv4-mapped IPv6 (``::ffff:169.254.169.254``) correctly.
    """
    if host is None:
        return False
    name = _normalize_host_name(host).split("%", 1)[0]  # drop any IPv6 zone id
    try:
        ip = ipaddress.ip_address(name)
    except ValueError:
        return False
    return ip.is_link_local or ip.is_unspecified or ip.is_multicast or ip.is_reserved


class EgressBlocked(OSError):
    """Raised when SOVEREIGN_MODE blocks a connection to a non-allowlisted host.

    Subclasses :class:`OSError` so HTTP clients (httpx/httpcore) that catch
    connection errors re-raise it as their own error type while preserving this
    as ``__cause__`` — the block stays traceable through the exception chain.
    """

    def __init__(self, host: str) -> None:
        self.host = host
        super().__init__(
            f"SOVEREIGN_MODE: outbound connection to {host!r} is not allowlisted "
            f"(loopback/private hosts and ALLOWLISTED_HOSTS are permitted)"
        )


@dataclass(frozen=True)
class EgressPolicy:
    """Decides whether an outbound host is permitted.

    Loopback and RFC-1918/ULA *private* IP literals are the sovereign boundary (this box)
    and are allowed; public hostnames must be explicitly allowlisted. **Link-local is NOT
    treated as inside the box**: ``169.254.169.254`` (and the rest of 169.254.0.0/16 /
    fe80::/10) is the cloud-metadata / auto-config range and the classic SSRF-exfil target,
    so it is blocked under sovereign mode even though Python's ``is_private`` includes it.
    """

    sovereign: bool
    allowlist: frozenset[str] = frozenset()
    allow_loopback: bool = True
    allow_private: bool = True

    def __post_init__(self) -> None:
        # Normalize allowlist entries (lower/strip/de-dot) so an operator's "Crt.SH " or
        # "crt.sh." entry is honored instead of silently never matching (fail-closed bug).
        normalized = frozenset(_normalize_host_name(h) for h in self.allowlist if h and h.strip())
        object.__setattr__(self, "allowlist", normalized)

    def is_allowed(self, host: str | None) -> bool:
        if not self.sovereign:
            return True
        if host is None:
            return True  # bind/listen path, not an outbound target
        name = _normalize_host_name(host)
        try:
            ip: ipaddress.IPv4Address | ipaddress.IPv6Address | None = ipaddress.ip_address(name)
        except ValueError:
            ip = None
        if ip is not None:
            # IP literal: a dangerous range is rejected BEFORE the allowlist, so an operator
            # cannot (even by mistake) re-enable the cloud-metadata / link-local SSRF target by
            # allowlisting its literal. Only loopback and genuine RFC-1918/ULA private are "the box".
            if ip.is_loopback:
                return self.allow_loopback
            if ip.is_link_local or ip.is_unspecified or ip.is_multicast or ip.is_reserved:
                return False
            if name in self.allowlist:
                return True
            return self.allow_private if ip.is_private else False
        # Hostname: allowlisted explicitly, or loopback name; everything else is blocked.
        if name in self.allowlist:
            return True
        return self.allow_loopback if name in _LOOPBACK_NAMES else False

    def assert_allowed(self, host: str | None) -> None:
        if not self.is_allowed(host):
            # is_allowed(None) is always True, so host is a str on this branch.
            resolved = host if host is not None else "<unknown>"
            log.warning("egress_blocked", host=resolved)
            raise EgressBlocked(resolved)


@dataclass
class _GuardState:
    policy: EgressPolicy | None = None
    # IPs an *allowlisted hostname* resolved to — so connect() to that IP is permitted end-to-end
    # (the connect layer sees only the IP, which would otherwise be blocked as a public address).
    resolved_allowlisted_ips: set[str] = field(default_factory=set)
    orig_getaddrinfo: Any = None
    orig_connect: Any = None
    orig_connect_ex: Any = None
    orig_sendto: Any = None
    orig_sendmsg: Any = None
    orig_gethostbyname: Any = None
    orig_gethostbyname_ex: Any = None
    orig_gethostbyaddr: Any = None
    orig_getnameinfo: Any = None
    installed: bool = False
    lock: threading.Lock = field(default_factory=threading.Lock)


_state = _GuardState()


def _host_str(host: Any) -> str | None:
    """Normalize a resolver host argument to a comparable string.

    ``getaddrinfo`` and friends accept a **bytes** hostname; ``str(b'crt.sh')``
    would yield ``"b'crt.sh'"`` and wrongly fail the allowlist, so decode bytes.
    """
    if host is None:
        return None
    if isinstance(host, bytes | bytearray):
        try:
            return bytes(host).decode("ascii")
        except UnicodeDecodeError:
            return bytes(host).decode("utf-8", "replace")
    return str(host)


def _extract_host(address: Any) -> str | None:
    """Pull the target host out of a ``socket.connect``/``sendto`` address."""
    if isinstance(address, tuple) and address:
        return _host_str(address[0]) if isinstance(address[0], str | bytes | bytearray) else None
    return None  # AF_UNIX (str/bytes path) or unknown family: not a network egress


def active_policy() -> EgressPolicy | None:
    """Return the currently installed policy, or ``None`` if the guard is off."""
    return _state.policy


def install(policy: EgressPolicy) -> None:  # noqa: PLR0915 - installs many socket-family patches
    """Install the guard process-wide (idempotent; updates the active policy)."""
    with _state.lock:
        # A replacement policy invalidates IPs resolved under the PREVIOUS allowlist: clear the
        # tracked set so a host the new (stricter) policy rejects is not still reachable via a
        # stale resolved-IP entry. (No-op on first install; the set starts empty.)
        _state.resolved_allowlisted_ips.clear()
        _state.policy = policy
        if _state.installed:
            return

        real_getaddrinfo = socket.getaddrinfo
        real_connect = socket.socket.connect
        real_connect_ex = socket.socket.connect_ex
        real_sendto = socket.socket.sendto
        # Windows sockets have no sendmsg; guard it only where the platform provides it.
        real_sendmsg = getattr(socket.socket, "sendmsg", None)
        real_gethostbyname = socket.gethostbyname
        real_gethostbyname_ex = socket.gethostbyname_ex
        real_gethostbyaddr = socket.gethostbyaddr
        real_getnameinfo = socket.getnameinfo

        def _check(host: str | None) -> None:
            current = _state.policy
            if current is not None:
                current.assert_allowed(host)

        def _check_connect(host: str | None) -> None:
            # The connect layer sees the resolved IP. Permit an IP an allowlisted hostname just
            # resolved to (so allowlisting a public host actually enables egress end-to-end);
            # everything else goes through the normal policy. A dangerous range is NEVER honored
            # from the resolved set (defense in depth alongside the insertion-time filter). Note
            # this dangerous-range re-check applies to connect-by-IP (the resolved-IP path); a
            # caller that connects by HOSTNAME is checked by name via the normal _check/is_allowed
            # path instead (the guarded resolver is what admits an allowlisted host's safe IPs).
            if host is not None and host in _state.resolved_allowlisted_ips and not _is_dangerous_ip(host):
                return
            _check(host)

        def guarded_getaddrinfo(host: Any, *args: Any, **kwargs: Any) -> Any:
            host_str = _host_str(host)
            _check(host_str)
            result = real_getaddrinfo(host, *args, **kwargs)
            current = _state.policy
            if current is not None and host_str and _normalize_host_name(host_str) in current.allowlist:
                for entry in result:  # (family, type, proto, canonname, sockaddr); sockaddr[0]=ip
                    sockaddr = entry[4]
                    # Track only SAFE resolved IPs: a dangerous range (link-local / metadata /
                    # reserved) must never become connectable just because an allowlisted host
                    # resolved to it (DNS rebinding / malicious allowlisted domain -> SSRF).
                    if sockaddr and not _is_dangerous_ip(str(sockaddr[0])):
                        _state.resolved_allowlisted_ips.add(str(sockaddr[0]))
            return result

        def guarded_gethostbyname(hostname: Any) -> Any:
            _check(_host_str(hostname))
            return real_gethostbyname(hostname)

        def guarded_gethostbyname_ex(hostname: Any) -> Any:
            _check(_host_str(hostname))
            return real_gethostbyname_ex(hostname)

        def guarded_gethostbyaddr(host: Any) -> Any:
            _check(_host_str(host))
            return real_gethostbyaddr(host)

        def guarded_getnameinfo(sockaddr: Any, flags: Any) -> Any:
            _check(_extract_host(sockaddr))
            return real_getnameinfo(sockaddr, flags)

        def guarded_connect(self: socket.socket, address: Any) -> Any:
            _check_connect(_extract_host(address))
            return real_connect(self, address)

        def guarded_connect_ex(self: socket.socket, address: Any) -> Any:
            _check_connect(_extract_host(address))
            return real_connect_ex(self, address)

        def guarded_sendto(self: socket.socket, *args: Any, **kwargs: Any) -> Any:
            # sendto(data, address) or sendto(data, flags, address): address is last positional.
            _check_connect(_extract_host(args[-1]) if args else None)
            return real_sendto(self, *args, **kwargs)

        def guarded_sendmsg(self: socket.socket, *args: Any, **kwargs: Any) -> Any:
            # sendmsg(buffers[, ancdata[, flags[, address]]]).
            positional = args[_SENDMSG_ADDR_INDEX] if len(args) > _SENDMSG_ADDR_INDEX else None
            address = kwargs.get("address", positional)
            if address is not None:
                _check_connect(_extract_host(address))
            assert real_sendmsg is not None  # only installed when the platform has sendmsg
            return real_sendmsg(self, *args, **kwargs)

        _state.orig_getaddrinfo = real_getaddrinfo
        _state.orig_connect = real_connect
        _state.orig_connect_ex = real_connect_ex
        _state.orig_sendto = real_sendto
        _state.orig_sendmsg = real_sendmsg
        _state.orig_gethostbyname = real_gethostbyname
        _state.orig_gethostbyname_ex = real_gethostbyname_ex
        _state.orig_gethostbyaddr = real_gethostbyaddr
        _state.orig_getnameinfo = real_getnameinfo
        socket.getaddrinfo = guarded_getaddrinfo
        socket.gethostbyname = guarded_gethostbyname
        socket.gethostbyname_ex = guarded_gethostbyname_ex
        socket.gethostbyaddr = guarded_gethostbyaddr
        socket.getnameinfo = guarded_getnameinfo
        socket.socket.connect = guarded_connect  # type: ignore[method-assign, assignment]
        socket.socket.connect_ex = guarded_connect_ex  # type: ignore[method-assign, assignment]
        socket.socket.sendto = guarded_sendto  # type: ignore[method-assign, assignment]
        if real_sendmsg is not None:
            socket.socket.sendmsg = guarded_sendmsg  # type: ignore[method-assign, assignment]
        _state.installed = True
        log.info(
            "egress_guard_installed",
            sovereign=policy.sovereign,
            allowlist=sorted(policy.allowlist),
        )


def uninstall() -> None:
    """Restore the original socket functions (mainly for tests)."""
    with _state.lock:
        if not _state.installed:
            _state.policy = None
            return
        socket.getaddrinfo = _state.orig_getaddrinfo
        socket.gethostbyname = _state.orig_gethostbyname
        socket.gethostbyname_ex = _state.orig_gethostbyname_ex
        socket.gethostbyaddr = _state.orig_gethostbyaddr
        socket.getnameinfo = _state.orig_getnameinfo
        socket.socket.connect = _state.orig_connect  # type: ignore[method-assign]
        socket.socket.connect_ex = _state.orig_connect_ex  # type: ignore[method-assign]
        socket.socket.sendto = _state.orig_sendto  # type: ignore[method-assign]
        if _state.orig_sendmsg is not None:
            socket.socket.sendmsg = _state.orig_sendmsg  # type: ignore[method-assign]
        _state.installed = False
        _state.policy = None
        _state.resolved_allowlisted_ips = set()


def caused_by_egress_block(exc: BaseException) -> bool:
    """True if :class:`EgressBlocked` appears anywhere in ``exc``'s cause/context chain.

    HTTP clients wrap the guard's ``EgressBlocked`` (an ``OSError``) in their own
    error type, so engines must walk the chain — not just ``isinstance`` — to keep a
    sovereignty block from being silently swallowed as an ordinary source failure.
    """
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if isinstance(current, EgressBlocked):
            return True
        current = current.__cause__ or current.__context__
    return False


def running_loop_is_guarded() -> bool:
    """True if the currently running asyncio loop routes egress through the patched
    ``socket`` layer (the selector loop's ``sock_connect`` uses ``socket.connect``).

    **uvloop** resolves/connects in libuv (C) and is therefore NOT guard-visible.
    Returns ``True`` when called with no running loop (a synchronous context, which
    is fully guarded).
    """
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return True
    return not type(loop).__module__.startswith("uvloop")


def install_from_settings(settings: Settings) -> EgressPolicy:
    """Build a policy from :class:`~p2c.config.Settings` and install it."""
    policy = EgressPolicy(sovereign=settings.sovereign_mode, allowlist=settings.allowlisted_hosts)
    install(policy)
    return policy


@contextmanager
def egress_guard(policy: EgressPolicy) -> Iterator[EgressPolicy]:
    """Context manager that installs ``policy`` and restores prior state on exit."""
    prev_policy = _state.policy
    prev_installed = _state.installed
    install(policy)
    try:
        yield policy
    finally:
        if not prev_installed:
            uninstall()
        elif prev_policy is not None:
            _state.policy = prev_policy
