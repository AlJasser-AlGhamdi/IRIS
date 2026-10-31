"""httpx probe parsing (Stage 3): live host, scheme, headers, tech. Pinned v1.9.0.

**Absence contract.** Findings that assert something is missing (a security header, an
HTTPS redirect) are derived only from a row that records a response the scanner actually
received. A row whose fetch never completed carries no status line, and such an
indeterminate read yields no findings: unknown is not absent (see :func:`response_received`).

**Detector contract, ``insecure_cookie``.** *Observable*: the ``Set-Cookie`` headers of a
response that was received. *Positive*: at least one of those cookies carries no ``Secure``
attribute. *Negative*: every cookie observed carries it. *Inconclusive*: no response, or a
response that set no cookies at all. That last case is the important one, and it is why the
finding is scoped to the cookies actually seen: one unauthenticated fetch of one path observes
the cookies that path sets, not every cookie the application can issue, so the evidence is
"an observed cookie lacked ``Secure``", never "this site uses insecure cookies". *Evidence*:
the ``Set-Cookie`` values, on :attr:`HttpProbe.set_cookie`.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime

import structlog

from p2c.scanning.catalog import CheckId
from p2c.scanning.headers import analyze_security_headers

log = structlog.get_logger("p2c.scanning.httpx")


@dataclass(frozen=True)
class HttpProbe:
    """One httpx result row."""

    url: str
    host: str
    scheme: str
    status_code: int
    headers: dict[str, str] = field(default_factory=dict)
    tech: tuple[str, ...] = ()
    # Set-Cookie is the one response header that legitimately repeats, and ``headers`` is a
    # mapping, so a flattened copy would hide every cookie but one. The cookie detector needs
    # all of them, so they are carried separately rather than by widening ``headers`` and
    # rewriting every consumer of it.
    set_cookie: tuple[str, ...] = ()
    # Up to 64 KB of the body where the scan read it (b"" where it did not look), ``None`` where it
    # tried and could not (an encoded body): a block page is recognised by its body as well.
    body: bytes | None = b""


def parse_httpx(output: str) -> list[HttpProbe]:
    """Parse httpx ``-json`` JSONL rows into :class:`HttpProbe`s."""
    probes: list[HttpProbe] = []
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        try:
            obj = json.loads(stripped)
        except json.JSONDecodeError:
            continue
        url = obj.get("url")
        if not isinstance(url, str):
            continue
        raw_headers = obj.get("header") or obj.get("headers") or {}
        headers = {str(k): str(v) for k, v in raw_headers.items()} if isinstance(raw_headers, dict) else {}
        set_cookie = _set_cookie_values(raw_headers)
        raw_status = obj.get("status_code")
        status_code = raw_status if isinstance(raw_status, int) else 0
        raw_tech = obj.get("tech")
        tech = tuple(str(t) for t in raw_tech) if isinstance(raw_tech, list) else ()
        probes.append(
            HttpProbe(
                url=url,
                host=str(obj.get("host") or obj.get("input") or ""),
                scheme=str(obj.get("scheme") or (url.split("://", 1)[0] if "://" in url else "")),
                status_code=status_code,
                headers=headers,
                tech=tech,
                set_cookie=set_cookie,
            )
        )
    return probes


def _set_cookie_values(raw_headers: object) -> tuple[str, ...]:
    """Every ``Set-Cookie`` value in the row, whether the encoder emitted one string or a list."""
    if not isinstance(raw_headers, dict):
        return ()
    for key, value in raw_headers.items():
        if str(key).lower() != "set-cookie":
            continue
        if isinstance(value, list):
            return tuple(str(v) for v in value)
        return tuple(part for part in str(value).splitlines() if part.strip())
    return ()


# ASCII digits only: str.isdigit() also accepts characters such as superscripts that int() rejects,
# so a hostile Set-Cookie could otherwise raise mid-parse and drop the host's other header findings.
_MAX_AGE = re.compile(r"(-?)([0-9]+)")


def _max_age_expired(value: str) -> bool | None:
    """Whether a Max-Age value is zero or less, read from its sign and digits without int() (which
    refuses very long digit strings); ``None`` if the value is not a well-formed Max-Age."""
    match = _MAX_AGE.fullmatch(value.strip())
    if match is None:
        return None
    return bool(match.group(1)) or match.group(2).strip("0") == ""


def cookie_deletion(set_cookie: str) -> bool:
    """True if this ``Set-Cookie`` deletes its cookie (Max-Age of zero or less, or an Expires past). Where
    Max-Age is given it alone decides, as RFC 6265 (5.3) gives it precedence over Expires."""
    parts = [p.strip() for p in set_cookie.split(";")[1:]]
    for part in parts:
        name, _, value = part.partition("=")
        expired = _max_age_expired(value) if name.strip().lower() == "max-age" else None
        if expired is not None:
            return expired
    for part in parts:
        name, _, value = part.partition("=")
        if name.strip().lower() == "max-age" and _max_age_expired(value):
            return True
        if name.strip().lower() == "expires":
            try:
                expires = parsedate_to_datetime(value.strip())
            except (TypeError, ValueError):
                continue
            if expires.tzinfo is None:  # "-0000" parses without a zone: RFC 6265 dates are in UTC
                expires = expires.replace(tzinfo=UTC)
            if expires < datetime.now(UTC):
                return True
    return False


def cookie_lacks_secure(set_cookie: str) -> bool:
    """True if this ``Set-Cookie`` value carries no ``Secure`` attribute (RFC 6265, 5.2: the attribute
    is named by what precedes any ``=``, so ``Secure=true`` is Secure, as browsers read it)."""
    parts = [part.strip() for part in set_cookie.split(";")[1:]]
    attributes = {part.split("=", 1)[0].strip().lower() for part in parts}
    # A deletion (Max-Age of zero or less, or an Expires in the past) carries no value to protect.
    return "secure" not in attributes and not cookie_deletion(set_cookie)


# ``exposed_dev_environment`` detector contract. *Observable*: the response headers of a received
# response. *Positive*: a header that only a development server or a debug profiler emits. Werkzeug
# ships the Flask development server, whose own documentation says it is not for production use;
# ``X-Debug-Token`` is the Symfony web profiler, which is a development-only bundle. *Negative*: a
# received response carrying none of them. *Inconclusive*: no response. *Evidence*: the matched
# header. A hostname is deliberately not evidence: ``dev.example.com`` may be supporting context but
# it establishes nothing on its own, and the estate is full of names that mean nothing. The
# signature set is narrow on purpose, so the detector under-reports rather than guesses; absence of
# a signature is not evidence that no development environment is exposed.
# Django's runserver and Python's wsgiref answer "WSGIServer/<v> CPython/<v>", http.server "SimpleHTTP/<v>".
_DEV_SERVER_MARKERS = ("werkzeug", "webrick", "rack-dev", "django-devserver", "wsgiserver/", "simplehttp/")
_DEV_HEADERS = ("x-debug-token", "x-debug-token-link", "x-symfony-profiler")


def dev_environment_signature(headers: dict[str, str]) -> str | None:
    """The header evidence of a development server or debug profiler, or ``None``."""
    for name, value in headers.items():
        lowered = name.lower()
        if lowered in _DEV_HEADERS:
            return f"{name}: {value}"
        if lowered == "server" and any(marker in value.lower() for marker in _DEV_SERVER_MARKERS):
            return f"{name}: {value}"
    return None


_REDIRECT_MIN, _REDIRECT_MAX = 300, 400  # 3xx status range
_STATUS_MIN, _STATUS_MAX = 100, 599  # a real HTTP status line


def response_received(probe: HttpProbe) -> bool:
    """True if this row records an HTTP response the scanner actually received.

    ``parse_httpx`` yields ``status_code`` 0 for a row with no usable status line, which is
    what an aborted fetch (timeout, refused connection, TLS failure) leaves behind. Such a
    read is indeterminate and must not be mistaken for a compliant-or-missing observation.
    """
    return _STATUS_MIN <= probe.status_code <= _STATUS_MAX


def redirects_to_https(probe: HttpProbe) -> bool:
    """True if a plain-HTTP probe answered with a 3xx redirect to an ``https://`` Location."""
    if not (_REDIRECT_MIN <= probe.status_code < _REDIRECT_MAX):
        return False
    location = next((v for k, v in probe.headers.items() if k.lower() == "location"), "")
    return location.strip().lower().startswith("https://")


def checks_for_probe(probe: HttpProbe) -> list[CheckId]:
    """Tier-1 checks derivable from a single HTTP(S) probe: missing headers + no-HTTPS.

    ``NO_HTTPS_REDIRECT`` is only raised when a plain-HTTP endpoint does **not** redirect to
    HTTPS — an ``http://`` probe that 301/302s to ``https://`` is compliant, so flagging it on
    scheme alone was a false positive. A probe with no received response yields nothing at all.
    """
    if not response_received(probe):
        log.warning("http_read_indeterminate", url=probe.url, status_code=probe.status_code)
        return []
    checks: list[CheckId] = []
    if probe.scheme == "http" and not redirects_to_https(probe):
        checks.append(CheckId.NO_HTTPS_REDIRECT)
    # response_received above already establishes that a response arrived, which is the whole of
    # the absence contract. An earlier scheme-or-headers guard here made an https response with an
    # empty header map raise all six reads while an http one raised none; that asymmetry was not
    # documented anywhere and is gone.
    checks.extend(analyze_security_headers(probe.headers))
    if any(cookie_lacks_secure(value) for value in probe.set_cookie):
        checks.append(CheckId.INSECURE_COOKIE)
    if dev_environment_signature(probe.headers) is not None:
        checks.append(CheckId.EXPOSED_DEV_ENVIRONMENT)
    return checks
