"""Path probes on a web origin (Stage 3, Tier-1): listings, exposed files and login panels.

Three detectors fetch a small fixed set of paths and read the body. All three share one rule:
**a finding needs a content signature in a response the scanner received.** A status code is never
enough, because many servers answer every path with ``200`` and a "not found" page (a soft 404).
And absence is reported only when every probed path answered; a path whose fetch did not complete
leaves the detector inconclusive rather than clean.

**Detector contract, ``directory_listing_enabled``.**
*Observable*: the bodies of ``GET`` on the origin root and a few common directory paths.
*Positive*: a ``200`` body carrying an auto-generated index signature (nginx and Apache
``<title>Index of /...``, IIS ``[To Parent Directory]``, Python ``Directory listing for``).
*Negative*: every path answered and none carries a signature. *Inconclusive*: some path did not
answer and none matched. *Evidence*: the URL and the matched signature.

**Detector contract, ``exposed_sensitive_file``.**
*Observable*: the bodies of ``GET`` on paths where deployment leftovers live. *Positive*: a ``200``
body matching that file's own format: a Git ``HEAD`` reference, ``.env`` assignments, the
``.DS_Store`` magic, a SQL dump header, an Apache status page or a ``phpinfo()`` page. *Negative*:
every path answered without its format. *Inconclusive*: some path did not answer and none matched.
*Evidence*: the URL and the format matched.

**Detector contract, ``exposed_login_panel``.**
*Observable*: the responses to ``GET`` on common administration and login paths. *Positive*: a
``200`` HTML body holding a form with a password input, or a ``401`` (with an authentication
challenge, ``WWW-Authenticate``, or without one): either way an authentication surface is reachable
from outside.
*Negative*: every path answered with neither. *Inconclusive*: some path did not answer and none
matched, or a login path answered ``200`` with no password input but either exactly the page the
site serves for a path that cannot exist or a page that runs script (an application shell, which
may draw its login form in script the body does not show); a ``404`` still shows the path is not
served.
*Evidence*: the URL and what was seen. What the detector cannot tell is whether the panel enforces
a second factor; it reports the surface, not its strength.

The probes are plain ``GET`` requests with no credentials, no payloads and no form submission. A
baseline request for a path that cannot exist comes first, and a signature the site serves there
too (a login widget or an index page on every page) is not evidence about the path probed. A rate
limit (``429``), a server error (``5xx``), a bot challenge (``cf-mitigated``) or a ``403`` the
baseline gets as well is not an answer. Redirects are followed only within the
same origin, each body is read up to a fixed size on the wire, and a whole probe has a deadline.

*Test oracle*: ``httpx.MockTransport`` in the unit tests; planted paths in the integration matrix.
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from enum import StrEnum

import httpx
import structlog

from p2c.scanning.catalog import CheckId
from p2c.sovereignty.egress_guard import caused_by_egress_block

log = structlog.get_logger("p2c.scanning.web_paths")

_HTTP_OK = 200
_SCRIPT = re.compile(rb"(?i)<script\b")
_HTTP_UNAUTHORISED = 401
_MAX_BODY = 65_536
_BASELINE_PATH = "/p2c-nonexistent-7f3a9c1e/"  # a path no site serves on purpose
_HTTP_TOO_MANY = 429
_HTTP_UNAUTHORIZED = 401
_HTTP_FORBIDDEN = 403
_HTTP_SERVER_ERROR = 500
_REDIRECT_MIN, _REDIRECT_MAX = 300, 400
_MAX_REDIRECTS = 3

DIRECTORY_PATHS: tuple[str, ...] = ("/", "/files/", "/uploads/", "/backup/", "/images/")
LOGIN_PATHS: tuple[str, ...] = (
    "/admin/",
    "/login",
    "/wp-login.php",
    "/administrator/",
    "/user/login",
    "/manager/html",
    "/phpmyadmin/",
)

_LISTING = (
    re.compile(r"<title>\s*Index of /", re.IGNORECASE),  # Apache, nginx, lighttpd
    re.compile(r"\[To Parent Directory\]", re.IGNORECASE),  # IIS
    re.compile(r"<title>\s*Directory listing for /", re.IGNORECASE),  # Python, Caddy
    re.compile(r"<title>\s*Directory Listing For \[?/", re.IGNORECASE),  # Tomcat
    re.compile(r"<title>\s*Directory: /", re.IGNORECASE),  # Jetty
    re.compile(r"<title>\s*listing directory /", re.IGNORECASE),  # Express serve-index
)
_PASSWORD_INPUT = re.compile(r"<input\b[^>]*\btype\s*=\s*[\"']?password\b", re.IGNORECASE)
# /login and /user/login serve customer sign-in as often as administration: a password form there is an
# administrative login only when the page's title, a heading or the form's action names one.
_GENERIC_LOGIN_PATHS = frozenset({"/login", "/user/login"})
_HEADING = re.compile(r"(?is)<(title|h1|h2)\b[^>]*>(.*?)</\1\s*>")
_TAG = re.compile(r"<[^>]*>")
# A heading names an administrative login only with both words: "Admin login", "cPanel Login",
# never a firm called "... Administration" or a client portal's "control panel" alone.
_ADMIN_WORD = re.compile(
    r"(?i)\b(?:admin|administrator|administration|control panel|cpanel|plesk|webmin|backend|back office)\b"
    r"|لوحة التحكم"
)
_LOGIN_WORD = re.compile(r"(?i)\b(?:log\s?in|sign\s?in|logon)\b|تسجيل الدخول")
_ADMIN_ACTION = re.compile(r"(?i)\baction\s*=\s*[\"']?[^\"'>\s]*(?:admin|backend|cpanel|plesk)")
_FORM_BODY = re.compile(r"(?is)<form\b([^>]*)>(.*?)(?:</form>|$)")


def _admin_headings(text: str) -> set[str]:
    """The title and headings of a page that name an administrative login."""
    found = set()
    for heading in _HEADING.finditer(text):
        words = " ".join(_TAG.sub(" ", heading[2]).split())
        if _ADMIN_WORD.search(words) and _LOGIN_WORD.search(words):
            found.add(words.lower())
    return found


def _names_admin(text: str, template: str = "") -> bool:
    """The page's title or a heading names an administrative login, unless the site's page for a path
    that cannot exist (``template``) carries the same heading (the site's own banner, not the login's),
    or the form holding the password input posts to an administrative action (another form's action,
    a site search say, does not count)."""
    if _admin_headings(text) - _admin_headings(template):
        return True
    return any(
        _PASSWORD_INPUT.search(form[2]) and _ADMIN_ACTION.search(form[1])
        for form in _FORM_BODY.finditer(text)
    )
_FORM = re.compile(r"<form\b", re.IGNORECASE)


def _git_head(body: bytes) -> bool:
    text = body[:200].decode("ascii", "replace").strip()
    return text.startswith("ref: refs/") or bool(re.fullmatch(r"[0-9a-f]{40}", text))


_MIN_ASSIGNMENTS = 2  # one KEY=VALUE line could be any text; two in a mostly-assignment body is a .env


def _dotenv(body: bytes) -> bool:
    """Mostly ``KEY=VALUE`` lines, comments aside (``export KEY=...`` and ``KEY = value`` too)."""
    text = body[:4096].decode("utf-8", "replace")
    lines = [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#")]
    assignments = [ln for ln in lines if re.match(r"^(?:export\s+)?[A-Z][A-Z0-9_]*\s*=", ln)]
    return len(assignments) >= _MIN_ASSIGNMENTS and len(assignments) >= len(lines) // 2


def _ds_store(body: bytes) -> bool:
    return body[:8] == b"\x00\x00\x00\x01Bud1"


def _sql_dump(body: bytes) -> bool:
    text = body[:4096].decode("utf-8", "replace")
    return bool(re.search(r"(MySQL dump|PostgreSQL database dump|^CREATE TABLE )", text, re.MULTILINE))


def _apache_status(body: bytes) -> bool:
    return b"Apache Server Status for" in body[:4096]


def _phpinfo(body: bytes) -> bool:
    return b"<title>phpinfo()</title>" in body[:4096] or b"PHP Version </td>" in body[:65536]


SENSITIVE_FILES: dict[str, Callable[[bytes], bool]] = {
    "/.git/HEAD": _git_head,
    "/.env": _dotenv,
    "/.DS_Store": _ds_store,
    "/backup.sql": _sql_dump,
    "/server-status": _apache_status,
    "/phpinfo.php": _phpinfo,
}


def _non_answer(status: int) -> bool:
    """A rate limit or a server error is no answer about the path: the read stays open."""
    return status == _HTTP_TOO_MANY or status >= _HTTP_SERVER_ERROR


def _unanswered(status: int) -> bool:
    """No answer about a path: a rate limit, a server error, or any status but a page, a redirect, not
    found, or an authentication wall or refusal (which the path detectors read on their own terms)."""
    walls = (_HTTP_UNAUTHORIZED, _HTTP_FORBIDDEN)
    return _non_answer(status) or not (site_answer(status) or status in walls)


# Headers a bot or WAF gateway sets on a challenge or block page it serves in the site's place.
# (Only headers set on a challenge or block: a gateway's presence markers, set on every page it passes,
# would turn the site's own pages into block pages.)
_GATEWAY_HEADERS = frozenset({"cf-mitigated", "x-amzn-waf-action"})
# The body of a block or challenge page a WAF or bot gateway serves in the site's place, whatever its
# status (F5's default rejection page and many challenges come with a 200).
_BLOCK_PAGE = re.compile(
    rb"(?i)The requested URL was rejected\. Please consult with your administrator"
    rb"|Your support ID is"
    rb"|Incapsula incident ID"
    rb"|Sucuri WebSite Firewall|sucuri_cloudproxy_js"  # Sucuri's block page and its JavaScript challenge
    rb"|<title>\s*Attention Required! \| Cloudflare\s*</title>"
    rb"|<title>\s*Just a moment\.\.\.\s*</title>"
    rb"|window\._cf_chl_opt|/cdn-cgi/challenge-platform/h/[bg]/orchestrate/"
    rb"|captcha-delivery\.com"
    rb"|generated by Mod_Security|ModSecurity Action"
    rb"|Unauthorized Activity Has Been Detected"  # Radware AppWall
    rb"|Access denied by Imunify360|imunify360-webshield"
    rb"|Attack ID:\s*\d+"  # Fortinet FortiWeb's block page
    rb"|Reference&#32;&#35;\d+\.[0-9a-f]+\.\d+|Reference #\d+\.[0-9a-f]+\.\d+"
)
_SITE_ANSWERS = frozenset({404, 410})  # beside 2xx and 3xx: the site says the page does not exist


def site_answer(status: int) -> bool:
    """A status the site itself answers with: a page, a redirect, or not found. Any other (a 406 from
    a filtering module, a 405, a rate limit, a server error) is no answer about the page."""
    return 200 <= status < 400 or status in _SITE_ANSWERS  # noqa: PLR2004


# Imperva's JavaScript challenge: a page that is little more than its script. Imperva also injects that
# script into the site's own pages, so it counts only on a near-empty page or one marked noindex.
_IMPERVA_SCRIPT = re.compile(rb"_Incapsula_Resource\?(?:SWJIYLWA|CWUDNSAI)=")
_NOINDEX = re.compile(rb"(?i)<meta\s+name\s*=\s*[\"']?robots[\"']?\s+content\s*=\s*[\"']?noindex")
_CHALLENGE_PAGE_BYTES = 2048


def block_page(body: bytes | None) -> bool:
    """Whether a body is a known WAF or bot gateway's block or challenge page."""
    if body is None:
        return False
    head = body[:_MAX_BODY]
    if _IMPERVA_SCRIPT.search(head) and (len(body) < _CHALLENGE_PAGE_BYTES or _NOINDEX.search(head)):
        return True
    return _BLOCK_PAGE.search(head) is not None


def gateway_response(status: int, headers: dict[str, str], body: bytes | None = b"") -> bool:
    """Whether a response is a gateway's rather than the site's: a challenge header, a block page's
    body, or any status but a page, a redirect or not found (an authentication wall, a block, a
    challenge, a rate limit, a server error). Its headers and body describe the gateway."""
    if any(k.lower() in _GATEWAY_HEADERS for k in headers):
        return True
    return block_page(body) or not site_answer(status)


def blocked(fetched: Fetched, baseline: Fetched | None) -> bool:
    """A bot or WAF block, or an authentication wall, stands in for the site: a challenge page, or a
    401 or 403 the site also serves for a path that cannot exist. Such a response says nothing about
    the path, so the read stays open."""
    if any(k.lower() in _GATEWAY_HEADERS for k in fetched.headers) or block_page(fetched.body):
        return True
    walls = (_HTTP_UNAUTHORIZED, _HTTP_FORBIDDEN)
    return fetched.status in walls and baseline is not None and baseline.status == fetched.status


class PathState(StrEnum):
    FOUND = "found"
    CLEAN = "clean"
    UNREAD = "unread"


@dataclass(frozen=True)
class Fetched:
    url: str
    status: int
    headers: dict[str, str]
    body: bytes


@dataclass(frozen=True)
class PathResult:
    check: CheckId
    state: PathState
    evidence: tuple[str, ...] = field(default_factory=tuple)

    @property
    def checks(self) -> tuple[CheckId, ...]:
        return (self.check,) if self.state is PathState.FOUND else ()


def listing_signature(fetched: Fetched) -> str | None:
    if fetched.status != _HTTP_OK:
        return None
    text = fetched.body.decode("utf-8", "replace")
    match = next((m for pattern in _LISTING if (m := pattern.search(text))), None)
    return match.group(0) if match else None


def admin_login_page(body: bytes) -> bool:
    """A page with a password form that names an administrative surface (a dedicated admin host
    serving its login at the root, say)."""
    text = body.decode("utf-8", "replace")
    return bool(_FORM.search(text) and _PASSWORD_INPUT.search(text) and _names_admin(text))


def login_signature(fetched: Fetched) -> str | None:
    if fetched.status == _HTTP_UNAUTHORISED:
        # An authentication wall at a login path: with its challenge, or bare (a framework's login
        # required with no login view). A wall the site serves on every path is caught by the baseline.
        challenge = next((v for k, v in fetched.headers.items() if k.lower() == "www-authenticate"), None)
        return f"401 challenge: {challenge.split(' ', 1)[0]}" if challenge else "401 without a challenge"
    if fetched.status != _HTTP_OK:
        return None
    text = fetched.body.decode("utf-8", "replace")
    if _FORM.search(text) and _PASSWORD_INPUT.search(text):
        return "form with a password input"
    return None


class WebPathInspector:
    """Fetches the fixed path sets of one origin and classifies the three path detectors."""

    def __init__(
        self, client: httpx.Client | None = None, *, timeout: float = 10.0, deadline: float = 30.0
    ) -> None:
        self._client = client
        self._timeout = timeout
        self._deadline = deadline  # a whole probe, redirects and body included, never runs longer

    def _fetch(self, url: str) -> Fetched | None:
        """One bounded read. Redirects are followed only within the same origin (scheme, host,
        port), at most :data:`_MAX_REDIRECTS` times, so a probe never leaves the consented host; a
        redirect elsewhere is classified as the answer it is. The body is streamed and read up to
        :data:`_MAX_BODY` bytes, so a large or endless response cannot exhaust the scanner."""
        try:
            if self._client is not None:
                return self._read(self._client, url)
            with httpx.Client(timeout=self._timeout, follow_redirects=False, trust_env=False) as client:
                return self._read(client, url)
        except Exception as exc:
            if caused_by_egress_block(exc):
                raise
            log.warning("web_path_read_indeterminate", url=url, error=type(exc).__name__)
            return None

    def _read(self, client: httpx.Client, url: str) -> Fetched | None:
        origin = httpx.URL(url)
        current = origin
        started = time.monotonic()
        for _ in range(_MAX_REDIRECTS + 1):
            if time.monotonic() - started > self._deadline:
                log.warning("web_path_deadline_exceeded", url=url)
                return None  # the deadline covers every hop, not only the body
            # Identity encoding and raw bytes: the cap applies to what arrives on the wire, so a small
            # compressed reply cannot expand past it in memory before it is counted. Redirects are
            # never followed by the client, even an injected one, only by the same-origin rule below.
            with client.stream(
                "GET", current, headers={"Accept-Encoding": "identity"}, follow_redirects=False
            ) as response:
                location = response.headers.get("location")
                if response.is_redirect and location:
                    target = current.join(location)
                    if (target.scheme, target.host, target.port) == (origin.scheme, origin.host, origin.port):
                        current = target
                        continue
                encoding = response.headers.get("content-encoding", "identity").strip().lower()
                if encoding not in ("", "identity"):
                    log.warning("web_path_encoded_body_unread", url=str(response.url), encoding=encoding)
                    return None  # compressed despite the request: unread rather than decoded unbounded
                body = bytearray()
                for chunk in response.iter_raw():
                    body.extend(chunk)
                    if len(body) >= _MAX_BODY:
                        break
                    if time.monotonic() - started > self._deadline:
                        log.warning("web_path_deadline_exceeded", url=url)
                        return None  # a slow drip: the read did not complete in time
                return Fetched(
                    url=str(response.url),
                    status=response.status_code,
                    headers=dict(response.headers),
                    body=bytes(body[:_MAX_BODY]),
                )
        log.warning("web_path_redirect_loop", url=url)
        return None  # same-origin redirects without end: no answer, so the read stays open

    def _classify(
        self,
        check: CheckId,
        base: str,
        paths: Iterable[str],
        match: Callable[[str, Fetched], str | None],
        *,
        catch_all_unread: bool = False,
        undecided: Callable[[str, Fetched, Fetched], bool] | None = None,
    ) -> PathResult:
        unread = forbidden = False
        # What the site serves for a path that cannot exist. A signature it also carries (a login
        # wall or an index page on every page) says nothing about the path probed. Without a clean
        # baseline that filter is off, so nothing the paths show can be trusted: the read stays open.
        baseline = self._fetch(base.rstrip("/") + _BASELINE_PATH)
        if baseline is None or _unanswered(baseline.status) or blocked(baseline, None):
            return PathResult(check, PathState.UNREAD)
        for path in paths:
            fetched = self._fetch(base.rstrip("/") + path)
            # A redirect left in the answer points off the site (same-site ones are followed), so
            # the path was not read here either way.
            off_site = fetched is not None and _REDIRECT_MIN <= fetched.status < _REDIRECT_MAX
            if fetched is None or off_site or _unanswered(fetched.status) or blocked(fetched, baseline):
                unread = True
                continue
            forbidden = forbidden or fetched.status == _HTTP_FORBIDDEN
            signature = match(path, fetched)
            same_page = (fetched.status, fetched.body) == (baseline.status, baseline.body)
            shell = same_page or _SCRIPT.search(fetched.body) is not None
            if catch_all_unread and fetched.status == _HTTP_OK and signature is None and shell:
                # The page every path gets, or one that runs script: a login form drawn by script at
                # this path would look the same, so the path was not read.
                unread = True
                continue
            if signature is not None and undecided is not None and undecided(path, fetched, baseline):
                unread = True  # a sign-in page that may be the customers': neither found nor clean
                continue
            if signature is not None and match(path, baseline) is not None:
                # Served on every path (a site-wide login or auth wall): it neither shows nor rules out
                # the path probed, so the read stays open rather than clean.
                unread = True
                continue
            if signature is not None:
                return PathResult(check, PathState.FOUND, (fetched.url, signature))
        if forbidden and not unread:
            # A rate-based block can start mid-group and answer 403 everywhere from then on: ask for the
            # path that cannot exist again, and if it is refused too, the 403s were the block's.
            again = self._fetch(base.rstrip("/") + _BASELINE_PATH)
            if again is None or _non_answer(again.status) or again.status == _HTTP_FORBIDDEN:
                unread = True
        return PathResult(check, PathState.UNREAD if unread else PathState.CLEAN)

    def directory_listing(self, base: str) -> PathResult:
        return self._classify(
            CheckId.DIRECTORY_LISTING_ENABLED, base, DIRECTORY_PATHS, lambda _p, f: listing_signature(f)
        )

    def sensitive_files(self, base: str) -> PathResult:
        def match(path: str, fetched: Fetched) -> str | None:
            if fetched.status == _HTTP_OK and SENSITIVE_FILES[path](fetched.body):
                return f"{path} format"
            return None

        return self._classify(CheckId.EXPOSED_SENSITIVE_FILE, base, SENSITIVE_FILES, match)

    def login_panel(self, base: str) -> PathResult:
        return self._classify(
            CheckId.EXPOSED_LOGIN_PANEL,
            base,
            LOGIN_PATHS,
            lambda _p, f: login_signature(f),
            catch_all_unread=True,
            undecided=lambda p, f, b: (
                p in _GENERIC_LOGIN_PATHS
                and not _names_admin(f.body.decode("utf-8", "replace"), b.body.decode("utf-8", "replace"))
            ),
        )

    def inspect(self, base: str) -> list[CheckId]:
        """Every path detector's finding for one origin (``base`` is ``scheme://host[:port]``)."""
        results = (self.directory_listing(base), self.sensitive_files(base), self.login_panel(base))
        return [check for result in results for check in result.checks]
