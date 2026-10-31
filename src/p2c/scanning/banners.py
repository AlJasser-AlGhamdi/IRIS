"""Version banner inspection (Stage 3, Tier-1): outdated and end-of-life software.

**Detector contract, ``outdated_exposed_software`` and ``eol_software_exposed``.**

*Observable*
    The ``Server`` and ``X-Powered-By`` headers of an HTTP response the scanner received, read for
    ``product/version`` tokens of the products in the dated release-cycle snapshot
    (``data/lifecycle.json``: nginx, Apache httpd and PHP, from endoflife.date).

*Positive*
    ``eol_software_exposed``: a token names a version whose release cycle had ended on the scan
    date. ``outdated_exposed_software``: a token names a version of a supported cycle that is older
    than the cycle's newest patch release in the snapshot, and the first patch it lacks came out more
    than :data:`PATCH_WINDOW_DAYS` (three months) before the scan date. A version is never both: an
    ended cycle has no current patch to fall behind.

*Negative*
    Every covered product named in the banners carries a full version of a cycle still supported on
    the scan date, and each is the newest patch or lacks only patches released within three months.
    The NCA's patch management policy template asks applications to be patched at least every three
    months, so a gap inside that window does not show patch management unmet.

*Inconclusive, and it raises nothing*
    No response; no banner; a banner with no version (``Server: nginx``, the usual hardened form);
    a product or a release cycle the snapshot does not cover (OpenSSH and IIS among them), including
    any other product named, with or without a version, beside a covered one (``OpenSSL/1.0.2k`` in
    Apache's full banner, ``Microsoft-IIS`` or ``LiteSpeed`` beside ``PHP/8.4``); a covered product
    named with no ``Server`` header at all, so the web server is unknown; a version that names only the cycle
    (``Apache/2.4``) for a supported cycle; an older patch whose missed patch the snapshot does not
    date; or a covered product named without a version beside a versioned one. A missing
    version is unknown, never current. This is the contract the evaluation's banner-suppression
    evasion relies on: hiding the version leaves these reads unread rather than clean.

*Evidence retained*
    The header, the token, the cycle and its snapshot entry, and the release date of the first
    patch the version lacks, on :class:`BannerResult`.

*What a banner cannot show*
    A banner is the server's own claim. It can be false (spoofed to a current version, the evasion
    the adversary model names), and distributions backport fixes without changing the upstream
    version string, so an outdated banner is evidence of an unpatched component, not proof. The
    detector reads only what the server says about itself.

*Test oracle*
    Fixture headers in the unit tests; planted banners in the integration matrix.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import date
from enum import StrEnum
from functools import cache
from pathlib import Path

import structlog

from p2c.scanning.catalog import CheckId
from p2c.scanning.httpx_probe import HttpProbe, response_received

log = structlog.get_logger("p2c.scanning.banners")

_SNAPSHOT = Path(__file__).parent / "data" / "lifecycle.json"
# Banner product token (lower case) to snapshot product key.
_PRODUCTS: dict[str, str] = {"nginx": "nginx", "apache": "apache-http-server", "php": "php"}
# Each version component is capped at six digits: a banner is attacker-controlled text, and an
# unbounded run of digits would make int() raise (Python's integer-string limit) or burn time.
_TOKEN = re.compile(r"(?i)\b(nginx|apache|php)/(\d{1,6}(?:\.\d{1,6}){1,3})\b")
_BANNER_HEADERS = ("server", "x-powered-by")
# A covered product named with no version after it (``Server: nginx``, ``Apache-Coyote``).
_BARE = re.compile(r"(?i)\b(nginx|apache|php)\b(?!/\d)")
# A distribution build: the vendor backports fixes under the upstream version number, so neither the
# patch level nor the support status can be read from the banner (nginx/1.24.0 (Ubuntu) is a
# supported package although upstream 1.24 has ended).
_DISTRO = re.compile(
    r"(?i)\((?:ubuntu|debian|raspbian|red hat[^)]*|centos[^)]*|rocky[^)]*|almalinux[^)]*|fedora[^)]*"
    r"|suse[^)]*|opensuse[^)]*|amazon[^)]*|oracle[^)]*|alpine[^)]*)\)"
    r"|[-+~.]\d*(?:deb\d|ubuntu|el\d|fc\d|amzn)"  # PHP/8.1.2-1ubuntu2.14, 8.3.6-0ubuntu0.24.04.1
)
# A comment in a banner (``(Ubuntu)``), and the separators between its product tokens.
_COMMENT = re.compile(r"\([^)]*\)")
_SEPARATORS = re.compile(r"[\s,;]+")
_STALE_AFTER_DAYS = 180
# The NCA's patch management policy template asks applications on all systems to be patched at least
# every three months (monthly on internet-connected critical systems); 92 days is the longest three
# calendar months, so a patch missed for longer is past any window the template allows.
PATCH_WINDOW_DAYS = 92


class BannerState(StrEnum):
    READ = "read"
    NO_RESPONSE = "no_response"
    NO_BANNER = "no_banner"  # no banner header, or none naming a covered product with a version
    UNCOVERED = "uncovered"  # a covered product, but a cycle the snapshot does not list


@dataclass(frozen=True)
class BannerToken:
    header: str
    product: str
    version: str
    cycle: str | None = None
    latest: str | None = None
    eol: str | bool | None = None
    missed: str | None = None  # release date of the first patch the version lacks


@dataclass(frozen=True)
class BannerResult:
    checks: tuple[CheckId, ...] = ()
    state: BannerState = BannerState.NO_RESPONSE
    tokens: tuple[BannerToken, ...] = field(default_factory=tuple)
    # On a READ with a finding, the other banner detector when its negative is not established: an
    # end-of-life or unplaced product leaves "outdated" open, an unplaced one leaves "end of life" open.
    unread: tuple[CheckId, ...] = ()


@cache
def lifecycle_snapshot() -> dict[str, list[dict[str, object]]]:
    """The committed release-cycle snapshot, keyed by product."""
    doc = json.loads(_SNAPSHOT.read_text(encoding="utf-8"))
    products: dict[str, list[dict[str, object]]] = doc["products"]
    return products


def _version_tuple(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in version.split("."))


def _cycle_for(product: str, version: str) -> dict[str, object] | None:
    """The snapshot cycle a version belongs to: the longest cycle string that prefixes it."""
    parts = _version_tuple(version)
    best: dict[str, object] | None = None
    best_len = 0
    for entry in lifecycle_snapshot().get(product, []):
        cycle = _version_tuple(str(entry["cycle"]))
        if parts[: len(cycle)] == cycle and len(cycle) > best_len:
            best, best_len = entry, len(cycle)
    return best


def _first_missed(entry: dict[str, object], version: str) -> str | None:
    """The release date of the first patch of the cycle newer than ``version``, if the snapshot dates it."""
    patches = entry.get("patches")
    if not isinstance(patches, dict):
        return None
    mine = _version_tuple(version)
    newer = [(_version_tuple(name), day) for name, day in patches.items() if _version_tuple(name) > mine]
    return min(newer)[1] if newer else None


def _ended(eol: object, today: date) -> bool:
    """True if a cycle had ended on ``today``. ``False`` means supported; a date means it ends then."""
    if eol is True:
        return True
    if isinstance(eol, str):
        return date.fromisoformat(eol) <= today
    return False


def banner_tokens(headers: dict[str, str]) -> list[BannerToken]:
    """Every ``product/version`` token of a covered product in the banner headers."""
    tokens: list[BannerToken] = []
    for name, value in headers.items():
        if name.lower() not in _BANNER_HEADERS:
            continue
        for match in _TOKEN.finditer(value):
            product = _PRODUCTS[match.group(1).lower()]
            tokens.append(BannerToken(header=name, product=product, version=match.group(2)))
    return tokens


def _bare_products(headers: dict[str, str]) -> bool:
    """True if a banner header names a covered product without a version (``Server: nginx``)."""
    return any(_BARE.search(value) for name, value in headers.items() if name.lower() in _BANNER_HEADERS)


def _other_products(headers: dict[str, str]) -> bool:
    """True if a banner header names, with or without a version, a product the snapshot does not
    cover (``OpenSSL/1.0.2k``, ``Microsoft-IIS``, ``LiteSpeed``), or there is no ``Server`` header:
    either way software the snapshot cannot place is exposed, so the banner is not current."""
    banners = [value for name, value in headers.items() if name.lower() in _BANNER_HEADERS]
    if not any(name.lower() == "server" for name in headers):
        return True
    words = (w for value in banners for w in _SEPARATORS.split(_COMMENT.sub(" ", value)))
    return any(w[:1].isalpha() and w.split("/", 1)[0].lower() not in _PRODUCTS for w in words)


def snapshot_retrieved() -> date:
    """The date the release-cycle snapshot was fetched."""
    return date.fromisoformat(json.loads(_SNAPSHOT.read_text(encoding="utf-8"))["retrieved"])


def snapshot_is_stale(today: date) -> bool:
    """True when the scan date runs past the snapshot by more than :data:`_STALE_AFTER_DAYS`.

    A cycle the snapshot records as supported may have ended since, and its newest patch moved on,
    so a stale snapshot under-reports both detectors. The scan should refresh it; the verdicts
    are still given, with the snapshot date on the evidence."""
    return (today - snapshot_retrieved()).days > _STALE_AFTER_DAYS


def evaluate_banners(headers: dict[str, str], *, today: date) -> BannerResult:
    """Classify the banner headers of one received response against the snapshot on ``today``."""
    if snapshot_is_stale(today):
        log.warning("lifecycle_snapshot_stale", scan_date=today.isoformat())
    tokens = banner_tokens(headers)
    if not tokens:
        return BannerResult(state=BannerState.NO_BANNER)
    if any(_DISTRO.search(v) for k, v in headers.items() if k.lower() in _BANNER_HEADERS):
        return BannerResult(state=BannerState.UNCOVERED, tokens=tuple(tokens))  # see _DISTRO
    assessed: list[BannerToken] = []
    checks: set[CheckId] = set()
    uncovered = unplaced = _other_products(headers)  # software beside a covered one is unplaced too
    ended = False
    for token in tokens:
        entry = _cycle_for(token.product, token.version)
        if entry is None:
            uncovered = unplaced = True
            assessed.append(token)
            continue
        cycle, latest, eol = str(entry["cycle"]), str(entry["latest"]), entry["eol"]
        missed: str | None = None
        if _ended(eol, today):
            checks.add(CheckId.EOL_SOFTWARE_EXPOSED)
            ended = True
        elif len(_version_tuple(token.version)) <= len(_version_tuple(cycle)):
            uncovered = True  # the cycle alone (ServerTokens Minor): the patch level is unknown
        elif _version_tuple(token.version) < _version_tuple(latest):
            missed = _first_missed(entry, token.version)
            uncovered |= missed is None  # an undated patch: the patch window cannot be read
            if missed and (today - date.fromisoformat(missed)).days > PATCH_WINDOW_DAYS:
                checks.add(CheckId.OUTDATED_EXPOSED_SOFTWARE)
        assessed.append(
            BannerToken(token.header, token.product, token.version, cycle, latest, eol, missed)  # type: ignore[arg-type]
        )
    if checks:
        bare = _bare_products(headers)
        open_checks = [
            check
            for check, unknown in (
                (CheckId.OUTDATED_EXPOSED_SOFTWARE, uncovered or ended or bare),
                (CheckId.EOL_SOFTWARE_EXPOSED, unplaced or bare),
            )
            if unknown and check not in checks
        ]
        return BannerResult(
            checks=tuple(sorted(checks)),
            state=BannerState.READ,
            tokens=tuple(assessed),
            unread=tuple(open_checks),
        )
    if uncovered:
        # A token the snapshot cannot place leaves the read open: an unknown cycle is not current.
        return BannerResult(state=BannerState.UNCOVERED, tokens=tuple(assessed))
    if _bare_products(headers):
        # A covered product named without a version beside a current one: one of them is unknown.
        return BannerResult(state=BannerState.NO_BANNER, tokens=tuple(assessed))
    return BannerResult(state=BannerState.READ, tokens=tuple(assessed))


def banner_checks(probe: HttpProbe, *, today: date) -> list[CheckId]:
    """The banner detectors' verdict on one probe; nothing at all for an unreceived response."""
    if not response_received(probe):
        log.warning("banner_read_indeterminate", url=probe.url, status_code=probe.status_code)
        return []
    return list(evaluate_banners(probe.headers, today=today).checks)
