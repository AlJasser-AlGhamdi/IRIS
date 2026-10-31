"""MTA-STS inspection (Stage 3, Tier-1): is an SMTP TLS policy published? (RFC 8461)

**Detector contract, ``mta_sts_missing``.**

*Observable*
    The TXT record at ``_mta-sts.<domain>``, and, when that record announces a policy, the policy
    document at ``https://mta-sts.<domain>/.well-known/mta-sts.txt``.

*Naming*
    The detector fires on a published ``mode: none`` or ``mode: testing`` policy as well as on an
    absent one, so its
    identifier reads more narrowly than its behaviour. The identifier is frozen: it keys the
    recorded RQ2 baseline predictions, and the row's title is the exact text those models were
    shown. What defines the category is the title's parenthetical, "no enforced inbound TLS",
    which a ``mode: none`` policy satisfies, and so does ``mode: testing``, under which RFC 8461 has
    senders deliver even when TLS fails. ``dmarc_missing_or_none`` treats ``p=none``
    identically and is named for it, which is the convention this row would follow if its
    identifier were not already recorded.

*Positive*
    The TXT read completed and either no record is published, or the published record does not
    announce a policy (no ``v=STSv1``). RFC 8461 is explicit that a sender facing either state
    "MUST assume the recipient domain does not have an available MTA-STS Policy", so both are
    definitive reads of an absent policy, not guesses.

*Negative*
    A ``v=STSv1`` record is published and the policy document parses with the fields the RFC
    requires (``version``, ``mode``, ``max_age`` and ``mx``) **and** declares ``mode: enforce``.
    ``mode: none`` and ``mode: testing`` parse correctly and are still findings: the catalogue row
    is "MTA-STS policy absent (no enforced inbound TLS)", and a policy under which senders deliver
    whatever the TLS outcome is a definitive read of exactly that state.

*Inconclusive, and it raises nothing*
    The TXT read did not complete; or the record announces a policy and the policy endpoint could
    not be fetched or did not parse. The last case is deliberate. The domain has published a
    claim that a policy exists, and a fetch failure cannot distinguish a misconfiguration from an
    endpoint that is momentarily down or is refusing this particular client. The detector reports
    the state and stays silent, exactly as an unread DNS record does.

*Evidence retained*
    Which of the four states was observed, and the policy body when one was fetched, on
    :class:`MtaStsResult`.

*Test oracle*
    Fixture resolvers and ``respx`` for the policy endpoint in the unit tests; a local policy host
    in the integration matrix.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass
from enum import StrEnum

import httpx
import structlog

from p2c.scanning.catalog import CheckId
from p2c.scanning.dns_sec import RecordResolver, _is_definitive_absence
from p2c.sovereignty.egress_guard import caused_by_egress_block

log = structlog.get_logger("p2c.scanning.mta_sts")

_POLICY_URL = "https://mta-sts.{domain}/.well-known/mta-sts.txt"
_REQUIRED_FIELDS = ("version", "mode", "max_age")
_MODES = frozenset({"enforce", "testing", "none"})
# The mode that has a sender refuse delivery without TLS. ``none`` and ``testing`` are well-formed
# and enforce nothing, so they read as an absent policy for this control, not a compliant one.
_ENFORCING_MODES = frozenset({"enforce"})
_HTTP_OK = 200
_MAX_POLICY_BYTES = 65_536  # RFC 8461, section 3.3: senders SHOULD cap the policy body; 64 KiB
_MAX_POLICY_SECONDS = 30.0  # a server that drips bytes cannot hold the fetch open longer than this


def _get_capped(client: httpx.Client, url: str) -> tuple[int, str] | None:
    """The policy response as (status, text), read up to the cap; ``None`` when it runs past it. The
    body is asked for uncompressed, and the whole fetch is given :data:`_MAX_POLICY_SECONDS` (checked
    between parts of the body)."""
    deadline = time.monotonic() + _MAX_POLICY_SECONDS
    with client.stream("GET", url, headers={"Accept-Encoding": "identity"}) as response:
        body = bytearray()
        for chunk in response.iter_bytes():
            body.extend(chunk)
            if len(body) > _MAX_POLICY_BYTES:
                return None
            if time.monotonic() > deadline:
                raise httpx.ReadTimeout(f"the policy took longer than {_MAX_POLICY_SECONDS:.0f} seconds")
        return response.status_code, body.decode("utf-8", "replace")


class MtaStsState(StrEnum):
    """The four states RFC 8461 distinguishes, kept apart rather than collapsed into a bool."""

    RECORD_ABSENT = "record_absent"
    RECORD_MALFORMED = "record_malformed"
    POLICY_NOT_ENFORCING = "policy_not_enforcing"
    POLICY_UNREACHABLE = "policy_unreachable"
    POLICY_VALID = "policy_valid"
    UNREAD = "unread"


@dataclass(frozen=True)
class MtaStsResult:
    checks: tuple[CheckId, ...] = ()
    state: MtaStsState = MtaStsState.UNREAD
    policy: str | None = None


_STS_ID = re.compile(r"(?:^|;)\s*id=[A-Za-z0-9]{1,32}\s*(?:;|$)")


def _announces_policy(records: tuple[str, ...]) -> bool:
    """Exactly one record that begins ``v=STSv1``, and it carries the ``id`` field.

    RFC 8461 section 3.1: records that do not begin with "v=STSv1;" are discarded, and "if the number
    of resulting records is not one, or if the resulting record is syntactically invalid, senders MUST
    assume the recipient domain does not have an available MTA-STS Policy". Two such records is
    therefore an absent policy, not a matched one, and so is a record without the ``id`` field the
    record's syntax requires (section 3.1).
    """
    sts = [r for r in records if r.strip().lower().startswith("v=stsv1")]
    return len(sts) == 1 and bool(_STS_ID.search(sts[0]))


_QUOTED = re.compile(r'"((?:[^"\\]|\\.)*)"')


def _txt_text(record: str) -> str:
    """A TXT record as the text it carries. A generic resolver returns presentation form, with the
    quotes and the seams between strings (``"v=STSv1; " "id=1"``), which would never begin ``v=``."""
    parts = _QUOTED.findall(record)
    return "".join(parts) if parts and record.lstrip().startswith('"') else record


def policy_mode(body: str) -> str | None:
    """The declared mode of a well-formed policy, or ``None`` if the body is not one."""
    fields: dict[str, list[str]] = {}
    for line in body.splitlines():
        key, sep, value = line.partition(":")
        if sep:
            fields.setdefault(key.strip().lower(), []).append(value.strip())
    if any(field not in fields for field in _REQUIRED_FIELDS):
        return None
    if fields["version"][0].lower() != "stsv1":
        return None
    mode = fields["mode"][0].lower()
    if mode not in _MODES or not fields["max_age"][0].isdigit():
        return None
    if mode != "none" and not fields.get("mx"):
        return None
    return mode


def parse_policy(body: str) -> bool:
    """True if ``body`` is a well-formed MTA-STS policy (RFC 8461 section 3.2)."""
    fields: dict[str, list[str]] = {}
    for line in body.splitlines():
        key, sep, value = line.partition(":")
        if sep:
            fields.setdefault(key.strip().lower(), []).append(value.strip())
    if any(field not in fields for field in _REQUIRED_FIELDS):
        return False
    if fields["version"][0].lower() != "stsv1":
        return False
    mode = fields["mode"][0].lower()
    if mode not in _MODES:
        return False
    if not fields["max_age"][0].isdigit():
        return False
    return mode == "none" or bool(fields.get("mx"))


class MtaStsInspector:
    """Reads the MTA-STS record and, when it announces a policy, the policy itself."""

    def __init__(self, resolver: RecordResolver, client: httpx.Client | None = None) -> None:
        self._resolver = resolver
        self._client = client

    def inspect(self, domain: str) -> list[CheckId]:
        return list(self.inspect_detailed(domain).checks)

    def inspect_detailed(self, domain: str) -> MtaStsResult:
        name = f"_mta-sts.{domain}"
        try:
            # The record's own strings where the resolver offers them, else its presentation form unquoted.
            read = getattr(self._resolver, "resolve_txt", None)
            raw = read(name) if read else [_txt_text(r) for r in self._resolver.resolve(name, "TXT")]
            records = tuple(raw)
        except Exception as exc:
            if caused_by_egress_block(exc):
                raise
            if not _is_definitive_absence(exc):
                log.warning("mta_sts_read_indeterminate", domain=domain, error=type(exc).__name__)
                return MtaStsResult(state=MtaStsState.UNREAD)
            records = ()
        if not records:
            return MtaStsResult(checks=(CheckId.MTA_STS_MISSING,), state=MtaStsState.RECORD_ABSENT)
        if not _announces_policy(records):
            return MtaStsResult(checks=(CheckId.MTA_STS_MISSING,), state=MtaStsState.RECORD_MALFORMED)
        return self._fetch_policy(domain)

    def _fetch_policy(self, domain: str) -> MtaStsResult:
        url = _POLICY_URL.format(domain=domain)
        try:
            if self._client is not None:
                fetched = _get_capped(self._client, url)
            else:
                with httpx.Client(timeout=10.0, follow_redirects=False, trust_env=False) as client:
                    fetched = _get_capped(client, url)
        except Exception as exc:
            if caused_by_egress_block(exc):
                raise
            log.warning("mta_sts_policy_unreachable", domain=domain, error=type(exc).__name__)
            return MtaStsResult(state=MtaStsState.POLICY_UNREACHABLE)
        if fetched is None:
            log.warning("mta_sts_policy_oversized", domain=domain, limit=_MAX_POLICY_BYTES)
            return MtaStsResult(state=MtaStsState.POLICY_UNREACHABLE)
        status, text = fetched
        if status != _HTTP_OK:
            return MtaStsResult(state=MtaStsState.POLICY_UNREACHABLE, policy=text)
        mode = policy_mode(text)
        if mode is None:
            return MtaStsResult(state=MtaStsState.POLICY_UNREACHABLE, policy=text)
        if mode not in _ENFORCING_MODES:
            return MtaStsResult(
                checks=(CheckId.MTA_STS_MISSING,),
                state=MtaStsState.POLICY_NOT_ENFORCING,
                policy=text,
            )
        return MtaStsResult(state=MtaStsState.POLICY_VALID, policy=text)
