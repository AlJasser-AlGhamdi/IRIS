"""Contract tests for the DNSSEC and MTA-STS detectors.

The resolver is a fixture, and the dnspython-shaped exceptions are declared locally for the same
reason ``test_scanning_sources.py`` declares them: the inspectors classify by class-name lineage,
so these exercise the real classification path without dnspython being in the test's import graph.

The case that matters most here is ``SERVFAIL``. A validating resolver answers ``SERVFAIL`` for a
zone that is signed but whose chain does not verify. Calling that "DNSSEC missing" would be wrong
twice over, so it must resolve to silence, not to a finding.
"""

from __future__ import annotations

import httpx
import pytest

from p2c.scanning.catalog import CheckId
from p2c.scanning.dns_sec import DnssecInspector
from p2c.scanning.mta_sts import MtaStsInspector, MtaStsState, parse_policy
from p2c.sovereignty.egress_guard import EgressBlocked

DOMAIN = "example.com"


class NXDOMAIN(Exception):
    """Definitive: the name does not exist."""


class NoAnswer(Exception):
    """Definitive: NOERROR with no record of that type in the answer."""


class Timeout(Exception):
    """Indeterminate: the query timed out."""


class NoNameservers(Exception):
    """Indeterminate: every nameserver failed. This is how dnspython surfaces SERVFAIL."""


class FakeResolver:
    """Serves recorded records keyed by ``(name, rdtype)``; unknown keys answer definitively empty."""

    def __init__(
        self,
        records: dict[tuple[str, str], list[str]] | None = None,
        *,
        failures: dict[tuple[str, str], Exception] | None = None,
    ) -> None:
        self._records = records or {}
        self._failures = failures or {}

    def resolve(self, name: str, rdtype: str) -> list[str]:
        key = (name, rdtype)
        if key in self._failures:
            raise self._failures[key]
        if key not in self._records:
            raise NoAnswer(f"{name}/{rdtype}")
        return self._records[key]


# --- dnssec_missing ------------------------------------------------------------------------


def test_an_unsigned_zone_is_reported() -> None:
    result = DnssecInspector(FakeResolver()).inspect_detailed(DOMAIN)
    assert result.checks == (CheckId.DNSSEC_MISSING,)
    assert result.fully_read


def test_a_ds_record_means_signed() -> None:
    resolver = FakeResolver({(DOMAIN, "DS"): ["2371 13 2 abcd"]})
    assert DnssecInspector(resolver).inspect(DOMAIN) == []


def test_a_dnskey_alone_means_signed() -> None:
    """Mid-rollout: the zone publishes keys before the parent publishes the DS."""
    resolver = FakeResolver({(DOMAIN, "DNSKEY"): ["257 3 13 mdsw..."]})
    assert DnssecInspector(resolver).inspect(DOMAIN) == []


def test_servfail_is_not_absence() -> None:
    """A validating resolver answers SERVFAIL for a bogus zone: signed, but broken. Not missing."""
    failures = {(DOMAIN, "DS"): NoNameservers(DOMAIN), (DOMAIN, "DNSKEY"): NoNameservers(DOMAIN)}
    resolver = FakeResolver(failures=failures)
    result = DnssecInspector(resolver).inspect_detailed(DOMAIN)
    assert result.checks == ()
    assert not result.fully_read


def test_a_timeout_is_not_absence() -> None:
    resolver = FakeResolver(failures={(DOMAIN, "DS"): Timeout(DOMAIN), (DOMAIN, "DNSKEY"): Timeout(DOMAIN)})
    assert DnssecInspector(resolver).inspect(DOMAIN) == []


def test_one_unread_lookup_blocks_the_absence_claim() -> None:
    """DS is definitively absent, but DNSKEY did not resolve, so the zone is not provably unsigned."""
    resolver = FakeResolver(failures={(DOMAIN, "DNSKEY"): Timeout(DOMAIN)})
    result = DnssecInspector(resolver).inspect_detailed(DOMAIN)
    assert result.checks == ()
    assert result.ds.resolved and not result.dnskey.resolved


def test_nxdomain_is_a_definitive_absence() -> None:
    resolver = FakeResolver(failures={(DOMAIN, "DS"): NXDOMAIN(DOMAIN), (DOMAIN, "DNSKEY"): NXDOMAIN(DOMAIN)})
    assert DnssecInspector(resolver).inspect(DOMAIN) == [CheckId.DNSSEC_MISSING]


def test_an_egress_block_propagates_and_is_never_silent() -> None:
    resolver = FakeResolver(failures={(DOMAIN, "DS"): EgressBlocked("blocked")})
    with pytest.raises(EgressBlocked):
        DnssecInspector(resolver).inspect(DOMAIN)


# --- mta_sts_missing -----------------------------------------------------------------------

_RECORD = {("_mta-sts.example.com", "TXT"): ["v=STSv1; id=20260830T000000"]}
_VALID_POLICY = "version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 604800\n"


def _client(handler: object) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))  # type: ignore[arg-type]


def test_no_record_is_a_definitive_absence() -> None:
    result = MtaStsInspector(FakeResolver()).inspect_detailed(DOMAIN)
    assert result.checks == (CheckId.MTA_STS_MISSING,)
    assert result.state is MtaStsState.RECORD_ABSENT


def test_a_record_that_announces_no_policy_is_also_absence() -> None:
    """RFC 8461: a syntactically invalid record means the sender must assume no policy."""
    resolver = FakeResolver({("_mta-sts.example.com", "TXT"): ["v=spf1 -all"]})
    result = MtaStsInspector(resolver).inspect_detailed(DOMAIN)
    assert result.checks == (CheckId.MTA_STS_MISSING,)
    assert result.state is MtaStsState.RECORD_MALFORMED


def test_a_valid_record_and_policy_raise_nothing() -> None:
    client = _client(lambda request: httpx.Response(200, text=_VALID_POLICY))
    result = MtaStsInspector(FakeResolver(_RECORD), client).inspect_detailed(DOMAIN)
    assert result.checks == ()
    assert result.state is MtaStsState.POLICY_VALID


def test_an_unreachable_policy_endpoint_raises_nothing() -> None:
    """The domain claims a policy exists; a failed fetch cannot tell misconfiguration from downtime."""
    client = _client(lambda request: httpx.Response(404))
    result = MtaStsInspector(FakeResolver(_RECORD), client).inspect_detailed(DOMAIN)
    assert result.checks == ()
    assert result.state is MtaStsState.POLICY_UNREACHABLE


def test_a_malformed_policy_raises_nothing_and_keeps_the_body() -> None:
    client = _client(lambda request: httpx.Response(200, text="version: STSv1\nmode: enforce\n"))
    result = MtaStsInspector(FakeResolver(_RECORD), client).inspect_detailed(DOMAIN)
    assert result.checks == ()
    assert result.state is MtaStsState.POLICY_UNREACHABLE
    assert result.policy == "version: STSv1\nmode: enforce\n"


def test_a_transport_failure_on_the_policy_raises_nothing() -> None:
    def _boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    result = MtaStsInspector(FakeResolver(_RECORD), _client(_boom)).inspect_detailed(DOMAIN)
    assert result.checks == ()
    assert result.state is MtaStsState.POLICY_UNREACHABLE


def test_an_unread_txt_lookup_raises_nothing() -> None:
    resolver = FakeResolver(failures={("_mta-sts.example.com", "TXT"): Timeout(DOMAIN)})
    result = MtaStsInspector(resolver).inspect_detailed(DOMAIN)
    assert result.checks == ()
    assert result.state is MtaStsState.UNREAD


def test_the_mta_sts_egress_block_propagates() -> None:
    resolver = FakeResolver(failures={("_mta-sts.example.com", "TXT"): EgressBlocked("blocked")})
    with pytest.raises(EgressBlocked):
        MtaStsInspector(resolver).inspect(DOMAIN)


@pytest.mark.parametrize(
    ("body", "valid"),
    [
        (_VALID_POLICY, True),
        ("version: STSv1\nmode: none\nmax_age: 604800\n", True),  # mx is not required in mode none
        ("version: STSv1\nmode: enforce\nmax_age: 604800\n", False),  # mx required otherwise
        ("version: STSv2\nmode: enforce\nmx: m\nmax_age: 1\n", False),
        ("version: STSv1\nmode: sometimes\nmx: m\nmax_age: 1\n", False),
        ("version: STSv1\nmode: enforce\nmx: m\nmax_age: soon\n", False),
        ("", False),
    ],
)
def test_policy_parsing_against_the_rfc_fields(body: str, valid: bool) -> None:
    assert parse_policy(body) is valid


def test_two_records_are_an_absent_policy() -> None:
    """RFC 8461 section 3.1: if the number of records is not one, assume no policy."""
    resolver = FakeResolver({("_mta-sts.example.com", "TXT"): ["v=STSv1; id=a", "v=STSv1; id=b"]})
    result = MtaStsInspector(resolver).inspect_detailed(DOMAIN)
    assert result.checks == (CheckId.MTA_STS_MISSING,)
    assert result.state is MtaStsState.RECORD_MALFORMED


def test_a_policy_that_enforces_nothing_is_a_finding() -> None:
    """``mode: none`` parses correctly and asks senders to enforce nothing, which is the row."""
    body = "version: STSv1\nmode: none\nmax_age: 604800\n"
    client = _client(lambda request: httpx.Response(200, text=body))
    result = MtaStsInspector(FakeResolver(_RECORD), client).inspect_detailed(DOMAIN)
    assert result.checks == (CheckId.MTA_STS_MISSING,)
    assert result.state is MtaStsState.POLICY_NOT_ENFORCING


def test_testing_mode_enforces_nothing_and_is_a_finding() -> None:
    # RFC 8461: under mode testing a sender delivers even when TLS fails, so inbound TLS is not enforced.
    body = "version: STSv1\nmode: testing\nmx: mail.example.com\nmax_age: 604800\n"
    client = _client(lambda request: httpx.Response(200, text=body))
    result = MtaStsInspector(FakeResolver(_RECORD), client).inspect_detailed(DOMAIN)
    assert result.checks == (CheckId.MTA_STS_MISSING,)


def test_a_policy_past_the_size_cap_is_unread_not_parsed() -> None:
    # RFC 8461 section 3.3 asks senders to cap the policy body; a body past 64 KiB is not read on.
    oversized = "version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 86400\n" + "#" * 70_000
    client = _client(lambda request: httpx.Response(200, text=oversized))
    result = MtaStsInspector(FakeResolver(_RECORD), client).inspect_detailed(DOMAIN)
    assert result.state is MtaStsState.POLICY_UNREACHABLE and result.checks == ()


def test_a_record_in_presentation_form_is_read_as_its_text() -> None:
    # A generic resolver returns TXT as dnspython's to_text(): quoted, split into strings. Read raw,
    # that never begins "v=STSv1" and a valid policy would be a false finding (pilot review round 7).
    quoted = FakeResolver({("_mta-sts.example.com", "TXT"): ['"v=STSv1; " "id=20261015"']})
    client = _client(lambda request: httpx.Response(200, text=_VALID_POLICY))
    result = MtaStsInspector(quoted, client).inspect_detailed(DOMAIN)
    assert result.checks == () and result.state is MtaStsState.POLICY_VALID


def test_an_unrelated_txt_beside_the_record_is_discarded_as_the_rfc_says() -> None:
    other = FakeResolver({("_mta-sts.example.com", "TXT"): ["google-site-verification=x", "v=STSv1; id=1"]})
    client = _client(lambda request: httpx.Response(200, text=_VALID_POLICY))
    assert MtaStsInspector(other, client).inspect_detailed(DOMAIN).state is MtaStsState.POLICY_VALID
