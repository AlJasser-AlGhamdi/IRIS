"""Contract tests for the version banner detectors (outdated and end-of-life software).

The snapshot is the committed one (data/lifecycle.json, retrieved 2026-10-14), so the expected
verdicts are facts about that file: nginx 1.30 supported with 1.30.5 newest (1.30.2 released
2026-05-22, 1.30.5 on 2026-09-15), Apache 2.2 ended in 2017, PHP 8.1 ended 2025-12-31, PHP 8.2 ends
2026-12-31.
"""

from __future__ import annotations

from datetime import date

import pytest

from p2c.scanning.banners import BannerState, banner_checks, evaluate_banners, lifecycle_snapshot
from p2c.scanning.catalog import CheckId
from p2c.scanning.httpx_probe import HttpProbe

SCAN_DAY = date(2026, 10, 14)


def _probe(headers: dict[str, str], status: int = 200) -> HttpProbe:
    return HttpProbe(
        url="https://x.example/", host="x.example", scheme="https", status_code=status, headers=headers
    )


def test_snapshot_is_the_dated_endoflife_export() -> None:
    snap = lifecycle_snapshot()
    assert set(snap) == {"nginx", "apache-http-server", "php"}
    assert any(e["cycle"] == "1.30" and e["latest"] == "1.30.5" for e in snap["nginx"])


def test_current_version_of_a_supported_cycle_is_clean() -> None:
    result = evaluate_banners({"Server": "nginx/1.30.5"}, today=SCAN_DAY)
    assert result.state is BannerState.READ and result.checks == ()


def test_older_patch_of_a_supported_cycle_is_outdated() -> None:
    # 1.30.2, the first patch 1.30.1 lacks, came out 145 days before the scan: past three months
    result = evaluate_banners({"Server": "nginx/1.30.1"}, today=SCAN_DAY)
    assert result.checks == (CheckId.OUTDATED_EXPOSED_SOFTWARE,)
    assert result.tokens[0].missed == "2026-05-22"


def test_a_patch_missed_inside_three_months_is_not_a_finding() -> None:
    # 1.30.5 came out 29 days before the scan, inside the NCA template's three-month cycle
    result = evaluate_banners({"Server": "nginx/1.30.4"}, today=SCAN_DAY)
    assert result.state is BannerState.READ and result.checks == ()
    assert evaluate_banners({"Server": "nginx/1.30.4"}, today=date(2026, 12, 16)).checks == ()  # 92 days
    assert evaluate_banners({"Server": "nginx/1.30.4"}, today=date(2026, 12, 17)).checks == (
        CheckId.OUTDATED_EXPOSED_SOFTWARE,
    )


def test_a_missed_patch_without_a_date_leaves_outdated_unread(monkeypatch: pytest.MonkeyPatch) -> None:
    undated = {"nginx": [{"cycle": "1.30", "latest": "1.30.5", "eol": False, "releaseDate": "2026-04-14"}]}
    monkeypatch.setattr("p2c.scanning.banners.lifecycle_snapshot", lambda: undated)
    result = evaluate_banners({"Server": "nginx/1.30.1"}, today=SCAN_DAY)
    assert result.state is BannerState.UNCOVERED and result.checks == ()


def test_ended_cycle_is_end_of_life_and_not_also_outdated() -> None:
    result = evaluate_banners({"Server": "Apache/2.2.15"}, today=SCAN_DAY)
    assert result.checks == (CheckId.EOL_SOFTWARE_EXPOSED,)


@pytest.mark.parametrize(
    "banner",
    [
        "nginx/1.24.0 (Ubuntu)",
        "Apache/2.4.58 (Ubuntu)",
        "Apache/2.4.37 (Red Hat Enterprise Linux)",
        "Apache/2.2.15 (CentOS)",
        "nginx/1.22.1-deb12u1",
    ],
)
def test_a_distribution_build_leaves_both_banner_reads_open(banner: str) -> None:
    # A vendor backports fixes under the upstream version: patch level and support are not readable.
    result = evaluate_banners({"Server": banner}, today=SCAN_DAY)
    assert result.state is BannerState.UNCOVERED and result.checks == ()


def test_x_powered_by_is_read_too() -> None:
    result = evaluate_banners({"Server": "nginx", "X-Powered-By": "PHP/8.1.2"}, today=SCAN_DAY)
    assert result.checks == (CheckId.EOL_SOFTWARE_EXPOSED,)


def test_end_of_life_follows_the_scan_date() -> None:
    headers = {"X-Powered-By": "PHP/8.2.34"}
    assert evaluate_banners(headers, today=SCAN_DAY).checks == ()
    assert evaluate_banners(headers, today=date(2027, 1, 1)).checks == (CheckId.EOL_SOFTWARE_EXPOSED,)


def test_versionless_banner_is_unread_not_current() -> None:
    # The hardened form. Unknown is never clean: suppression leaves the read open.
    result = evaluate_banners({"Server": "nginx"}, today=SCAN_DAY)
    assert result.state is BannerState.NO_BANNER and result.checks == ()


def test_cycle_outside_the_snapshot_is_uncovered() -> None:
    result = evaluate_banners({"Server": "nginx/0.1.0"}, today=SCAN_DAY)
    assert result.state is BannerState.UNCOVERED and result.checks == ()


def test_uncovered_products_are_not_read() -> None:
    assert evaluate_banners({"Server": "Microsoft-IIS/8.5"}, today=SCAN_DAY).state is BannerState.NO_BANNER


def test_a_spoofed_current_version_reads_clean() -> None:
    # Documented limit: a banner is the server's own claim (evasion 2, string spoofing).
    assert evaluate_banners({"Server": "nginx/1.30.5"}, today=SCAN_DAY).checks == ()


def test_unreceived_response_raises_nothing() -> None:
    assert banner_checks(_probe({"Server": "Apache/2.2.15"}, status=0), today=SCAN_DAY) == []
    assert banner_checks(_probe({"Server": "Apache/2.2.15"}), today=SCAN_DAY) == [
        CheckId.EOL_SOFTWARE_EXPOSED
    ]


def test_a_hostile_banner_cannot_break_the_parser() -> None:
    # Attacker-controlled text: a version with thousands of digits is simply not a token.
    result = evaluate_banners({"Server": "nginx/" + "9" * 5000 + ".1"}, today=SCAN_DAY)
    assert result.checks == () and result.state is BannerState.NO_BANNER


# --- review fixes (2026-10-14) ----------------------------------------------------------------


def test_a_bare_product_beside_a_versioned_one_leaves_the_read_open() -> None:
    # Two Server headers joined by the client: the bare one is a product whose version is unknown.
    result = evaluate_banners({"Server": "nginx, nginx/1.30.5"}, today=SCAN_DAY)
    assert result.state is BannerState.NO_BANNER and result.checks == ()
    mixed = evaluate_banners({"Server": "nginx", "X-Powered-By": "PHP/8.4.26"}, today=SCAN_DAY)
    assert mixed.state is BannerState.NO_BANNER and mixed.checks == ()


def test_a_positive_still_fires_beside_a_bare_product() -> None:
    result = evaluate_banners({"Server": "nginx", "X-Powered-By": "PHP/8.1.2"}, today=SCAN_DAY)
    assert result.checks == (CheckId.EOL_SOFTWARE_EXPOSED,)


def test_a_cycle_only_version_cannot_be_outdated() -> None:
    # ServerTokens Minor: "Apache/2.4" names the cycle, not the patch level.
    result = evaluate_banners({"Server": "Apache/2.4"}, today=SCAN_DAY)
    assert result.state is BannerState.UNCOVERED and result.checks == ()
    # An ended cycle is still visible from the cycle alone.
    cycle_only = evaluate_banners({"Server": "Apache/2.2"}, today=SCAN_DAY)
    assert cycle_only.checks == (CheckId.EOL_SOFTWARE_EXPOSED,)
    assert cycle_only.unread == (CheckId.OUTDATED_EXPOSED_SOFTWARE,)  # nor is the patch level known


def test_a_scan_long_after_the_snapshot_is_flagged_stale() -> None:
    from p2c.scanning.banners import snapshot_is_stale  # noqa: PLC0415

    assert not snapshot_is_stale(SCAN_DAY)
    assert snapshot_is_stale(date(2027, 10, 14))


def test_an_end_of_life_banner_leaves_outdated_unread_not_clean() -> None:
    # Pilot review round 7: "outdated" is clean only when every covered product is the newest patch of a
    # supported cycle, which an end-of-life product rules out either way.
    result = evaluate_banners({"Server": "Apache/2.2.15"}, today=SCAN_DAY)
    assert result.checks == (CheckId.EOL_SOFTWARE_EXPOSED,)
    assert result.unread == (CheckId.OUTDATED_EXPOSED_SOFTWARE,)


def test_a_finding_beside_an_unplaced_product_leaves_the_other_detector_unread() -> None:
    headers = {"Server": "Apache/2.2.15", "X-Powered-By": "PHP/9.9.1"}
    result = evaluate_banners(headers, today=SCAN_DAY)
    assert CheckId.EOL_SOFTWARE_EXPOSED in result.checks
    assert result.unread == (CheckId.OUTDATED_EXPOSED_SOFTWARE,)


@pytest.mark.parametrize("server", ["LiteSpeed", "Microsoft-IIS", "openresty", "cloudflare"])
def test_an_unversioned_server_the_snapshot_cannot_place_leaves_both_reads_open(server: str) -> None:
    # Pilot review round 16: a current PHP beside a web server of unknown version is not current.
    result = evaluate_banners({"Server": server, "X-Powered-By": "PHP/8.3.35"}, today=SCAN_DAY)
    assert result.state is BannerState.UNCOVERED and result.checks == ()


def test_a_covered_product_with_no_server_header_leaves_the_reads_open() -> None:
    assert evaluate_banners({"X-Powered-By": "PHP/8.3.35"}, today=SCAN_DAY).state is BannerState.UNCOVERED
    both = {"Server": "nginx/1.30.5", "X-Powered-By": "PHP/8.3.35"}
    assert evaluate_banners(both, today=SCAN_DAY).state is BannerState.READ  # both placed and current
