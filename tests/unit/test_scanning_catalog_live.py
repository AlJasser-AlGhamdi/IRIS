"""The LIVE_CHECKS registry must match what the inspector modules actually emit.

The toolkit's Appendix A live column is checked against LIVE_CHECKS by the number gate,
so this test is what keeps that column truthful when an inspector is added or removed.
"""

import re
from pathlib import Path

from p2c import scanning
from p2c.evaluation.harness import LIVE_INSPECTOR_CHECKS
from p2c.scanning.catalog import LIVE_CHECKS, CheckId

_INSPECTOR_MODULES = (
    "email_dns",
    "tls",
    "headers",
    "ports",
    "httpx_probe",
    "nuclei",
    "dns_sec",
    "mta_sts",
    "services",
    "web_paths",
    "banners",
    "fingerprints",
    "dns_axfr",
)


def test_live_checks_match_inspector_sources() -> None:
    src = Path(scanning.__file__).parent
    emitted: set[str] = set()
    for mod in _INSPECTOR_MODULES:
        text = (src / f"{mod}.py").read_text(encoding="utf-8")
        emitted |= set(re.findall(r"CheckId\.([A-Z_]+)", text))
    assert {c.name for c in LIVE_CHECKS} == emitted


def test_live_checks_are_catalog_members() -> None:
    assert set(CheckId) >= LIVE_CHECKS
    assert len(LIVE_CHECKS) == len(CheckId) == 32  # every detector has a live inspector


def test_the_implemented_only_slice_reads_the_same_live_set() -> None:
    """The evaluation's live set must be the catalog's, not a second copy of it.

    ``harness.LIVE_INSPECTOR_CHECKS`` drives ``_implemented_only``, which produces the toolkit's
    implemented-only figure. It used to be a hand-maintained duplicate of these same fifteen
    strings with nothing asserting the two agreed, so registering a new inspector here would have
    left the slice scoring the old control set while the write-up claimed the new count. It is
    now derived; this test is what stops anyone hand-listing it again.
    """
    assert {check.value for check in LIVE_CHECKS} == LIVE_INSPECTOR_CHECKS
