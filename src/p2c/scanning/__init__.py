"""Stage 3 — controlled active inspection (GATED by Stage 1).

CVSS-normalized, control-tagged Tier-1 findings from consented assets, unified
through nuclei. **Active scanning is impossible without a valid ownership
verification** (Phase-1 hard gate, no override — enforced in :class:`ScanEngine`).
Tool choices + the sslyze/checkdmarc/wafw00f substitutions are in ADR-0004.

:mod:`p2c.scanning.engine` is deliberately NOT imported here. ``ScanEngine`` is the
live-scan orchestrator and depends on the ownership-authorization package (``p2c.authz``),
carried back from ATLAS for the private field pilot (``p2c.pilot.runner``); an eager import
would drag it, httpx and dnspython into every ``p2c.scanning.catalog`` and
``p2c.mapping.rules`` import. The evaluation path never runs a live scan: findings come
from ``p2c.evaluation.synthetic.EvalCase.findings()``.
"""

from __future__ import annotations

from pathlib import Path

from p2c.scanning.banners import BannerResult, BannerState, banner_checks, evaluate_banners
from p2c.scanning.catalog import CATALOG, CheckId, CheckSpec, build_finding
from p2c.scanning.dns_axfr import AxfrResult, ZoneTransferInspector
from p2c.scanning.dns_sec import DnspythonResolver, DnssecInspector, DnssecResult, RecordResolver
from p2c.scanning.email_dns import (
    DKIM_SELECTORS,
    DnsReadIndeterminate,
    DnsRecordAbsent,
    EmailDnsInspector,
    EmailDnsResult,
)
from p2c.scanning.fingerprints import DdosInspector, DdosResult, waf_checks, waf_signature
from p2c.scanning.headers import analyze_security_headers
from p2c.scanning.httpx_probe import (
    HttpProbe,
    checks_for_probe,
    dev_environment_signature,
    parse_httpx,
    response_received,
)
from p2c.scanning.mta_sts import MtaStsInspector, MtaStsResult, MtaStsState
from p2c.scanning.nuclei import NucleiResult, NucleiRunner, parse_nuclei
from p2c.scanning.ports import classify_port, parse_naabu
from p2c.scanning.services import ServiceInspector, ServiceProbe, checks_for_service, identify_database
from p2c.scanning.signing import TemplateSigner, sign_bytes, verify_bytes
from p2c.scanning.tls import TlsInfo, TlsInspector, evaluate_tls
from p2c.scanning.web_paths import PathResult, PathState, WebPathInspector

TEMPLATES_DIR = Path(__file__).parent / "templates"

__all__ = [
    "CATALOG",
    "DKIM_SELECTORS",
    "TEMPLATES_DIR",
    "AxfrResult",
    "BannerResult",
    "BannerState",
    "CheckId",
    "CheckSpec",
    "DdosInspector",
    "DdosResult",
    "DnsReadIndeterminate",
    "DnsRecordAbsent",
    "DnspythonResolver",
    "DnssecInspector",
    "DnssecResult",
    "EmailDnsInspector",
    "EmailDnsResult",
    "HttpProbe",
    "MtaStsInspector",
    "MtaStsResult",
    "MtaStsState",
    "NucleiResult",
    "NucleiRunner",
    "PathResult",
    "PathState",
    "RecordResolver",
    "ServiceInspector",
    "ServiceProbe",
    "TemplateSigner",
    "TlsInfo",
    "TlsInspector",
    "WebPathInspector",
    "ZoneTransferInspector",
    "analyze_security_headers",
    "banner_checks",
    "build_finding",
    "checks_for_probe",
    "checks_for_service",
    "classify_port",
    "dev_environment_signature",
    "evaluate_banners",
    "evaluate_tls",
    "identify_database",
    "parse_httpx",
    "parse_naabu",
    "parse_nuclei",
    "response_received",
    "sign_bytes",
    "verify_bytes",
    "waf_checks",
    "waf_signature",
]
