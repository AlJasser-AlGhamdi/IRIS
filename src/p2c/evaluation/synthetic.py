"""Seeded synthetic-SME-profile generator with a scanner detection model (Stage 8).

Generates the toolkit's evaluation corpus: N SME profiles, each carrying two distinct
layers that the harness keeps separate.

1. **True latent state** (``true_injected``): the issues an organization actually has on
   its external surface. This is the answer key. It is derived from the deterministic
   mapping RULES, which encode the ECC/NCNICC taxonomy, and it is *never* handed to the
   pipeline (leakage guard, following Arp et al. on label leakage).

2. **Observed state** (``injected``): what a real external scanner reports for that
   organization, obtained by pushing the true state through a documented detection model.
   A scanner has finite sensitivity (it misses issues it cannot confirm from outside) and a
   non-zero false-alarm rate (it reports issues that are not really there). The observed
   state, not the true state, drives the findings the pipeline receives.

The estates are deliberately complex and role-aware: each profile is an apex domain plus a
band-conditioned set of sector-flavored subdomains (a small firm carries apex + 1..4 subdomains,
a medium firm apex + 3..8; SOURCES.md §2), and issues are placed by host role. Web hardening,
TLS, ports, software, end-of-life exposure, and login-panel exposure are per host;
development and staging hosts additionally risk a reachable non-production environment;
email authentication, DNS security, and DDoS-mitigation posture are domain-level and are
placed once at the apex. Of the 32 externally observable checks, 17 map to the 11 Tier-1
subcontrols the taxonomy marks observable (several observations evidence more than one control);
the other 15 are hardening findings recorded against no control.

Each profile also carries a third layer the scan never touches: **off-surface evidence**, the
Tier-2 internal assessments and Tier-3 declarations a firm holds on controls outside the 11
externally checkable subcontrols (governance, personnel, physical, backup). It is what makes the
documented score a different number from the assessed one, and it is drawn last so that adding it
left every other draw, and therefore every recovery and contradiction number, untouched.

Splitting truth from observation lets the harness report two honest and different numbers.
Given what the scanner *observed*, the mapper reproduces the taxonomy-correct controls
exactly (mapping integrity, correct by construction). Against what is *truly* present, the
end-to-end pipeline recovers the control state only imperfectly, because the scanner's
sensing is imperfect.

The detection rates are modelling assumptions grounded in documented external-scanning
limits (banner-based version detection is unreliable; WAF and DDoS mitigation cannot be
confirmed from outside; DKIM probing is selector limited; passive port data has currency
limits; sensitive-file probing checks only a fixed path list). They are recorded in
docs/threats-to-validity.md, not measured ground.

Everything is deterministic: profile i is built from ``Random(seed + i)`` over fixed pools
and the detection draws come from the same stream, so ``make reproduce`` regenerates
byte-identical cases.
"""

from __future__ import annotations

import hashlib
import json
import random
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from pathlib import Path

from p2c.config import get_settings
from p2c.discovery.synthetic import SyntheticAsset, SyntheticProfile
from p2c.mapping.catalog import load_default_index
from p2c.mapping.rules import RULES
from p2c.scanning.catalog import CheckId, build_finding
from p2c.schemas.enums import AssetType
from p2c.schemas.models import Attestation, Finding

# A fixed clock for the generated corpus so findings/timestamps are byte-reproducible.
EVAL_EPOCH = datetime(2026, 1, 1, tzinfo=UTC)
_ATTESTATION_VALID_UNTIL = EVAL_EPOCH + timedelta(days=365)

# CheckId categories — the axes threat-intel weights act on. The union must cover every
# check in the catalog (the expert key is built from all of them).
CATEGORIES: dict[str, tuple[CheckId, ...]] = {
    "web_headers": (
        CheckId.MISSING_HSTS,
        CheckId.MISSING_CSP,
        CheckId.MISSING_X_FRAME_OPTIONS,
        CheckId.MISSING_X_CONTENT_TYPE_OPTIONS,
        CheckId.MISSING_REFERRER_POLICY,
        CheckId.NO_HTTPS_REDIRECT,
        CheckId.MISSING_PERMISSIONS_POLICY,
        CheckId.INSECURE_COOKIE,
        CheckId.DIRECTORY_LISTING_ENABLED,
        CheckId.EXPOSED_SENSITIVE_FILE,
    ),
    "waf": (CheckId.WAF_ABSENT,),
    "tls": (
        CheckId.LEGACY_TLS_VERSION,
        CheckId.WEAK_TLS_CIPHER,
        CheckId.EXPIRED_CERTIFICATE,
        CheckId.SELF_SIGNED_CERTIFICATE,
        CheckId.WEAK_CERTIFICATE_KEY,
    ),
    "ports": (
        CheckId.EXPOSED_INTERNAL_PORT,
        CheckId.EXPOSED_MANAGEMENT_PORT,
        CheckId.HIGH_RISK_PORT_OPEN,
        CheckId.EXPOSED_DATABASE_PORT,
        CheckId.EXPOSED_PRINTER_SERVICE,
    ),
    "software": (CheckId.OUTDATED_EXPOSED_SOFTWARE,),
    "eol": (CheckId.EOL_SOFTWARE_EXPOSED,),
    "auth": (CheckId.EXPOSED_LOGIN_PANEL,),
    "dev_env": (CheckId.EXPOSED_DEV_ENVIRONMENT,),
    "email": (
        CheckId.SPF_MISSING,
        CheckId.DMARC_MISSING_OR_NONE,
        CheckId.DKIM_MISSING,
        CheckId.MTA_STS_MISSING,
    ),
    "dns": (CheckId.DNSSEC_MISSING, CheckId.DNS_ZONE_TRANSFER_OPEN),
    "ddos": (CheckId.NO_DDOS_PROTECTION,),
}
_CHECK_CATEGORY = {check: cat for cat, checks in CATEGORIES.items() for check in checks}

# Per-host web-facing categories; login exposure and dev-environment exposure are placed by
# host role (below). Email, DNS, and DDoS posture are domain-level and placed once at apex.
_HOST_CATEGORIES: tuple[str, ...] = ("web_headers", "waf", "tls", "ports", "software", "eol")
_APEX_CATEGORIES: tuple[str, ...] = ("email", "dns", "ddos")
_APEX_ONLY_CHECKS: frozenset[CheckId] = frozenset(c for cat in _APEX_CATEGORIES for c in CATEGORIES[cat])
_DEV_ONLY_CHECKS: frozenset[CheckId] = frozenset({CheckId.EXPOSED_DEV_ENVIRONMENT})

# Host roles inferred from the subdomain label.
_DEV_LABELS: frozenset[str] = frozenset({"dev", "staging", "uat", "test", "sandbox"})
_ADMIN_LABELS: frozenset[str] = frozenset(
    {"admin", "portal", "vpn", "auth", "secure", "login", "eservices", "sis", "ib"}
)

# Conditional propensities: given a category is present on a host, how likely each specific
# issue in it is. A misconfigured web host typically lacks several headers at once; expired
# and self-signed certificates are rarer than legacy TLS; DMARC "none" and absent MTA-STS
# are common; open zone transfer is rare.
_SUBSET_PROB: dict[CheckId, float] = {
    CheckId.MISSING_HSTS: 0.60,
    CheckId.MISSING_CSP: 0.55,
    CheckId.MISSING_X_FRAME_OPTIONS: 0.50,
    CheckId.MISSING_X_CONTENT_TYPE_OPTIONS: 0.45,
    CheckId.MISSING_REFERRER_POLICY: 0.45,
    CheckId.NO_HTTPS_REDIRECT: 0.30,
    CheckId.MISSING_PERMISSIONS_POLICY: 0.50,
    CheckId.INSECURE_COOKIE: 0.45,
    CheckId.DIRECTORY_LISTING_ENABLED: 0.20,
    CheckId.EXPOSED_SENSITIVE_FILE: 0.12,
    CheckId.WAF_ABSENT: 1.0,
    CheckId.LEGACY_TLS_VERSION: 0.50,
    CheckId.WEAK_TLS_CIPHER: 0.40,
    CheckId.EXPIRED_CERTIFICATE: 0.15,
    CheckId.SELF_SIGNED_CERTIFICATE: 0.18,
    CheckId.WEAK_CERTIFICATE_KEY: 0.15,
    CheckId.EXPOSED_INTERNAL_PORT: 0.30,
    # Management and high-risk port propensities are incident-informed (SOURCES.md §4):
    # brute force is the top detected attack type in Saudi SOC telemetry and valid
    # accounts the second-largest IR initial-access vector (sirar 2023), with VPN and
    # edge devices rising eight-fold as exploitation vectors (DBIR 2025). Magnitudes
    # remain declared; the database propensity keeps its prior (no regional evidence).
    CheckId.EXPOSED_MANAGEMENT_PORT: 0.50,
    CheckId.HIGH_RISK_PORT_OPEN: 0.50,
    CheckId.EXPOSED_DATABASE_PORT: 0.25,
    # Printers answering on the internet are a measured class (Shadowserver's Open IPP report, about
    # 80,000 a day in 2020) with no SME rate; the magnitude is declared, the rarest of the port classes.
    CheckId.EXPOSED_PRINTER_SERVICE: 0.10,
    CheckId.OUTDATED_EXPOSED_SOFTWARE: 1.0,
    CheckId.EOL_SOFTWARE_EXPOSED: 1.0,
    CheckId.EXPOSED_LOGIN_PANEL: 1.0,
    CheckId.EXPOSED_DEV_ENVIRONMENT: 1.0,
    CheckId.SPF_MISSING: 0.50,
    CheckId.DMARC_MISSING_OR_NONE: 0.70,
    CheckId.DKIM_MISSING: 0.60,
    CheckId.MTA_STS_MISSING: 0.70,
    CheckId.DNSSEC_MISSING: 0.85,
    CheckId.DNS_ZONE_TRANSFER_OPEN: 0.10,
    CheckId.NO_DDOS_PROTECTION: 1.0,
}

# Scanner detection model. SENSITIVITY[check] is the **signal reliability**: P(the scanner
# confirms a truly-present issue) on a fully reachable host under a competent scan, BEFORE the
# per-host acquisition condition and per-org competence of _observe scale it down (Phase 2).
# FALSE_ALARM[check] = P(the scanner reports an issue that is truly absent).
#
# The signal reliabilities are calibrated against how the reference implementation's own
# inspectors behave (docs/detection-calibration.md), not free assumptions:
#   - Deterministic reads confirm a present-or-absent artifact directly and are near-certain on a
#     reachable host: HTTP security headers and cookies (analyze_security_headers, measured 1.0 on
#     the test-target), TLS version/cipher and certificate validity (TlsInspector), open ports
#     (naabu, which found every real listener on the validation host), and SPF/DMARC/MTA-STS/DNSSEC
#     DNS records (EmailDnsInspector, correct on the real validation domain). These sit at 0.95-0.99.
#   - Path or selector limited probes see only a fixed list: sensitive-file and directory-listing
#     probing, and DKIM (a fixed selector catalog, RFC 6376) sit lower and carry a false-alarm mode.
#   - Fingerprint and banner signals are inherently ambiguous from outside: WAF presence (wafw00f
#     cannot confirm absence), DDoS mitigation, and banner-based version and end-of-life detection
#     (spoofable or absent banners) sit at 0.70-0.90 and carry the material false-alarm modes below.
# The per-host acquisition condition (reachable/throttled/CDN-fronted/blocked) that a real scan run
# faces is modelled separately in _observe, so a miss is attributed to signal ambiguity OR to scan
# obstruction, not conflated into one flat rate.
SENSITIVITY: dict[CheckId, float] = {
    CheckId.MISSING_HSTS: 0.99,
    CheckId.MISSING_CSP: 0.99,
    CheckId.MISSING_X_FRAME_OPTIONS: 0.99,
    CheckId.MISSING_X_CONTENT_TYPE_OPTIONS: 0.99,
    CheckId.MISSING_REFERRER_POLICY: 0.99,
    CheckId.NO_HTTPS_REDIRECT: 0.98,
    CheckId.MISSING_PERMISSIONS_POLICY: 0.99,
    CheckId.INSECURE_COOKIE: 0.98,
    CheckId.DIRECTORY_LISTING_ENABLED: 0.92,
    CheckId.EXPOSED_SENSITIVE_FILE: 0.75,
    CheckId.WAF_ABSENT: 0.90,
    CheckId.LEGACY_TLS_VERSION: 0.96,
    CheckId.WEAK_TLS_CIPHER: 0.96,
    CheckId.EXPIRED_CERTIFICATE: 0.99,
    CheckId.SELF_SIGNED_CERTIFICATE: 0.98,
    CheckId.WEAK_CERTIFICATE_KEY: 0.97,
    CheckId.EXPOSED_INTERNAL_PORT: 0.95,
    CheckId.EXPOSED_MANAGEMENT_PORT: 0.95,
    CheckId.HIGH_RISK_PORT_OPEN: 0.95,
    CheckId.EXPOSED_DATABASE_PORT: 0.95,
    CheckId.EXPOSED_PRINTER_SERVICE: 0.95,
    CheckId.OUTDATED_EXPOSED_SOFTWARE: 0.72,
    CheckId.EOL_SOFTWARE_EXPOSED: 0.70,
    CheckId.EXPOSED_LOGIN_PANEL: 0.88,
    CheckId.EXPOSED_DEV_ENVIRONMENT: 0.96,
    CheckId.SPF_MISSING: 0.99,
    CheckId.DMARC_MISSING_OR_NONE: 0.99,
    CheckId.DKIM_MISSING: 0.93,
    CheckId.MTA_STS_MISSING: 0.98,
    CheckId.DNSSEC_MISSING: 0.99,
    CheckId.DNS_ZONE_TRANSFER_OPEN: 0.90,
    CheckId.NO_DDOS_PROTECTION: 0.85,
}
# A false alarm rate is modelled only for checks with a genuine probabilistic detection mode:
# heuristic or fingerprint-based signals (WAF/DDoS presence, banner-based version and end-of-life,
# selector-limited DKIM, currency-limited passive port data, login-panel/dev-environment
# recognition, sensitive-file/directory probing, zone-transfer attempts). TLS version and cipher
# carry only a SMALL residual rate (0.02): the handshake is read directly, but cipher-strength
# classification and negotiation edge cases (a downgrade dance, a load balancer terminating TLS)
# leave a slight spurious-detection margin, unlike certificate validity, which is a pure read. The
# remaining checks are DETERMINISTIC reads of a present-or-absent artifact (an HTTP security header,
# an SPF/DMARC/MTA-STS/DNSSEC DNS record, a served certificate's validity and key strength): the
# scanner observes the artifact directly, so there is no false-positive mode and the rate is 0.0. The
# set of checks with a nonzero rate is exactly _FALSE_ALARM_CHECKS below (asserted in the tests), so no
# rate here is documented-but-unapplied.
FALSE_ALARM: dict[CheckId, float] = {
    CheckId.MISSING_HSTS: 0.0,
    CheckId.MISSING_CSP: 0.0,
    CheckId.MISSING_X_FRAME_OPTIONS: 0.0,
    CheckId.MISSING_X_CONTENT_TYPE_OPTIONS: 0.0,
    CheckId.MISSING_REFERRER_POLICY: 0.0,
    CheckId.NO_HTTPS_REDIRECT: 0.0,
    CheckId.MISSING_PERMISSIONS_POLICY: 0.0,
    CheckId.INSECURE_COOKIE: 0.0,
    CheckId.DIRECTORY_LISTING_ENABLED: 0.03,
    CheckId.EXPOSED_SENSITIVE_FILE: 0.06,
    CheckId.WAF_ABSENT: 0.20,
    CheckId.LEGACY_TLS_VERSION: 0.02,
    CheckId.WEAK_TLS_CIPHER: 0.02,
    CheckId.EXPIRED_CERTIFICATE: 0.0,
    CheckId.SELF_SIGNED_CERTIFICATE: 0.0,
    CheckId.WEAK_CERTIFICATE_KEY: 0.0,
    CheckId.EXPOSED_INTERNAL_PORT: 0.04,
    CheckId.EXPOSED_MANAGEMENT_PORT: 0.04,
    CheckId.HIGH_RISK_PORT_OPEN: 0.04,
    CheckId.EXPOSED_DATABASE_PORT: 0.04,
    CheckId.EXPOSED_PRINTER_SERVICE: 0.04,
    CheckId.OUTDATED_EXPOSED_SOFTWARE: 0.06,
    CheckId.EOL_SOFTWARE_EXPOSED: 0.08,
    CheckId.EXPOSED_LOGIN_PANEL: 0.08,
    CheckId.EXPOSED_DEV_ENVIRONMENT: 0.04,
    CheckId.SPF_MISSING: 0.0,
    CheckId.DMARC_MISSING_OR_NONE: 0.0,
    CheckId.DKIM_MISSING: 0.24,
    CheckId.MTA_STS_MISSING: 0.0,
    CheckId.DNSSEC_MISSING: 0.0,
    CheckId.DNS_ZONE_TRANSFER_OPEN: 0.02,
    CheckId.NO_DDOS_PROTECTION: 0.20,
}
# The checks with a material (nonzero) false-alarm mode: exactly those spurious detections are drawn.
# Order is load-bearing (it fixes the RNG draw sequence), so keep it stable; the set-equality with the
# nonzero FALSE_ALARM entries is asserted in the tests.

# Low-confidence checks: the genuinely ambiguous signals whose false-alarm rate is high enough
# (>= LOW_CONFIDENCE_FA) that a lone such finding should not by itself assert a control. These are the
# WAF and DDoS fingerprints, selector-limited DKIM, banner-based end-of-life, and login-panel
# recognition. This is a STRICT subset of the checks with a nonzero false-alarm mode: deterministic
# reads with only a small residual false alarm (open ports, TLS version and cipher) stay high
# confidence, because a detected open port or negotiated legacy protocol is a real observation, not a
# guess. A control evidenced ONLY by a single low-confidence finding is provisional; a corroboration
# aware assessment (harness corroborated recovery) requires either a high-confidence signal or a second
# independent finding before asserting such a control as a hard gap, trading a little recall for
# precision the way a careful analyst does. Corroboration therefore holds back the ambiguous-signal
# false challenges specifically, not the rare high-confidence false alarm.
LOW_CONFIDENCE_FA = 0.08  # false-alarm rate at or above which a check is treated as low confidence
LOW_CONFIDENCE_CHECKS: frozenset[CheckId] = frozenset(
    c for c, v in FALSE_ALARM.items() if v >= LOW_CONFIDENCE_FA
)


# ---- Per-host acquisition condition (correlated scan obstruction) ----
# A real external scan does not sense every host equally: some are directly reachable, some are rate
# limited, some sit behind a CDN or WAF that hides the origin, and a few are unreachable at scan time.
# The condition is a per-host latent drawn once, so a degraded host loses its directly fetched signals
# TOGETHER (a correlated failure, the way a real scan run behaves) rather than each check missing
# independently. DNS-observable signals (email authentication, DNS security, DDoS posture) are queried
# from DNS and are not gated by a host's HTTP reachability, so the condition does not apply to them.
# Control-level recovery stays robust because a control is usually evidenced across several hosts, so
# one obstructed host rarely hides a control the estate exhibits elsewhere.
SCAN_CONDITIONS: tuple[str, ...] = ("reachable", "throttled", "cdn_fronted", "blocked")
# A condition scales two check classes differently. ORIGIN checks read the host itself (open ports,
# software banners, a reachable dev environment, exposed files): a CDN or WAF in front of the host
# hides those, so they are heavily depressed when CDN fronted. EDGE checks read whatever answers the
# request (HTTP security headers, TLS, WAF fingerprint, a login page): a CDN still serves these from
# the edge, so CDN fronting barely touches them. Both classes collapse when the host is blocked and
# degrade mildly when throttled. This mirrors how a real external scan sees a CDN fronted estate.
CONDITION_FACTOR_ORIGIN: dict[str, float] = {
    "reachable": 1.00,
    "throttled": 0.90,
    "cdn_fronted": 0.40,
    "blocked": 0.20,
}
CONDITION_FACTOR_EDGE: dict[str, float] = {
    "reachable": 1.00,
    "throttled": 0.92,
    "cdn_fronted": 0.95,
    "blocked": 0.20,
}
# Share of hosts in each condition. Skewed to reachable because a genuinely public-facing host is,
# by definition, reachable to an external scanner most of the time; blocking is the rare case.
CONDITION_SHARES: dict[str, float] = {
    "reachable": 0.85,
    "throttled": 0.09,
    "cdn_fronted": 0.05,
    "blocked": 0.01,
}
# Per-org scanner competence: most authorized scans run competently, with a small spread for the
# run-to-run acquisition quality of a real deployment. Applies to every host-fetched check in the org.
COMPETENCE_MIN, COMPETENCE_MAX = 0.97, 1.00
# Origin checks read the host directly and are hidden behind a CDN; the rest of the host-fetched
# checks are edge-served. DNS-observable apex signals resolve from DNS regardless of HTTP reachability.
_ORIGIN_CHECKS: frozenset[CheckId] = frozenset(
    c for cat in ("ports", "software", "eol", "dev_env") for c in CATEGORIES[cat]
) | {CheckId.EXPOSED_SENSITIVE_FILE, CheckId.DIRECTORY_LISTING_ENABLED}
_HOST_FETCHED_CHECKS: frozenset[CheckId] = frozenset(c for c in SENSITIVITY if c not in _APEX_ONLY_CHECKS)
_FALSE_ALARM_CHECKS: tuple[CheckId, ...] = (
    CheckId.WAF_ABSENT,
    CheckId.LEGACY_TLS_VERSION,
    CheckId.WEAK_TLS_CIPHER,
    CheckId.EXPOSED_INTERNAL_PORT,
    CheckId.EXPOSED_MANAGEMENT_PORT,
    CheckId.HIGH_RISK_PORT_OPEN,
    CheckId.EXPOSED_DATABASE_PORT,
    CheckId.OUTDATED_EXPOSED_SOFTWARE,
    CheckId.EOL_SOFTWARE_EXPOSED,
    CheckId.EXPOSED_SENSITIVE_FILE,
    CheckId.DIRECTORY_LISTING_ENABLED,
    CheckId.DKIM_MISSING,
    CheckId.NO_DDOS_PROTECTION,
    CheckId.EXPOSED_LOGIN_PANEL,
    CheckId.EXPOSED_DEV_ENVIRONMENT,
    CheckId.DNS_ZONE_TRANSFER_OPEN,
    CheckId.EXPOSED_PRINTER_SERVICE,
)


@dataclass(frozen=True)
class Sector:
    """A market sector with a per-finding-category exposure weight.

    Weights are relative propensities (the likelihood a host exhibits an issue of that
    category). Prevalences are SOURCED (Monsha'at Q1 2022 stock distribution, aggregated;
    see dataset/sources/SOURCES.md §3). The per-category weight rows are INCIDENT-INFORMED
    modelling assumptions (SOURCES.md §4): no measurement of Saudi SME exposure by category
    exists, so the magnitudes are declared, but the direction and rank of the ports,
    software, eol, and auth columns follow the regional incident record (Saudi IR and SOC
    reporting, ransomware victimology, and the wiper-campaign lineage; SOURCES.md §4 and
    docs/DECISIONS.md 2026-08-16). Documented row by row below and in
    docs/threats-to-validity.md.
    """

    name: str
    prevalence: float  # share of the corpus drawn from this sector (SOURCED, SOURCES.md §3)
    weights: dict[str, float]  # per-category exposure propensity (DECLARED, SOURCES.md §4)


WEIGHT_KEYS: tuple[str, ...] = (
    "web_headers",
    "waf",
    "tls",
    "ports",
    "software",
    "eol",
    "auth",
    "ddos",
    "email",
    "dns",
    "dev_env",
)


def _w(*values: float) -> dict[str, float]:
    """Build a category-weight dict from positional values in ``WEIGHT_KEYS`` order."""
    return dict(zip(WEIGHT_KEYS, values, strict=True))


# The eight Class-B SME sectors (SOURCES.md §3). Prevalences are SOURCED from the Monsha'at
# Q1 2022 stock distribution (aggregated; residual allocation declared) and sum to 1.00. They
# replace the old six threat-flavored categories, which reflected attacker prevalence rather
# than the SME population. "government" is dropped (a government body is not a Class-B private
# SME) and e-commerce is folded into retail_wholesale (GASTAT treats online selling as a
# capability, not a sector).
#
# The 8x11 weight rows are INCIDENT-INFORMED modelling assumptions (SOURCES.md §4) — there is
# NO Saudi source for per-category exposure rates, so the magnitudes are declared, but the
# ports, software, eol, and auth columns were reweighted 2026-08-16 to follow the regional
# incident record (docs/DECISIONS.md): Saudi IR engagements enter overwhelmingly through the
# reachable surface (exploit public-facing application and valid accounts far above phishing,
# sirar 2023), brute force tops Saudi SOC detections, the top exploited CVEs in the Kingdom
# are all internet-facing enterprise applications with multi-year patch latency, the regional
# wiper lineage (Shamoon 2, ZeroCleare) entered through credentials and public-facing servers,
# and regional ransomware victimology skews to manufacturing and construction mid-market firms
# (SOCRadar 2024), so those sectors carry the larger ports/software/eol raises. Each row stays
# in [0.30, 0.85] like the originals:
#   - retail_wholesale, food_accommodation: customer-facing storefronts / payment surface, so
#     heavier web_headers/tls/waf/ddos weight.
#   - construction, transport_logistics, manufacturing: lighter public web surface (web_headers
#     lower); more software/eol (older on-prem stacks) and the larger incident-informed
#     ports raises.
#   - education, health: heavier auth (login portals) and dev_env (student/patient portals,
#     staging systems) weight.
# The headers, waf, tls, ddos, email, dns, and dev_env columns are unchanged: the regional
# record is silent on them (headers, tls, dev_env), qualitative only (waf, ddos), or measured
# against the naive expectation (email; SOURCES.md §4). The dns weight stays high across all
# sectors because DNSSEC, although available under the signed .sa zone, is scarcely deployed.
# A reviewer must read the magnitudes as assumptions, not measured rates.
SECTORS: tuple[Sector, ...] = (
    #                              web   waf   tls   port  soft  eol   auth  ddos  email dns   dev
    Sector("retail_wholesale", 0.27, _w(0.72, 0.72, 0.55, 0.50, 0.56, 0.48, 0.54, 0.62, 0.60, 0.78, 0.45)),
    Sector("construction", 0.20, _w(0.42, 0.50, 0.40, 0.55, 0.62, 0.62, 0.50, 0.40, 0.65, 0.82, 0.40)),
    Sector("food_accommodation", 0.10, _w(0.70, 0.70, 0.55, 0.48, 0.58, 0.52, 0.50, 0.60, 0.62, 0.80, 0.42)),
    Sector("prof_admin_services", 0.14, _w(0.55, 0.58, 0.45, 0.50, 0.55, 0.50, 0.56, 0.48, 0.60, 0.78, 0.48)),
    Sector("manufacturing", 0.10, _w(0.42, 0.50, 0.42, 0.60, 0.65, 0.65, 0.50, 0.40, 0.63, 0.82, 0.42)),
    Sector("transport_logistics", 0.05, _w(0.45, 0.52, 0.45, 0.60, 0.58, 0.56, 0.54, 0.45, 0.62, 0.80, 0.45)),
    Sector("education", 0.07, _w(0.58, 0.62, 0.45, 0.55, 0.64, 0.60, 0.72, 0.50, 0.62, 0.80, 0.62)),
    Sector("health", 0.07, _w(0.58, 0.65, 0.48, 0.55, 0.62, 0.56, 0.75, 0.52, 0.60, 0.80, 0.60)),
)


@dataclass(frozen=True)
class SizeBand:
    """A Class-B firm-size band. Drawn FIRST per profile; conditions estate size and posture.

    Shares are SOURCED (Monsha'at Q4 2023 size split within Class B: small 150,788, medium
    18,723 -> 0.89 / 0.11; SOURCES.md §1). Estate host-count ranges are a DECLARED shape
    anchored to GASTAT 2024/2025 ICT-usage rates (a Class-B SME has a small external presence;
    SOURCES.md §2): a small firm is apex + 1..4 subdomains, a medium firm apex + 3..8. Posture
    shares are DECLARED, weakly conditioned on the band (medium firms skew slightly stronger,
    per Huaman et al. USENIX 2021; SOURCES.md §5).
    """

    name: str
    share: float  # share of the Class-B population (SOURCED, SOURCES.md §1)
    min_subs: int  # min subdomains beyond the apex (DECLARED shape, SOURCES.md §2)
    max_subs: int  # max subdomains beyond the apex (DECLARED shape, SOURCES.md §2)
    posture_shares: dict[str, float]  # strong/moderate/weak shares for this band (SOURCES.md §5)


SIZE_BANDS: tuple[SizeBand, ...] = (
    SizeBand("small", 0.89, 1, 4, {"strong": 0.15, "moderate": 0.35, "weak": 0.50}),
    SizeBand("medium", 0.11, 3, 8, {"strong": 0.30, "moderate": 0.40, "weak": 0.30}),
)

# Posture multipliers scale every issue propensity (DECLARED propensity scale, unchanged from
# the old flat model; SOURCES.md §5). Strong = mature program (few externally observable gaps);
# weak = neglected surface (many gaps).
POSTURE_MULT: dict[str, float] = {"strong": 0.20, "moderate": 0.55, "weak": 1.00}
_POSTURE_NAMES: tuple[str, ...] = ("strong", "moderate", "weak")


@dataclass(frozen=True)
class Posture:
    """An organization's overall security maturity, scaling every issue propensity.

    ``mult`` is the propensity multiplier (SOURCES.md §5). ``share`` is the corpus-MARGINAL
    posture share (derived from the band shares below); it is NOT used to draw a posture — the
    draw is band-conditioned via ``_pick_posture(rng, band)`` over ``band.posture_shares``. The
    marginal is retained only so the priors enumerator (the number gate) reads a valid
    posture-share set while the toolkit is unwritten. When tab:priors is authored, the per-band
    shares in SIZE_BANDS are authoritative.
    """

    name: str
    share: float  # corpus-marginal share (derived; see class docstring), not the draw weight
    mult: float


def _marginal_posture_shares() -> dict[str, float]:
    """Corpus-marginal posture shares implied by the band shares and per-band posture shares."""
    out = dict.fromkeys(_POSTURE_NAMES, 0.0)
    for band in SIZE_BANDS:
        for name in _POSTURE_NAMES:
            out[name] += band.share * band.posture_shares[name]
    return out


_MARGINAL_POSTURE = _marginal_posture_shares()
POSTURES: tuple[Posture, ...] = tuple(
    Posture(name, round(_MARGINAL_POSTURE[name], 6), POSTURE_MULT[name]) for name in _POSTURE_NAMES
)
_POSTURE_BY_NAME: dict[str, Posture] = {p.name: p for p in POSTURES}

# Tier-3 attestation behavior. An organization self-attests compliance for controls it is
# truly clean on (honest documentation) and, as the overstatement adversary, for some
# controls it actually fails (a claim a Tier-1 finding should refute). These are modelling
# assumptions used only to exercise contradiction detection; they are the answer key for
# that metric and are never shown to the mapping pipeline.
P_ATTEST_CLEAN = 0.70  # P(attest a truly-compliant control)
P_OVERSTATE = 0.50  # P(attest a truly-violated control) -> a genuine contradiction

# TLD pool (SOURCES.md §6). SaudiNIC/CST: under 5% of SMEs hold a .sa domain, so SME sites are
# predominantly gTLD. DECLARED weights reflecting that (was uniform over the four).
_TLDS: tuple[str, ...] = ("com", "com.sa", "sa", "net.sa")
_TLD_WEIGHTS: dict[str, float] = {"com": 0.55, "com.sa": 0.20, "sa": 0.15, "net.sa": 0.10}

# Sector-flavored subdomain pools so profiles read like real SME estates, one pool per sector
# name (the generator keys _SUBDOMAIN_POOLS by exact sector name). Each pool holds >= 8 labels
# so it covers the largest (medium) estate, and carries admin-ish labels (admin/portal/vpn/
# login/secure/eservices/sis) and dev-ish labels (dev/staging/uat/test) so login-panel and
# dev-environment exposure have real targets, matching _ADMIN_LABELS / _DEV_LABELS.
# The einvoice label reflects the ZATCA (Fatoora) e-invoicing integration surface that every
# VAT-registered Saudi firm operates; it appears in the customer-facing sector pools.
_SUBDOMAIN_POOLS: dict[str, tuple[str, ...]] = {
    "retail_wholesale": ("www", "shop", "checkout", "api", "cdn", "mail", "pay", "einvoice", "admin", "staging", "dev"),
    "construction": ("www", "mail", "portal", "projects", "vpn", "api", "docs", "dev", "staging", "test"),
    "food_accommodation": ("www", "book", "order", "menu", "api", "mail", "cdn", "einvoice", "admin", "staging", "dev"),
    "prof_admin_services": ("www", "portal", "mail", "api", "crm", "vpn", "docs", "einvoice", "login", "staging", "dev"),
    "manufacturing": ("www", "mail", "portal", "erp", "api", "vpn", "shop", "secure", "dev", "uat"),
    "transport_logistics": ("www", "track", "api", "portal", "mail", "vpn", "edi", "fleet", "dev", "test"),
    "education": ("www", "portal", "lms", "sis", "mail", "vpn", "library", "elearning", "dev", "staging"),
    "health": ("www", "portal", "patients", "appointments", "api", "mail", "vpn", "lab", "dev", "uat"),
}
# Back-compat exports for the priors enumerator (the number gate:_priors_numbers), which
# reads these while the toolkit is unwritten. Generation is band-conditioned via SIZE_BANDS.min_subs
# / max_subs; these are the corpus host-count envelope (smallest small firm to largest medium
# firm). When tab:priors is authored, the per-band ranges in SIZE_BANDS are authoritative.
MIN_SUBS = min(b.min_subs for b in SIZE_BANDS)
MAX_SUBS = max(b.max_subs for b in SIZE_BANDS)


def expert_key() -> dict[CheckId, frozenset[str]]:
    """The expert-correct control mapping per check (from the taxonomy-derived RULES).

    Validated against the catalog so the answer key can never reference a non-existent
    control (fail-closed at call time, mirroring the mapping engine's rule validation).
    """
    index = load_default_index()
    key: dict[CheckId, frozenset[str]] = {}
    for check, rule in RULES.items():
        ids = frozenset(rule.control_ids)
        missing = [cid for cid in ids if index.get(cid) is None]
        if missing:
            raise ValueError(f"expert key for {check.value} references non-catalog ids {missing}")
        key[check] = ids
    return key


@dataclass(frozen=True)
class InjectedFinding:
    """One scanner-observable issue placed on an asset."""

    asset: str
    check: CheckId


@dataclass(frozen=True)
class InternalAssessment:
    """One Tier-2 internal-assessment record a firm holds on an OFF-SURFACE control.

    ``compliant`` is the firm's own reading of its internal evidence, not a latent truth: nothing
    in the model and nothing an external scan can do settles an off-surface control, which is
    exactly why the control sits outside Tier 1. The record exists so the documented score is
    computed over the evidence a firm actually holds rather than over the scan's reach alone.
    """

    control_id: str
    compliant: bool


@dataclass(frozen=True)
class GroundTruth:
    """The answer keys for a case — NEVER passed to discovery/scan/mapping.

    ``control_ids`` is the *true* control state (from the latent issues). ``observed_ids``
    is the control state implied by what the scanner actually observed; the harness scores
    mapping integrity against it and end-to-end recovery against ``control_ids``.
    """

    control_ids: frozenset[str]
    observed_ids: frozenset[str]
    per_asset: dict[str, frozenset[str]] = field(default_factory=dict)


@dataclass(frozen=True)
class EvalCase:
    """One synthetic profile: pipeline-visible profile, observed findings, hidden truth."""

    case_id: str
    sector: str
    size_band: str  # Class-B firm-size band (small/medium); conditions estate size + posture
    profile: SyntheticProfile  # visible to the pipeline (assets only, no labels)
    injected: tuple[InjectedFinding, ...]  # OBSERVED states -> drive the synthetic scan
    true_injected: tuple[InjectedFinding, ...]  # latent truth -> hidden answer key
    ground_truth: GroundTruth  # hidden answer keys
    attestations: tuple[Attestation, ...]  # Tier-3 self-claims (some overstated) for scoring
    posture: str  # organization security maturity (strong/moderate/weak)
    baseline_seconds: float  # modelled manual-annotation time for this profile
    internal_evidence: tuple[InternalAssessment, ...] = ()  # Tier-2 records on off-surface controls
    forced_true_fallback: bool = False  # the never-empty-org fallback fired (should be False on the corpus)
    scan_conditions: dict[str, str] = field(default_factory=dict)  # per-host acquisition condition
    scanner_competence: float = 1.0  # per-org scan competence multiplier

    def pipeline_input(self) -> SyntheticProfile:
        """Exactly what the pipeline receives — the profile, never the ground truth."""
        return self.profile

    def findings(self, *, now: datetime = EVAL_EPOCH, consent_ref: str = "eval") -> list[Finding]:
        """Build the Stage-3 findings the scanner would emit for the OBSERVED states.

        Uses the scanner's own ``build_finding`` (so the Findings are byte-faithful to a real
        scan) but **strips the scan-catalog control tags** — the mapping engine must re-derive
        the control from the observable check alone (its Stage-4 job). This is the leakage
        control: the answer key is never handed to the thing being evaluated. The mapper
        recovers the check via ``finding_id.split(":", 1)[0]``, so the id starts with the check
        value. Never reads ``ground_truth``.
        """
        return [
            build_finding(
                inj.check,
                asset=inj.asset,
                observed_state=f"{inj.check.value} detected on {inj.asset} (synthetic)",
                consent_ref=consent_ref,
                source_tool="atlas-scan:synthetic",
                tool_version="synthetic-1",
                finding_id=f"{inj.check.value}:{self.case_id}:{inj.asset}",
                now=now,
            ).model_copy(update={"control_ids": []})
            for inj in self.injected
        ]


def _weighted_tld(rng: random.Random) -> str:
    """Draw a TLD from the DECLARED gTLD-skewed weights (SOURCES.md §6)."""
    r = rng.random() * sum(_TLD_WEIGHTS.values())
    upto = 0.0
    for tld in _TLDS:
        upto += _TLD_WEIGHTS[tld]
        if r <= upto:
            return tld
    return _TLDS[-1]


# Arabic IDN apexes (SOURCES.md §6). The SaudiNIC registry reports 807 Arabic-script
# registrations (.السعودية) against 93,154 national domains (nic.sa statistics, retrieved
# 2026-08-16), about 1% of the national register, so that share of national-TLD estates sits
# under an Arabic-script apex. The generator emits the punycode (xn--) form directly, because
# that is the label an external scanner reads on the wire; the Unicode originals are generic
# business words ("establishment" / "enterprise" / "company"), index-salted with Arabic-Indic
# digits and a terminal Arabic letter to satisfy the IDNA bidi rules, so every apex stays
# unique.
IDN_APEX_SHARE = 0.01  # conditional on a .sa-family TLD draw
_IDN_APEX_WORDS: tuple[str, ...] = ("منشاة", "مؤسسة", "شركة")
_ARABIC_DIGITS = "٠١٢٣٤٥٦٧٨٩"


def _idn_apex_label(rng: random.Random, index: int) -> str:
    """Punycode apex label for an Arabic IDN firm: word + Arabic-Indic index + terminal letter."""
    word = rng.choice(_IDN_APEX_WORDS)
    digits = "".join(_ARABIC_DIGITS[int(c)] for c in f"{index:03d}")
    return f"{word}{digits}م".encode("idna").decode("ascii")


def _domain_for(rng: random.Random, index: int) -> str:
    # The IDN decision draws from a dedicated per-firm stream, not the shared one, so a
    # cosmetic naming feature cannot perturb the issue draws that follow it.
    suffix = rng.choice(("grp", "co", "ltd", "org"))
    tld = _weighted_tld(rng)
    idn_rng = random.Random(0xA11A + index)
    if tld != "com" and idn_rng.random() < IDN_APEX_SHARE:
        return f"{_idn_apex_label(idn_rng, index)}.{tld}"
    return f"sme{index:03d}-{suffix}.{tld}"


def _host_label(host: str, apex: str) -> str:
    return "apex" if host == apex else host.split(".", 1)[0]


def _draw_subset(rng: random.Random, category: str) -> list[CheckId]:
    """Given a present category, pick a realistic, non-empty subset of its checks."""
    checks = CATEGORIES[category]
    chosen = [c for c in checks if rng.random() < _SUBSET_PROB[c]]
    if not chosen:
        chosen = [rng.choice(checks)]
    return chosen


def _control_ids_for(injected: list[InjectedFinding], key: dict[CheckId, frozenset[str]]) -> frozenset[str]:
    if not injected:
        return frozenset()
    return frozenset().union(*(key[i.check] for i in injected))


def _dedup(injected: list[InjectedFinding]) -> list[InjectedFinding]:
    """Drop duplicate (asset, check) pairs, order-stable."""
    seen: set[tuple[str, CheckId]] = set()
    out: list[InjectedFinding] = []
    for inj in injected:
        marker = (inj.asset, inj.check)
        if marker not in seen:
            seen.add(marker)
            out.append(inj)
    return out


def _true_issues(
    rng: random.Random, sector: Sector, hosts: list[str], apex: str, mult: float
) -> tuple[list[InjectedFinding], bool]:
    """Latent TRUE issues, placed by host role plus apex-only domain-level categories.

    ``mult`` is the posture multiplier: a strong organization (small ``mult``) exhibits far
    fewer issues than a weak one, so the corpus spans the full maturity range. Returns the
    issues and a flag recording whether the never-empty-organization fallback had to fire (it
    should not on the reported corpus; asserted in the tests so a future prior change surfaces).
    """
    true: list[InjectedFinding] = []
    for host in hosts:
        label = _host_label(host, apex)
        for cat in _HOST_CATEGORIES:
            if rng.random() < sector.weights[cat] * mult:
                true.extend(InjectedFinding(asset=host, check=c) for c in _draw_subset(rng, cat))
        # Login-panel exposure is far likelier on admin/portal/vpn hosts than on www/api.
        w_auth = sector.weights["auth"]
        p_auth = (min(1.0, w_auth * 2.0) if label in _ADMIN_LABELS else w_auth * 0.35) * mult
        if rng.random() < p_auth:
            true.append(InjectedFinding(asset=host, check=CheckId.EXPOSED_LOGIN_PANEL))
        # A reachable dev/staging environment only on hosts actually named as one.
        if label in _DEV_LABELS and rng.random() < sector.weights["dev_env"] * mult:
            true.append(InjectedFinding(asset=host, check=CheckId.EXPOSED_DEV_ENVIRONMENT))
    for cat in _APEX_CATEGORIES:  # email auth, DNS security, DDoS posture are domain-level
        if rng.random() < sector.weights[cat] * mult:
            true.extend(InjectedFinding(asset=apex, check=c) for c in _draw_subset(rng, cat))
    used_fallback = not true
    if used_fallback:  # never a degenerate empty organization
        true.append(InjectedFinding(asset=apex, check=CheckId.SPF_MISSING))
    return _dedup(true), used_fallback


# Share of attestations that are lapsed at the evaluation epoch (a real attestation set carries some
# expired and some not-yet-effective claims). A lapsed attestation must not be counted as a live
# contradiction: the detector and the harness ground truth both honor the validity window.
P_ATTEST_EXPIRED = 0.10
P_ATTEST_NOT_YET = 0.05


def _attestation_window(rng: random.Random) -> tuple[datetime, datetime]:
    """Draw a validity window: mostly current, some expired before the epoch, some not yet effective."""
    r = rng.random()
    if r < P_ATTEST_EXPIRED:  # expired before the evaluation epoch
        return EVAL_EPOCH - timedelta(days=400), EVAL_EPOCH - timedelta(days=1 + int(59 * rng.random()))
    if r < P_ATTEST_EXPIRED + P_ATTEST_NOT_YET:  # not yet effective
        return EVAL_EPOCH + timedelta(days=1 + int(29 * rng.random())), EVAL_EPOCH + timedelta(days=365)
    return EVAL_EPOCH - timedelta(days=30), EVAL_EPOCH + timedelta(days=30 + int(335 * rng.random()))


def _attestations(
    rng: random.Random, case_id: str, true_control_ids: frozenset[str], all_controls: frozenset[str]
) -> tuple[Attestation, ...]:
    """Seeded Tier-3 self-attestations: honest ones on clean controls, overstatements on
    truly-violated ones, each with a validity window (some current, some expired, some not yet
    effective). An overstatement on a CURRENT attestation is a genuine contradiction a Tier-1 finding
    refutes; a lapsed one must be ignored by both the detector and the ground truth."""
    out: list[Attestation] = []
    for cid in sorted(all_controls):
        violated = cid in true_control_ids
        if rng.random() < (P_OVERSTATE if violated else P_ATTEST_CLEAN):
            digest = hashlib.sha256(f"{case_id}:{cid}".encode()).hexdigest()
            valid_from, valid_until = _attestation_window(rng)
            out.append(
                Attestation(
                    attestation_id=f"att-{case_id}-{cid}",
                    control_id=cid,
                    statement=f"Control {cid} is implemented and operating effectively.",
                    signer_identity=f"ciso@{case_id}",
                    payload_hash=digest,
                    valid_from=valid_from,
                    valid_until=valid_until,
                )
            )
    return tuple(out)


# ---- Off-surface evidence: what a firm documents beyond the scan's reach ----
# A firm's compliance position is not confined to the 16 externally checkable subcontrols. It also
# holds internal-assessment evidence (Tier 2: a backup restoration test, a log retention
# configuration) and signed declarations (Tier 3: a governance committee, personnel screening,
# physical access) on controls no external observation can settle. Without that stream the corpus
# never exercises the three-tier design: every declaration would land on a Tier-1 checkable
# control, lowest-tier-wins would collapse it onto the Tier-1 record, and the documented score
# would equal the assessed one for every firm by construction.
#
# The control identifiers come from the tracked ID-keyed sort overlay (no NCA control text is read
# or embedded), and the two pools are exactly the overlay's internal-assessment (77) and
# declaration (103) rows. Neither pool holds a control hierarchically related to any Tier-1
# mappable control, so an off-surface declaration is UNREFUTABLE by construction: no Tier-1
# finding can reach it, the contradiction detector never flags it, and contradiction precision and
# recall are untouched. That property is enforced fail-closed at load time below and asserted in
# the tests rather than assumed.
_OVERLAY_PATH = Path(__file__).resolve().parents[3] / "taxonomy" / "release" / "sort_overlay.json"

# Share of the off-surface catalogue a firm has evidenced at the evaluation epoch. DECLARED, with
# NO source: no measurement of how much of the must-answer catalogue a Saudi SME has documented
# exists. Posture-correlated in the plausible direction, because documenting an off-surface
# control costs the firm exactly the internal work an external scan cannot do, and a firm with a
# mature program has more of it behind them. Kept deliberately thin: a weak small firm evidences
# about 9 of the 180 must-answer rows, a strong one about 36, never the whole catalogue.
OFF_SURFACE_COVERAGE: dict[str, float] = {"strong": 0.20, "moderate": 0.12, "weak": 0.05}
# Share of the controls a firm assesses INTERNALLY that come back not yet implemented. DECLARED:
# an internal assessment that never returns a gap is not an assessment. Deliberately flat across
# postures, because the corpus carries no latent off-surface truth to anchor a posture effect on;
# the record is the firm's own reading, and the model does not claim to know better. A Tier-3
# declaration has no equivalent rate: a declaration asserts compliance by definition, and nothing
# outside the firm can test one on an off-surface control.
P_INTERNAL_GAP = 0.25


@lru_cache(maxsize=1)
def off_surface_pools() -> tuple[tuple[str, ...], tuple[str, ...]]:
    """The (internal-assessment, declaration) control-id pools, from the tracked sort overlay.

    Sorted for determinism and validated fail-closed: a pool holding a control that a Tier-1
    finding could refute (equal to, or an ancestor of, a Tier-1 checkable control)
    would silently move the contradiction metrics, so it is rejected here rather than discovered
    in a diff.
    """
    from p2c.scoring.assemble import TIER1_CHECKABLE  # noqa: PLC0415 (avoids an import cycle)
    from p2c.scoring.contradictions import hierarchy_related  # noqa: PLC0415

    rows = json.loads(_OVERLAY_PATH.read_text(encoding="utf-8"))["controls"]
    pools: dict[int, list[str]] = {2: [], 3: []}
    for row in rows:
        tier = int(row["tier"])
        if tier in pools:
            pools[tier].append(str(row["id"]))
    for tier, ids in pools.items():
        # A pool control equal to, or an ancestor of, a checkable one would be fixed by the scan
        # itself; a record that a list of requirements is implemented (rule 4) is checkable on purpose.
        reachable = [c for c in ids if any(hierarchy_related(c, t) for t in TIER1_CHECKABLE)]
        if reachable:
            raise ValueError(f"off-surface tier-{tier} pool holds scan-reachable controls {reachable}")
    return tuple(sorted(pools[2])), tuple(sorted(pools[3]))


def _off_surface_internal(rng: random.Random, posture: str) -> tuple[InternalAssessment, ...]:
    """Draw the firm's Tier-2 internal-assessment records over the off-surface catalogue."""
    internal, _ = off_surface_pools()
    coverage = OFF_SURFACE_COVERAGE[posture]
    return tuple(
        InternalAssessment(control_id=cid, compliant=rng.random() >= P_INTERNAL_GAP)
        for cid in internal
        if rng.random() < coverage
    )


def _off_surface_declarations(
    rng: random.Random, case_id: str, posture: str
) -> tuple[Attestation, ...]:
    """Draw the firm's Tier-3 declarations on off-surface controls.

    One declarations model, one pool: these are minted exactly like the on-surface declarations of
    :func:`_attestations`, with the same statement, signer, and validity-window model, and they
    join the same ``attestations`` tuple. The contradiction detector therefore sees them and must
    ignore them on its own, which is the point: nothing special-cases them out.
    """
    _, declarable = off_surface_pools()
    coverage = OFF_SURFACE_COVERAGE[posture]
    out: list[Attestation] = []
    for cid in declarable:
        if rng.random() >= coverage:
            continue
        digest = hashlib.sha256(f"{case_id}:{cid}".encode()).hexdigest()
        valid_from, valid_until = _attestation_window(rng)
        out.append(
            Attestation(
                attestation_id=f"att-{case_id}-{cid}",
                control_id=cid,
                statement=f"Control {cid} is implemented and operating effectively.",
                signer_identity=f"ciso@{case_id}",
                payload_hash=digest,
                valid_from=valid_from,
                valid_until=valid_until,
            )
        )
    return tuple(out)


def draw_off_surface_evidence(
    rng: random.Random, case_id: str, posture: str
) -> tuple[tuple[InternalAssessment, ...], tuple[Attestation, ...]]:
    """Both off-surface streams, drawn in a fixed order (Tier 2 then Tier 3).

    **Must be the LAST draw of a case.** Every existing per-firm draw (estate, true issues,
    observation, on-surface declarations) then consumes the same stream positions it did before
    this evidence existed, so the corpus, the recovery metrics, and the contradiction metrics are
    byte-identical to the two-tier corpus. Cohort B calls this too, for the same reason.
    """
    return _off_surface_internal(rng, posture), _off_surface_declarations(rng, case_id, posture)


def _weighted_condition(rng: random.Random) -> str:
    """Draw one host's scan condition from ``CONDITION_SHARES``."""
    r = rng.random()
    upto = 0.0
    for cond in SCAN_CONDITIONS:
        upto += CONDITION_SHARES[cond]
        if r <= upto:
            return cond
    return SCAN_CONDITIONS[-1]


def _draw_conditions(rng: random.Random, hosts: list[str]) -> tuple[dict[str, str], float]:
    """A per-host scan condition and one per-org scanner competence, drawn once (seeded)."""
    competence = COMPETENCE_MIN + (COMPETENCE_MAX - COMPETENCE_MIN) * rng.random()
    conditions = {host: _weighted_condition(rng) for host in hosts}
    return conditions, competence


def _condition_factor(check: CheckId, condition: str) -> float:
    """The acquisition factor for a check under a host condition (origin checks hide behind a CDN,
    edge checks are still served from the edge)."""
    table = CONDITION_FACTOR_ORIGIN if check in _ORIGIN_CHECKS else CONDITION_FACTOR_EDGE
    return table[condition]


def _effective_sensitivity(check: CheckId, host: str, conditions: dict[str, str], competence: float) -> float:
    """Signal reliability scaled by the host's acquisition condition and the org's scan competence.

    DNS-observable apex signals are exempt from the host condition and competence: they are queried
    from DNS, so a host's HTTP reachability does not gate them."""
    base = SENSITIVITY[check]
    if check in _HOST_FETCHED_CHECKS:
        return base * competence * _condition_factor(check, conditions[host])
    return base


def _observe(
    rng: random.Random,
    true: list[InjectedFinding],
    hosts: list[str],
    apex: str,
    conditions: dict[str, str],
    competence: float,
) -> list[InjectedFinding]:
    """OBSERVED state: the detection model over the true issues, plus scanner false alarms.

    Detection is the check's signal reliability scaled by the host's acquisition condition and the
    org's scan competence (host-fetched checks only), so obstructed hosts lose their findings
    together. False alarms on a host are likewise scaled down by its condition: a scanner that cannot
    reach a host does not raise spurious findings on it. A firm whose scan surfaces nothing keeps an
    empty finding set: no true issue is ever copied into the observation (leakage control)."""
    true_present = {(i.asset, i.check) for i in true}
    observed: list[InjectedFinding] = []
    for inj in true:  # sensitivity: some truly-present issues are not confirmable externally
        if rng.random() < _effective_sensitivity(inj.check, inj.asset, conditions, competence):
            observed.append(inj)
    # every check with a nonzero rate: the fixed tuple keeps the baseline's draw order, and a sweep
    # that raises the rate of a deterministic read adds that check after it
    extra = tuple(c for c, rate in FALSE_ALARM.items() if rate > 0 and c not in _FALSE_ALARM_CHECKS)
    for host in hosts:  # false alarms: the scanner reports issues that are not truly there
        label = _host_label(host, apex)
        for check in _FALSE_ALARM_CHECKS + extra:
            if check in _APEX_ONLY_CHECKS and host != apex:
                continue
            if check in _DEV_ONLY_CHECKS and label not in _DEV_LABELS:
                continue
            if (host, check) in true_present:
                continue
            fa = FALSE_ALARM[check]
            if check in _HOST_FETCHED_CHECKS:
                fa *= _condition_factor(check, conditions[host])
            if rng.random() < fa:
                observed.append(InjectedFinding(asset=host, check=check))
    return _dedup(observed)


def _generate_case(
    index: int,
    seed: int,
    key: dict[CheckId, frozenset[str]],
    all_controls: frozenset[str],
    *,
    clean: bool = False,
) -> EvalCase:
    """Build one evaluation case. When ``clean`` is set, the organization has no true external gap
    (a well-run estate): the only observed findings are scanner false alarms, so the case measures
    whether ATLAS wrongly asserts a control it should not (a negative control for specificity)."""
    rng = random.Random(seed + index)
    band = _pick_size_band(rng)  # firm-size band FIRST: it conditions posture and estate size
    sector = _weighted_choice(rng, SECTORS, [s.prevalence for s in SECTORS])
    posture = _pick_posture(rng, band)
    apex = _domain_for(rng, index)

    pool = _SUBDOMAIN_POOLS[sector.name]
    n_subs = min(rng.randint(band.min_subs, band.max_subs), len(pool))
    sub_names = rng.sample(pool, n_subs)
    hosts = [apex, *(f"{s}.{apex}" for s in sub_names)]

    conditions, competence = _draw_conditions(rng, hosts)
    true: list[InjectedFinding] = []
    forced_true = False
    if not clean:
        true, forced_true = _true_issues(rng, sector, hosts, apex, posture.mult)
    observed = _observe(rng, true, hosts, apex, conditions, competence)
    true_control_ids = _control_ids_for(true, key)
    attestations = _attestations(rng, f"eval-{index:03d}", true_control_ids, all_controls)
    # Off-surface evidence is drawn LAST, so every draw above holds the stream position it held
    # before this stream existed and the recovery and contradiction corpora are unchanged.
    internal, off_surface = draw_off_surface_evidence(rng, f"eval-{index:03d}", posture.name)
    attestations = attestations + off_surface

    per_asset: dict[str, frozenset[str]] = {}
    for inj in true:
        per_asset[inj.asset] = per_asset.get(inj.asset, frozenset()) | key[inj.check]

    assets = [SyntheticAsset(value=apex, asset_type=AssetType.DOMAIN.value)] + [
        SyntheticAsset(value=f"{s}.{apex}", asset_type=AssetType.SUBDOMAIN.value) for s in sub_names
    ]
    profile = SyntheticProfile(profile_id=f"eval-{index:03d}", apex=apex, assets=assets)
    # Manual annotation time modelled as ~4 min per observed finding + 5 min base (toolkit baseline).
    baseline = 300.0 + 240.0 * len(observed)
    return EvalCase(
        case_id=f"eval-{index:03d}",
        sector=sector.name,
        size_band=band.name,
        profile=profile,
        injected=tuple(observed),
        true_injected=tuple(true),
        ground_truth=GroundTruth(
            control_ids=true_control_ids,
            observed_ids=_control_ids_for(observed, key),
            per_asset=per_asset,
        ),
        attestations=attestations,
        posture=posture.name,
        baseline_seconds=baseline,
        internal_evidence=internal,
        forced_true_fallback=forced_true,
        scan_conditions=conditions,
        scanner_competence=competence,
    )


def _weighted_choice(rng: random.Random, items: tuple[Sector, ...], weights: list[float]) -> Sector:
    total = sum(weights)
    r = rng.random() * total
    upto = 0.0
    for item, w in zip(items, weights, strict=True):
        upto += w
        if r <= upto:
            return item
    return items[-1]


def _pick_size_band(rng: random.Random) -> SizeBand:
    """Draw a firm-size band from the SOURCED Class-B population split (SOURCES.md §1)."""
    r = rng.random() * sum(b.share for b in SIZE_BANDS)
    upto = 0.0
    for b in SIZE_BANDS:
        upto += b.share
        if r <= upto:
            return b
    return SIZE_BANDS[-1]


def _pick_posture(rng: random.Random, band: SizeBand) -> Posture:
    """Draw a posture from the band's DECLARED, band-conditioned shares (SOURCES.md §5)."""
    shares = band.posture_shares
    r = rng.random() * sum(shares.values())
    upto = 0.0
    for name in _POSTURE_NAMES:
        upto += shares[name]
        if r <= upto:
            return _POSTURE_BY_NAME[name]
    return _POSTURE_BY_NAME[_POSTURE_NAMES[-1]]


def generate_cases(n: int = 100, *, seed: int | None = None) -> list[EvalCase]:
    """Generate ``n`` deterministic evaluation cases (default seed = ``GLOBAL_SEED``)."""
    if n <= 0:
        raise ValueError("n must be positive")
    resolved = get_settings().global_seed if seed is None else seed
    key = expert_key()
    all_controls = frozenset().union(*key.values())
    return [_generate_case(i, resolved, key, all_controls) for i in range(n)]


def generate_clean_cases(n: int = 30, *, seed: int | None = None) -> list[EvalCase]:
    """Generate ``n`` deterministic CLEAN cases: well-run estates with no true external gap.

    The only findings a clean case can carry are scanner false alarms, so the pipeline's output on
    these is a negative control: ideally it asserts no Tier-1 gap. Offset the seed so a clean corpus
    does not alias the main corpus's domains/estates."""
    if n <= 0:
        raise ValueError("n must be positive")
    resolved = (get_settings().global_seed if seed is None else seed) + 500_000
    key = expert_key()
    all_controls = frozenset().union(*key.values())
    return [_generate_case(i, resolved, key, all_controls, clean=True) for i in range(n)]
