"""Cohort B: a second, structurally independent synthetic-SME generator (robustness R2).

This is a transfer experiment, not a new headline claim. The toolkit's recovery number is an
integrity check that restates the modelled detection rates on one synthetic population. A fair
objection is that the number could be an artifact of *that one generator's structural choices*.
Cohort B answers it: a second population built to a genuinely different structural specification,
never tuned against cohort A, pushed through the identical pipeline and detection model. If
recovery and contradiction transfer, the result is not an artifact of the generator's structure,
and recovery is governed by the shared detection model, which is exactly the integrity-check
reading. The residual dependence on the modelled detection rates (conceded elsewhere) is unchanged.

What is DELIBERATELY IDENTICAL to ``synthetic.py`` (same pipeline, different population):
  * the 31-check catalog and ``CheckId`` set, and the mapping / :func:`expert_key`;
  * the detection model: ``SENSITIVITY`` / ``FALSE_ALARM`` and the scan-condition / competence
    acquisition model. Cohort B calls the SAME :func:`synthetic._observe` and
    :func:`synthetic._draw_conditions` verbatim, so a truly-present issue is confirmed, missed, or
    spuriously raised under byte-identical rates;
  * the attestation / contradiction mechanism: cohort B calls the SAME :func:`synthetic._attestations`;
  * the off-surface evidence stream: cohort B calls the SAME
    :func:`synthetic.draw_off_surface_evidence`, drawn last, keyed on its own posture label. Cohort
    B reports recovery and contradiction only, neither of which the stream touches, but running it
    two-tier while cohort A runs three-tier would make the two populations differ in the pipeline
    they exercise as well as in their structure, which is the one thing the comparison must not do.

What is STRUCTURALLY DIFFERENT (set once from first principles, NEVER tuned to match or to differ
from cohort A; see docs/DECISIONS.md, entry "R2 cohort B"):
  1. **Subdomain naming and host roles.** No sector-keyed semantic pools and no role inferred from a
     label's membership in an admin/dev set. Estates use flat indexed functional hostnames
     (``svc1``..``svcK``), and roles are assigned by an explicit POSITIONAL rule: the first
     subdomain is the admin host (login-panel heavy) and, when the estate is large enough, the last
     subdomain is the dev host (named ``sandbox`` so the shared detector's dev-environment
     false-alarm mode still recognises it). Cohort A places a variable number of role hosts drawn
     from semantic pools; cohort B places at most one of each, by position.
  2. **Finding-correlation model.** No category-conditional ``_SUBSET_PROB``. Each host carries a
     single latent NEGLECT score, and every check on that host fires with probability
     ``neglect * BASE_PREVALENCE[check]``. All of a host's findings therefore correlate through one
     latent that spans categories (a neglected host tends to fail web, TLS, and port checks at once),
     rather than through per-category presence with independent within-category draws.
  3. **Posture model.** No three fixed bands. Each firm draws a CONTINUOUS posture (a Beta-distributed
     firm-level neglect), and each host's neglect is that firm level plus bounded host-level jitter.
     The corpus spans a continuum rather than {strong, moderate, weak} at fixed shares.
  4. **Sector mix, exposure, estate sizes.** No 8x11 sector-by-category exposure matrix and no
     Monsha'at-sourced demographics. Four independent sectors parameterise only (a) the firm-neglect
     Beta and (b) the estate-size range; per-category exposure emerges from the neglect model, not
     from a weight matrix.

Cohort B shares the detection model and the mapping, so it probes robustness to POPULATION
STRUCTURE only, not to the detection assumptions (those are already probed by the +-0.10 detection
sweep and the Monte-Carlo ensemble in ``harness.py``).

Everything is a deterministic function of the seed: firm ``i`` is built from ``Random(seed_b + i)``
over fixed pools and orders, so ``make reproduce`` regenerates byte-identical cases. The seed is
offset from cohort A's so the two corpora never alias domains.
"""

from __future__ import annotations

import random

from p2c.config import get_settings
from p2c.discovery.synthetic import SyntheticAsset, SyntheticProfile
from p2c.evaluation.synthetic import (
    _APEX_CATEGORIES,
    _HOST_CATEGORIES,
    CATEGORIES,
    EvalCase,
    GroundTruth,
    InjectedFinding,
    _attestations,
    _control_ids_for,
    _dedup,
    _draw_conditions,
    _observe,
    draw_off_surface_evidence,
    expert_key,
)
from p2c.scanning.catalog import CheckId
from p2c.schemas.enums import AssetType

# Offset so cohort B never aliases cohort A's domains, clean corpus, or robustness corpora.
_SEED_OFFSET_B = 770_000

# Host-level neglect drives every check on the host together. BASE_PREVALENCE[check] is the
# probability a MAXIMALLY neglected host (neglect = 1.0) carries that issue; the realised
# probability is ``neglect * BASE_PREVALENCE[check]``. These are DECLARED modelling assumptions set
# once from the character of each check (common misconfigurations high, rare cryptographic or
# exposure faults low), NOT copied from cohort A's _SUBSET_PROB and NEVER tuned to a result. Every
# host-observable and apex-observable check has an entry; the two role checks (login panel, dev
# environment) are placed by role below and are not in this table.
BASE_PREVALENCE: dict[CheckId, float] = {
    # web headers and cookies: cheap to omit, common on a neglected host
    CheckId.MISSING_HSTS: 0.80,
    CheckId.MISSING_CSP: 0.75,
    CheckId.MISSING_X_FRAME_OPTIONS: 0.70,
    CheckId.MISSING_X_CONTENT_TYPE_OPTIONS: 0.65,
    CheckId.MISSING_REFERRER_POLICY: 0.60,
    CheckId.MISSING_PERMISSIONS_POLICY: 0.60,
    CheckId.NO_HTTPS_REDIRECT: 0.40,
    CheckId.INSECURE_COOKIE: 0.55,
    CheckId.DIRECTORY_LISTING_ENABLED: 0.20,
    CheckId.EXPOSED_SENSITIVE_FILE: 0.12,
    # web application firewall: often simply absent on a small estate
    CheckId.WAF_ABSENT: 0.70,
    # TLS: legacy protocol and cipher moderate; certificate faults rarer
    CheckId.LEGACY_TLS_VERSION: 0.50,
    CheckId.WEAK_TLS_CIPHER: 0.45,
    CheckId.EXPIRED_CERTIFICATE: 0.15,
    CheckId.SELF_SIGNED_CERTIFICATE: 0.15,
    CheckId.WEAK_CERTIFICATE_KEY: 0.12,
    # ports: a neglected host leaks some, databases least often
    CheckId.EXPOSED_INTERNAL_PORT: 0.30,
    CheckId.EXPOSED_MANAGEMENT_PORT: 0.35,
    CheckId.HIGH_RISK_PORT_OPEN: 0.35,
    CheckId.EXPOSED_DATABASE_PORT: 0.20,
    CheckId.EXPOSED_PRINTER_SERVICE: 0.10,
    # software currency
    CheckId.OUTDATED_EXPOSED_SOFTWARE: 0.55,
    CheckId.EOL_SOFTWARE_EXPOSED: 0.45,
    # email authentication (apex): DMARC/MTA-STS commonly weak, SPF/DKIM moderate
    CheckId.SPF_MISSING: 0.45,
    CheckId.DMARC_MISSING_OR_NONE: 0.65,
    CheckId.DKIM_MISSING: 0.55,
    CheckId.MTA_STS_MISSING: 0.70,
    # DNS security (apex): DNSSEC rarely deployed; open zone transfer rare
    CheckId.DNSSEC_MISSING: 0.80,
    CheckId.DNS_ZONE_TRANSFER_OPEN: 0.10,
    # DDoS mitigation (apex): commonly absent on a small firm
    CheckId.NO_DDOS_PROTECTION: 0.75,
}

# Role checks, placed by host role rather than by category presence.
BASE_LOGIN_ADMIN = 0.75  # login panel on the admin host
BASE_LOGIN_OTHER = 0.10  # login panel on an ordinary host
BASE_DEV_ENV = 0.70  # dev environment on the dev host

# Host-level neglect is the firm's continuous posture plus bounded per-host jitter.
_HOST_JITTER = 0.15
_DEV_LABEL_B = "sandbox"  # a dev-role token in synthetic._DEV_LABELS, so the shared detector recognises it


class SectorB:
    """A cohort-B sector: a prevalence, a firm-neglect Beta, and an estate-size range.

    Sectors parameterise only overall posture and estate size. There is no per-category exposure
    matrix; per-category exposure emerges from the neglect model. All values are DECLARED and
    independent of cohort A (no shared source), set once and never tuned.
    """

    __slots__ = ("name", "prevalence", "neglect_a", "neglect_b", "min_subs", "max_subs")

    def __init__(
        self, name: str, prevalence: float, neglect_a: float, neglect_b: float, min_subs: int, max_subs: int
    ) -> None:
        self.name = name
        self.prevalence = prevalence
        self.neglect_a = neglect_a  # Beta alpha for the firm-level neglect
        self.neglect_b = neglect_b  # Beta beta for the firm-level neglect
        self.min_subs = min_subs
        self.max_subs = max_subs


# Four independent sectors. Prevalences sum to 1.0. Beta(a, b) has mean a/(a+b): industrial firms run
# older stacks (more neglected), civic estates are better maintained (less), SaaS and commerce sit in
# between; estate sizes differ by sector (SaaS runs many services, professional firms few).
SECTORS_B: tuple[SectorB, ...] = (
    SectorB("saas", 0.30, 2.0, 2.5, 4, 10),  # mean neglect ~0.44, large estates
    SectorB("industrial", 0.25, 2.5, 2.0, 1, 4),  # mean neglect ~0.56, small estates
    SectorB("civic", 0.20, 2.0, 3.0, 2, 6),  # mean neglect ~0.40, medium estates
    SectorB("commerce", 0.25, 2.2, 2.2, 3, 7),  # mean neglect ~0.50, medium-large estates
)

# gTLD-skewed pool, independent of cohort A's weights.
_TLDS_B: tuple[str, ...] = ("com", "sa", "com.sa", "io", "net")
_TLD_WEIGHTS_B: dict[str, float] = {"com": 0.45, "sa": 0.20, "com.sa": 0.15, "io": 0.12, "net": 0.08}
_SECTOR_TAG: dict[str, str] = {"saas": "sw", "industrial": "in", "civic": "cv", "commerce": "cm"}


def _clamp01(value: float) -> float:
    return 0.0 if value < 0.0 else 1.0 if value > 1.0 else value


def _weighted_tld_b(rng: random.Random) -> str:
    r = rng.random() * sum(_TLD_WEIGHTS_B.values())
    upto = 0.0
    for tld in _TLDS_B:
        upto += _TLD_WEIGHTS_B[tld]
        if r <= upto:
            return tld
    return _TLDS_B[-1]


def _pick_sector_b(rng: random.Random) -> SectorB:
    r = rng.random() * sum(s.prevalence for s in SECTORS_B)
    upto = 0.0
    for s in SECTORS_B:
        upto += s.prevalence
        if r <= upto:
            return s
    return SECTORS_B[-1]


def _build_estate(rng: random.Random, sector: SectorB, index: int) -> tuple[str, list[str], str, str | None]:
    """Apex plus indexed subdomains with roles assigned by explicit position.

    Returns ``(apex, hosts, admin_host, dev_host)``. Ordinary subdomains are ``svc1``..``svcK``; the
    first subdomain is the admin host (by position, kept as its indexed name), and, when the estate has
    at least three subdomains, the last subdomain is renamed to a dev-role token so the shared detector
    recognises it. Cohort A draws a variable count of role hosts from a semantic pool; cohort B fixes at
    most one of each by position.
    """
    apex = f"biz{index:03d}-{_SECTOR_TAG[sector.name]}.{_weighted_tld_b(rng)}"
    m = rng.randint(sector.min_subs, sector.max_subs)
    subs = [f"svc{i + 1}" for i in range(m)]
    dev_label: str | None = None
    if m >= 3:
        subs[-1] = _DEV_LABEL_B  # last subdomain becomes the dev host
        dev_label = _DEV_LABEL_B
    hosts = [apex, *(f"{s}.{apex}" for s in subs)]
    admin_host = f"{subs[0]}.{apex}" if m >= 1 else apex  # first subdomain is the admin host
    dev_host = f"{dev_label}.{apex}" if dev_label is not None else None
    return apex, hosts, admin_host, dev_host


def _true_issues_b(
    rng: random.Random,
    hosts: list[str],
    apex: str,
    admin_host: str,
    dev_host: str | None,
    firm_neglect: float,
) -> tuple[list[InjectedFinding], bool]:
    """Latent TRUE issues under the per-host latent-neglect correlation model.

    Each host draws one neglect score (the firm posture plus bounded jitter); every applicable check
    then fires with probability ``neglect * BASE_PREVALENCE[check]``, so a host's findings correlate
    across categories through that single latent. The draw order is fixed (hosts in list order, checks
    in category-tuple order) for byte determinism. Returns the issues and the never-empty-organization
    fallback flag (should stay False on the reported corpus, asserted in the tests)."""
    true: list[InjectedFinding] = []
    for host in hosts:
        neglect = _clamp01(firm_neglect + rng.uniform(-_HOST_JITTER, _HOST_JITTER))
        for cat in _HOST_CATEGORIES:  # web_headers, waf, tls, ports, software, eol
            for check in CATEGORIES[cat]:
                if rng.random() < neglect * BASE_PREVALENCE[check]:
                    true.append(InjectedFinding(asset=host, check=check))
        base_login = BASE_LOGIN_ADMIN if host == admin_host else BASE_LOGIN_OTHER
        if rng.random() < neglect * base_login:
            true.append(InjectedFinding(asset=host, check=CheckId.EXPOSED_LOGIN_PANEL))
        if host == dev_host and rng.random() < neglect * BASE_DEV_ENV:
            true.append(InjectedFinding(asset=host, check=CheckId.EXPOSED_DEV_ENVIRONMENT))
        if host == apex:  # email authentication, DNS security, and DDoS posture are domain-level
            for cat in _APEX_CATEGORIES:
                for check in CATEGORIES[cat]:
                    if rng.random() < neglect * BASE_PREVALENCE[check]:
                        true.append(InjectedFinding(asset=apex, check=check))
    used_fallback = not true
    if used_fallback:  # never a degenerate empty organization (matches cohort A's guard)
        true.append(InjectedFinding(asset=apex, check=CheckId.SPF_MISSING))
    return _dedup(true), used_fallback


def _firm_posture_label(neglect: float) -> str:
    """A coarse posture label for the schema field only (cohort B's posture is continuous)."""
    if neglect < 0.34:
        return "strong"
    if neglect < 0.67:
        return "moderate"
    return "weak"


def _generate_case_b(
    index: int, seed: int, key: dict[CheckId, frozenset[str]], all_controls: frozenset[str]
) -> EvalCase:
    """Build one cohort-B evaluation case, emitting the same EvalCase schema as cohort A."""
    rng = random.Random(seed + index)
    sector = _pick_sector_b(rng)
    firm_neglect = rng.betavariate(sector.neglect_a, sector.neglect_b)  # continuous firm posture
    apex, hosts, admin_host, dev_host = _build_estate(rng, sector, index)

    conditions, competence = _draw_conditions(rng, hosts)
    true, forced_true = _true_issues_b(rng, hosts, apex, admin_host, dev_host, firm_neglect)
    observed = _observe(rng, true, hosts, apex, conditions, competence)
    true_control_ids = _control_ids_for(true, key)
    attestations = _attestations(rng, f"evalb-{index:03d}", true_control_ids, all_controls)
    # Off-surface evidence, drawn LAST for the same reason as in cohort A: every draw above keeps
    # its stream position, so cohort B's gated recovery and contradiction numbers do not move.
    internal, off_surface = draw_off_surface_evidence(
        rng, f"evalb-{index:03d}", _firm_posture_label(firm_neglect)
    )
    attestations = attestations + off_surface

    per_asset: dict[str, frozenset[str]] = {}
    for inj in true:
        per_asset[inj.asset] = per_asset.get(inj.asset, frozenset()) | key[inj.check]

    sub_hosts = hosts[1:]
    assets = [SyntheticAsset(value=apex, asset_type=AssetType.DOMAIN.value)] + [
        SyntheticAsset(value=h, asset_type=AssetType.SUBDOMAIN.value) for h in sub_hosts
    ]
    profile = SyntheticProfile(profile_id=f"evalb-{index:03d}", apex=apex, assets=assets)
    baseline = 300.0 + 240.0 * len(observed)  # same modelled manual-annotation cost as cohort A
    return EvalCase(
        case_id=f"evalb-{index:03d}",
        sector=sector.name,
        size_band="broad" if len(hosts) > 4 else "compact",  # cohort-B size label (continuous estate)
        profile=profile,
        injected=tuple(observed),
        true_injected=tuple(true),
        ground_truth=GroundTruth(
            control_ids=true_control_ids,
            observed_ids=_control_ids_for(observed, key),
            per_asset=per_asset,
        ),
        attestations=attestations,
        posture=_firm_posture_label(firm_neglect),
        baseline_seconds=baseline,
        internal_evidence=internal,
        forced_true_fallback=forced_true,
        scan_conditions=conditions,
        scanner_competence=competence,
    )


def generate_cases_b(n: int = 100, *, seed: int | None = None) -> list[EvalCase]:
    """Generate ``n`` deterministic cohort-B evaluation cases (default seed = ``GLOBAL_SEED``).

    Cohort B is structurally independent of cohort A (see the module docstring) but emits the identical
    EvalCase schema, so the existing harness metrics score it unchanged. The seed is offset so the two
    corpora never share a domain."""
    if n <= 0:
        raise ValueError("n must be positive")
    resolved = (get_settings().global_seed if seed is None else seed) + _SEED_OFFSET_B
    key = expert_key()
    all_controls = frozenset().union(*key.values())
    return [_generate_case_b(i, resolved, key, all_controls) for i in range(n)]
