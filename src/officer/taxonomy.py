"""The 204-row control map: rows, tiers, Class B scope and Arabic group names, from the public overlay."""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import cache
from pathlib import Path

from p2c.mapping._arabic import DOMAIN_AR, SUBDOMAIN_AR

OVERLAY = Path(__file__).resolve().parents[2] / "taxonomy" / "release" / "sort_overlay.json"

DOMAIN_EN = {
    "1": "Governance",
    "2": "Defense",
    "3": "Resilience",
    "4": "Third parties and cloud",
}


@dataclass(frozen=True)
class Row:
    id: str
    kind: str
    domain: str
    subdomain: str  # "" for the NCNICC-only rows, which sit under their own heading
    tier: int  # 1 externally testable, 2 internal assessment, 3 declaration
    class_b: str | None  # "M" mandatory, "R" recommended, None outside Class B
    class_a: str | None
    scanner_checks: tuple[str, ...]

    @property
    def in_class_b(self) -> bool:
        return self.class_b in ("M", "R")


@cache
def rows() -> tuple[Row, ...]:
    data = json.loads(OVERLAY.read_text(encoding="utf-8"))
    out = []
    for r in data["controls"]:
        domain = r["domain"] or r["id"].split("-")[0]
        out.append(
            Row(
                id=r["id"],
                kind=r["kind"],
                domain=domain,
                subdomain=r["subdomain"] or "",
                tier=int(r["tier"]),
                class_b=r["ncnicc_class_b_status"],
                class_a=r["ncnicc_class_a_status"],
                scanner_checks=tuple(r["scanner_checks"]),
            )
        )
    return tuple(out)


@cache
def by_id() -> dict[str, Row]:
    return {r.id: r for r in rows()}


def subdomain_name(subdomain: str, lang: str = "ar") -> str:
    if not subdomain:
        return "ضوابط خاصة بالمنشآت الصغيرة والمتوسطة" if lang == "ar" else "NCNICC-only controls"
    return SUBDOMAIN_AR.get(subdomain, subdomain) if lang == "ar" else subdomain


def domain_name(domain: str, lang: str = "ar") -> str:
    return DOMAIN_AR.get(domain, domain) if lang == "ar" else DOMAIN_EN.get(domain, domain)


def counts() -> dict[str, int]:
    all_rows = rows()
    return {
        "rows": len(all_rows),
        "tier1": sum(r.tier == 1 for r in all_rows),
        "tier2": sum(r.tier == 2 for r in all_rows),  # noqa: PLR2004
        "tier3": sum(r.tier == 3 for r in all_rows),  # noqa: PLR2004
        "class_b": sum(r.in_class_b for r in all_rows),
        "class_b_mandatory": sum(r.class_b == "M" for r in all_rows),
    }
