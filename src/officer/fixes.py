"""Which scan group reads each detector, and which allowlisted fix clears which detectors."""

from __future__ import annotations

from dataclasses import dataclass

from officer.contract import FixId, Group
from p2c.scanning.catalog import CATALOG, CheckId

C = CheckId

GROUP_OF: dict[CheckId, Group] = {
    C.SPF_MISSING: Group.DNS, C.DMARC_MISSING_OR_NONE: Group.DNS, C.DKIM_MISSING: Group.DNS,
    C.MTA_STS_MISSING: Group.DNS, C.DNSSEC_MISSING: Group.DNS, C.DNS_ZONE_TRANSFER_OPEN: Group.DNS,
    C.NO_DDOS_PROTECTION: Group.DNS,
    C.MISSING_HSTS: Group.WEB, C.MISSING_CSP: Group.WEB, C.MISSING_X_FRAME_OPTIONS: Group.WEB,
    C.MISSING_X_CONTENT_TYPE_OPTIONS: Group.WEB, C.MISSING_REFERRER_POLICY: Group.WEB,
    C.MISSING_PERMISSIONS_POLICY: Group.WEB, C.NO_HTTPS_REDIRECT: Group.WEB, C.INSECURE_COOKIE: Group.WEB,
    C.DIRECTORY_LISTING_ENABLED: Group.WEB, C.EXPOSED_SENSITIVE_FILE: Group.WEB,
    C.EXPOSED_DEV_ENVIRONMENT: Group.WEB, C.EXPOSED_LOGIN_PANEL: Group.WEB, C.WAF_ABSENT: Group.WEB,
    C.OUTDATED_EXPOSED_SOFTWARE: Group.WEB, C.EOL_SOFTWARE_EXPOSED: Group.WEB,
    C.LEGACY_TLS_VERSION: Group.TLS, C.WEAK_TLS_CIPHER: Group.TLS, C.EXPIRED_CERTIFICATE: Group.TLS,
    C.SELF_SIGNED_CERTIFICATE: Group.TLS, C.WEAK_CERTIFICATE_KEY: Group.TLS,
    C.EXPOSED_INTERNAL_PORT: Group.PORTS, C.EXPOSED_MANAGEMENT_PORT: Group.PORTS,
    C.HIGH_RISK_PORT_OPEN: Group.PORTS, C.EXPOSED_DATABASE_PORT: Group.PORTS,
    C.EXPOSED_PRINTER_SERVICE: Group.PORTS,
}
assert set(GROUP_OF) == set(CheckId), "every detector belongs to exactly one scan group"


@dataclass(frozen=True)
class FixSpec:
    fix_id: FixId
    clears: tuple[CheckId, ...]
    group: Group
    title_ar: str
    title_en: str
    # What a real owner or their IT provider does; the lab applies the same change itself.
    steps_ar: str
    steps_en: str


FIXES: dict[FixId, FixSpec] = {
    f.fix_id: f
    for f in (
        FixSpec(FixId.PUBLISH_SPF, (C.SPF_MISSING,), Group.DNS,
                "نشر سجل SPF", "Publish an SPF record",
                "أضف سجل TXT على النطاق بالقيمة: v=spf1 mx -all (أو قيمة مزوّد بريدكم).",
                "Add a TXT record on the domain: v=spf1 mx -all (or your mail provider's value)."),
        FixSpec(FixId.SET_DMARC_REJECT, (C.DMARC_MISSING_OR_NONE,), Group.DNS,
                "ضبط سياسة DMARC على الرفض", "Set the DMARC policy to reject",
                "عدّل سجل TXT في _dmarc إلى: v=DMARC1; p=reject",
                "Set the TXT record at _dmarc to: v=DMARC1; p=reject"),
        FixSpec(FixId.CLOSE_DB_PORT, (C.EXPOSED_DATABASE_PORT, C.EXPOSED_INTERNAL_PORT), Group.PORTS,
                "إغلاق منفذ قاعدة البيانات", "Close the database port",
                "امنع المنفذ 3306 من الإنترنت في الجدار الناري، واترك الوصول من الشبكة الداخلية فقط.",
                "Block port 3306 from the internet at the firewall; allow it from the internal network only."),
        FixSpec(FixId.CLOSE_CACHE_PORT, (C.EXPOSED_INTERNAL_PORT, C.EXPOSED_DATABASE_PORT), Group.PORTS,
                "إغلاق منفذ خدمة التخزين المؤقت", "Close the cache service port",
                "امنع المنفذ 6379 من الإنترنت في الجدار الناري.",
                "Block port 6379 from the internet at the firewall."),
        FixSpec(FixId.CLOSE_PRINTER_PORTS, (C.EXPOSED_PRINTER_SERVICE,), Group.PORTS,
                "إخفاء خدمات الطباعة عن الإنترنت", "Take print services off the internet",
                "امنع المنفذين 631 و515 من الإنترنت، وأبقِ الطباعة داخل الشبكة.",
                "Block ports 631 and 515 from the internet; keep printing on the internal network."),
        FixSpec(FixId.CLOSE_FTP_PORT, (C.HIGH_RISK_PORT_OPEN,), Group.PORTS,
                "إغلاق خدمة FTP", "Close the FTP service",
                "أوقف خدمة FTP أو امنع المنفذ 21 من الإنترنت، واستخدم SFTP بدلاً منها.",
                "Stop the FTP service or block port 21 from the internet; use SFTP instead."),
        FixSpec(FixId.ENABLE_HTTPS_REDIRECT, (C.NO_HTTPS_REDIRECT,), Group.WEB,
                "تحويل HTTP إلى HTTPS تلقائياً", "Redirect HTTP to HTTPS",
                "فعّل في إعدادات الموقع تحويل كل طلبات HTTP إلى HTTPS (رمز 301).",
                "Enable a permanent (301) redirect of every HTTP request to HTTPS in the site settings."),
    )
}

# Findings the agent never fixes on its own: a wrong move locks the owner out, so a person decides.
ESCALATE_ONLY: dict[CheckId, str] = {
    C.EXPOSED_MANAGEMENT_PORT: "closing remote management could lock the owner out of the server",
}


def fixes_for(open_checks: set[CheckId]) -> list[FixSpec]:
    """Fixes that would clear at least one open finding."""
    return [f for f in FIXES.values() if set(f.clears) & open_checks]


def controls_of(check: CheckId) -> tuple[str, ...]:
    return CATALOG[check].control_ids
