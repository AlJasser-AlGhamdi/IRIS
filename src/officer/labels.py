"""Arabic names, urgency and hand-over steps for the engine's 32 detectors."""

from __future__ import annotations

CHECK_AR = {
    "missing_hsts": "ترويسة HSTS غير مفعّلة",
    "missing_csp": "سياسة أمان المحتوى (CSP) غير مفعّلة",
    "missing_x_frame_options": "لا حماية من تضمين الموقع في إطار",
    "missing_x_content_type_options": "ترويسة X-Content-Type-Options مفقودة",
    "missing_referrer_policy": "سياسة Referrer مفقودة",
    "missing_permissions_policy": "سياسة الأذونات مفقودة",
    "no_https_redirect": "الموقع لا يحوّل إلى HTTPS",
    "legacy_tls_version": "إصدار TLS قديم مفعّل",
    "weak_tls_cipher": "تشفير TLS ضعيف مفعّل",
    "expired_certificate": "شهادة منتهية",
    "self_signed_certificate": "شهادة موقّعة ذاتياً",
    "weak_certificate_key": "مفتاح شهادة ضعيف",
    "waf_absent": "لا يوجد جدار حماية لتطبيقات الويب",
    "no_ddos_protection": "لا حماية من هجمات حجب الخدمة",
    "exposed_internal_port": "خدمة داخلية ظاهرة للإنترنت",
    "exposed_management_port": "دخول عن بُعد ظاهر للإنترنت",
    "exposed_database_port": "قاعدة بيانات ظاهرة للإنترنت",
    "exposed_printer_service": "خدمة طباعة ظاهرة للإنترنت",
    "high_risk_port_open": "منفذ عالي الخطورة مفتوح",
    "outdated_exposed_software": "برنامج قديم ظاهر للإنترنت",
    "eol_software_exposed": "برنامج انتهى دعمه ظاهر للإنترنت",
    "exposed_login_panel": "لوحة دخول إدارية ظاهرة للإنترنت",
    "exposed_dev_environment": "بيئة تطوير مكشوفة",
    "exposed_sensitive_file": "ملف حساس مكشوف",
    "directory_listing_enabled": "عرض محتويات المجلدات مفعّل",
    "insecure_cookie": "ملفات تعريف ارتباط غير محمية",
    "spf_missing": "لا يوجد سجل SPF",
    "dmarc_missing_or_none": "لا توجد سياسة DMARC فعّالة",
    "dkim_missing": "توقيع DKIM غير مفعّل",
    "mta_sts_missing": "MTA-STS غير مفعّل",
    "dnssec_missing": "DNSSEC غير مفعّل",
    "dns_zone_transfer_open": "نقل منطقة DNS مفتوح للجميع",
}

URGENT = frozenset({
    "exposed_management_port", "exposed_database_port", "exposed_internal_port", "exposed_printer_service",
    "high_risk_port_open", "exposed_login_panel", "exposed_dev_environment", "exposed_sensitive_file",
    "outdated_exposed_software", "eol_software_exposed", "expired_certificate", "dns_zone_transfer_open",
    "directory_listing_enabled",
})

HEADERS = frozenset({"missing_hsts", "missing_csp", "missing_x_frame_options", "missing_x_content_type_options",
                     "missing_referrer_policy", "missing_permissions_policy"})

_CERT = ("أصدروا شهادة من جهة موثوقة (Let's Encrypt مجانية) بمفتاح 2048 بت على الأقل.", "فعّلوا التجديد التلقائي.")
_TLS = ("عطّلوا TLS 1.0 و1.1 والتشفير الضعيف، وأبقوا TLS 1.2 و1.3 فقط.",)
_EDGE = ("ضعوا الموقع خلف خدمة حماية (WAF أو CDN) تصدّ الهجمات الشائعة وحجب الخدمة.",)
STEPS: dict[str, tuple[str, ...]] = {
    "exposed_management_port": (
        "اجعلوا الدخول عن بُعد (SSH) متاحاً عبر VPN فقط، أو لعناوين محددة.",
        "عطّلوا الدخول بكلمة المرور واستخدموا المفاتيح فقط، وعطّلوا دخول المستخدم root.",
        "تأكدوا أن لديكم طريقة دخول بديلة قبل التغيير.",
    ),
    "exposed_login_panel": ("اجعلوا لوحة الدخول متاحة عبر VPN أو لعناوين محددة فقط.", "فعّلوا التحقق الثنائي لحساباتها."),
    "exposed_dev_environment": ("أوقفوا بيئة التطوير أو احموها بكلمة مرور وقيّدوها بعناوين محددة.",
                                "تأكدوا أنها لا تحمل بيانات حقيقية."),
    "exposed_sensitive_file": ("احذفوا الملف من الخادم أو امنعوا الوصول إليه.",
                               "غيّروا أي كلمة مرور أو مفتاح كان فيه، فقد يكون نُسخ."),
    "outdated_exposed_software": ("حدّثوا البرنامج إلى آخر إصدار مدعوم.", "فعّلوا التحديث التلقائي إن أمكن."),
    "eol_software_exposed": ("استبدلوا البرنامج بإصدار مدعوم؛ الإصدار الحالي لم يعد يتلقى تحديثات أمنية.",),
    "expired_certificate": _CERT,
    "self_signed_certificate": _CERT,
    "weak_certificate_key": _CERT,
    "legacy_tls_version": _TLS,
    "weak_tls_cipher": _TLS,
    "directory_listing_enabled": ("عطّلوا عرض محتويات المجلدات في إعدادات خادم الويب.",),
    "dns_zone_transfer_open": ("اقصروا نقل منطقة DNS على الخوادم الثانوية المعروفة فقط.",),
    "insecure_cookie": ("فعّلوا خصائص Secure وHttpOnly وSameSite لملفات تعريف الارتباط.",),
    "high_risk_port_open": ("أغلقوا المنفذ أو اقصروه على عناوين محددة.",),
    "dkim_missing": ("فعّلوا توقيع DKIM من لوحة مزوّد البريد وانشروا سجله.",),
    "mta_sts_missing": ("انشروا سياسة MTA-STS لبريدكم.",),
    "dnssec_missing": ("فعّلوا DNSSEC لدى مزوّد النطاق.",),
    "waf_absent": _EDGE,
    "no_ddos_protection": _EDGE,
    "headers": ("أضيفوا ترويسات الأمان في إعدادات خادم الويب: HSTS وCSP وX-Frame-Options وX-Content-Type-Options "
                "وReferrer-Policy وPermissions-Policy.",),
}

ANSWER_AR = {"yes": "نعم", "no": "لا", "partial": "جزئياً", "unknown": "لا أعرف"}


def check_ar(check: str) -> str:
    return CHECK_AR.get(check, check)


def count_ar(n: int, one: str, two: str, few: str, many: str) -> str:
    """A counted Arabic noun: one and two as words, 3 to 10 with the plural, 11 and up with the singular."""
    words = {1: one, 2: two}
    if n in words:
        return words[n]
    return f"{n} {few if n % 100 in range(3, 11) else many}"
