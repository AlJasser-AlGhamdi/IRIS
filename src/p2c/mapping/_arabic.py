"""Arabic (MSA) working translations for the OSCAL catalog (Stage 4, bilingual).

The NCA publishes ECC-2:2024 / NCNICC-1:2025 as Arabic PDFs (the Arabic being the
legally binding text), but there is no machine-readable feed, so ATLAS re-encodes
the taxonomy. These strings are **unofficial working translations** authored for
bilingual evidence/reporting — they are clearly marked ``x-atlas-translation`` in
the catalog and must never be presented as the binding NCA Arabic text.

Coverage is honest and explicit:
- ``domain`` / ``subdomain`` names: full (4 + 28).
- The three ECC boilerplate control families (identify-document-approve / implement
  / periodic-review): generated from a reviewed template + the Arabic subdomain name.
- The 16 Tier-1 scanner-observable subcontrols (the ones that flow through the
  mapping/reporting path): hand-translated.
- Remaining Tier-2/3 detail subcontrols: marked ``pending`` (English prose retained)
  rather than machine-translated, so nothing unreviewed is presented as Arabic.
"""

from __future__ import annotations

from typing import Literal

TranslationStatus = Literal["translated", "template", "pending"]

DOMAIN_AR: dict[str, str] = {
    "1": "حوكمة الأمن السيبراني",
    "2": "تحصين الأمن السيبراني",
    "3": "صمود الأمن السيبراني",
    "4": "الأمن السيبراني المتعلق بالأطراف الخارجية والحوسبة السحابية",
}

SUBDOMAIN_AR: dict[str, str] = {
    "1-1": "استراتيجية الأمن السيبراني",
    "1-2": "إدارة الأمن السيبراني",
    "1-3": "سياسات وإجراءات الأمن السيبراني",
    "1-4": "أدوار ومسؤوليات الأمن السيبراني",
    "1-5": "إدارة مخاطر الأمن السيبراني",
    "1-6": "الأمن السيبراني ضمن إدارة مشاريع تقنية المعلومات",
    "1-7": "الالتزام بتشريعات ومعايير الأمن السيبراني",
    "1-8": "المراجعة والتدقيق الدوري للأمن السيبراني",
    "1-9": "الأمن السيبراني المتعلق بالموارد البشرية",
    "1-10": "برنامج التوعية والتدريب بالأمن السيبراني",
    "2-1": "إدارة الأصول",
    "2-2": "إدارة هويات الدخول والصلاحيات",
    "2-3": "حماية الأنظمة وأجهزة معالجة المعلومات",
    "2-4": "حماية البريد الإلكتروني",
    "2-5": "إدارة أمن الشبكات",
    "2-6": "أمن الأجهزة المحمولة",
    "2-7": "حماية البيانات والمعلومات",
    "2-8": "التشفير",
    "2-9": "إدارة النسخ الاحتياطية",
    "2-10": "إدارة الثغرات",
    "2-11": "اختبار الاختراق",
    "2-12": "إدارة سجلات الأحداث ومراقبة الأمن السيبراني",
    "2-13": "إدارة حوادث وتهديدات الأمن السيبراني",
    "2-14": "الأمن المادي",
    "2-15": "حماية تطبيقات الويب",
    "3-1": "جوانب صمود الأمن السيبراني في إدارة استمرارية الأعمال",
    "4-1": "الأمن السيبراني المتعلق بالأطراف الخارجية",
    "4-2": "الأمن السيبراني المتعلق بالحوسبة السحابية والاستضافة",
}

# Hand translations of individual control clauses are withheld from this public copy: they render
# NCA control text. Only the domain and subdomain names above ship here.
CLAUSE_AR: dict[str, str] = {}

# Boilerplate detection -> Arabic template (formatted with the Arabic subdomain name).
_TEMPLATE_IMPLEMENT = "يجب تطبيق متطلبات الأمن السيبراني في مجال {name}."
_TEMPLATE_IDENTIFY = "يجب تحديد وتوثيق واعتماد متطلبات الأمن السيبراني في مجال {name}."
_TEMPLATE_REVIEW = "يجب مراجعة تطبيق متطلبات الأمن السيبراني في مجال {name} بشكل دوري."


def _template_for(clause_en: str) -> str | None:
    lowered = clause_en.lower()
    if "periodically reviewed" in lowered:
        return _TEMPLATE_REVIEW
    if "identified, documented" in lowered:
        return _TEMPLATE_IDENTIFY
    if "shall be implemented" in lowered:
        return _TEMPLATE_IMPLEMENT
    return None


def arabic_clause(control_id: str, subdomain: str, clause_en: str) -> tuple[str, TranslationStatus]:
    """Return ``(arabic_prose, status)`` for a control clause.

    ``status`` is ``translated`` (hand), ``template`` (reviewed boilerplate pattern),
    or ``pending`` (no reviewed Arabic yet — caller retains English and flags it).
    """
    if control_id in CLAUSE_AR:
        return CLAUSE_AR[control_id], "translated"
    template = _template_for(clause_en)
    if template is not None:
        return template.format(name=SUBDOMAIN_AR.get(subdomain, subdomain)), "template"
    return "", "pending"
