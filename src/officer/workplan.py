"""What happens after the report: a ranked 30/60/90-day plan, handover tickets for what the agent will not
change itself, and a calendar of recurring tasks the owner can import.

All three are built by code from the session's typed state; nothing here calls the model.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, timedelta
from typing import Any

from officer.contract import FixId
from officer.fixes import ESCALATE_ONLY, FIXES, fixes_for
from officer.labels import HEADERS, STEPS, URGENT, check_ar
from officer.questions import AnswerClass, by_qid
from officer.session import Scope, in_scope

URGENT_DAYS = 30
TOPIC_AR = {"Q01": "البريد", "Q02": "الشبكة", "Q03": "الطابعات", "Q04": "التشفير", "Q05": "الحسابات",
            "Q06": "التحديثات", "Q07": "النسخ الاحتياطي", "Q08": "الثغرات", "Q09": "السجلات", "Q10": "الحوادث",
            "Q11": "الحماية المادية", "Q12": "الأصول", "Q13": "الحوكمة", "Q14": "التوعية",
            "Q15": "الأجهزة والبيانات", "Q16": "المزوّدون والسحابة"}
DOC_FOR = {"Q13": "سياسة الأمن السيبراني", "Q10": "خطة الاستجابة للحوادث", "Q07": "إجراء النسخ الاحتياطي والاستعادة",
           "Q05": "إجراء إدارة الحسابات والصلاحيات", "Q12": "سجل الأصول", "Q14": "رسالة توعية للموظفين"}


@dataclass(frozen=True)
class Item:
    days: int  # due within
    kind: str  # "exposure", "handover" or "gap"
    title_ar: str
    mandatory: int
    source: str  # fix id, detector id or question id


def action_plan(agent: Any) -> list[Item]:
    """Open work, ranked: internet-facing exposures first, then mandatory gaps, then the rest."""
    scope = in_scope(agent.state.scope or Scope.CLASS_B)
    items: list[Item] = []
    open_checks = {c for _h, c in agent.state.findings}
    for spec in fixes_for(open_checks):
        items.append(Item(URGENT_DAYS, "exposure", spec.title_ar, 0, spec.fix_id.value))
    for t in tickets(agent):
        days = URGENT_DAYS if t["urgent"] else 90
        items.append(Item(days, "handover", t["title_ar"], 0, t["check"]))
    fixed = {c.value for f in agent.state.fixes_verified for c in FIXES[FixId(f)].clears}
    open_values = {c.value for c in open_checks}
    for qid, parsed in agent.state.answers.items():
        q = by_qid()[qid]
        seen = set(q.contradictable_by)
        if parsed.answer is AnswerClass.YES or (seen & fixed and not seen & open_values):
            continue  # nothing to do, or the agent's verified fix already closed what the owner admitted
        mandatory = sum(scope.get(c, False) for c in q.controls)
        doc = DOC_FOR.get(qid)
        title = f"{TOPIC_AR[qid]}: " + (f"اعتماد مسودة «{doc}» وتطبيقها" if doc else "سدّ الفجوة وتوثيق ذلك")
        items.append(Item(60 if mandatory else 90, "gap", title, mandatory, qid))
    order = {"exposure": 0, "handover": 1, "gap": 2}
    return sorted(items, key=lambda i: (i.days, order[i.kind], -i.mandatory))


def tickets(agent: Any) -> list[dict[str, Any]]:
    """A ready-to-send ticket for each open problem the agent will not change itself: risky ones it
    escalated, fixes a re-scan could not confirm, and findings outside its allowlisted fixes."""
    hosts_of: dict[str, list[str]] = {}
    for host, check in sorted(agent.state.findings):
        key = "headers" if check.value in HEADERS else check.value
        if host not in hosts_of.setdefault(key, []):
            hosts_of[key].append(host)
    out: dict[str, dict[str, Any]] = {}
    for esc in agent.state.escalations:
        reason = esc["reason"]
        check = reason.split(":", 1)[1] if ":" in reason else ""
        if reason.startswith(("fix_not_verified", "fix_unverifiable", "fix_failed")):
            spec = FIXES[FixId(check)]
            out[check] = {"check": check, "title_ar": spec.title_ar, "why_ar": esc["text_ar"], "urgent": True,
                          "hosts": [], "steps_ar": [spec.steps_ar]}
        elif check in STEPS and check in hosts_of:
            out[check] = {"check": check, "title_ar": check_ar(check), "why_ar": esc["text_ar"], "urgent": True,
                          "hosts": hosts_of[check], "steps_ar": list(STEPS[check])}
    fixable = {c.value for f in FIXES.values() for c in f.clears} | {c.value for c in ESCALATE_ONLY}
    for check, hosts in hosts_of.items():
        if check in out or check in fixable or check not in STEPS:
            continue
        title = "ترويسات الأمان في الموقع" if check == "headers" else check_ar(check)
        out[check] = {"check": check, "title_ar": title, "why_ar": "رصده الفحص، وإصلاحه يحتاج من يدير الخادم.",
                      "urgent": check in URGENT, "hosts": hosts, "steps_ar": list(STEPS[check])}
    return sorted(out.values(), key=lambda t: (not t["urgent"], t["check"]))


def calendar_ics(agent: Any, start: date | None = None) -> str:
    """Recurring tasks as an iCalendar file (RFC 5545) the owner can import into any calendar."""
    day = start or agent.clock().date()
    name = agent.company.name_ar
    tasks = [
        ("جولة مراقبة أمنية", "FREQ=WEEKLY", 7, "يعيد الوكيل الفحص ويعالج ما رجع."),
        ("تجربة استعادة من النسخة الاحتياطية", "FREQ=MONTHLY;INTERVAL=3", 90, "استعيدوا ملفاً وقاعدة بيانات وسجلوا النتيجة."),
        ("مراجعة الحسابات والصلاحيات", "FREQ=MONTHLY;INTERVAL=6", 180, "احذفوا ما لم يعد مستخدماً وتأكدوا من التحقق الثنائي."),
        ("تذكير الموظفين برسائل التصيّد", "FREQ=MONTHLY;INTERVAL=3", 30, "أرسلوا رسالة التوعية للموظفين."),
        ("مراجعة سياسة الأمن السيبراني", "FREQ=YEARLY", 365, "راجعوا السياسة واعتمدوا أي تعديل."),
        ("تمرين مكتبي على حادث برنامج فدية", "FREQ=YEARLY", 300, "طبّقوا خطة الاستجابة للحوادث على سيناريو."),
    ]
    stamp = agent.clock().strftime("%Y%m%dT%H%M%SZ")
    lines = ["BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//compliance-officer//calendar//AR", "CALSCALE:GREGORIAN"]
    for i, (title, rule, offset, note) in enumerate(tasks):
        first = (day + timedelta(days=offset)).strftime("%Y%m%d")
        lines += ["BEGIN:VEVENT", f"UID:{agent.company.apex}-{i}-{stamp}@officer", f"DTSTAMP:{stamp}",
                  f"DTSTART;VALUE=DATE:{first}", f"RRULE:{rule}", f"SUMMARY:{title} · {name}",
                  f"DESCRIPTION:{note}", "END:VEVENT"]
    lines.append("END:VCALENDAR")
    return "\r\n".join(lines) + "\r\n"
