"""The owner's report: bilingual, right-to-left, every statement tied to a finding, an answer or the audit log."""

from __future__ import annotations

import html
from collections import Counter
from datetime import UTC, datetime
from typing import Any

from officer import taxonomy
from officer.assessment import Assessed, Tile
from officer.fixes import controls_of
from officer.labels import ANSWER_AR, check_ar
from officer.questions import by_qid

TILE_AR = {
    Tile.VIOLATION: "مخالفة مرصودة من الخارج", Tile.CLEAN: "لم تُرصد مخالفة من الخارج",
    Tile.CONTRADICTED: "إقرار يناقضه الفحص", Tile.NOT_OBSERVABLE: "تعذّرت رؤيته من الخارج",
    Tile.DECLARED_EVIDENCE: "مُقرّ مع دليل", Tile.DECLARED: "مُقرّ (إقرار)", Tile.SELF_GAP: "فجوة أقرّ بها المالك",
    Tile.NEEDS_ANSWER: "يحتاج إجابة", Tile.UNKNOWN: "غير معروف",
}


def render(agent: Any, assessed: Assessed, metrics: dict[str, Any]) -> str:
    e = html.escape
    company, state, log = agent.company, agent.state, agent.log
    scope_rows = {k for k, v in (assessed.tiles.items())}
    counts = Counter(t for k, t in assessed.tiles.items() if k in scope_rows)
    findings = sorted({(h, c.value) for h, c in state.findings})
    contradictions = [ev["data"] for ev in log.events if ev["type"] == "contradiction"]
    fixes = [ev["data"] for ev in log.events if ev["type"] == "fix_result"]
    escalations = state.escalations
    now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")

    def row(cells: list[str]) -> str:
        return "<tr>" + "".join(f"<td>{c}</td>" for c in cells) + "</tr>"

    finding_rows = "".join(
        row([e(check_ar(check)), f"<bdi dir=ltr>{e(check)}</bdi>", f"<bdi dir=ltr>{e(host)}</bdi>",
             e(", ".join(controls_of(_check(check))) or "—")])
        for host, check in findings
    )
    answer_rows = "".join(
        row([e(qid), e(by_qid()[qid].prompt_ar), e(ANSWER_AR[p.answer.value]), "✓" if p.evidence_offered else "—",
             str(len(by_qid()[qid].controls))])
        for qid, p in state.answers.items()
    )
    contra_rows = "".join(row([e(c["qid"]), e(", ".join(c["controls"])), e(", ".join(c["observed"]))])
                          for c in contradictions)
    fix_rows = "".join(row([e(f["fix_id"]), _fix_state(f)]) for f in fixes)
    esc_rows = "".join(row([e(x["reason"]), e(x["text_ar"])]) for x in escalations)
    tile_rows = "".join(row([e(TILE_AR[t]), str(n)]) for t, n in counts.most_common())
    return f"""<!doctype html><html lang="ar" dir="rtl"><head><meta charset="utf-8">
<title>تقرير الامتثال: {e(company.name_ar)}</title>
<style>body{{font-family:'IBM Plex Sans Arabic',system-ui,sans-serif;max-width:900px;margin:32px auto;padding:0 16px;
color:#0F1720;background:#fff}}h1{{font-size:22px}}h2{{font-size:16px;margin-top:28px;border-bottom:2px solid #5B6CFF;
padding-bottom:4px}}table{{width:100%;border-collapse:collapse;font-size:13px}}td{{border-bottom:1px solid #E2DED5;
padding:6px 4px;vertical-align:top}}.kpi{{display:grid;grid-template-columns:repeat(4,1fr);gap:10px}}.kpi div{{
background:#F6F4EF;border-radius:10px;padding:10px}}.kpi b{{display:block;font-size:22px}}.muted{{color:#5B6672;
font-size:12px}}details{{background:#F6F4EF;border-radius:10px;padding:10px 14px;margin:8px 0}}summary{{cursor:pointer;font-weight:600}}h4{{font-size:14px;margin:14px 0 4px}}.blank{{color:#8A6D1F}}bdi{{font-family:'IBM Plex Mono',monospace}}</style></head><body>
<h1>تقرير تقييم الامتثال للأمن السيبراني</h1>
<p>{e(company.name_ar)} · <bdi dir=ltr>{e(company.apex)}</bdi> · النطاق: {e(str(metrics.get("scope")))} · {now}</p>
<div class="kpi"><div>لم تُرصد مخالفة من الخارج<b>{pct(metrics.get("assessed_after"))}</b>
<span class="muted">قبل المعالجة: {pct(metrics.get("assessed_before"))}</span></div>
<div>الموثّق<b>{pct(metrics.get("documented"))}</b><span class="muted">بأدلة أو إقرارات، ولا يُدمج مع الأول</span></div>
<div>تعديلات متحقق منها<b>{len(metrics.get("fixes_verified", []))}</b></div>
<div>تناقضات<b>{len(contradictions)}</b></div></div>
<p class="muted">الفحص الخارجي يختبر ولا يثبت: غياب المخالفة لا يعني الامتثال. الإقرارات مسجلة كإقرارات، لا كأدلة.
هذا التقرير لا يتضمن نص ضوابط الهيئة الوطنية للأمن السيبراني؛ المعرّفات تشير إلى إصداراتها الرسمية.</p>
<h2>حالة الضوابط ({len(assessed.tiles)} صفاً)</h2><table>{tile_rows}</table>
<h2>ما رصده الفحص الخارجي</h2><table>{finding_rows or row(["لا شيء"])}</table>
<h2>إجابات المالك</h2><table>{row(["السؤال", "النص", "الإجابة", "دليل", "ضوابط"])}{answer_rows}</table>
<h2>تناقضات بين الإجابات والفحص</h2><table>{contra_rows or row(["لا يوجد"])}</table>
<h2>المعالجة</h2><table>{fix_rows or row(["لا يوجد"])}</table>
<h2>أحيل إلى إنسان</h2><table>{esc_rows or row(["لا يوجد"])}</table>
{_plan(agent)}{_tickets(agent)}{_monitor(agent)}{_drafts(agent)}<h2>سجل التدقيق</h2><p class="muted">آخر بصمة في سلسلة الأحداث: <bdi dir=ltr>{e(log.head)}</bdi> ·
تحقق: <bdi dir=ltr>officer audit-verify</bdi></p>
<p class="muted">{e(taxonomy.counts().__repr__())}</p>
</body></html>"""


def _fix_state(f: dict[str, Any]) -> str:
    if f.get("reason") == "nothing_to_change":
        return "لا حاجة: لم يكن هناك ما يُغيَّر"
    return "✓ تحقق بفحص جديد" if f["verified"] else "✗ لم يتحقق"


def _monitor(agent: Any) -> str:
    m = getattr(agent, "monitor", None)
    if not m:
        return ""
    e = html.escape
    rounds = [ev["data"] for ev in agent.log.events if ev["type"] == "monitor_round" and ev["data"]["stage"] == "end"]
    rows = "".join(
        f"<tr><td>{r['round']}</td><td>{e(', '.join(r['new']) or 'لا جديد')}</td>"
        f"<td>{e(', '.join(r['verified']) or '—')}</td><td>{e(', '.join(r['approved'] + r['declined']) or '—')}</td>"
        f"<td>{e(', '.join(r['escalated']) or '—')}</td></tr>"
        for r in rounds
    )
    head = "<tr><td>الجولة</td><td>ما ظهر من جديد</td><td>أُصلح وتُحقق منه</td><td>بموافقتكم</td><td>أحيل</td></tr>"
    return (f"<h2>المراقبة المستمرة ({m['rounds']} جولات)</h2><p class=\"muted\">بعد التقييم يعيد الوكيل الفحص في كل "
            f"جولة، ويعيد تطبيق ما اعتمدتموه وثبت نجاحه إذا رجعت المشكلة، ويستأذنكم في أي تعديل جديد.</p>"
            f"<table>{head}{rows}</table>")


def _plan(agent: Any) -> str:
    from officer.workplan import action_plan  # noqa: PLC0415

    if not getattr(agent, "metrics", None):
        return ""
    items = action_plan(agent)
    if not items:
        return ""
    e = html.escape
    kind = {"exposure": "ظاهر للإنترنت", "handover": "تذكرة للدعم التقني", "gap": "فجوة أقررتم بها"}
    rows = "".join(f"<tr><td>{i.days} يوماً</td><td>{e(i.title_ar)}</td><td>{kind[i.kind]}</td>"
                   f"<td>{i.mandatory or '—'}</td></tr>" for i in items)
    ics = agent.log.path.with_suffix(".calendar.ics").name if agent.log.path else ""
    link = f' <a href="{e(ics)}">أضيفوا المهام الدورية إلى تقويمكم</a>' if ics else ""
    return (f"<h2>خطة العمل للأيام الـ٩٠ القادمة</h2><p class=\"muted\">مرتبة: ما يظهر للإنترنت أولاً، ثم الفجوات "
            f"الإلزامية، ثم الباقي.{link}</p><table><tr><td>خلال</td><td>المهمة</td><td>النوع</td>"
            f"<td>صفوف إلزامية</td></tr>{rows}</table>")


def _tickets(agent: Any) -> str:
    from officer.workplan import tickets  # noqa: PLC0415

    found = tickets(agent)
    if not found:
        return ""
    e = html.escape
    blocks = "".join(
        f"<details open><summary>{e(t['title_ar'])} · <bdi dir=ltr>{e(t['check'])}</bdi></summary>"
        f"<p>{e(t['why_ar'])}</p><p class=\"muted\">المواقع: "
        f"{'، '.join(f'<bdi dir=ltr>{e(h)}</bdi>' for h in t['hosts']) or '—'}</p>"
        f"<ol>{''.join(f'<li>{e(s)}</li>' for s in t['steps_ar'])}</ol>"
        f"<p class=\"muted\">بعد التنفيذ نعيد الفحص في جولة المراقبة التالية ونغلق التذكرة إن تحققنا.</p></details>"
        for t in found
    )
    return "<h2>تذاكر جاهزة للدعم التقني</h2><p class=\"muted\">ما لا نغيّره بأنفسنا: يحتاج من يدير الخادم، أو قد يقطع وصولكم إن غُيّر تلقائياً.</p>" + blocks


def _drafts(agent: Any) -> str:
    drafts = getattr(agent, "drafts", None)
    if not drafts:
        return ""
    blocks = "".join(f"<details><summary>{d.title_ar}</summary>{d.body}</details>" for d in drafts)
    return ("<h2>مسودات جاهزة لاعتمادكم</h2><p class=\"muted\">كتبها الوكيل من إجاباتكم وما رصده الفحص، وترك فراغات لما "
            "تعرفونه أنتم وحدكم. لا تُحتسب في التقييم حتى تعتمدوها وتطبقوها.</p>" + blocks)


def pct(value: float | None) -> str:
    return "—" if value is None else f"{round(value * 100)}%"


def _check(value: str) -> Any:
    from p2c.scanning.catalog import CheckId  # noqa: PLC0415

    return CheckId(value)
