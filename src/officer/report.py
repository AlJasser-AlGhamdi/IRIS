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


TILE_EN = {
    Tile.VIOLATION: "Violation observed", Tile.CLEAN: "No violation observed",
    Tile.CONTRADICTED: "Claim contradicted", Tile.NOT_OBSERVABLE: "Not observable",
    Tile.DECLARED_EVIDENCE: "Declared with evidence", Tile.DECLARED: "Declared", Tile.SELF_GAP: "Owner-reported gap",
    Tile.NEEDS_ANSWER: "Needs an answer", Tile.UNKNOWN: "Not known yet",
}
TILE_VAR = {
    Tile.VIOLATION: "violation", Tile.CLEAN: "clean", Tile.CONTRADICTED: "contradicted",
    Tile.NOT_OBSERVABLE: "steel", Tile.DECLARED_EVIDENCE: "declared", Tile.DECLARED: "declared-soft",
    Tile.SELF_GAP: "gap", Tile.NEEDS_ANSWER: "needs", Tile.UNKNOWN: "unknown",
}

CSS = """:root{color-scheme:dark;--carbon:#05070A;--graphite:#0D1218;--raised:#111922;--steel:#3A4654;--line:#24313E;
--white:#F4F8FB;--text:#C8D2DC;--muted:#758390;--cyan:#35D7FF;--violet:#716BFF;--violation:#FF4D5A;--clean:#39F0AE;
--contradicted:#FFB454;--needs:#53A8FF;--declared:#43D8C6;--declared-soft:rgba(67,216,198,.55);--gap:#FF8F4D;
--unknown:#26313C;--font:"Segoe UI",system-ui,sans-serif;--font-ar:"Segoe UI",Tahoma,system-ui,sans-serif;
--display:Bahnschrift,"Segoe UI",system-ui,sans-serif;--mono:"Cascadia Mono",Consolas,ui-monospace,monospace}
*{box-sizing:border-box}html,body{margin:0}
body{background:radial-gradient(900px 520px at 72% -180px,rgba(113,107,255,.13),transparent 72%),
linear-gradient(rgba(53,215,255,.025) 1px,transparent 1px),linear-gradient(90deg,rgba(53,215,255,.025) 1px,transparent 1px),
var(--carbon);background-size:auto,48px 48px,48px 48px,auto;color:var(--text);font:14px/1.65 var(--font);
-webkit-font-smoothing:antialiased}
html[lang=ar] body{font-family:var(--font-ar)}
.wrap{max-width:980px;margin:0 auto;padding:28px 20px 72px}
.top{display:flex;align-items:center;gap:14px;padding-bottom:18px;border-bottom:1px solid var(--line)}
.top svg{width:40px;height:40px;flex:none}.word{color:var(--white);font:600 18px/1 var(--display);letter-spacing:.3em}
.tag{margin-inline-start:auto;color:var(--muted);font:11px/1.4 var(--mono);text-align:end}
h1{margin:30px 0 6px;color:var(--white);font:600 28px/1.25 var(--display)}
.meta{color:var(--muted);font-size:13px}.meta bdi{color:var(--text)}
.kpi{display:grid;grid-template-columns:repeat(4,1fr);gap:1px;margin:24px 0 10px;padding:1px;background:var(--line)}
.kpi div{padding:16px 16px 14px;background:var(--graphite);color:var(--muted);font-size:12px}
.kpi b{display:block;margin:6px 0 2px;color:var(--white);font:600 34px/1.1 var(--mono)}
.kpi div:nth-child(1) b{color:var(--cyan)}.kpi div:nth-child(2) b{color:#B8B5FF}
.kpi div:nth-child(3) b{color:var(--clean)}.kpi div:nth-child(4) b{color:var(--contradicted)}
.note{margin:12px 0 0;color:var(--muted);font-size:12px}
.panel{margin-top:18px;background:rgba(5,7,10,.97);border:1px solid var(--line)}
.panel-head{display:flex;align-items:center;gap:10px;padding:12px 16px;border-bottom:1px solid var(--line)}
.panel-index{color:var(--cyan);font:700 11px var(--mono)}
.panel-head h2{margin:0;color:var(--white);font:700 12px/1.3 var(--font);letter-spacing:.14em;text-transform:uppercase}
html[lang=ar] .panel-head h2{letter-spacing:0;text-transform:none;font-size:14px}
.panel-body{padding:14px 16px}.panel-body>p:first-child{margin-top:0}
table{width:100%;border-collapse:collapse;font-size:13px}td{padding:9px 8px;border-bottom:1px solid var(--line);vertical-align:top}
tr:last-child td{border-bottom:0}tr.h td{color:var(--muted);font:700 10.5px/1.4 var(--mono);letter-spacing:.08em;text-transform:uppercase}
html[lang=ar] tr.h td{font-family:var(--font-ar);font-size:12px;letter-spacing:0}
bdi,.id{color:#9FB0BF;font:12px var(--mono)}.muted{color:var(--muted);font-size:12.5px}
.bar{display:flex;height:16px;margin:4px 0 14px;gap:2px}.bar span{display:block;min-width:3px}
.legend{display:flex;flex-wrap:wrap;gap:8px 18px;font-size:12.5px}.legend span{display:inline-flex;align-items:center;gap:7px}
.legend i{width:10px;height:10px;display:inline-block}.legend b{color:var(--white);font:600 12px var(--mono)}
.chip{display:inline-block;padding:2px 10px;border:1px solid;font-size:12px;white-space:nowrap}
.chip.ok{color:var(--clean);border-color:rgba(57,240,174,.45);background:rgba(57,240,174,.07)}
.chip.bad{color:var(--violation);border-color:rgba(255,77,90,.45);background:rgba(255,77,90,.07)}
.chip.warn{color:var(--contradicted);border-color:rgba(255,180,84,.45);background:rgba(255,180,84,.07)}
.chip.info{color:var(--muted);border-color:var(--line)}
.days{color:var(--cyan);font:600 12px var(--mono);white-space:nowrap}
details{margin:10px 0;background:var(--graphite);border:1px solid var(--line);border-inline-start:2px solid var(--violet)}
details.urgent{border-inline-start-color:var(--violation)}
summary{padding:11px 14px;color:var(--white);font-weight:600;cursor:pointer}details>*:not(summary){margin-inline:14px}
details>ol,details>ul{padding-inline-start:22px}details table{width:calc(100% - 28px)}
h4{margin:16px 14px 4px;color:var(--cyan);font-size:13px}
.blank{color:var(--contradicted)}a{color:var(--cyan)}a:hover{color:var(--white)}
.foot{margin-top:28px;color:var(--muted);font:11px/1.6 var(--mono)}
@media (max-width:700px){.kpi{grid-template-columns:1fr 1fr}.tag{display:none}}
@media print{:root{color-scheme:light;--carbon:#fff;--graphite:#fff;--raised:#F5F7F9;--line:#D6DDE3;--white:#0B1117;
--text:#1B2630;--muted:#5B6672;--cyan:#0A7EA4;--clean:#0E8F62;--contradicted:#B86E00;--violation:#C9252F;--unknown:#E3E8ED}
body{background:#fff}.panel,details{break-inside:avoid}.kpi div:nth-child(2) b{color:#4B45D6}
.bar span,.legend i,.chip{-webkit-print-color-adjust:exact;print-color-adjust:exact}}"""

ANSWER_CHIP = {"yes": "ok", "no": "bad", "partial": "warn", "unknown": "info"}
KIND_CHIP = {"exposure": "bad", "handover": "warn", "gap": "info"}

TAGS = {"ar": ("rtl", "تقييم ضوابط الهيئة الوطنية للأمن السيبراني"), "en": ("ltr", "NCA cybersecurity control assessment")}


def mark_svg() -> str:
    seg = '<rect x="30.7" y="3" width="2.6" height="10" rx="1.3" fill="{c}" transform="rotate({a:.3f} 32 32)"/>'
    segs = "".join(seg.format(c="#35D7FF" if i % 2 == 0 else "#716BFF", a=i * 360 / 28) for i in range(28))
    return (f'<svg viewBox="0 0 64 64" aria-hidden="true">{segs}'
            '<circle cx="32" cy="32" r="17.5" fill="#05070A" stroke="#35D7FF" stroke-width="1.5"/></svg>')


def page_head(lang: str, title: str) -> str:
    direction, tag = TAGS[lang]
    return (f'<!doctype html><html lang="{lang}" dir="{direction}"><head><meta charset="utf-8">'
            f'<meta name="viewport" content="width=device-width,initial-scale=1"><title>{html.escape(title)}</title>'
            f'<style>{CSS}</style></head><body><div class="wrap"><div class="top">{mark_svg()}'
            f'<span class="word">IRIS</span><span class="tag">{tag}</span></div>')


def panel(n: int, title: str, body: str) -> str:
    return (f'<section class="panel"><div class="panel-head"><span class="panel-index">{n:02d}</span>'
            f'<h2>{title}</h2></div><div class="panel-body">{body}</div></section>')


def state_bar(counts: dict[Tile, int], lang: str) -> str:
    names = TILE_AR if lang == "ar" else TILE_EN
    order = [t for t in TILE_VAR if counts.get(t)]
    bar = "".join(f'<span style="flex:{counts[t]};background:var(--{TILE_VAR[t]})"></span>' for t in order)
    legend = "".join(f'<span><i style="background:var(--{TILE_VAR[t]})"></i>{names[t]} <b>{counts[t]}</b></span>'
                     for t in order)
    return f'<div class="bar">{bar}</div><div class="legend">{legend}</div>'


def catalog_line(c: dict[str, int], lang: str) -> str:
    if lang == "ar":
        return (f"الكتالوج: {c['rows']} ضابطاً · {c['class_b']} في الفئة ب · {c['class_b_mandatory']} إلزامية · "
                f"{c['tier1']} قابلة للاختبار من الخارج")
    return (f"Catalogue: {c['rows']} controls · {c['class_b']} in Class B · {c['class_b_mandatory']} mandatory · "
            f"{c['tier1']} testable from outside")


def render(agent: Any, assessed: Assessed, metrics: dict[str, Any]) -> str:
    e = html.escape
    company, state, log = agent.company, agent.state, agent.log
    counts = Counter(assessed.tiles.values())
    findings = sorted({(h, c.value) for h, c in state.findings})
    contradictions = [ev["data"] for ev in log.events if ev["type"] == "contradiction"]
    fixes = [ev["data"] for ev in log.events if ev["type"] == "fix_result"]
    escalations = state.escalations
    now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")

    finding_rows = "".join(
        row([e(check_ar(check)), f"<bdi dir=ltr>{e(check)}</bdi>", f"<bdi dir=ltr>{e(host)}</bdi>",
             e(", ".join(controls_of(_check(check))) or "—")])
        for host, check in findings
    )
    answer_rows = "".join(
        row([e(qid), e(by_qid()[qid].prompt_ar), f'<span class="chip {ANSWER_CHIP[p.answer.value]}">{e(ANSWER_AR[p.answer.value])}</span>', "✓" if p.evidence_offered else "—",
             str(len(by_qid()[qid].controls))])
        for qid, p in state.answers.items()
    )
    contra_rows = "".join(row([e(c["qid"]), e(", ".join(c["controls"])), e(", ".join(c["observed"]))])
                          for c in contradictions)
    fix_rows = "".join(row([f'<span class="id">{e(f["fix_id"])}</span>', _fix_state(f)]) for f in fixes)
    esc_rows = "".join(row([f'<span class="chip warn">{e(x["reason"])}</span>', e(x["text_ar"])]) for x in escalations)
    sections = [
        (f"حالة الضوابط ({len(assessed.tiles)} صفاً)", state_bar(counts, "ar")),
        ("ما رصده الفحص الخارجي", f"<table>{finding_rows or row(['لا شيء'])}</table>"),
        ("إجابات المالك", f"<table>{row(['السؤال', 'النص', 'الإجابة', 'دليل', 'ضوابط'], 'h')}{answer_rows}</table>"),
        ("تناقضات بين الإجابات والفحص", f"<table>{contra_rows or row(['لا يوجد'])}</table>"),
        ("المعالجة", f"<table>{fix_rows or row(['لا يوجد'])}</table>"),
        ("أحيل إلى إنسان", f"<table>{esc_rows or row(['لا يوجد'])}</table>"),
        *_plan(agent), *_tickets(agent), *_monitor(agent), *_drafts(agent),
        ("سجل التدقيق", f"<p class=\"muted\">آخر بصمة في سلسلة الأحداث: <bdi dir=ltr>{e(log.head)}</bdi> · "
                        f"تحقق: <bdi dir=ltr>officer audit-verify</bdi></p>"),
    ]
    body = "".join(panel(i, title, content) for i, (title, content) in enumerate(sections, 1))
    return f"""{page_head("ar", f"تقرير الامتثال: {company.name_ar}")}
<h1>تقرير تقييم الامتثال للأمن السيبراني</h1>
<p class="meta">{e(company.name_ar)} · <bdi dir=ltr>{e(company.apex)}</bdi> · النطاق: {e(str(metrics.get("scope")))} · {now}</p>
<div class="kpi"><div>لم تُرصد مخالفة من الخارج<b>{pct(metrics.get("assessed_after"))}</b>
<span class="muted">قبل المعالجة: {pct(metrics.get("assessed_before"))}</span></div>
<div>الموثّق<b>{pct(metrics.get("documented"))}</b><span class="muted">بأدلة أو إقرارات، ولا يُدمج مع الأول</span></div>
<div>تعديلات متحقق منها<b>{len(metrics.get("fixes_verified", []))}</b></div>
<div>تناقضات<b>{len(contradictions)}</b></div></div>
<p class="note">الفحص الخارجي يختبر ولا يثبت: غياب المخالفة لا يعني الامتثال. الإقرارات مسجلة كإقرارات، لا كأدلة.
هذا التقرير لا يتضمن نص ضوابط الهيئة الوطنية للأمن السيبراني؛ المعرّفات تشير إلى إصداراتها الرسمية.</p>
{body}<p class="foot">{e(catalog_line(taxonomy.counts(), "ar"))}</p>
</div></body></html>"""


def row(cells: list[str], cls: str = "") -> str:
    return f"<tr{f' class={cls}' if cls else ''}>" + "".join(f"<td>{c}</td>" for c in cells) + "</tr>"


def _fix_state(f: dict[str, Any]) -> str:
    if f.get("reason") == "nothing_to_change":
        return '<span class="chip info">لا حاجة: لم يكن هناك ما يُغيَّر</span>'
    return '<span class="chip ok">✓ تحقق بفحص جديد</span>' if f["verified"] else '<span class="chip bad">✗ لم يتحقق</span>'


def _monitor(agent: Any) -> list[tuple[str, str]]:
    m = getattr(agent, "monitor", None)
    if not m:
        return []
    e = html.escape
    rounds = [ev["data"] for ev in agent.log.events if ev["type"] == "monitor_round" and ev["data"]["stage"] == "end"]
    rows = "".join(
        f"<tr><td class=days>{r['round']}</td><td>{e(', '.join(r['new']) or 'لا جديد')}</td>"
        f"<td>{e(', '.join(r['verified']) or '—')}</td><td>{e(', '.join(r['approved'] + r['declined']) or '—')}</td>"
        f"<td>{e(', '.join(r['escalated']) or '—')}</td></tr>"
        for r in rounds
    )
    head = "<tr class=h><td>الجولة</td><td>ما ظهر من جديد</td><td>أُصلح وتُحقق منه</td><td>بموافقتكم</td><td>أحيل</td></tr>"
    return [(f"المراقبة المستمرة ({m['rounds']} جولات)",
             "<p class=\"muted\">بعد التقييم يعيد الوكيل الفحص في كل جولة، ويعيد تطبيق ما اعتمدتموه وثبت نجاحه إذا رجعت "
             f"المشكلة، ويستأذنكم في أي تعديل جديد.</p><table>{head}{rows}</table>")]


def _plan(agent: Any) -> list[tuple[str, str]]:
    from officer.workplan import action_plan  # noqa: PLC0415

    if not getattr(agent, "metrics", None):
        return []
    items = action_plan(agent)
    if not items:
        return []
    e = html.escape
    kind = {"exposure": "ظاهر للإنترنت", "handover": "تذكرة للدعم التقني", "gap": "فجوة أقررتم بها"}
    rows = "".join(f"<tr><td class=days>{i.days} يوماً</td><td>{e(i.title_ar)}</td><td><span class='chip {KIND_CHIP[i.kind]}'>{kind[i.kind]}</span></td>"
                   f"<td>{i.mandatory or '—'}</td></tr>" for i in items)
    ics = agent.log.path.with_suffix(".calendar.ics").name if agent.log.path else ""
    link = f' <a href="{e(ics)}">أضيفوا المهام الدورية إلى تقويمكم</a>' if ics else ""
    return [("خطة العمل للأيام الـ٩٠ القادمة",
             f"<p class=\"muted\">مرتبة: ما يظهر للإنترنت أولاً، ثم الفجوات الإلزامية، ثم الباقي.{link}</p><table>"
             f"<tr class=h><td>خلال</td><td>المهمة</td><td>النوع</td><td>صفوف إلزامية</td></tr>{rows}</table>")]


def _tickets(agent: Any) -> list[tuple[str, str]]:
    from officer.workplan import tickets  # noqa: PLC0415

    found = tickets(agent)
    if not found:
        return []
    e = html.escape
    blocks = "".join(
        f"<details open{' class=urgent' if t.get('urgent') else ''}><summary>{e(t['title_ar'])} · "
        f"<bdi dir=ltr>{e(t['check'])}</bdi></summary>"
        f"<p>{e(t['why_ar'])}</p><p class=\"muted\">المواقع: "
        f"{'، '.join(f'<bdi dir=ltr>{e(h)}</bdi>' for h in t['hosts']) or '—'}</p>"
        f"<ol>{''.join(f'<li>{e(s)}</li>' for s in t['steps_ar'])}</ol>"
        f"<p class=\"muted\">بعد التنفيذ نعيد الفحص في جولة المراقبة التالية ونغلق التذكرة إن تحققنا.</p></details>"
        for t in found
    )
    return [("تذاكر جاهزة للدعم التقني",
             "<p class=\"muted\">ما لا نغيّره بأنفسنا: يحتاج من يدير الخادم، أو قد يقطع وصولكم إن غُيّر تلقائياً.</p>"
             + blocks)]


def _drafts(agent: Any) -> list[tuple[str, str]]:
    drafts = getattr(agent, "drafts", None)
    if not drafts:
        return []
    blocks = "".join(f"<details><summary>{d.title_ar}</summary>{d.body}</details>" for d in drafts)
    return [("مسودات جاهزة لاعتمادكم",
             "<p class=\"muted\">كتبها الوكيل من إجاباتكم وما رصده الفحص، وترك فراغات لما تعرفونه أنتم وحدكم. لا تُحتسب "
             "في التقييم حتى تعتمدوها وتطبقوها.</p>" + blocks)]


def pct(value: float | None) -> str:
    return "—" if value is None else f"{round(value * 100)}%"


def _check(value: str) -> Any:
    from p2c.scanning.catalog import CheckId  # noqa: PLC0415

    return CheckId(value)
