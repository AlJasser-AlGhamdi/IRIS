"""Draft documents for the gaps a scan cannot close: a policy, an incident plan, backup and account
procedures, and an asset register pre-filled from the scan.

A draft is written when the owner answered no, partly or "don't know" on its question. It is filled with
what the session learned (company, scope, hosts, what the scan saw, what went to a person) and leaves
blanks for what only the owner knows. Drafts never change a score: a control counts once the owner adopts
the document and declares it.
"""

from __future__ import annotations

import html
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from officer.labels import ANSWER_AR, check_ar, count_ar
from officer.questions import AnswerClass

BLANK = '<span class="blank">[............]</span>'


@dataclass(frozen=True)
class Draft:
    slug: str
    qid: str
    title_ar: str
    title_en: str
    body: str  # HTML, right-to-left

    @property
    def sections(self) -> int:
        return self.body.count("<h4>")


def drafts(agent: Any) -> list[Draft]:
    answers = agent.state.answers
    gaps = {qid for qid, p in answers.items() if p.answer is not AnswerClass.YES}
    ctx = _context(agent)
    out = []
    for qid, slug, title_ar, title_en, build in (
        ("Q13", "policy", "سياسة الأمن السيبراني", "Cybersecurity policy", _policy),
        ("Q10", "incident", "خطة الاستجابة للحوادث", "Incident response plan", _incident),
        ("Q07", "backup", "إجراء النسخ الاحتياطي والاستعادة", "Backup and restore procedure", _backup),
        ("Q05", "accounts", "إجراء إدارة الحسابات والصلاحيات", "Accounts and access procedure", _accounts),
        ("Q12", "assets", "سجل الأصول", "Asset register", _assets),
        ("Q14", "awareness", "رسالة توعية للموظفين", "Staff awareness message", _awareness),
    ):
        if qid in gaps:
            said = ANSWER_AR.get(answers[qid].answer.value, "")
            note = f'<p class="muted">أعددنا هذه المسودة لأن إجابتكم في التقييم كانت: «{said}».</p>'
            out.append(Draft(slug, qid, title_ar, title_en, note + build(ctx)))
    return out


def _context(agent: Any) -> dict[str, Any]:
    e = html.escape
    company = agent.company
    today = agent.clock().date()
    hosts = [company.apex, *company.hosts]
    seen: dict[str, list[str]] = {}
    for host, check in sorted(agent.state.findings):
        seen.setdefault(host, []).append(check_ar(str(check.value)))
    return {
        "name": e(company.name_ar),
        "staff": company.staff,
        "hosts": hosts,
        "seen": seen,
        "domains": "، ".join(f"<bdi dir=ltr>{e(h)}</bdi>" for h in hosts),
        "today": today.isoformat(),
        "next_year": (today + timedelta(days=365)).isoformat(),
        "next_quarter": (today + timedelta(days=90)).isoformat(),
        "risky": [x["text_ar"] for x in agent.state.escalations],
    }


def _sign() -> str:
    return (f"<h4>الاعتماد</h4><p>اعتمدها: {BLANK} · المنصب: {BLANK} · التاريخ: {BLANK} · التوقيع: {BLANK}</p>")


def _policy(c: dict[str, Any]) -> str:
    staff = f"(قرابة {count_ar(c['staff'], 'موظف واحد', 'موظفَين', 'موظفين', 'موظفاً')})" if c["staff"] else ""
    return f"""
<h4>الغرض</h4><p>تحمي هذه السياسة معلومات {c['name']} وأنظمتها وخدماتها من الوصول غير المصرّح به والتعطّل
والتسريب، وتحدد من يتولى ذلك.</p>
<h4>النطاق</h4><p>جميع الموظفين {staff} والأجهزة والحسابات والخدمات السحابية التي تستخدمها المنشأة، ومنها
النطاقات: {c['domains']}.</p>
<h4>المسؤولية</h4><p>يعيّن المدير العام {BLANK} مسؤولاً عن الأمن السيبراني. يتابع تطبيق هذه السياسة ويرفع للإدارة
ملخصاً كل ثلاثة أشهر.</p>
<h4>القواعد</h4><ul>
<li>لكل موظف حساب خاص، والتحقق الثنائي إلزامي للبريد والدخول عن بُعد وحسابات الإدارة.</li>
<li>تُحدَّث الأجهزة والأنظمة بانتظام، والحماية من البرمجيات الضارة مفعّلة على كل جهاز.</li>
<li>لا تُفتح للإنترنت أي خدمة داخلية (قواعد البيانات، الطابعات، الدخول عن بُعد) إلا عبر VPN.</li>
<li>تؤخذ نسخ احتياطية منتظمة وتُجرَّب الاستعادة منها.</li>
<li>يتلقى كل موظف توعية عند انضمامه وتذكيراً دورياً برسائل التصيّد.</li>
<li>يبلّغ أي موظف عن أي حادث أو اشتباه فوراً حسب خطة الاستجابة للحوادث.</li></ul>
<h4>المراجعة</h4><p>تُراجع السياسة سنوياً أو عند أي تغيير جوهري. المراجعة القادمة: <bdi dir=ltr>{c['next_year']}</bdi>.</p>
{_sign()}"""


def _incident(c: dict[str, Any]) -> str:
    known = "".join(f"<li>{html.escape(t)}</li>" for t in c["risky"]) or "<li>لا شيء أحيل إلى مختص وقت الكتابة.</li>"
    return f"""
<h4>متى تُفعَّل</h4><p>عند الاشتباه في اختراق، أو برنامج فدية، أو تسرّب بيانات، أو تعطّل غير مفهوم لأي نظام.</p>
<h4>الأدوار</h4><table>
<tr><td>قائد الاستجابة</td><td>{BLANK}</td><td>الجوال: {BLANK}</td></tr>
<tr><td>الدعم التقني (داخلي أو شركة)</td><td>{BLANK}</td><td>الجوال: {BLANK}</td></tr>
<tr><td>التواصل مع العملاء والجهات</td><td>{BLANK}</td><td>الجوال: {BLANK}</td></tr></table>
<h4>الخطوات</h4><ol>
<li>افصلوا الجهاز المصاب عن الشبكة، ولا تطفئوه ولا تمسحوا شيئاً.</li>
<li>أبلغوا قائد الاستجابة فوراً.</li>
<li>حدّدوا الأنظمة والبيانات المتأثرة ومتى بدأ الحادث.</li>
<li>أبلغوا الجهات المطلوبة نظاماً خلال المدة المحددة: {BLANK}.</li>
<li>استعيدوا من نسخة احتياطية سليمة بعد التأكد من إزالة السبب.</li>
<li>وثّقوا ما حدث وما تعلمتموه خلال أسبوع.</li></ol>
<p>لا تتواصلوا مع المهاجم ولا تدفعوا أي فدية قبل الرجوع إلى قائد الاستجابة.</p>
<h4>نقاط ضعف معروفة وقت كتابة الخطة</h4><ul>{known}</ul>
<h4>التمرين</h4><p>تمرين مكتبي مرة في السنة على سيناريو برنامج فدية. الموعد القادم: <bdi dir=ltr>{c['next_year']}</bdi>.</p>
{_sign()}"""


def _backup(c: dict[str, Any]) -> str:
    return f"""
<h4>ما يُنسخ</h4><p>{BLANK} (مثل: قاعدة بيانات المحاسبة، ملفات العملاء، البريد، إعدادات الموقع).</p>
<h4>التكرار</h4><p>يومياً للبيانات التي تتغير، ونسخة كاملة أسبوعياً.</p>
<h4>مكان الحفظ</h4><p>نسختان على الأقل: واحدة خارج المكتب أو في سحابة داخل المملكة، وأخرى غير متصلة بالشبكة حتى لا
يصل إليها برنامج فدية.</p>
<h4>تجربة الاستعادة</h4><p>كل ثلاثة أشهر تُستعاد عينة (ملف وقاعدة بيانات) ويُسجَّل الوقت والنتيجة. التجربة القادمة:
<bdi dir=ltr>{c['next_quarter']}</bdi>.</p>
<h4>المسؤول</h4><p>{BLANK}</p>
<h4>السجل</h4><table><tr><td>التاريخ</td><td>ما نُسخ أو استُعيد</td><td>النتيجة</td><td>المنفّذ</td></tr>
<tr><td>{BLANK}</td><td>{BLANK}</td><td>{BLANK}</td><td>{BLANK}</td></tr></table>
{_sign()}"""


def _accounts(c: dict[str, Any]) -> str:
    return f"""
<h4>القاعدة</h4><p>لكل موظف حساب خاص به، ولا حسابات مشتركة. الصلاحيات بقدر ما يحتاجه العمل فقط.</p>
<h4>الانضمام</h4><p>يُنشأ الحساب بطلب من المدير المباشر، ويُفعَّل التحقق الثنائي قبل أول دخول.</p>
<h4>المغادرة</h4><p>تُعطَّل كل حسابات الموظف في آخر يوم عمل له، وتُغيَّر أي كلمة مرور مشتركة كان يعرفها.</p>
<h4>التحقق الثنائي</h4><p>إلزامي للبريد، والدخول عن بُعد، وحسابات الإدارة، والخدمات السحابية.</p>
<h4>المراجعة</h4><p>مراجعة قائمة الحسابات والصلاحيات كل ستة أشهر، وحذف ما لم يعد مستخدماً.</p>
<h4>قائمة تحقق المغادرة</h4><table>
<tr><td>البريد</td><td>☐</td></tr><tr><td>النظام المحاسبي</td><td>☐</td></tr><tr><td>الدخول عن بُعد وVPN</td><td>☐</td></tr>
<tr><td>الخدمات السحابية</td><td>☐</td></tr><tr><td>كلمات المرور المشتركة</td><td>☐</td></tr></table>
{_sign()}"""


def _awareness(c: dict[str, Any]) -> str:
    spoofable = any("DMARC" in s or "SPF" in s for found in c["seen"].values() for s in found)
    email_line = ("<li>بريدنا لم يكن محمياً بالكامل من انتحال اسمه وقت الفحص، فقد تصلكم رسائل تبدو منا وهي ليست منا. "
                  "تأكدوا بالهاتف قبل أي تحويل مالي.</li>" if spoofable else "")
    return f"""
<h4>الرسالة (جاهزة للإرسال في مجموعة الموظفين)</h4>
<p>السلام عليكم، تذكير سريع لحماية {c['name']}:</p><ul>
<li>لا تفتحوا رابطاً أو مرفقاً غير متوقع حتى لو بدا من زميل أو عميل أو بنك.</li>
<li>أي طلب تحويل مالي أو تغيير حساب بنكي يُؤكَّد بمكالمة على رقم معروف، لا بالرد على الرسالة.</li>
{email_line}<li>لا تشاركوا كلمة المرور أو رمز التحقق مع أي أحد، حتى الدعم الفني.</li>
<li>إذا شككتم في شيء أبلغوا {BLANK} فوراً، والإبلاغ المبكر لا يُلام عليه أحد.</li></ul>
<h4>التكرار</h4><p>عند انضمام أي موظف، ثم كل ثلاثة أشهر. التذكير القادم: <bdi dir=ltr>{c['next_quarter']}</bdi>.</p>"""


def _assets(c: dict[str, Any]) -> str:
    rows = "".join(
        f"<tr><td><bdi dir=ltr>{html.escape(h)}</bdi></td><td>{'، '.join(c['seen'].get(h, [])) or 'لم يُرصد شيء ظاهر'}</td>"
        f"<td>{BLANK}</td><td><bdi dir=ltr>{c['today']}</bdi></td></tr>"
        for h in c["hosts"]
    )
    internal = "".join(f"<tr><td>{kind}</td><td>{BLANK}</td><td>{BLANK}</td><td>{BLANK}</td></tr>"
                       for kind in ("أجهزة الموظفين", "الطابعات", "الخادم أو التخزين المشترك", "الشبكة (الموجّه والمبدّلات)"))
    return f"""
<h4>ما رأيناه من الخارج</h4><p>عبأنا هذا الجزء من الفحص. راجعوه وأضيفوا المسؤول عن كل أصل.</p>
<table><tr><td>الأصل</td><td>ما رصده الفحص</td><td>المسؤول</td><td>آخر تحديث</td></tr>{rows}</table>
<h4>ما لا يراه الفحص</h4><table><tr><td>النوع</td><td>العدد والوصف</td><td>المسؤول</td><td>آخر تحديث</td></tr>{internal}</table>
<h4>التحديث</h4><p>يُحدَّث السجل عند شراء أو إخراج أي جهاز أو نظام، ويُراجع كاملاً كل ستة أشهر.</p>
{_sign()}"""
