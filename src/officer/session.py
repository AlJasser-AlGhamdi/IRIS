"""The agent: one SME's compliance assessment, from the owner's first message to the report.

In each phase (scope, ownership, scan, interview, reconcile, fix, report) code lists the legal actions, the
model or the priority policy picks one, and code runs and records it. The owner is asked only where law or
safety needs a person: staff count, ownership record, answers no scan can give, approval of changes.
"""

from __future__ import annotations

import dataclasses
import re
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Protocol

from officer import brain, taxonomy
from officer.assessment import Assessed, assess
from officer.contract import FixId, Group, ScanIn
from officer.events import EventLog
from officer.fixes import ESCALATE_ONLY, FIXES, GROUP_OF, FixSpec, fixes_for
from officer.llm import Call, Provider
from officer.questions import AnswerClass, Declaration, Question, bank, by_qid, declarations
from officer.worker import Worker, WorkerError
from p2c.scanning.catalog import CheckId


class Phase(StrEnum):
    SCOPE = "scope"
    OWNERSHIP = "ownership"
    SCAN = "scan"
    INTERVIEW = "interview"
    RECONCILE = "reconcile"
    FIX = "fix"
    REPORT = "report"
    DONE = "done"


class Scope(StrEnum):
    CLASS_B = "class_b"  # NCNICC-1:2025, 6 to 249 staff
    CLASS_A = "class_a"  # NCNICC-1:2025, larger private entities
    ECC = "ecc"  # ECC-2:2024 in full (e.g. a supplier to government)
    OUT = "out"  # fewer than 6 staff: outside both


@dataclass(frozen=True)
class Config:
    lab: bool = True  # apply approved fixes in the lab; otherwise draft them for the owner
    scan: bool = True
    interview: bool = True
    contradictions: bool = True
    action_gate: bool = True
    verify_rescan: bool = True
    documents: bool = True  # draft a policy, plans and an asset register for the gaps
    explain: bool = False  # templates (docs/ITERATIONS.md, #9)
    max_followups: int = 1
    simulated_dns: bool = True  # lab and simulator: the owner's "I added the record" is applied for them


@dataclass(frozen=True)
class OwnerRequest:
    kind: str  # "staff_count" | "publish_txt" | "answer" | "buttons" | "approve_fixes"
    text_ar: str
    text_en: str
    options: tuple[str, ...] = ()
    payload: dict[str, Any] = field(default_factory=dict)
    seq: int = -1  # the owner_request event this request was announced in


@dataclass(frozen=True)
class OwnerReply:
    text: str = ""
    choices: tuple[str, ...] = ()
    scope_update: dict[str, Any] | None = None  # the owner corrects company facts mid-session


class Owner(Protocol):
    def reply(self, request: OwnerRequest) -> OwnerReply: ...


@dataclass
class Company:
    name_ar: str
    name_en: str
    apex: str
    hosts: list[str]
    staff: int | None = None
    supplies_government: bool = False


@dataclass
class State:
    phase: Phase = Phase.SCOPE
    scope: Scope | None = None
    verification_ids: list[str] = field(default_factory=list)
    challenge_ids: list[str] = field(default_factory=list)
    scanned: set[Group] = field(default_factory=set)
    findings: set[tuple[str, CheckId]] = field(default_factory=set)
    unread: set[tuple[str, CheckId]] = field(default_factory=set)
    answers: dict[str, brain.Parsed] = field(default_factory=dict)
    followups: dict[str, int] = field(default_factory=dict)
    declared: list[Declaration] = field(default_factory=list)
    asked: list[str] = field(default_factory=list)
    halted: str | None = None
    escalations: list[dict[str, str]] = field(default_factory=list)
    fixes_verified: list[str] = field(default_factory=list)
    fixes_failed: list[str] = field(default_factory=list)
    human_touches: int = 0
    model_calls: int = 0
    fallbacks: dict[str, int] = field(default_factory=lambda: {"parse": 0, "choose": 0, "explain": 0})
    illegal_choices: int = 0
    decisions: int = 0  # every model decision point (only-option steps excluded)
    first_assessment: dict[str, float] | None = None


_DIGITS = str.maketrans("٠١٢٣٤٥٦٧٨٩۰۱۲۳۴۵۶۷۸۹", "01234567890123456789")
_LEGAL = re.compile(r"غرام[ةه]|القانون|قانوني|محام|legal|lawyer|penalt|\bfined\b|\bsue\b", re.IGNORECASE)
_STAFF_WORDS = re.compile(r"موظف|عامل|شخص|staff|employee|people|person", re.IGNORECASE)
STAFF_BANDS = {"fewer_than_6": 3, "6_to_249": 40, "250_or_more": 300}


def parse_staff(text: str) -> int | None:
    """The staff count in a reply, or None when missing or ambiguous (the agent then asks for a band)."""
    t = text.translate(_DIGITS)
    t = re.sub(r"(?<=\d)[,٬](?=\d{3})", "", t)  # thousands separators
    numbers = [(m.start(), int(m.group())) for m in re.finditer(r"\d+", t)]
    if len(numbers) == 1:
        return numbers[0][1]
    words = [m.start() for m in _STAFF_WORDS.finditer(t)]
    if numbers and words:
        return min(numbers, key=lambda n: min(abs(n[0] - w) for w in words))[1]
    return None


def scope_for(staff: int | None, supplies_government: bool) -> Scope:
    if supplies_government:
        return Scope.ECC
    if staff is None or 6 <= staff <= 249:  # noqa: PLR2004
        return Scope.CLASS_B
    return Scope.CLASS_A if staff > 249 else Scope.OUT  # noqa: PLR2004


def in_scope(scope: Scope) -> dict[str, bool]:
    """Row id -> mandatory? for every row in scope (recommended rows map to False)."""
    out: dict[str, bool] = {}
    for row in taxonomy.rows():
        if scope is Scope.CLASS_B and row.in_class_b:
            out[row.id] = row.class_b == "M"
        elif scope is Scope.CLASS_A and row.class_a in ("M", "R"):
            out[row.id] = row.class_a == "M"
        elif scope is Scope.ECC and row.kind != "ncnicc_exclusive":
            out[row.id] = True
    return out


class Agent:
    def __init__(self, company: Company, worker: Worker, owner: Owner, provider: Provider | None,
                 log: EventLog, config: Config | None = None, clock: Callable[[], datetime] | None = None) -> None:
        self.company = company
        self.worker = worker
        self.owner = owner
        self.provider = provider
        self.log = log
        self.config = config or Config()
        self.state = State()
        self.clock = clock or (lambda: datetime.now(UTC))
        self._t0 = time.perf_counter()
        self._blocked_at_start = 0
        self.metrics: dict[str, Any] = {}
        self.drafts: list[Any] = []
        self.monitor: dict[str, Any] | None = None

    # Bookkeeping

    def _ask(self, request: OwnerRequest) -> OwnerReply:
        self.state.human_touches += 1
        event = self.log.emit("owner_request", kind=request.kind, text_ar=request.text_ar, text_en=request.text_en,
                              options=list(request.options), payload=request.payload,
                              human_touches=self.state.human_touches)
        reply = self.owner.reply(dataclasses.replace(request, seq=event["seq"]))
        self.log.emit("owner_reply", kind=request.kind, text=reply.text, choices=list(reply.choices))
        if reply.scope_update:
            self._rescope(reply.scope_update)
        return reply

    def _say(self, text_ar: str, text_en: str, **extra: Any) -> None:
        self.log.emit("agent_message", text_ar=text_ar, text_en=text_en, **extra)

    def _model_event(self, call: Call | None, role: str, verdict: str, **extra: Any) -> None:
        if verdict != "only_option":
            self.state.decisions += 1
        if call is None:
            if verdict != "only_option":
                self.state.fallbacks[role] += 1
            self.log.emit("model_call", role=role, model=None, verdict=verdict, **extra)
            return
        self.state.model_calls += 1
        if verdict != "accepted":
            self.state.fallbacks[role] += 1
        self.log.emit("model_call", role=role, model=call.model, ms=call.ms, prompt=call.user,
                      output=call.raw[:800], prompt_tokens=call.prompt_tokens, verdict=verdict, **extra)

    def _escalate(self, reason_code: str, text_ar: str, text_en: str) -> None:
        self.state.escalations.append({"reason": reason_code, "text_ar": text_ar, "text_en": text_en})
        self.log.emit("escalation", reason=reason_code, text_ar=text_ar, text_en=text_en)

    def _phase(self, phase: Phase) -> None:
        self.state.phase = phase
        self.log.emit("phase", phase=phase.value)

    def _unscanned(self) -> set[tuple[str, CheckId]]:
        """Checks of groups not (yet) scanned: unread, never clean."""
        gaps: set[tuple[str, CheckId]] = set()
        for check, group in GROUP_OF.items():
            if group in self.state.scanned:
                continue
            hosts = [self.company.apex] if group is Group.DNS else [self.company.apex, *self.company.hosts]
            gaps |= {(h, check) for h in hosts}
        return gaps

    def assessment(self) -> Assessed:
        unread = self.state.unread | self._unscanned()
        return assess(self.state.findings, unread, self.state.declared, now=self.clock(),
                      interview_open=self.state.phase in (Phase.INTERVIEW, Phase.RECONCILE, Phase.FIX,
                                                          Phase.REPORT, Phase.DONE))

    def _publish_assessment(self, stage: str = "") -> Assessed:
        a = self.assessment()
        scope = in_scope(self.state.scope or Scope.CLASS_B)
        self.log.emit(
            "assessment",
            tiles={k: v.value for k, v in a.tiles.items()},
            scope={k: ("M" if m else "R") for k, m in scope.items()},
            assessed=round(a.score.assessed_score, 4),
            documented=round(a.score.documented_score, 4),
            coverage=round(a.score.coverage, 4),
            evidence_coverage=round(a.score.evidence_coverage, 4),
            contradictions=sorted({c.control_id for c in a.contradictions}),
            counts=a.counts(),
            stage=stage,
        )
        return a

    def _choose(self, phase: str, facts: Sequence[str], menu: Sequence[tuple[str, str]],
                full_menu: Sequence[tuple[str, str]] | None = None) -> str:
        """The gate: the model picks only from ``menu``. With the gate off (ablation) it is offered
        ``full_menu``, and a pick outside ``menu`` is counted as illegal and replaced by policy."""
        offered = menu if (self.config.action_gate or full_menu is None) else full_menu
        choice = brain.choose_action(self.provider, phase, facts, offered)
        legal = {a for a, _ in menu}
        if choice.action_id not in legal:
            self.state.illegal_choices += 1
            self._model_event(choice.call, "choose", "illegal_refused", menu=[a for a, _ in offered],
                              picked=choice.action_id)
            return menu[0][0]
        if choice.source == "single":
            verdict = "only_option"
        elif choice.source == "model":
            verdict = "accepted"
        else:
            verdict = f"policy ({choice.rejected})" if choice.rejected else "policy"
        self._model_event(choice.call, "choose", verdict, menu=[a for a, _ in offered], picked=choice.action_id,
                          reason_ar=choice.reason_ar)
        return choice.action_id

    def _explain(self, facts: dict[str, str], template_ar: str, template_en: str, topic: str) -> None:
        if not self.config.explain:  # templates by design, not a model decision
            self.log.emit("model_call", role="explain", model=None, verdict="template", facts=facts)
            self._say(template_ar, template_en, topic=topic, explained_by="template")
            return
        e = brain.explain(self.provider, facts, template_ar)
        verdict = "accepted" if e.source == "model" else f"template ({e.rejected})" if e.rejected else "template"
        self._model_event(e.call, "explain", verdict, facts=facts)
        self._say(e.text_ar, template_en, topic=topic, explained_by=e.source)

    # The run

    def run(self) -> dict[str, Any]:
        from officer.sovereignty import BLOCKED, allowlist  # noqa: PLC0415

        self._blocked_at_start = len(BLOCKED)
        self.log.emit("session_started", company=self.company.name_en, company_ar=self.company.name_ar,
                      apex=self.company.apex, hosts=self.company.hosts, config=self.config.__dict__,
                      model=getattr(self.provider, "name", None), rows=taxonomy.counts(),
                      egress_allowlist=["loopback", "private ranges"] + (["lab worker (tailnet)"] if allowlist() else []))
        self._scope_phase()
        if self.state.scope is Scope.OUT:
            return self._finish()
        if self.config.scan:
            self._ownership_phase()
            if not self.state.halted:
                self._scan_phase()
        if self.config.interview:
            self._interview_phase()
        if self.config.contradictions:
            self._reconcile_phase()
        if self.config.scan and not self.state.halted:
            self._fix_phase()
        return self._finish()

    def _scope_phase(self) -> None:
        self._phase(Phase.SCOPE)
        if self.company.staff is None:
            reply = self._ask(OwnerRequest(
                "staff_count",
                "قبل أن نبدأ: كم عدد موظفي منشأتكم تقريباً؟ (لتحديد الضوابط التي تنطبق عليكم)",
                "Before we start: roughly how many people work at your company? (This decides which "
                "controls apply.)"))
            self.company.staff = parse_staff(reply.text)
            if self.company.staff is None:
                band = self._ask(OwnerRequest("staff_band", "اختاروا عدد الموظفين التقريبي:",
                                              "Pick the closest staff size:", options=tuple(STAFF_BANDS)))
                picked = band.choices[0] if band.choices else "6_to_249"
                self.company.staff = STAFF_BANDS.get(picked, STAFF_BANDS["6_to_249"])
        self._set_scope()

    def _set_scope(self) -> None:
        scope = scope_for(self.company.staff, self.company.supplies_government)
        changed = self.state.scope is not None and scope is not self.state.scope
        self.state.scope = scope
        rows = in_scope(scope)
        self.log.emit("scope", scope=scope.value, staff=self.company.staff, rows=len(rows),
                      mandatory=sum(rows.values()), changed=changed)
        if scope is Scope.OUT:
            if changed:
                self.state.halted = "out_of_scope"
            self._explain({"kind": "scope", "staff": str(self.company.staff), "class_b_range": "6 to 249 staff",
                           "next": "explain the company is below the smallest class"},
                          "منشأتكم أصغر من الفئات التي تغطيها هذه الضوابط، لذلك لن نجري التقييم الكامل.",
                          "Your company is below the classes these controls cover, so we will not run the full "
                          "assessment.", "scope")
        elif changed:
            self._say("تغيّر نطاق التقييم بناءً على المعلومات الجديدة، وأعدنا ترتيب الأسئلة المتبقية.",
                      "The assessment scope changed with the new company facts; the remaining questions are "
                      "re-prioritised.", topic="scope_change", scope=scope.value)

    def _rescope(self, update: dict[str, Any]) -> None:
        if "staff" in update:
            staff = parse_staff(str(update["staff"]))
            if staff is not None:
                self.company.staff = staff
        if "supplies_government" in update:
            self.company.supplies_government = bool(update["supplies_government"])
        self._set_scope()

    def _ownership_phase(self) -> None:
        self._phase(Phase.OWNERSHIP)
        try:
            challenges = self.worker.challenge(self.company.apex, self.company.hosts)
        except WorkerError as exc:
            self.state.halted = str(exc)
            self._escalate("worker_error", "تعذّر التواصل مع خدمة الفحص.", "The scan service could not be reached.")
            return
        self.state.challenge_ids = [c.challenge_id for c in challenges]
        records = [{"name": c.record_name, "type": "TXT", "value": c.token} for c in challenges]
        self.log.emit("ownership_challenge", records=[{"name": r["name"], "type": "TXT"} for r in records])
        for _attempt in range(2):
            self._ask(OwnerRequest(
                "publish_txt",
                "لن نفحص أي نطاق قبل أن نتأكد أنه لكم. أضيفوا سجلات TXT التالية لدى مزوّد النطاق ثم أخبرونا.",
                "We scan nothing until we know the domain is yours. Add these TXT records at your DNS "
                "provider, then tell us.",
                payload={"records": records}))
            try:
                if self.config.simulated_dns:
                    self.worker.owner_publish([c.challenge_id for c in challenges])
                results = [self.worker.verify(c.challenge_id) for c in challenges]
            except WorkerError as exc:
                self.state.halted = str(exc)
                self._escalate("worker_error", "تعذّر التحقق من الملكية بسبب خطأ في خدمة الفحص.",
                               "Ownership could not be checked: the scan service failed.")
                return
            if all(r.verified for r in results):
                self.state.verification_ids = [r.verification_id for r in results if r.verification_id]
                self.log.emit("ownership_verified", names=len(results))
                return
        self.state.halted = "ownership_not_verified"
        self._escalate("ownership_not_verified", "لم نتمكن من التحقق من ملكية النطاق، وأحلنا الأمر إلى مختص.",
                       "Domain ownership could not be verified; handed to a person.")

    def _scan_group(self, group: Group) -> bool:
        request = ScanIn(apex=self.company.apex, hosts=self.company.hosts,
                         verification_ids=self.state.verification_ids, groups=[group])
        self.log.emit("tool_call", tool="scan", group=group.value)
        try:
            result = self.worker.scan(request)
        except WorkerError as exc:
            self.state.halted = str(exc)
            self._escalate("scan_refused", "رفضت خدمة الفحص الطلب.", "The scan service refused the request.")
            return False
        if result.stopped:
            self.state.halted = result.stop_reason.value if result.stop_reason else "stopped"
            self._escalate(self.state.halted,
                           "توقف الفحص لأن سجل الملكية لم يعد موجوداً. لن نكمل الفحص حتى يُعاد.",
                           "The scan stopped because the ownership record disappeared; it will not continue "
                           "until the record is back.")
            return False
        self.state.findings = {(h, c) for (h, c) in self.state.findings if GROUP_OF[c] is not group}
        self.state.unread = {(h, c) for (h, c) in self.state.unread if GROUP_OF[c] is not group}
        for r in result.results:
            self.state.findings |= {(r.host, CheckId(c)) for c in r.findings}
            self.state.unread |= {(r.host, CheckId(c)) for c in r.unread}
        self.state.scanned.add(group)
        self.log.emit("tool_result", tool="scan", group=group.value, audit_head=result.audit_head,
                      duration_ms=result.duration_ms,
                      findings=sorted({c for r in result.results for c in r.findings}),
                      unread=sorted({c for r in result.results for c in r.unread}))
        return True

    def _scan_phase(self) -> None:
        self._phase(Phase.SCAN)
        labels = {Group.DNS: "Read email and DNS settings", Group.WEB: "Read the website",
                  Group.TLS: "Read the certificates", Group.PORTS: "Check exposed services"}
        while len(self.state.scanned) < len(Group) and not self.state.halted:
            menu = [(f"scan_{g.value}", labels[g]) for g in Group if g not in self.state.scanned]
            facts = [f"Ownership verified for {len(self.state.verification_ids)} names.",
                     f"Groups done: {', '.join(sorted(g.value for g in self.state.scanned)) or 'none'}."]
            action = self._choose("SCAN", facts, menu, self._full_menu(menu))
            self._scan_group(Group(action.removeprefix("scan_")))
            a = self._publish_assessment()
        if not self.state.halted:
            a = self._publish_assessment(stage="post_scan")
            self.state.first_assessment = {"assessed": a.score.assessed_score, "documented": a.score.documented_score}
            violations = sorted({c.value for _h, c in self.state.findings if taxonomy_relevant(c)})
            self._explain(
                {"kind": "scan_summary", "violations_seen": ", ".join(violations) or "none",
                 "not_observable": str(len({c for _h, c in self.state.unread})),
                 "next": "ask the questions a scan cannot answer"},
                "انتهى الفحص الخارجي. رصدنا ما يمكن رؤيته من الخارج، والباقي نحتاج فيه إجاباتكم.",
                "The outside scan is done. We recorded what can be seen from outside; for the rest we need your "
                "answers.", "scan_summary")

    def _full_menu(self, legal: Sequence[tuple[str, str]]) -> list[tuple[str, str]]:
        """Everything the agent could ever do, for the no-gate ablation."""
        extra = [("scan_dns", "Read email and DNS settings"), ("apply_close_db_port", "Close the database port"),
                 ("write_report", "Write the report"), ("finish_interview", "Finish the interview"),
                 ("issue_challenge", "Issue an ownership challenge")]
        seen = {a for a, _ in legal}
        return list(legal) + [(a, d) for a, d in extra if a not in seen]

    # Interview

    def _priority(self, q: Question) -> float:
        scope = in_scope(self.state.scope or Scope.CLASS_B)
        rows = [c for c in q.controls if c in scope]
        score = 2.0 * sum(scope[c] for c in rows) + sum(not scope[c] for c in rows)
        open_checks = {c.value for _h, c in self.state.findings}
        unread_checks = {c.value for _h, c in self.state.unread}
        if set(q.contradictable_by) & open_checks:
            score += 3  # where the scan saw a problem, ask early
        if set(q.contradictable_by) & unread_checks and not set(q.contradictable_by) & open_checks:
            score += 4  # the scan could not see it: the owner is the only source
        return score

    def _interview_menu(self) -> list[tuple[str, str]]:
        scope = in_scope(self.state.scope or Scope.CLASS_B)
        menu: list[tuple[str, str]] = []
        for qid, parsed in self.state.answers.items():
            if parsed.needs_followup and self.state.followups.get(qid, 0) < self.config.max_followups:
                menu.append((f"followup_{qid}", f"Follow up on {by_qid()[qid].topic}"))
        remaining = [q for q in bank() if q.qid not in self.state.answers and any(c in scope for c in q.controls)]
        remaining.sort(key=lambda q: -self._priority(q))
        for q in remaining[:3]:
            mandatory = sum(scope.get(c, False) for c in q.controls)
            menu.append((f"ask_{q.qid}", f"Ask about {q.topic} ({mandatory} mandatory rows)"))
        mandatory_open = [q for q in remaining if any(scope.get(c, False) for c in q.controls)]
        if not mandatory_open:
            menu.append(("finish_interview", "Finish the interview"))
        return menu

    def _interview_phase(self) -> None:
        self._phase(Phase.INTERVIEW)
        self._publish_assessment()
        while not self.state.halted:
            menu = self._interview_menu()
            if not menu:
                break
            facts = [f"Questions answered: {len(self.state.answers)}.",
                     f"Unread scan reads: {len({c for _h, c in self.state.unread})}."]
            action = self._choose("INTERVIEW", facts, menu, self._full_menu(menu))
            if action == "finish_interview":
                break
            kind, qid = action.split("_", 1)
            self._ask_question(by_qid()[qid], followup=kind == "followup")
            self._publish_assessment()

    def _ask_question(self, q: Question, *, followup: bool) -> None:
        if followup:
            self.state.followups[q.qid] = self.state.followups.get(q.qid, 0) + 1
            text_ar = f"لنوضح أكثر: {q.prompt_ar} أجيبوا بنعم أو لا أو جزئياً، ويمكنكم إرفاق دليل: {q.evidence_hint_ar}"
            text_en = f"To be precise: {q.prompt_en} Answer yes, no or partly; you can attach proof: {q.evidence_hint_en}"
        else:
            self.state.asked.append(q.qid)
            text_ar, text_en = q.prompt_ar, q.prompt_en
        reply = self._ask(OwnerRequest("answer", text_ar, text_en, payload={"qid": q.qid, "followup": followup}))
        if _LEGAL.search(reply.text):
            self._escalate("legal_question", "سؤالكم القانوني يحتاج مختصاً، وأحلناه إليه. سنكمل التقييم.",
                           "Your legal question needs a specialist; it has been handed over. The assessment "
                           "continues.")
        parsed = brain.parse_answer(self.provider, q, reply.text)
        verdict = "accepted" if parsed.source == "model" else "lexicon"
        self._model_event(parsed.call, "parse", verdict, qid=q.qid, answer=parsed.answer.value,
                          evidence=parsed.evidence_offered)
        exhausted = followup or self.config.max_followups == 0
        if parsed.answer in (AnswerClass.PARTIAL, AnswerClass.UNKNOWN) and exhausted:
            choice = self._ask(OwnerRequest("buttons", "اختاروا الأقرب لوضعكم:", "Pick the closest:",
                                            options=("yes", "partial", "no", "unknown"), payload={"qid": q.qid}))
            picked = choice.choices[0] if choice.choices else "unknown"
            if picked not in {a.value for a in AnswerClass}:
                picked = "unknown"
            parsed = brain.Parsed(AnswerClass(picked), parsed.evidence_offered, False, "high", "buttons", None)
        self.state.answers[q.qid] = parsed
        self.state.declared = [d for d in self.state.declared if d.question != q.qid]
        self.state.declared += declarations(q, parsed.answer, evidence=parsed.evidence_offered)
        self.log.emit("answer", qid=q.qid, answer=parsed.answer.value, evidence=parsed.evidence_offered,
                      source=parsed.source, controls=len(q.controls))

    # Reconcile, fix, report

    def _reconcile_phase(self) -> None:
        self._phase(Phase.RECONCILE)
        a = self._publish_assessment()
        by_question: dict[str, list[str]] = {}
        for c in a.contradictions:
            q = next((q for q in bank() if c.control_id in q.controls and q.qid in self.state.answers), None)
            if q is not None:
                by_question.setdefault(q.qid, []).append(c.control_id)
        for qid, controls in by_question.items():
            q = by_qid()[qid]
            seen = sorted({ch.value for _h, ch in self.state.findings if ch.value in q.contradictable_by})
            self.log.emit("contradiction", qid=qid, controls=sorted(set(controls)), observed=seen)
            self._explain({"kind": "contradiction", "claim": f"the owner said yes to the {q.topic} question",
                           "observation": ", ".join(seen), "next": "record the observed state; the scan decides"},
                          "ذكرتم أن هذا مطبّق، لكن الفحص رصد خلاف ذلك. سنعتمد ما رصده الفحص في التقييم.",
                          "You said this is in place, but the scan observed otherwise. The assessment keeps what "
                          "the scan observed.", "contradiction")

    def _fix_phase(self) -> None:
        self._phase(Phase.FIX)
        open_checks = {c for _h, c in self.state.findings}
        proposals = fixes_for(open_checks)
        for check, reason in ESCALATE_ONLY.items():
            if check in open_checks:
                self._escalate(f"risky_fix:{check.value}",
                               "الدخول عن بُعد إلى الخادم مفتوح على الإنترنت، لكن إغلاقه تلقائياً قد يمنعكم من "
                               "الوصول إلى الخادم، لذلك أحلنا القرار إلى المسؤول عنه.",
                               f"Remote management is open to the internet, but {reason}; handed to a person.")
        if not proposals:
            return
        self.log.emit("plan", fixes=[{"fix_id": f.fix_id.value, "title_ar": f.title_ar, "title_en": f.title_en,
                                      "steps_ar": f.steps_ar, "steps_en": f.steps_en,
                                      "clears": [c.value for c in f.clears]} for f in proposals])
        reply = self._ask(OwnerRequest(
            "approve_fixes",
            "هذه التعديلات تعالج ما رصده الفحص. اختاروا ما توافقون على تطبيقه:",
            "These changes fix what the scan found. Choose which ones you approve:",
            options=tuple(f.fix_id.value for f in proposals)))
        approved = [FIXES[FixId(x)] for x in reply.choices if x in {f.fix_id.value for f in proposals}]
        by_group: dict[Group, list[FixSpec]] = {}
        for spec in approved:
            by_group.setdefault(spec.group, []).append(spec)
        for specs in by_group.values():
            self._apply_group(specs)
        self._publish_assessment()

    def _apply_fixes(self, pending: list[FixSpec], attempt: int) -> list[FixSpec]:
        """A fix the worker refuses is escalated and dropped."""
        applied = []
        for spec in pending:
            self.log.emit("tool_call", tool="fix", fix_id=spec.fix_id.value, attempt=attempt + 1)
            try:
                out = self.worker.fix(spec.fix_id)
            except WorkerError:
                self.state.fixes_failed.append(spec.fix_id.value)
                self.log.emit("fix_result", fix_id=spec.fix_id.value, verified=False)
                self._escalate(f"fix_failed:{spec.fix_id.value}", f"تعذّر تطبيق: {spec.title_ar}.",
                               f"Could not apply: {spec.title_en}.")
                continue
            if not out.applied:  # e.g. close the cache port when the exposed port was the database's
                self.log.emit("fix_result", fix_id=spec.fix_id.value, verified=None, reason="nothing_to_change")
                continue
            applied.append(spec)
        return applied

    def _confirm_fixes(self, pending: list[FixSpec]) -> list[FixSpec]:
        """After a re-scan: confirmed fixes are recorded, unreadable ones escalated, the rest returned."""
        open_checks = {c for _h, c in self.state.findings}
        unread_checks = {c for _h, c in self.state.unread}
        still_open = []
        for spec in pending:
            if set(spec.clears) & open_checks:
                still_open.append(spec)
                continue
            if set(spec.clears) & unread_checks:  # the re-scan could not read it: not verified
                self.state.fixes_failed.append(spec.fix_id.value)
                self.log.emit("fix_result", fix_id=spec.fix_id.value, verified=False, reason="unread")
                self._escalate(f"fix_unverifiable:{spec.fix_id.value}",
                               f"لم نتمكن من قراءة نتيجة: {spec.title_ar}، لذلك لا نعدّها مُصلحة.",
                               f"The re-scan could not read: {spec.title_en}; it is not counted as fixed.")
                continue
            self.state.fixes_verified.append(spec.fix_id.value)
            self.log.emit("fix_result", fix_id=spec.fix_id.value, verified=True)
            self._explain({"kind": "verified_fix", "fix": spec.title_en,
                           "result": "a new scan no longer observes the problem"},
                          f"تم: {spec.title_ar}. الفحص الجديد لم يعد يرصد المشكلة.",
                          f"Done: {spec.title_en}. A new scan no longer observes the problem.", "fix")
        return still_open

    def _apply_group(self, specs: list[FixSpec]) -> None:
        """Apply one scan group's fixes together, then re-scan once: fixes that share a detector (two exposed
        database ports) can only be confirmed together. A fix whose detectors survive is retried once, then
        handed to a person."""
        if not self.config.lab:
            for spec in specs:
                self.log.emit("fix_drafted", fix_id=spec.fix_id.value, steps_ar=spec.steps_ar,
                              steps_en=spec.steps_en)
            return
        pending = list(specs)
        for attempt in range(2):
            pending = self._apply_fixes(pending, attempt)
            if not pending:
                return
            if not self.config.verify_rescan:
                for spec in pending:
                    self.state.fixes_verified.append(spec.fix_id.value)  # claimed, not verified (ablation)
                    self.log.emit("fix_result", fix_id=spec.fix_id.value, verified=None)
                return
            if not self._scan_group(pending[0].group):
                return
            pending = self._confirm_fixes(pending)
            if not pending:
                return
        for spec in pending:
            self.state.fixes_failed.append(spec.fix_id.value)
            self.log.emit("fix_result", fix_id=spec.fix_id.value, verified=False)
            self._escalate(f"fix_not_verified:{spec.fix_id.value}", f"لم يتأكد الفحص من نجاح: {spec.title_ar}.",
                           f"The re-scan could not confirm: {spec.title_en}.")

    def _finish(self) -> dict[str, Any]:
        from officer.sovereignty import BLOCKED  # noqa: PLC0415

        self._phase(Phase.REPORT)
        a = self._publish_assessment()
        metrics = {
            "human_touches": self.state.human_touches,
            "questions_asked": len(self.state.asked),
            "followups": sum(self.state.followups.values()),
            "model_calls": self.state.model_calls,
            "fallbacks": self.state.fallbacks,
            "illegal_choices": self.state.illegal_choices,
            "decisions": self.state.decisions,
            "escalations": [e["reason"] for e in self.state.escalations],
            "fixes_verified": self.state.fixes_verified,
            "fixes_failed": self.state.fixes_failed,
            "assessed_before": (self.state.first_assessment or {}).get("assessed"),
            "assessed_after": round(a.score.assessed_score, 4),
            "documented": round(a.score.documented_score, 4),
            "contradictions": sorted({c.control_id for c in a.contradictions}),
            "halted": self.state.halted,
            "seconds": round(time.perf_counter() - self._t0, 1),
            "scope": self.state.scope.value if self.state.scope else None,
            "egress_blocked": len(BLOCKED) - self._blocked_at_start,
        }
        self.log.emit("metrics", **metrics)
        self.metrics = metrics
        if self.config.documents and not self.state.halted:
            from officer.documents import drafts  # noqa: PLC0415

            self.drafts = drafts(self)
            for d in self.drafts:
                self.log.emit("document_drafted", slug=d.slug, qid=d.qid, title_ar=d.title_ar, title_en=d.title_en,
                              sections=d.sections)
            from officer.workplan import URGENT_DAYS, action_plan, calendar_ics, tickets  # noqa: PLC0415

            plan = action_plan(self)
            self.log.emit("action_plan", items=len(plan), within_30=sum(i.days <= URGENT_DAYS for i in plan),
                          mandatory_gaps=sum(i.mandatory > 0 for i in plan))
            for t in tickets(self):
                self.log.emit("ticket_drafted", check=t["check"], title_ar=t["title_ar"], urgent=t["urgent"],
                              steps=len(t["steps_ar"]))
            if self.log.path is not None:
                ics = self.log.path.with_suffix(".calendar.ics")
                ics.write_text(calendar_ics(self), encoding="utf-8", newline="")
                self.log.emit("calendar_ready", file=ics.name)
        if self.log.path is not None:
            from officer.report import render  # noqa: PLC0415

            report = self.log.path.with_suffix(".report.html")
            report.write_text(render(self, a, metrics), encoding="utf-8", newline="\n")
            self.log.emit("report_ready", file=report.name)
        self._phase(Phase.DONE)
        return metrics


def taxonomy_relevant(check: CheckId) -> bool:
    """A detector that maps to at least one control (the rest are hardening findings)."""
    from officer.fixes import controls_of  # noqa: PLC0415

    return bool(controls_of(check))
