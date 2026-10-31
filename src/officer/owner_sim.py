"""A simulated SME owner for evaluation and the offline demo, driven by a synthetic firm's hidden truth.

Personas follow the engine's adversary model: ``honest`` tells the truth, ``overstating`` claims a missing
practice with probability 0.5 (the engine's P_OVERSTATE), and ``vague`` answers unclearly until followed up.
Replies come from templates in formal Arabic, Saudi dialect or English.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field

from officer.questions import AnswerClass, Question, by_qid
from officer.session import OwnerReply, OwnerRequest
from p2c.evaluation.synthetic import P_OVERSTATE, EvalCase

# Share of practices in place, by posture, where the firm holds no internal record. A simulator
# assumption: the engine models only the controls a firm holds records for.
P_IN_PLACE = {"strong": 0.8, "moderate": 0.55, "weak": 0.3}

TEMPLATES: dict[str, dict[AnswerClass, list[str]]] = {
    "dialect": {
        AnswerClass.YES: ["إيه، عندنا هذا ومطبقينه", "أكيد، مسوينه من زمان", "ايوه كله تمام عندنا",
                          "إيه مطبقين، {evidence}"],
        AnswerClass.NO: ["لا، ما عندنا", "لا والله ما سويناه", "ماعندنا شي من هذا", "لا للأسف"],
        AnswerClass.PARTIAL: ["بعضه بس مو كله", "عندنا شي بس مو دايم", "نسوي جزء منه"],
        AnswerClass.UNKNOWN: ["مدري والله", "ما أدري، أسأل الفني", "وش تقصد بالضبط؟"],
    },
    "msa": {
        AnswerClass.YES: ["نعم، هذا مطبّق لدينا", "نعم بالتأكيد", "نعم، ولدينا ما يثبت ذلك، {evidence}"],
        AnswerClass.NO: ["لا، غير مطبّق حالياً", "لا يوجد لدينا", "لا"],
        AnswerClass.PARTIAL: ["مطبّق جزئياً فقط", "في بعض الأنظمة دون غيرها"],
        AnswerClass.UNKNOWN: ["لست متأكداً", "لا أعرف الإجابة"],
    },
    "english": {
        AnswerClass.YES: ["Yes, we have that in place", "Yes, {evidence_en}"],
        AnswerClass.NO: ["No, we don't", "Not at all"],
        AnswerClass.PARTIAL: ["Partly, not everywhere", "Sometimes, but not consistently"],
        AnswerClass.UNKNOWN: ["Not sure, I'd have to ask IT", "No idea honestly"],
    },
}
EVIDENCE = ["وأقدر أرسل لكم صورة من الإعدادات", "وعندي تقرير أقدر أرفقه"]
EVIDENCE_EN = ["I can send a screenshot", "report attached"]
VAGUE = ["يعني تقريباً", "أظن، الفني يعرف أكثر", "it depends"]


@dataclass
class SimOwner:
    case: EvalCase
    persona: str = "honest"  # honest | overstating | vague
    seed: int = 0
    registers: tuple[str, ...] = ("dialect", "msa", "english")
    scope_update_at: int | None = None  # E5: correct the staff count at this answer
    scope_update: dict[str, object] = field(default_factory=dict)
    truth_said: dict[str, AnswerClass] = field(default_factory=dict, init=False)
    overstated: set[str] = field(default_factory=set, init=False)
    vague_first: set[str] = field(default_factory=set, init=False)
    _answers: int = field(default=0, init=False)
    _rng: random.Random = field(init=False)

    def __post_init__(self) -> None:
        self._rng = random.Random(f"{self.case.case_id}:{self.persona}:{self.seed}")

    def truth(self, q: Question) -> AnswerClass:
        """What is really in place for this question's area, from the firm's hidden state."""
        violated_checks = {i.check.value for i in self.case.true_injected}
        if set(q.contradictable_by) & violated_checks:
            return AnswerClass.NO
        records = [r for r in self.case.internal_evidence if r.control_id in q.controls]
        if any(not r.compliant for r in records):
            return AnswerClass.NO
        if records:
            return AnswerClass.YES
        rng = random.Random(f"{self.case.case_id}:truth:{q.qid}")
        return AnswerClass.YES if rng.random() < P_IN_PLACE.get(self.case.posture, 0.5) else AnswerClass.NO

    def said(self, q: Question) -> AnswerClass:
        if q.qid in self.truth_said:
            return self.truth_said[q.qid]
        truth = self.truth(q)
        said = truth
        rng = random.Random(f"{self.case.case_id}:{self.persona}:{self.seed}:overstate:{q.qid}")
        if self.persona == "overstating" and truth is AnswerClass.NO and rng.random() < P_OVERSTATE:
            said = AnswerClass.YES
            self.overstated.add(q.qid)
        self.truth_said[q.qid] = said
        return said

    def _render(self, cls: AnswerClass, key: str) -> str:
        rng = random.Random(f"{self.case.case_id}:{self.persona}:{self.seed}:render:{key}")
        register = rng.choice(self.registers)
        text = rng.choice(TEMPLATES[register][cls])
        return text.format(evidence=rng.choice(EVIDENCE), evidence_en=rng.choice(EVIDENCE_EN))

    def reply(self, request: OwnerRequest) -> OwnerReply:
        if request.kind == "staff_count":
            return OwnerReply(text=str(25 if self.case.size_band == "small" else 120))
        if request.kind == "staff_band":
            return OwnerReply(choices=("6_to_249",))
        if request.kind == "publish_txt":
            return OwnerReply(text="تم")
        if request.kind == "approve_fixes":
            return OwnerReply(choices=request.options)
        q = by_qid()[str(request.payload["qid"])]
        said = self.said(q)
        if request.kind == "buttons":
            return OwnerReply(choices=(said.value,))
        self._answers += 1
        update = self.scope_update if self.scope_update_at == self._answers else None
        first = not request.payload.get("followup")
        rng = random.Random(f"{self.case.case_id}:{self.persona}:{self.seed}:vague:{q.qid}")
        if self.persona == "vague" and first and rng.random() < 0.5:  # noqa: PLR2004
            self.vague_first.add(q.qid)
            return OwnerReply(text=rng.choice(VAGUE), scope_update=update)
        return OwnerReply(text=self._render(said, f"{q.qid}:{'first' if first else 'followup'}"), scope_update=update)
