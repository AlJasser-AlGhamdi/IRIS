"""The model's three narrow jobs, each with a schema, a validator and a fallback.

The model never maps findings to controls, never scores, and never sees text a scanned target wrote. When it
fails (invalid JSON, a choice outside the menu, a made-up number, a timeout) the agent takes a deterministic
path and records that it did.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from officer.llm import Call, ModelDown, Provider
from officer.questions import AnswerClass, Question

# 1. Understand an owner's answer

PARSE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "answer": {"type": "string", "enum": [a.value for a in AnswerClass]},
        "evidence_offered": {"type": "boolean"},
        "needs_followup": {"type": "boolean"},
        "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
    },
    "required": ["answer", "evidence_offered", "needs_followup", "confidence"],
}

PARSE_SYSTEM = """You classify a business owner's reply to one cybersecurity question.
The reply may be in formal Arabic, Saudi dialect, English, Arabizi, or a mix.
Return JSON only:
- answer: "yes" if the reply clearly says the practice is fully in place; "no" if it is clearly not in place
  (including "we have none" or "we share one account"); "partial" if only part is in place or it is
  irregular; "unknown" if the owner does not know, is unsure, asks what the question means, or changes topic.
- evidence_offered: true only if the owner offers or attaches proof (screenshot, report, document, log).
- needs_followup: true when answer is "partial" or "unknown", or the reply is ambiguous.
- confidence: how sure you are.
Saudi dialect hints: إيه / ايوه / اي / أكيد / طبعاً = yes. لا / مو / ما عندنا / ماعندنا = no.
مدري / ما أدري / ما أعرف / مو متأكد = unknown. بس / لكن / أحياناً / مو دايم = often partial.
Examples:
Q: Do you review logs? A: "إيه نراجعها كل يوم" -> {"answer":"yes","evidence_offered":false,"needs_followup":false,"confidence":"high"}
Q: Do you have MFA? A: "على الإيميل بس" -> {"answer":"partial","evidence_offered":false,"needs_followup":true,"confidence":"high"}
Q: Is the server room locked? A: "what do you mean by server room?" -> {"answer":"unknown","evidence_offered":false,"needs_followup":true,"confidence":"high"}
Q: Do you test restores? A: "No we never did" -> {"answer":"no","evidence_offered":false,"needs_followup":false,"confidence":"high"}"""


@dataclass(frozen=True)
class Parsed:
    answer: AnswerClass
    evidence_offered: bool
    needs_followup: bool
    confidence: str
    source: str  # "model" or "lexicon"
    call: Call | None


def parse_user_prompt(question: Question, reply: str) -> str:
    return f"Question: {question.prompt_en}\nOwner's reply: {reply.strip()[:600]}"


def parse_answer(provider: Provider | None, question: Question, reply: str) -> Parsed:
    if provider is not None:
        for _ in range(2):  # one retry
            try:
                call = provider.complete("parse", PARSE_SYSTEM, parse_user_prompt(question, reply), PARSE_SCHEMA)
            except ModelDown:
                break
            parsed = _valid_parse(call.parsed)
            if parsed is not None:
                answer, evidence, followup, confidence = parsed
                return Parsed(answer, evidence, followup, confidence, "model", call)
    return lexicon_parse(reply)


def _valid_parse(value: dict[str, Any] | None) -> tuple[AnswerClass, bool, bool, str] | None:
    if value is None:
        return None
    try:
        answer = AnswerClass(value["answer"])
        evidence = value["evidence_offered"]
        followup = value["needs_followup"]
        confidence = value["confidence"]
    except (KeyError, ValueError):
        return None
    if not isinstance(evidence, bool) or not isinstance(followup, bool):
        return None
    if confidence not in ("low", "medium", "high"):
        return None
    return answer, evidence, followup or answer in (AnswerClass.PARTIAL, AnswerClass.UNKNOWN), confidence


_DIACRITICS = re.compile(r"[ً-ٰٟـ]")


def normalize(text: str) -> str:
    text = unicodedata.normalize("NFKC", text).lower()
    text = _DIACRITICS.sub("", text)
    return (
        text.replace("أ", "ا").replace("إ", "ا").replace("آ", "ا").replace("ى", "ي").replace("ة", "ه")
    )


_UNKNOWN = ("مدري", "ما ادري", "ما اعرف", "مو متاكد", "لا اعرف", "لست متاكد", "تقصد", "يعني ايش",
            "وش يعني", "not sure", "don't know", "dont know", "no idea", "what do you mean")
_PARTIAL = ("بس", "لكن", "احيانا", "مو دايم", "مو دائما", "جزئي", "جزئيا", "بعض", "but", "partly", "sometimes",
            "only", "except")
_NO = ("لا", "مو", "ما عندنا", "ماعندنا", "ما فيه", "مافي", "ابد", "never", "no", "not", "don't", "dont")
_YES = ("ايه", "ايوه", "اي", "اكيد", "طبعا", "نعم", "عندنا", "مفعل", "yes", "of course", "sure")
_EVIDENCE = ("صوره", "لقطه", "تقرير", "ارسل", "اقدر ارسل", "مرفق", "screenshot", "report", "attached",
             "can share", "i can send")


def _has(text: str, phrases: tuple[str, ...]) -> bool:
    return any(f" {k} " in text for k in phrases)


def _words(reply: str) -> str:
    """Normalised words joined by single spaces, padded, so phrases match whole words only."""
    return " " + " ".join(re.findall(r"[\w']+", normalize(reply))) + " "


def lexicon_parse(reply: str) -> Parsed:
    """Deterministic fallback when the model is down or invalid. Errs toward follow-up."""
    text = _words(reply)
    evidence = _has(text, _EVIDENCE)
    if _has(text, _UNKNOWN):
        answer = AnswerClass.UNKNOWN
    elif _has(text, _PARTIAL):
        answer = AnswerClass.PARTIAL
    elif _has(text, _NO):
        answer = AnswerClass.NO
    elif _has(text, _YES):
        answer = AnswerClass.YES
    else:
        answer = AnswerClass.UNKNOWN
    followup = answer in (AnswerClass.PARTIAL, AnswerClass.UNKNOWN)
    return Parsed(answer, evidence, followup, "low", "lexicon", None)


# 2. Choose the next action from a menu code has already filtered

CHOOSE_SYSTEM = """You run a compliance assessment for a small Saudi company.
Code has listed the only actions allowed right now, best-first by its own priority rule.
Pick the single next action that best moves the assessment forward. Prefer the first option unless
the state facts give a clear reason to pick another. Return JSON: {"action_id": <one listed id>,
"reason_ar": <one short Arabic sentence for the owner, no numbers or control ids>}."""


@dataclass(frozen=True)
class Choice:
    action_id: str
    reason_ar: str
    source: str  # "model" or "policy"
    call: Call | None
    rejected: str | None = None  # why a model choice was refused, if it was


def choose_schema(menu: Sequence[str]) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {
            "action_id": {"type": "string", "enum": list(menu)},
            "reason_ar": {"type": "string", "maxLength": 160},
        },
        "required": ["action_id", "reason_ar"],
    }


def choose_user_prompt(phase: str, facts: Sequence[str], menu: Sequence[tuple[str, str]]) -> str:
    lines = [f"Phase: {phase}", "State facts:"] + [f"- {f}" for f in facts]
    lines += ["Allowed actions (best-first):"] + [f"- {aid}: {desc}" for aid, desc in menu]
    return "\n".join(lines)


def choose_action(
    provider: Provider | None, phase: str, facts: Sequence[str], menu: Sequence[tuple[str, str]]
) -> Choice:
    if not menu:
        raise ValueError("empty menu: the gate allows nothing, the session must stop or escalate")
    ids = [aid for aid, _ in menu]
    rejected = None
    if provider is not None and len(ids) > 1:
        try:
            call = provider.complete(
                "choose", CHOOSE_SYSTEM, choose_user_prompt(phase, facts, menu), choose_schema(ids)
            )
        except ModelDown:
            call = None
        if call is not None:
            value = call.parsed or {}
            action = value.get("action_id")
            reason = str(value.get("reason_ar", ""))[:160]
            if action in ids:
                return Choice(str(action), "" if _has_digits_or_ids(reason) else reason, "model", call)
            return Choice(ids[0], "", "policy", call, "not on the menu")
    return Choice(ids[0], "", "single" if len(ids) == 1 else "policy", None, rejected)


_ID_OR_NUMBER = re.compile(r"[0-9٠-٩]")


def _has_digits_or_ids(text: str) -> bool:
    return bool(_ID_OR_NUMBER.search(text))


# 3. Explain typed facts to the owner, in Arabic

EXPLAIN_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {"text_ar": {"type": "string", "maxLength": 600}},
    "required": ["text_ar"],
}

EXPLAIN_SYSTEM = """You explain one compliance fact to the owner of a small Saudi company, in clear,
polite Modern Standard Arabic (2 to 3 short sentences). Use ONLY the facts given. Do not add numbers,
dates, standards, product names or control identifiers that are not in the facts. If a fact is a
finding, say what it means for the business and what will happen next. Return JSON {"text_ar": ...}."""


@dataclass(frozen=True)
class Explanation:
    text_ar: str
    source: str  # "model" or "template"
    call: Call | None
    rejected: str | None = None


_TOKENS = re.compile(r"[0-9]+(?:[-.][0-9]+)*|[A-Za-z][A-Za-z0-9_-]{2,}(?:\.[A-Za-z0-9_-]+)*")  # no trailing "."
_ARABIC_DIGITS = str.maketrans("٠١٢٣٤٥٦٧٨٩۰۱۲۳۴۵۶۷۸۹", "01234567890123456789")


def unsupported_tokens(text: str, facts: dict[str, str]) -> list[str]:
    """Numbers (any script), ids and Latin terms in ``text`` that no fact supports. Numbers and ids must match
    a whole fact token ("249" does not support "24"); Latin words may appear inside a fact."""
    facts_text = " ".join(facts.values()).translate(_ARABIC_DIGITS).lower()
    fact_tokens = set(_TOKENS.findall(facts_text))
    out = []
    for tok in _TOKENS.findall(text.translate(_ARABIC_DIGITS)):
        low = tok.lower()
        numeric = low[0].isdigit()
        if (numeric and low not in fact_tokens) or (not numeric and low not in facts_text):
            out.append(tok)
    return out


def explain(provider: Provider | None, facts: dict[str, str], template_ar: str) -> Explanation:
    if provider is not None:
        user = "Facts:\n" + "\n".join(f"- {k}: {v}" for k, v in facts.items())
        try:
            call = provider.complete("explain", EXPLAIN_SYSTEM, user, EXPLAIN_SCHEMA)
        except ModelDown:
            call = None
        if call is not None:
            text = str((call.parsed or {}).get("text_ar", "")).strip()
            extra = unsupported_tokens(text, facts)
            if text and not extra and _mostly_arabic(text):
                return Explanation(text, "model", call)
            reason = f"unsupported: {extra[:3]}" if extra else "empty or not Arabic"
            return Explanation(template_ar, "template", call, reason)
    return Explanation(template_ar, "template", None)


def _mostly_arabic(text: str) -> bool:
    letters = [c for c in text if c.isalpha()]
    arabic = [c for c in letters if "؀" <= c <= "ۿ"]
    return bool(letters) and len(arabic) / len(letters) >= 0.6  # noqa: PLR2004
