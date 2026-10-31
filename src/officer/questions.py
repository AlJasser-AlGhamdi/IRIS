"""The interview: questions in our own words, the control rows each covers, and how answers are recorded."""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import StrEnum
from functools import cache
from pathlib import Path

from officer import taxonomy
from p2c.scanning.catalog import CATALOG
from p2c.scoring.contradictions import IMPLEMENTS, control_related, hierarchy_related

BANK = Path(__file__).resolve().parent / "data" / "question_bank.json"


class AnswerClass(StrEnum):
    YES = "yes"
    NO = "no"
    PARTIAL = "partial"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class Question:
    qid: str
    topic: str
    subdomains: tuple[str, ...]
    controls: tuple[str, ...]  # Class B rows (M or R) this question speaks for
    contradictable_by: tuple[str, ...]  # detectors whose findings can contradict a "yes"
    prompt_ar: str
    prompt_en: str
    evidence_hint_ar: str
    evidence_hint_en: str

    @property
    def mandatory(self) -> int:
        index = taxonomy.by_id()
        return sum(index[c].class_b == "M" for c in self.controls)


@dataclass(frozen=True)
class Declaration:
    """What one answer records for one control (mirrors the engine's declaration rows)."""

    control_id: str
    tier: int  # 2 with evidence on an internal-assessment row, else 3
    claim: str  # "compliant" or "non_compliant"
    question: str


@cache
def bank() -> tuple[Question, ...]:
    data = json.loads(BANK.read_text(encoding="utf-8"))
    raw: dict[str, list[str]] = {}
    for q in data["questions"]:
        ids = [r.id for r in taxonomy.rows() if r.subdomain in q["subdomains"] and r.in_class_b]
        raw[q["qid"]] = ids + [c for c in q["extra_controls"] if c not in ids]
    # A control that only says "the requirements listed in X are implemented" belongs to the question
    # that asks about X (the engine reads a claim on it as a claim on every listed requirement).
    for implementer, listed in IMPLEMENTS.items():
        home = next((qid for qid, ids in raw.items() if any(hierarchy_related(listed, c) for c in ids)
                     and not any(c == implementer for c in ids)), None)
        holders = [qid for qid, ids in raw.items() if implementer in ids]
        if home is not None and holders:
            for qid in holders:
                raw[qid].remove(implementer)
            raw[home].append(implementer)
    # Likewise a parent control goes with the question that holds its children.
    for qid, ids in raw.items():
        for c in list(ids):
            if any(r.startswith(f"{c}-") for r in ids):
                continue
            home = next((q2 for q2, ids2 in raw.items() if q2 != qid and any(r.startswith(f"{c}-") for r in ids2)),
                        None)
            if home is not None:
                ids.remove(c)
                raw[home].append(c)
    out = []
    for q in data["questions"]:
        ids = raw[q["qid"]]
        # Detectors whose findings contradict a "yes" here, by the engine's claim relation.
        contradictable = sorted({check.value for check, spec in CATALOG.items()
                                 for finding in spec.control_ids for c in ids if control_related(c, finding)})
        out.append(
            Question(
                qid=q["qid"],
                topic=q["topic"],
                subdomains=tuple(q["subdomains"]),
                controls=tuple(sorted(ids, key=_natural)),
                contradictable_by=tuple(contradictable),
                prompt_ar=q["prompt_ar"],
                prompt_en=q["prompt_en"],
                evidence_hint_ar=q["evidence_hint_ar"],
                evidence_hint_en=q["evidence_hint_en"],
            )
        )
    return tuple(out)


@cache
def by_qid() -> dict[str, Question]:
    return {q.qid: q for q in bank()}


def _natural(control_id: str) -> tuple[int, ...]:
    return tuple(int(p) for p in control_id.split("-"))


def declarations(question: Question, answer: AnswerClass, *, evidence: bool) -> list[Declaration]:
    """Yes with proof is Tier-2 evidence on an internal-assessment row, yes alone a Tier-3 declaration, no a
    self-reported gap. Partial and unknown record nothing; the agent follows up instead."""
    if answer not in (AnswerClass.YES, AnswerClass.NO):
        return []
    index = taxonomy.by_id()
    out = []
    for cid in question.controls:
        row = index[cid]
        tier = 2 if (evidence and row.tier == 2 and answer is AnswerClass.YES) else 3  # noqa: PLR2004
        claim = "compliant" if answer is AnswerClass.YES else "non_compliant"
        out.append(Declaration(control_id=cid, tier=tier, claim=claim, question=question.qid))
    return out
