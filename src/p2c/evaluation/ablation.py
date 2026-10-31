"""Ablation baseline for the evaluation (Stage 8): does the curated mapping add value?

Mapping integrity is 1.000 by construction, so a reader may ask whether the deterministic
rules are a real contribution or a triviality. This baseline answers that: it maps each
scanner check to the catalog control whose title shares the most tokens with the check's
title, the naive "just match the words" approach, and scores it against the curated rules'
answer key over the corpus. Scanner findings and Saudi regulatory control text share almost
no vocabulary, so the correspondence is not lexically recoverable and the naive baseline
scores far below the curated rules, which is exactly why the expert-curated cross-walk is
the toolkit's primary contribution rather than a lookup anyone could regenerate from text.

The scoring loop is shared with the stronger baselines in :mod:`p2c.evaluation.baselines`
(embedding-cosine, BGE-M3, and a zero-shot LLM), which reuse :func:`score_check_mapping`.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Mapping
from typing import Any

from p2c.evaluation import metrics as M
from p2c.evaluation.synthetic import expert_key, generate_cases
from p2c.mapping.catalog import ControlEntry, load_default_index
from p2c.scanning.catalog import CATALOG, CheckId

_STOP = frozenset(
    {
        "the",
        "of",
        "and",
        "to",
        "a",
        "an",
        "in",
        "for",
        "with",
        "by",
        "on",
        "is",
        "are",
        "use",
        "using",
        "absent",
        "missing",
        "no",
        "not",
        "enabled",
        "disabled",
        "or",
        "over",
        "external",
        "entity",
        "its",
        "into",
        "that",
        "this",
        "these",
    }
)
_MIN_TOKEN_LEN = 3
_STATEMENT_CHARS = 160  # how much control statement text a lexical baseline may see


def _tokens(text: str) -> set[str]:
    return {w for w in re.findall(r"[a-z]+", text.lower()) if w not in _STOP and len(w) >= _MIN_TOKEN_LEN}


def subcontrol_entries() -> list[ControlEntry]:
    """Every catalog subcontrol, sorted by native id (the candidate set a mapper chooses from)."""
    index = load_default_index()
    return sorted((e for e in index.entries.values() if e.is_subcontrol), key=lambda e: e.native_id)


# The RQ2 runs predate the data leakage prevention row (NCNICC 2-7-1-1, added 2026-10-21), so every
# mapper chooses among the 95 candidates the recorded language-model runs saw.
RQ2_LATER_ROWS: frozenset[str] = frozenset({"2-7-1-1"})


def rq2_candidates() -> list[ControlEntry]:
    """The RQ2 candidate set: every catalog subcontrol the recorded runs saw (95), sorted by native id."""
    return [e for e in subcontrol_entries() if e.native_id not in RQ2_LATER_ROWS]


def subcontrol_text(entry: ControlEntry) -> str:
    """The text a text-based baseline is allowed to see for a subcontrol (title + statement head)."""
    return f"{entry.title} {entry.statement_en[:_STATEMENT_CHARS]}"


def subcontrol_text_full(entry: ControlEntry) -> str:
    """The full PUBLIC regulatory text for a subcontrol: title plus the complete statement, untruncated.

    Used by the strengthened baselines to answer the objection that a title or truncated statement
    starves the mapper. The statement is the public NCA control text; ATLAS's expert authored
    remediation is deliberately withheld, because feeding an expert written fix back to a baseline
    would leak the very curation the baseline is meant to do without."""
    return f"{entry.title}. {entry.statement_en}"


# The RQ2 experiment was recorded on the 31 detectors that existed before the print service detector
# (2026-10-20), and the language-model ladder cannot be rerun here, so every mapper, the ceiling and
# the constant-mapper floor are scored on those 31 alone.
RQ2_EXCLUDED: frozenset[CheckId] = frozenset({CheckId.EXPOSED_PRINTER_SERVICE})


def _rq2_freq(n: int, seed: int | None) -> Counter[CheckId]:
    """How often each RQ2 detector's finding occurs over ``n`` profiles: the mapping experiments' weights."""
    return Counter(
        inj.check for c in generate_cases(n, seed=seed) for inj in c.injected if inj.check not in RQ2_EXCLUDED
    )


def check_query_text(check: CheckId) -> str:
    """The text a baseline is allowed to see for a scanner check (its title, no expert hint)."""
    return CATALOG[check].title


def _naive_map(check: CheckId, subcontrols: list[tuple[str, set[str]]]) -> str | None:
    """Map a check to the subcontrol whose title/statement tokens most overlap the check title.

    Ties are broken by control id for determinism (``max`` is stable on the first best seen
    once the candidates are sorted)."""
    want = _tokens(CATALOG[check].title)
    best_id: str | None = None
    best_score = -1
    for cid, toks in subcontrols:
        score = len(want & toks)
        if score > best_score:
            best_score = score
            best_id = cid
    return best_id


def keyword_fulltext_baseline(n: int = 100, *, seed: int | None = None) -> dict[str, Any]:
    """Naive keyword overlap, but the candidate is the FULL public control statement (untruncated).

    Strengthens the naive baseline by removing the truncation objection: it may see the complete
    public regulatory text of every control, and still recovers only the handful of definitional
    controls, so the finding to control link is not lexically recoverable even from full text."""
    subcontrols = [(e.native_id, _tokens(subcontrol_text_full(e))) for e in rq2_candidates()]
    naive = {check: _naive_map(check, subcontrols) for check in expert_key()}
    return score_check_mapping(
        naive,
        n,
        seed=seed,
        method="naive keyword title overlap over the full public control text",
        note="candidate is the complete public control statement, untruncated; still far below the "
        "curated cross-walk, so the mapping is not lexically recoverable even from full regulatory text",
    )


def score_check_mapping(
    predicted: Mapping[CheckId, str | frozenset[str] | None],
    n: int,
    *,
    seed: int | None,
    method: str,
    note: str,
) -> dict[str, Any]:
    """Score a check -> control mapping against the curated answer key over ``n`` profiles.

    A baseline predicts either a single control id (single-pick) or a SET of ids (multi-label)
    per check, with no access to the rules; this pools the prediction over the corpus (weighting
    each check by how often it is observed) and reports micro P/R/F1 against the curated key.
    ``curated_f1`` is 1.000 by construction, the number every baseline is measured against.
    """
    key = expert_key()
    freq = _rq2_freq(n, seed)
    pairs: list[tuple[set[str], set[str]]] = []
    for check, count in freq.items():
        gold = set(key.get(check, frozenset()))
        if not gold:
            continue
        raw = predicted.get(check)
        if raw is None:
            pred: set[str] = set()
        elif isinstance(raw, str):
            pred = {raw}
        else:
            pred = set(raw)
        pairs.extend((pred, gold) for _ in range(count))
    micro = M.micro_prf(pairs)
    return {
        "method": method,
        "micro_precision": micro.precision,
        "micro_recall": micro.recall,
        "micro_f1": micro.f1,
        "curated_f1": 1.0,
        "n_findings": len(pairs),
        "note": note,
    }


def naive_keyword_baseline(n: int = 100, *, seed: int | None = None) -> dict[str, Any]:
    """Score the naive keyword mapper against the curated answer key over ``n`` profiles."""
    subcontrols = [(e.native_id, _tokens(subcontrol_text(e))) for e in rq2_candidates()]
    naive = {check: _naive_map(check, subcontrols) for check in expert_key()}
    return score_check_mapping(
        naive,
        n,
        seed=seed,
        method="naive keyword title overlap over the full catalog",
        note="scanner findings and regulatory control text share little vocabulary, so the "
        "finding-to-control mapping is not lexically recoverable and needs the curated cross-walk",
    )


def observable_subcontrol_entries() -> list[ControlEntry]:
    """The subcontrols the taxonomy marks as externally observable (Tier 1): the fair candidate set.

    This is a property of the control catalog's tier field, independent of the finding-to-control
    answer key, so restricting a baseline's candidates to it is not the same as handing over the gold.
    A real operator mapping only externally observable findings would search this set, not all 200
    controls, so it is the fair candidate universe for the lexical baselines."""
    return [e for e in subcontrol_entries() if e.tier == 1]


def _naive_map_set(check: CheckId, subcontrols: list[tuple[str, set[str]]], k: int) -> frozenset[str]:
    """Multi-label naive mapper: the ``k`` subcontrols whose tokens most overlap the check title.

    Removes the single-pick handicap, so a mapper that may name several controls is no longer capped
    below 1.000 by the checks whose gold carries two controls."""
    want = _tokens(CATALOG[check].title)
    ranked = sorted(((len(want & toks), cid) for cid, toks in subcontrols), key=lambda t: (-t[0], t[1]))
    return frozenset(cid for overlap, cid in ranked[:k] if overlap > 0)


def naive_keyword_observable_baseline(
    n: int = 100, *, seed: int | None = None, full_text: bool = False
) -> dict[str, Any]:
    """Naive keyword mapper restricted to the externally observable candidate set (fair candidates).

    The all-catalog baselines search 200 controls when a real external mapper would search only the
    11 the taxonomy marks observable; this reports the fair candidate set. Even so the baseline lands
    far below the curated cross-walk, and, unlike the all-catalog condition, the full public control
    text now helps rather than hurts, because more candidate vocabulary matches on a small set."""
    text_fn = subcontrol_text_full if full_text else subcontrol_text
    subcontrols = [(e.native_id, _tokens(text_fn(e))) for e in observable_subcontrol_entries()]
    naive = {check: _naive_map(check, subcontrols) for check in expert_key()}
    scope = "full public control text" if full_text else "title"
    return score_check_mapping(
        naive,
        n,
        seed=seed,
        method=f"naive keyword over the {scope}, observable candidate set",
        note="candidates restricted to the taxonomy's externally observable controls, the fair set a "
        "real external mapper would search; still far below the curated cross-walk",
    )


def naive_keyword_multilabel_baseline(n: int = 100, *, seed: int | None = None, k: int = 2) -> dict[str, Any]:
    """Naive keyword mapper allowed to predict ``k`` controls per check (removes the single-pick cap).

    A single-pick mapper is capped below 1.000 by the multi-gold checks; this lets the baseline name
    the top ``k`` controls so the cap cannot explain a low score. Even uncapped it stays far below the
    curated cross-walk, so the single-pick handicap is not why the baselines fail."""
    subcontrols = [(e.native_id, _tokens(subcontrol_text_full(e))) for e in rq2_candidates()]
    multi = {check: _naive_map_set(check, subcontrols, k) for check in expert_key()}
    return score_check_mapping(
        multi,
        n,
        seed=seed,
        method=f"naive keyword multi-label (top {k}) over the full public control text",
        note="allowed to predict the top controls per check, removing the single-pick cap; still far "
        "below the curated cross-walk, so the cap does not explain the gap",
    )


# Definitional artifacts named literally in BOTH the public control statement and the scan check name,
# so a finding-to-control link can be read off text alone, independent of mapping/rules.py.
_DEFINITIONAL_ARTIFACTS: dict[str, str] = {
    "spf": "2-4-3-5",
    "dkim": "2-4-3-5",
    "dmarc": "2-4-3-5",
    "ddos": "2-5-3-9",
}


def definitional_agreement() -> dict[str, Any]:
    """Rule-free convergent validity for the definitional controls (breaks taxonomy circularity here).

    The search over all 95 candidates is the point: agreement only means something if the artifact
    name picks ONE control out of the whole universe, so ``ambiguous`` must come back empty.

    For artifacts named literally in both the public control statement and the scan check name (SPF,
    DKIM, DMARC in ECC-2:2024 2-4-3-5; DDoS in 2-5-3-9), a second gold can be read off the text alone,
    independent of :mod:`p2c.mapping.rules`. Agreement with the curated rules confirms that the
    correct-by-construction mapping for this subset is grounded in an independent source, not only in
    the rules that also define the answer key. Returns the links checked and the agreement count."""
    key = expert_key()
    links = confirmed = 0
    ambiguous: list[str] = []
    for artifact, cid in _DEFINITIONAL_ARTIFACTS.items():
        # Search the whole candidate universe for controls whose public text names the artifact,
        # rather than asking only whether the curated control happens to name it. The claim is that
        # the text SELECTS the control, so a second control naming the same artifact would refute it.
        naming = [
            e.native_id for e in rq2_candidates() if artifact in (e.title + " " + e.statement_en).lower()
        ]
        if naming != [cid]:
            ambiguous.append(f"{artifact}:{naming}")
        names_it = naming == [cid]
        for check, gold in key.items():
            if artifact in check.value.lower():  # the scan check itself names the artifact
                links += 1
                if names_it and cid in gold:  # statement names it AND the curated rule agrees
                    confirmed += 1
    return {
        "links": links,
        "confirmed": confirmed,
        "agreement_rate": round(confirmed / links, 3) if links else 1.0,
        "ambiguous_artifacts": ambiguous,
        "artifact_names_one_control": not ambiguous,
        "note": "finding-to-control links for artifacts named in both the control statement and the "
        "check (SPF, DKIM, DMARC, DDoS). Each artifact name is searched across all 95 candidate "
        "subcontrols; agreement counts only where the search returns exactly the curated control, so "
        "the definitional subset is grounded independently of the mapping rules.",
    }


def majority_class_mapper(n: int = 100, *, seed: int | None = None) -> dict[str, Any]:
    """The floor a mapper must clear: answer the single most frequent gold control to every check.

    A baseline that scores badly is only evidence of a hard task if a degenerate answer scores worse.
    Because observed findings are concentrated (web header checks dominate the corpus), naming the
    modal control every time is a real competitor, and any mapper below it has learned nothing. This
    is the mapping-side counterpart of :func:`single_pick_ceiling`: the ceiling bounds what a
    single-pick mapper can reach, this bounds what it must beat to mean anything.
    """
    key = expert_key()
    freq = _rq2_freq(n, seed)
    weight: Counter[str] = Counter()
    for check, count in freq.items():
        for cid in key.get(check, frozenset()):
            weight[cid] += count
    modal = min((cid for cid, w in weight.items() if w == max(weight.values())), default="")
    total = sum(count for check, count in freq.items() if key.get(check))
    result = score_check_mapping(
        dict.fromkeys(key, modal),
        n,
        seed=seed,
        method=f"constant: answer {modal} to every check, ignoring the finding",
        note="the degenerate floor every non-curated baseline must clear; it exploits the corpus's "
        "concentration on one control rather than reading the finding at all",
    )
    result["modal_control"] = modal
    result["modal_share"] = round(weight[modal] / total, 3) if total else 0.0
    return result


# The seven web application hardening checks the classification records against no control (no ECC
# requirement names a security header, a directory listing or an exposed file; 2026-10-20 recode). The
# competing reading, an assessor raising them under the parent 2-15-3 on its "as a minimum" clause,
# is reported as a sensitivity (the coarse reading); the key is NOT changed.
PARENT_READING_CHECKS: frozenset[str] = frozenset(
    {
        "missing_csp",
        "missing_x_frame_options",
        "missing_x_content_type_options",
        "missing_referrer_policy",
        "missing_permissions_policy",
        "directory_listing_enabled",
        "exposed_sensitive_file",
    }
)


def parent_reading_sensitivity(n: int = 100, *, seed: int | None = None) -> dict[str, Any]:
    """What the coarse reading does to the benchmark's concentration, without adopting it.

    Records the seven hardening checks, which the key links to no control, at the parent 2-15-3, and
    reports how the finding-weighted modal share and the degenerate constant-mapper floor move.
    """
    key = expert_key()
    freq = _rq2_freq(n, seed)

    def weights(remap: bool) -> Counter[str]:
        w: Counter[str] = Counter()
        for check, count in freq.items():
            for cid in ids_for(check, remap):
                w[cid] += count
        return w

    def ids_for(check: CheckId, remap: bool) -> frozenset[str]:
        coarse = remap and check.value in PARENT_READING_CHECKS
        return key.get(check, frozenset()) | ({"2-15-3"} if coarse else frozenset())

    out: dict[str, Any] = {}
    for label, remap in (("as_shipped", False), ("parent_reading", True)):
        total = sum(count for check, count in freq.items() if ids_for(check, remap))
        gold = sum(count * len(ids_for(check, remap)) for check, count in freq.items())
        w = weights(remap)
        modal, mw = max(w.items(), key=lambda kv: (kv[1], kv[0]))
        tp = 0
        for check, count in freq.items():
            ids = ids_for(check, remap)
            if modal in ids:
                tp += count
        precision, recall = tp / total, tp / gold
        out[label] = {
            "modal_control": modal,
            "modal_share": round(mw / total, 3),
            "constant_mapper_f1": round(2 * precision * recall / (precision + recall), 6),
        }
    out["note"] = (
        "sensitivity only. The shipped key is unchanged; the panel of Section 9.7 rules on the reading."
    )
    return out


def single_pick_ceiling(n: int = 100, *, seed: int | None = None) -> float:
    """The analytical micro-F1 ceiling for any one-control-per-check mapper on this corpus.

    Some checks carry a two-control gold, so a mapper that names one control per check cannot reach
    1.000 even when every pick is a true gold control. With ``N`` weighted findings and ``M`` of them
    carrying an extra gold control, the ceiling is ``2N / (2N + M)``. Single-pick baselines are
    measured against this, not against 1.000."""
    key = expert_key()
    freq = _rq2_freq(n, seed)
    total = extra = 0
    for check, count in freq.items():
        gold = key.get(check, frozenset())
        if not gold:
            continue
        total += count
        extra += count * (len(gold) - 1)
    return round(2 * total / (2 * total + extra), 3) if total else 1.0
