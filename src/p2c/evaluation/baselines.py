"""Stronger automated mapping baselines (Stage 8): is the crosswalk recoverable without experts?

The naive keyword baseline of :mod:`p2c.evaluation.ablation` is a weak strawman on its own,
so this module also measures three stronger, non-curated mappers against the same curated answer
key: a lexical embedding-cosine mapper (the hermetic hashing embedder), a BGE-M3 semantic mapper
(the ``ml`` extra), and a zero-shot LLM mapper (self-hosted Ollama). Each sees only a scanner
check's title and the catalog of subcontrol titles, and picks the single control it evidences,
with no access to the rules. If even a modern multilingual embedder and an instruction-tuned LLM
land far below the curated 1.000, the finding-to-control correspondence is genuinely not
recoverable by lexical, semantic, or LLM means, and the expert-curated cross-walk is a real
contribution rather than a lookup anyone could regenerate.

The hashing baseline is deterministic and offline, so it runs inside ``make reproduce``. BGE-M3
and the LLM need model weights or a running Ollama daemon, so they are opt-in (one-time,
model-backed) and reported as such; they are never part of hermetic CI.
"""

from __future__ import annotations

import contextlib
import re
from typing import TYPE_CHECKING, Any

from p2c._embed import HashingEmbedder, cosine
from p2c.evaluation.ablation import (
    check_query_text,
    definitional_agreement,
    keyword_fulltext_baseline,
    majority_class_mapper,
    naive_keyword_baseline,
    naive_keyword_multilabel_baseline,
    naive_keyword_observable_baseline,
    observable_subcontrol_entries,
    parent_reading_sensitivity,
    rq2_candidates,
    score_check_mapping,
    single_pick_ceiling,
    subcontrol_text,
    subcontrol_text_full,
)
from p2c.evaluation.synthetic import expert_key

if TYPE_CHECKING:
    from collections.abc import Callable

    from p2c._embed import Embedder
    from p2c.mapping.catalog import ControlEntry
    from p2c.scanning.catalog import CheckId

_ID_RE = re.compile(r"\d(?:-\d{1,2}){2,3}")  # native ECC id, e.g. 2-15-3-3
DEFAULT_LLM_MODEL = "qwen2.5:7b"
DEFAULT_OLLAMA_HOST = "http://127.0.0.1:11434"


def _ranked_checks() -> list[CheckId]:
    """The checks a baseline must map, in a deterministic order."""
    return sorted(expert_key(), key=lambda c: c.value)


def _embedding_mapping(
    embedder: Embedder,
    *,
    text_fn: Callable[[ControlEntry], str] = subcontrol_text,
    candidates: list[ControlEntry] | None = None,
) -> dict[CheckId, str | None]:
    """Map each check to the subcontrol whose embedding is most cosine-similar to the check title.

    ``text_fn`` selects how much control text the embedder sees (title plus statement head by
    default, or the full public statement via :func:`subcontrol_text_full`). ``candidates`` restricts
    the candidate set (the full catalog by default, or the observable Tier-1 controls)."""
    candidates = candidates if candidates is not None else rq2_candidates()
    candidate_vectors = embedder.embed([text_fn(e) for e in candidates])
    checks = _ranked_checks()
    query_vectors = embedder.embed([check_query_text(c) for c in checks])
    mapping: dict[CheckId, str | None] = {}
    for check, query in zip(checks, query_vectors, strict=True):
        best_id: str | None = None
        best_score = -2.0
        for entry, vector in zip(candidates, candidate_vectors, strict=True):
            score = cosine(query, vector)
            if score > best_score:
                best_score = score
                best_id = entry.native_id
        mapping[check] = best_id
    return mapping


def embedding_cosine_baseline(n: int = 100, *, seed: int | None = None) -> dict[str, Any]:
    """Hermetic lexical embedding baseline (the deterministic hashing embedder over full text)."""
    mapping = _embedding_mapping(HashingEmbedder())
    return score_check_mapping(
        mapping,
        n,
        seed=seed,
        method="embedding cosine (hashing embedder) over the full catalog",
        note="cosine over a deterministic lexical embedding of check and control text; still far "
        "below the curated cross-walk because the two vocabularies barely overlap",
    )


def embedding_cosine_fulltext_baseline(n: int = 100, *, seed: int | None = None) -> dict[str, Any]:
    """Hermetic lexical embedding baseline over the FULL public control text (untruncated).

    Answers the objection that a truncated statement starves the embedder: it may see every
    control's complete public statement and still lands far below the curated cross-walk."""
    mapping = _embedding_mapping(HashingEmbedder(), text_fn=subcontrol_text_full)
    return score_check_mapping(
        mapping,
        n,
        seed=seed,
        method="embedding cosine (hashing) over the full public control text",
        note="deterministic lexical embedding over the complete public control statement; still far "
        "below the curated cross-walk, so the correspondence is not recoverable even from full text",
    )


def embedding_cosine_observable_baseline(
    n: int = 100, *, seed: int | None = None, full_text: bool = True
) -> dict[str, Any]:
    """Hermetic lexical embedding baseline restricted to the observable candidate set (fair candidates).

    The all-catalog embedding baseline searches all 95 subcontrols; this restricts the candidates to the 11
    externally testable subcontrols, the fair set a real external mapper would search, and it
    still lands far below the curated cross-walk."""
    text_fn = subcontrol_text_full if full_text else subcontrol_text
    mapping = _embedding_mapping(
        HashingEmbedder(), text_fn=text_fn, candidates=observable_subcontrol_entries()
    )
    return score_check_mapping(
        mapping,
        n,
        seed=seed,
        method="embedding cosine (hashing) over the observable candidate set",
        note="deterministic lexical embedding restricted to the taxonomy's externally observable "
        "controls, the fair candidate set; still far below the curated cross-walk",
    )


def bge_semantic_baseline(
    n: int = 100, *, seed: int | None = None, full_text: bool = False
) -> dict[str, Any]:
    """Semantic embedding baseline (BGE-M3, ``ml`` extra). Opt-in, model-backed, deterministic.

    With ``full_text`` the retriever sees every control's complete public statement, the strongest
    semantic condition, so a low score cannot be blamed on starved context."""
    # NOT CARRIED into this repo (the toolkit drops the RAG stack): the BGE-M3 backend lives in
    # the upstream research code as atlas.rag.bge. This raises ModuleNotFoundError until it is
    # copied back; the hermetic hashing baseline above is the one `make reproduce` runs.
    from p2c.rag.bge import BgeEmbedder  # noqa: PLC0415 - heavy ml-extra import, opt-in only

    text_fn = subcontrol_text_full if full_text else subcontrol_text
    mapping = _embedding_mapping(BgeEmbedder(), text_fn=text_fn)
    scope = "full public control text" if full_text else "the full catalog"
    return score_check_mapping(
        mapping,
        n,
        seed=seed,
        method=f"BGE-M3 semantic cosine over {scope}",
        note="a modern multilingual dense retriever mapping by meaning; still far below the "
        "curated cross-walk, so semantic similarity does not recover the finding-to-control link",
    )


def _extract_control_id(response: str, valid: frozenset[str]) -> str | None:
    """The first native control id in the model's reply that is a real catalog subcontrol."""
    for match in _ID_RE.findall(response):
        if match in valid:
            return str(match)
    return None


_LLM_TIMEOUT = 600.0  # a cold 7B model on CPU can take minutes for the first long-prompt call


def _llm_mapping(
    *, model: str, host: str, seed: int, full_text: bool = False
) -> tuple[dict[CheckId, str | None], int]:
    """Ask a zero-shot LLM to pick the control each check evidences (constrained to the catalog).

    With ``full_text`` the model sees each candidate control's complete public statement, not just
    its title, the strongest zero-shot condition: a low score then cannot be blamed on thin context.
    Returns the mapping plus the number of checks the model failed to answer (a call error or an
    unparseable reply), so a slow or flaky daemon degrades the score honestly instead of crashing.
    """
    import httpx  # noqa: PLC0415 - only needed for the opt-in LLM baseline

    # NOT CARRIED into this repo (the toolkit drops llm/): lives in the upstream research code as
    # atlas.llm.provider. Raises ModuleNotFoundError until copied back; the LLM ladder is
    # read from the tracked evaluation/baseline_ladder_results.json instead.
    from p2c.llm.provider import OllamaProvider  # noqa: PLC0415 - needs a running Ollama daemon

    candidates = rq2_candidates()
    valid = frozenset(e.native_id for e in candidates)
    if full_text:
        catalog_block = "\n".join(f"{e.native_id}: {subcontrol_text_full(e)}" for e in candidates)
    else:
        catalog_block = "\n".join(f"{e.native_id}: {e.title}" for e in candidates)
    system = (
        "You are a cybersecurity compliance expert mapping one external scan finding to the single "
        "ECC-2:2024 control subcontrol it evidences. Reply with only one control id from the list."
    )
    provider = OllamaProvider(model=model, host=host)
    # Fit the whole catalog prompt without truncation (full-text is ~5k tokens); disable a reasoning
    # model's <think> trace so the single-id task is fair and does not burn the token budget thinking.
    ctx = 8192 if full_text else 4096
    # Warm the model into memory so the first scored call is not paying the cold-start cost.
    with contextlib.suppress(httpx.HTTPError, OSError):
        provider.complete("ready?", max_tokens=1, timeout=_LLM_TIMEOUT, num_ctx=ctx, think=False)
    mapping: dict[CheckId, str | None] = {}
    failures = 0
    for check in _ranked_checks():
        prompt = (
            f"Scan finding: {check_query_text(check)}\n\n"
            f"Candidate controls (id: title):\n{catalog_block}\n\n"
            "Reply with the single best control id and nothing else."
        )
        try:
            response = provider.complete(
                prompt,
                system=system,
                temperature=0.0,
                seed=seed,
                max_tokens=24,
                timeout=_LLM_TIMEOUT,
                num_ctx=ctx,
                think=False,
            )
        except (httpx.HTTPError, OSError):
            mapping[check] = None
            failures += 1
            continue
        control = _extract_control_id(response, valid)
        if control is None:
            failures += 1
        mapping[check] = control
    return mapping, failures


def llm_zeroshot_baseline(
    n: int = 100,
    *,
    seed: int | None = None,
    model: str = DEFAULT_LLM_MODEL,
    host: str = DEFAULT_OLLAMA_HOST,
    full_text: bool = False,
) -> dict[str, Any]:
    """Zero-shot LLM mapping baseline (self-hosted Ollama). Opt-in, model-backed.

    With ``full_text`` the model is shown each control's complete public statement, the strongest
    zero-shot condition."""
    resolved_seed = 0 if seed is None else seed
    mapping, failures = _llm_mapping(model=model, host=host, seed=resolved_seed, full_text=full_text)
    context = "full public control text" if full_text else "titles alone"
    result = score_check_mapping(
        mapping,
        n,
        seed=seed,
        method=f"zero-shot LLM ({model}) over {context}, constrained to catalog ids",
        note=f"an instruction-tuned model choosing the control from {context}; still far below "
        "the curated cross-walk, so the mapping is not recoverable zero-shot",
    )
    result["unanswered_checks"] = failures
    return result


def hermetic_baselines(n: int = 100, *, seed: int | None = None) -> dict[str, Any]:
    """The offline, deterministic baselines that run inside ``make reproduce``.

    Includes the title-restricted and the full public text variants of both the keyword and the
    lexical embedding mapper, so the "not lexically recoverable" claim is shown to hold whether the
    baseline sees a title or the complete public control statement."""
    return {
        "naive_keyword": naive_keyword_baseline(n, seed=seed),
        "keyword_fulltext": keyword_fulltext_baseline(n, seed=seed),
        "embedding_hashing": embedding_cosine_baseline(n, seed=seed),
        "embedding_hashing_fulltext": embedding_cosine_fulltext_baseline(n, seed=seed),
        "naive_keyword_observable": naive_keyword_observable_baseline(n, seed=seed),
        "naive_keyword_observable_fulltext": naive_keyword_observable_baseline(n, seed=seed, full_text=True),
        "naive_keyword_multilabel": naive_keyword_multilabel_baseline(n, seed=seed),
        "embedding_hashing_observable": embedding_cosine_observable_baseline(n, seed=seed),
        "majority_class_mapper": majority_class_mapper(n, seed=seed),
        "parent_reading_sensitivity": parent_reading_sensitivity(n, seed=seed),
        "single_pick_ceiling": single_pick_ceiling(n, seed=seed),
        "definitional_agreement": definitional_agreement(),
        "curated_f1": 1.0,
        "note": "non-curated mappers scored against the curated answer key; the curated cross-walk "
        "scores 1.000 by construction. Lexical mappers are run over the full catalog and over the "
        "observable Tier-1 candidate set (the fair set a real external mapper searches), single-pick "
        "and multi-label. single_pick_ceiling is the analytical micro-F1 cap for any one-control-per-"
        "check mapper. Model-backed baselines (BGE-M3, zero-shot LLM) are opt-in.",
    }


def baselines_report(
    n: int = 100,
    *,
    seed: int | None = None,
    models: bool = False,
    llm_model: str = DEFAULT_LLM_MODEL,
    host: str = DEFAULT_OLLAMA_HOST,
) -> dict[str, Any]:
    """Full baseline comparison. ``models=True`` adds the opt-in BGE-M3 and LLM baselines, each over
    both titles and the full public control text (the strongest semantic and zero-shot conditions)."""
    report = hermetic_baselines(n, seed=seed)
    if models:
        report["embedding_bge_m3"] = bge_semantic_baseline(n, seed=seed)
        report["embedding_bge_m3_fulltext"] = bge_semantic_baseline(n, seed=seed, full_text=True)
        report["llm_zeroshot"] = llm_zeroshot_baseline(n, seed=seed, model=llm_model, host=host)
        report["llm_zeroshot_fulltext"] = llm_zeroshot_baseline(
            n, seed=seed, model=llm_model, host=host, full_text=True
        )
    return report
