"""Deterministic hashing embedder — the one piece of the old RAG stack this repo keeps.

The RAG retrieval/grounding machinery is out of scope for this toolkit, but
:mod:`p2c.evaluation.baselines` needs a lexical embedding mapper to answer the question
"is the finding-to-control correspondence recoverable without expert curation?". That
baseline only needs a deterministic, dependency-free text embedder and a cosine, so the
minimum is inlined here rather than carrying a retrieval stack for one baseline.

Copied verbatim (bar the module docstring) from ``atlas.rag.embed`` so the baseline's
numbers stay identical to the ones in the old repo: char-n-gram hashing over BLAKE2b,
L2-normalized, with the Arabic IR normalization that makes a voweled and an unvoweled
spelling of a regulatory term embed as one.
"""

from __future__ import annotations

import hashlib
import math
import re
import unicodedata
from typing import Protocol, runtime_checkable

_TOKEN_RE = re.compile(r"\w+", re.UNICODE)
DEFAULT_DIM = 256
_NGRAM = 3

# Written with escapes: typed as Arabic characters, a right-to-left editor reordered this class so its
# first range ran from U+0610 to U+064B and swallowed every Arabic letter (2026-10-15).
# Harakat and Quranic marks, superscript alef, small high marks, and tatweel.
_ARABIC_DIACRITICS = re.compile("[\u0610-\u061a\u064b-\u065f\u0670\u06d6-\u06ed\u0640]")
_ARABIC_NORM_MAP = str.maketrans(
    {
        "أ": "ا",  # ALEF WITH HAMZA ABOVE -> ALEF
        "إ": "ا",  # ALEF WITH HAMZA BELOW -> ALEF
        "آ": "ا",  # ALEF WITH MADDA ABOVE -> ALEF
        "ٱ": "ا",  # ALEF WASLA -> ALEF
        "ى": "ي",  # ALEF MAKSURA -> YEH
        "ة": "ه",  # TEH MARBUTA -> HEH
    }
)


def normalize_text(text: str) -> str:
    """NFC + lowercase + Arabic-form normalization."""
    text = unicodedata.normalize("NFC", text).lower()
    text = _ARABIC_DIACRITICS.sub("", text)
    return text.translate(_ARABIC_NORM_MAP)


@runtime_checkable
class Embedder(Protocol):
    """Maps texts to fixed-dimension unit vectors (deterministic at a fixed config)."""

    dimension: int

    def embed(self, texts: list[str]) -> list[list[float]]: ...


def _char_ngrams(token: str, n: int) -> list[str]:
    padded = f"^{token}$"
    if len(padded) <= n:
        return [padded]
    return [padded[i : i + n] for i in range(len(padded) - n + 1)]


class HashingEmbedder:
    """Deterministic char-n-gram hashing embedder (dependency-free, language-agnostic).

    Bag-of-hashed-n-grams with L2 normalization → cosine similarity ≈ lexical overlap.
    Stable across runs/processes (uses BLAKE2b, not Python's salted ``hash``).
    """

    def __init__(self, dimension: int = DEFAULT_DIM, *, ngram: int = _NGRAM) -> None:
        self.dimension = dimension
        self._ngram = ngram
        self.name = "hashing"

    def _bucket(self, gram: str) -> int:
        digest = hashlib.blake2b(gram.encode("utf-8"), digest_size=8).digest()
        return int.from_bytes(digest, "big") % self.dimension

    def embed(self, texts: list[str]) -> list[list[float]]:
        return [self._embed_one(t) for t in texts]

    def _embed_one(self, text: str) -> list[float]:
        vector = [0.0] * self.dimension
        for token in _TOKEN_RE.findall(normalize_text(text)):
            for gram in _char_ngrams(token, self._ngram):
                vector[self._bucket(gram)] += 1.0
        norm = math.sqrt(sum(v * v for v in vector))
        if norm == 0.0:
            return vector
        return [v / norm for v in vector]


def cosine(a: list[float], b: list[float]) -> float:
    """Cosine similarity of two equal-length vectors (0 if either is a zero vector)."""
    if len(a) != len(b):
        raise ValueError("vectors must have equal length")
    dot = sum(x * y for x, y in zip(a, b, strict=True))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    if na == 0.0 or nb == 0.0:
        return 0.0
    return dot / (na * nb)
