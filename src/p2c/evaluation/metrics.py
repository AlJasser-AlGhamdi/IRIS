"""Research metrics for the evaluation harness (Stage 8), implemented natively.

Every statistic here is computed from first principles (numpy only) and pinned in
``tests/unit/test_evaluation_metrics.py`` against **published reference values**
(Cohen's kappa 0.4 example, a hand-computed Krippendorff alpha, SUS 50/100 anchors,
textbook precision/recall). This keeps the metrics hermetic in CI and provably
correct, rather than trusting a heavyweight stats dependency (same rationale as the
native AHP/BWM in ADR-0006). ``scikit-learn`` / ``krippendorff`` are used only as
opt-in cross-checks in the ``eval`` extra (``tests/unit/test_evaluation_xcheck.py``).

All functions are deterministic: the only randomness is the bootstrap, which takes an
explicit seed so ``make reproduce`` yields identical confidence intervals.
"""

from __future__ import annotations

import math
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from statistics import NormalDist

import numpy as np
from scipy.optimize import linear_sum_assignment

# A sentinel for a missing rating in reliability data (a coder skipped a unit).
MISSING = None

_MIN_RATINGS_PER_UNIT = 2  # a unit needs >= 2 ratings to inform agreement
_SUS_ITEMS = 10
_SUS_MIN, _SUS_MAX = 1, 5
_MIN_GROUP = 2  # Cohen's d needs >= 2 observations per group for a sample SD
_SUBCONTROL_SEGMENTS = 4  # a full subcontrol id is domain-subdomain-control-subcontrol


def _as_float(value: object) -> float:
    """Coerce a numeric rating to float, or reject a non-numeric one with a clear error."""
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise ValueError("krippendorff ratings must be numeric (encode categories as ints)")
    return float(value)


# --------------------------------------------------------------------------- #
# Classification: precision / recall / F1 over sets of control ids             #
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class PRF:
    """A precision/recall/F1 triple with the raw confusion counts."""

    precision: float
    recall: float
    f1: float
    true_positive: int
    false_positive: int
    false_negative: int


def _f1(precision: float, recall: float) -> float:
    return 0.0 if (precision + recall) == 0 else 2 * precision * recall / (precision + recall)


def prf_from_counts(tp: int, fp: int, fn: int) -> PRF:
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    return PRF(precision, recall, _f1(precision, recall), tp, fp, fn)


def set_prf(predicted: set[str], gold: set[str]) -> PRF:
    """Precision/recall/F1 of one predicted control-id set against the gold set."""
    tp = len(predicted & gold)
    return prf_from_counts(tp, len(predicted - gold), len(gold - predicted))


def case_f1(predicted: set[str], gold: set[str]) -> float:
    """Per-case F1 for macro-averaging, with the true-negative convention.

    A profile that truly has no gap and for which the pipeline predicts nothing is a
    correct "nothing to find, found nothing" outcome and scores 1.0, not the 0.0 that
    the raw F1 (0/0) convention would assign. Every non-empty case falls through to the
    ordinary :func:`set_prf` F1. Only the macro path uses this; micro-averaging pools
    confusion counts and is unaffected (an empty/empty case adds no tp/fp/fn there).
    """
    if not predicted and not gold:
        return 1.0
    return set_prf(predicted, gold).f1


def micro_prf(pairs: Sequence[tuple[set[str], set[str]]]) -> PRF:
    """Micro-averaged P/R/F1: pool the confusion counts across all (predicted, gold) cases.

    Micro-averaging weights every control-id decision equally (the right choice when
    profiles carry different numbers of findings), so a profile with more findings
    contributes proportionally more — see Arp et al. on inappropriate measures.
    """
    tp = fp = fn = 0
    for predicted, gold in pairs:
        tp += len(predicted & gold)
        fp += len(predicted - gold)
        fn += len(gold - predicted)
    return prf_from_counts(tp, fp, fn)


def macro_f1(pairs: Sequence[tuple[set[str], set[str]]]) -> float:
    """Macro-averaged F1: mean of per-case F1 (every profile weighted equally).

    Uses :func:`case_f1`, so a correct empty/empty case counts as 1.0 rather than
    dragging the mean down with a spurious 0.0.
    """
    if not pairs:
        return 0.0
    return float(np.mean([case_f1(p, g) for p, g in pairs]))


# --------------------------------------------------------------------------- #
# Whole-table measures: what F1 cannot see (the true negatives)                #
# --------------------------------------------------------------------------- #
def mcc_from_counts(tp: int, fp: int, fn: int, tn: int) -> float:
    """Matthews correlation coefficient over the full 2x2 decision table.

    F1 reads three cells and ignores the true negatives, so on a corpus with a high base
    rate it is bounded well above zero for a predictor that reads nothing at all: assert
    every control everywhere and F1 is 2b/(1+b) in the base rate b. MCC reads all four
    cells, and is 0.0 for any predictor that fills a single row or column of the table,
    predict-all included, which is why it is reported beside F1 (Chicco and Jurman, and
    the Arp et al. warning on inappropriate measures). The zero denominator of such a
    degenerate predictor is the conventional 0.0, its no-correlation value.
    """
    den = math.sqrt(float((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn)))
    return 0.0 if den == 0.0 else (tp * tn - fp * fn) / den


def balanced_accuracy_from_counts(tp: int, fp: int, fn: int, tn: int) -> float:
    """Mean of sensitivity and specificity, which is 0.5 for a constant predictor at any base rate."""
    tpr = tp / (tp + fn) if (tp + fn) else 0.0
    tnr = tn / (tn + fp) if (tn + fp) else 0.0
    return (tpr + tnr) / 2


# --------------------------------------------------------------------------- #
# Fuzzy control-id matching (parent/child near-miss credit)                    #
# --------------------------------------------------------------------------- #
def control_id_similarity(a: str, b: str) -> float:
    """Similarity of two native control ids, crediting only a genuine control-family relation.

    A *near miss* an expert would forgive is one within the same control family: an
    ancestor/descendant (``2-5-3-1`` vs its parent ``2-5-3``), which scores high (1 minus a
    one-level penalty per extra segment), or a *sibling subcontrol* under the same control
    (``2-15-3-1`` vs ``2-15-3-3``, sharing the domain-subdomain-control prefix and differing
    only in the final segment), which scores 0.8. Two ids in different subdomains (``2-8-3-3``
    vs ``2-15-3-3``) are unrelated and score 0.0, even though their digit strings are close;
    an edit-distance ratio would wrongly credit them, so it is not used for control ids.
    """
    if a == b:
        return 1.0
    pa, pb = a.split("-"), b.split("-")
    shorter, longer = (pa, pb) if len(pa) <= len(pb) else (pb, pa)
    if longer[: len(shorter)] == shorter:  # one is a prefix (ancestor) of the other
        extra = len(longer) - len(shorter)
        return max(0.0, 1.0 - 0.15 * extra)
    if len(pa) == len(pb) >= _SUBCONTROL_SEGMENTS and pa[:-1] == pb[:-1]:  # sibling subcontrols
        return 0.8
    return 0.0  # different control or subdomain: not a near miss


def fuzzy_set_prf(predicted: set[str], gold: set[str], *, threshold: float = 0.7) -> PRF:
    """P/R/F1 where a predicted id counts as a hit if it is >= ``threshold`` similar to
    SOME gold id, under an **optimal one-to-one** assignment (each prediction credits at
    most one gold and vice-versa).

    Uses maximum-weight bipartite matching (Hungarian) rather than a greedy pass: greedy by
    descending similarity can undercount (take a 0.9 pair that blocks two 0.75 pairs), which
    would understate the fuzzy score. The optimal matching maximizes credited near-misses.
    """
    preds, golds = sorted(predicted), sorted(gold)
    if not preds or not golds:
        return prf_from_counts(0, len(preds), len(golds))
    sim = np.array([[control_id_similarity(p, g) for g in golds] for p in preds])
    # Maximize total similarity over eligible (>= threshold) pairs. Ineligible pairs get a
    # cost that can never beat a single eligible pair, so they are only chosen as filler.
    eligible = sim >= threshold
    cost = np.where(eligible, -sim, sim.size + 1.0)
    rows, cols = linear_sum_assignment(cost)
    tp = int(sum(1 for r, c in zip(rows, cols, strict=True) if eligible[r, c]))
    return prf_from_counts(tp, len(preds) - tp, len(golds) - tp)


# --------------------------------------------------------------------------- #
# Inter-rater agreement                                                        #
# --------------------------------------------------------------------------- #
def cohens_kappa(rater_a: Sequence[object], rater_b: Sequence[object]) -> float:
    """Cohen's kappa for two raters over paired categorical labels.

    kappa = (po - pe) / (1 - pe). Returns 1.0 when both raters are constant and agree
    (pe == 1 -> perfect-agreement convention), 0.0 when they never agree with pe == 1.
    """
    if len(rater_a) != len(rater_b):
        raise ValueError("raters must label the same number of items")
    n = len(rater_a)
    if n == 0:
        raise ValueError("need at least one item")
    categories = sorted({*rater_a, *rater_b}, key=repr)
    idx = {c: i for i, c in enumerate(categories)}
    k = len(categories)
    conf = np.zeros((k, k))
    for a, b in zip(rater_a, rater_b, strict=True):
        conf[idx[a], idx[b]] += 1
    conf /= n
    po = float(np.trace(conf))
    pe = float(np.sum(conf.sum(axis=0) * conf.sum(axis=1)))
    if pe == 1.0:
        return 1.0 if po == 1.0 else 0.0
    return (po - pe) / (1 - pe)


def fleiss_kappa(units: Sequence[Sequence[object]]) -> float:
    """Fleiss' kappa for a fixed number of raters per unit (Fleiss 1971).

    ``units`` is units x raters: each row holds the labels every rater gave one unit, so every row
    must have the same length (at least two). kappa = (P - Pe) / (1 - Pe), with P the mean per-unit
    pairwise agreement and Pe the chance agreement from the pooled category shares. Returns 1.0 when
    chance agreement is already total and the raters agree (the perfect-agreement convention).
    """
    if not units:
        raise ValueError("need at least one unit")
    n = len(units[0])
    if n < _MIN_RATINGS_PER_UNIT or any(len(row) != n for row in units):
        raise ValueError("every unit needs the same number of raters, at least two")
    categories = sorted({label for row in units for label in row}, key=repr)
    totals = dict.fromkeys(categories, 0)
    agreement = 0.0
    for row in units:
        counts = dict.fromkeys(categories, 0)
        for label in row:
            counts[label] += 1
            totals[label] += 1
        agreement += sum(k * (k - 1) for k in counts.values()) / (n * (n - 1))
    p_bar = agreement / len(units)
    shares = [t / (len(units) * n) for t in totals.values()]
    p_e = sum(share * share for share in shares)
    if p_e == 1.0:
        return 1.0 if p_bar == 1.0 else 0.0
    return (p_bar - p_e) / (1 - p_e)


def _nominal_delta(c: float, k: float, _values: list[float]) -> float:
    return 0.0 if c == k else 1.0


def _ordinal_delta(c: float, k: float, values: list[float], marginals: dict[float, float]) -> float:
    """Ordinal difference^2 (Krippendorff): interval of ranks between the two values."""
    lo, hi = (c, k) if c <= k else (k, c)
    between = sum(marginals[g] for g in values if lo <= g <= hi)
    return (between - (marginals[c] + marginals[k]) / 2.0) ** 2


def krippendorff_alpha(reliability: Sequence[Sequence[object]], *, level: str = "nominal") -> float:
    """Krippendorff's alpha for any number of coders, with missing values allowed.

    ``reliability`` is coders x units; use :data:`MISSING` (None) for an unrated cell.
    ``level`` is ``"nominal"`` or ``"ordinal"``. Units rated by fewer than two coders are
    ignored (they carry no agreement information). Returns 1.0 for perfect agreement.
    """
    if level not in ("nominal", "ordinal"):
        raise ValueError("level must be 'nominal' or 'ordinal'")
    coders = [list(row) for row in reliability]
    if not coders:
        raise ValueError("need at least one coder")
    n_units = len(coders[0])
    if any(len(row) != n_units for row in coders):
        raise ValueError("every coder must rate the same number of units")

    # Ratings must be numeric (encode nominal categories as ints); the coincidence matrix
    # and both difference functions need a numeric domain.
    values = sorted({_as_float(v) for row in coders for v in row if v is not MISSING})
    if len(values) <= 1:
        return 1.0  # no variation -> perfect reliability by convention
    vidx = {v: i for i, v in enumerate(values)}
    m = len(values)
    # Coincidence matrix o_ck: within each unit, every ORDERED pair of distinct ratings
    # (i != j) contributes 1/(m_u - 1). This is Krippendorff's construction; the a==b
    # diagonal is filled by same-valued pairs, so o is symmetric and self-pairs count.
    coincidence = np.zeros((m, m))
    for u in range(n_units):
        ratings = [_as_float(row[u]) for row in coders if row[u] is not MISSING]
        mu = len(ratings)
        if mu < _MIN_RATINGS_PER_UNIT:
            continue
        for i in range(mu):
            for j in range(mu):
                if i == j:
                    continue
                coincidence[vidx[ratings[i]], vidx[ratings[j]]] += 1.0 / (mu - 1)

    n_marginal = coincidence.sum(axis=1)
    n_total = float(n_marginal.sum())
    if n_total == 0:
        return 1.0
    marg = {v: float(n_marginal[vidx[v]]) for v in values}

    def delta2(ci: int, ki: int) -> float:
        c, k = values[ci], values[ki]
        if level == "nominal":
            return _nominal_delta(c, k, values)
        return _ordinal_delta(c, k, values, marg)

    observed = sum(float(coincidence[ci, ki]) * delta2(ci, ki) for ci in range(m) for ki in range(m))
    expected = sum(
        float(n_marginal[ci]) * float(n_marginal[ki]) * delta2(ci, ki) for ci in range(m) for ki in range(m)
    ) / (n_total - 1)
    if expected == 0:
        return 1.0
    return 1.0 - observed / expected


def masi_distance(a: frozenset[str], b: frozenset[str]) -> float:
    """MASI distance between two set valued labels (Passonneau, LREC 2006).

    Similarity is the Jaccard index scaled by a monotonicity factor: 1 for identical
    sets, 2/3 when one set contains the other, 1/3 when they overlap but neither
    contains the other, 0 when they are disjoint. Distance is 1 minus that. This is
    the standard measure for annotation tasks where a coder may assign more than one
    label, and it is what a finding to control mapping needs: two experts who both
    name 2-8-3-3 but differ on whether 2-15-3-3 also applies partly agree, whereas two
    experts who name disjoint controls do not agree at all.
    """
    if a == b:
        return 0.0
    union = a | b
    if not union:
        return 0.0
    intersection = a & b
    if not intersection:
        return 1.0
    jaccard = len(intersection) / len(union)
    monotonicity = 2.0 / 3.0 if (a <= b or b <= a) else 1.0 / 3.0
    return 1.0 - jaccard * monotonicity


def krippendorff_alpha_sets(
    reliability: Sequence[Sequence[frozenset[str] | None]],
    *,
    distance: Callable[[frozenset[str], frozenset[str]], float] = masi_distance,
) -> float:
    """Krippendorff's alpha over set valued labels, using a set distance.

    ``reliability`` is coders x units, each cell the set of labels that coder assigned
    to that unit, or :data:`MISSING` for an unrated cell. Pass ``distance=`` to choose
    the difference function: the default :func:`masi_distance` gives partial credit for
    overlapping sets, while a strict identity distance scores only exact set matches.

    Computed in Krippendorff's observed over expected form,
    ``alpha = 1 - D_o / D_e``, so it needs no numeric coding of the label space and
    cannot be fooled by two coders who assign the same NUMBER of different labels.
    Units rated by fewer than two coders carry no agreement information and are skipped.
    """
    coders = [list(row) for row in reliability]
    if len(coders) < _MIN_RATINGS_PER_UNIT:
        raise ValueError("need at least two coders")
    n_units = len(coders[0])
    if any(len(row) != n_units for row in coders):
        raise ValueError("every coder must rate the same number of units")

    per_unit: list[list[frozenset[str]]] = []
    pool: list[frozenset[str]] = []
    for u in range(n_units):
        rated = [row[u] for row in coders if row[u] is not MISSING]
        if len(rated) < _MIN_RATINGS_PER_UNIT:
            continue
        ratings = [r for r in rated if r is not None]
        per_unit.append(ratings)
        pool.extend(ratings)

    n = len(pool)
    if n < _MIN_RATINGS_PER_UNIT:
        return 1.0

    observed = 0.0
    for ratings in per_unit:
        mu = len(ratings)
        observed += math.fsum(
            distance(ratings[i], ratings[j]) for i in range(mu) for j in range(mu) if i != j
        ) / (mu - 1)
    observed /= n

    expected = math.fsum(distance(pool[i], pool[j]) for i in range(n) for j in range(n) if i != j)
    expected /= n * (n - 1)

    if expected == 0.0:
        return 1.0  # no variation in the pool: perfect reliability by convention
    return 1.0 - observed / expected


# --------------------------------------------------------------------------- #
# System Usability Scale (SUS)                                                 #
# --------------------------------------------------------------------------- #
def sus_score(responses: Sequence[int]) -> float:
    """Score one 10-item SUS response (each item 1..5) to a 0..100 usability score.

    Odd items (1,3,5,7,9) contribute ``x-1``; even items (2,4,6,8,10) contribute
    ``5-x``; the sum is multiplied by 2.5. All-neutral (3s) -> 50; best case -> 100.
    """
    if len(responses) != _SUS_ITEMS:
        raise ValueError("SUS has exactly 10 items")
    if any(not (_SUS_MIN <= r <= _SUS_MAX) for r in responses):
        raise ValueError("SUS responses must be 1..5")
    total = 0
    for i, r in enumerate(responses):
        total += (r - 1) if i % 2 == 0 else (5 - r)  # 0-indexed: even index == odd item
    return total * 2.5


def sus_mean(all_responses: Sequence[Sequence[int]]) -> float:
    if not all_responses:
        raise ValueError("need at least one SUS response")
    return float(np.mean([sus_score(r) for r in all_responses]))


# --------------------------------------------------------------------------- #
# Latency                                                                      #
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class LatencyComparison:
    atlas_seconds: float
    baseline_seconds: float
    speedup: float  # baseline / atlas (how many times faster ATLAS is)


def latency_speedup(atlas_seconds: float, baseline_seconds: float) -> LatencyComparison:
    """Compare ATLAS wall-clock to the manual annotation baseline (both > 0)."""
    if atlas_seconds <= 0 or baseline_seconds <= 0:
        raise ValueError("latencies must be positive")
    return LatencyComparison(atlas_seconds, baseline_seconds, baseline_seconds / atlas_seconds)


# --------------------------------------------------------------------------- #
# Bootstrap CIs + effect size                                                  #
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Estimate:
    point: float
    ci_low: float
    ci_high: float
    level: float = 0.95


def bootstrap_ci(
    values: Sequence[float],
    *,
    statistic: Callable[[np.ndarray], float] = lambda x: float(np.mean(x)),
    n_boot: int = 10_000,
    level: float = 0.95,
    seed: int = 0,
) -> Estimate:
    """Percentile bootstrap CI for a statistic (mean by default). Deterministic via ``seed``.

    Resamples ``values`` with replacement ``n_boot`` times; the CI is the (1-level)/2 and
    (1+level)/2 percentiles of the bootstrap distribution. Two calls with the same seed
    return identical bounds (required for ``make reproduce``).
    """
    arr = np.asarray(values, dtype=float)
    if arr.size == 0:
        raise ValueError("need at least one value")
    point = statistic(arr)
    if arr.size == 1:
        return Estimate(point, point, point, level)
    rng = np.random.default_rng(seed)
    idx = rng.integers(0, arr.size, size=(n_boot, arr.size))
    boot = np.array([statistic(arr[row]) for row in idx])
    lo = float(np.percentile(boot, (1 - level) / 2 * 100))
    hi = float(np.percentile(boot, (1 + level) / 2 * 100))
    return Estimate(point, lo, hi, level)


def wilson_interval(successes: int, n: int, *, level: float = 0.95) -> Estimate:
    """Wilson score interval for a binomial proportion (successes out of n).

    Closed form (stdlib ``NormalDist`` for the z-quantile), so it is exact, hermetic, and
    deterministic. Preferred over the normal (Wald) interval for small n or proportions near
    0/1, where Wald degenerates to a zero-width interval — which is exactly the faithfulness
    (10/10) and per-control (small support) regime. Bounds are clamped to [0, 1].
    """
    if n <= 0:
        raise ValueError("n must be positive")
    if not (0 <= successes <= n):
        raise ValueError("successes must be in [0, n]")
    z = NormalDist().inv_cdf((1 + level) / 2)
    phat = successes / n
    denom = 1.0 + z * z / n
    center = (phat + z * z / (2 * n)) / denom
    margin = (z / denom) * math.sqrt(phat * (1 - phat) / n + z * z / (4 * n * n))
    return Estimate(phat, max(0.0, center - margin), min(1.0, center + margin), level)


def cohens_d(group_a: Sequence[float], group_b: Sequence[float]) -> float:
    """Cohen's d effect size between two independent groups (pooled SD)."""
    a, b = np.asarray(group_a, dtype=float), np.asarray(group_b, dtype=float)
    if a.size < _MIN_GROUP or b.size < _MIN_GROUP:
        raise ValueError("each group needs at least two observations")
    na, nb = a.size, b.size
    pooled_var = ((na - 1) * a.var(ddof=1) + (nb - 1) * b.var(ddof=1)) / (na + nb - 2)
    if pooled_var == 0:
        return 0.0
    return float((a.mean() - b.mean()) / math.sqrt(pooled_var))


def cliffs_delta(group_a: Sequence[float], group_b: Sequence[float]) -> float:
    """Cliff's delta: a nonparametric dominance effect size in [-1, 1].

    Appropriate for a bounded, non-normal metric like per-case F1, where a pooled-SD Cohen's d is
    mis-specified. Delta = P(a > b) - P(a < b) over all cross-group pairs; +1 means every ``a`` beats
    every ``b``, 0 means no dominance."""
    a, b = np.asarray(group_a, dtype=float), np.asarray(group_b, dtype=float)
    if a.size == 0 or b.size == 0:
        return 0.0
    greater = int((a[:, None] > b[None, :]).sum())
    lesser = int((a[:, None] < b[None, :]).sum())
    return float((greater - lesser) / (a.size * b.size))
