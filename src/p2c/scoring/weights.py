"""Criteria weighting for dual scoring: AHP (primary) + BWM cross-check (Stage 5).

Two independent weight derivations so the toolkit can report a robustness result
(spec §6 improvement 3):

- **AHP** (Saaty) — principal-eigenvector weights from a reciprocal pairwise matrix,
  with the consistency ratio ``CR = CI / RI``. Pairwise judgements with **CR > 0.10
  are rejected** (``InconsistentComparisons``): garbage-in is refused, not silently
  scored (spec §7 fail-safe).
- **BWM** (Rezaei, Best-Worst Method) — weights from best-to-others / others-to-worst
  vectors via a small linear program (``scipy.optimize.linprog``). BWM needs far
  fewer comparisons and is typically more consistent — reported as a cross-check.

Both are self-hosted, permissive-licensed (numpy BSD, scipy BSD) and deterministic;
the GPL ``pydecision`` the spec names is deliberately avoided (ADR-0006).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

import numpy as np
from scipy.optimize import linprog

# Consistency threshold: judgements above this are rejected (Saaty's 0.10 rule).
CR_THRESHOLD = 0.10

# Saaty's Random Index (average CI of random reciprocal matrices) by matrix order.
SAATY_RI: dict[int, float] = {
    1: 0.0,
    2: 0.0,
    3: 0.58,
    4: 0.90,
    5: 1.12,
    6: 1.24,
    7: 1.32,
    8: 1.41,
    9: 1.45,
    10: 1.49,
    11: 1.51,
    12: 1.48,
    13: 1.56,
    14: 1.57,
    15: 1.59,
}

# Rezaei's BWM consistency index by the best-to-worst judgement a_BW (1..9).
BWM_CI: dict[int, float] = {
    1: 0.0,
    2: 0.44,
    3: 1.0,
    4: 1.63,
    5: 2.30,
    6: 3.0,
    7: 3.73,
    8: 4.47,
    9: 5.23,
}

_RECIPROCAL_ATOL = 1e-9
_UNIT_TOL = 1e-9  # tolerance for "equals 1" / "equals 0" float comparisons


class InconsistentComparisons(ValueError):
    """Raised when a pairwise judgement set exceeds the consistency threshold."""


@dataclass(frozen=True)
class AHPResult:
    """AHP weights + consistency diagnostics for one pairwise matrix."""

    weights: tuple[float, ...]
    lambda_max: float
    consistency_index: float
    consistency_ratio: float
    order: int

    @property
    def consistent(self) -> bool:
        return self.consistency_ratio <= CR_THRESHOLD


@dataclass(frozen=True)
class BWMResult:
    """BWM weights + the ratio-scale consistency ratio.

    ``xi`` is the consistency indicator on the RATIO scale (max deviation of the realized
    ratios ``w_B/w_j`` and ``w_j/w_W`` from the stated judgements) — the scale Rezaei's CI
    table is defined on, so ``consistency_ratio = xi / CI(a_BW)``. ``lp_xi`` is the raw
    linearized-LP min-max slack (absolute weight-difference scale), kept for reference only;
    it is NOT comparable to the CI table.
    """

    weights: tuple[float, ...]
    xi: float
    consistency_ratio: float
    lp_xi: float = 0.0

    @property
    def consistent(self) -> bool:
        return self.consistency_ratio <= CR_THRESHOLD


_NDIM_2D = 2


def _validate_reciprocal(matrix: np.ndarray) -> None:
    if matrix.ndim != _NDIM_2D or matrix.shape[0] != matrix.shape[1]:
        raise ValueError("pairwise matrix must be square")
    if matrix.shape[0] < 1:
        raise ValueError("pairwise matrix must be non-empty")
    if np.any(matrix <= 0):
        raise ValueError("pairwise entries must be positive")
    n = matrix.shape[0]
    if not np.allclose(np.diagonal(matrix), 1.0, atol=_RECIPROCAL_ATOL):
        raise ValueError("pairwise diagonal must be 1")
    if not np.allclose(matrix * matrix.T, np.ones((n, n)), atol=1e-6):
        raise ValueError("pairwise matrix must be reciprocal (a_ij * a_ji == 1)")


def ahp_weights(matrix: Sequence[Sequence[float]]) -> AHPResult:
    """Principal-eigenvector weights + consistency ratio for a reciprocal matrix.

    Weights are the normalized Perron eigenvector (positive, sum 1). ``CR`` uses
    ``CI = (lambda_max - n)/(n-1)`` and Saaty's RI. Does not raise on inconsistency —
    inspect :attr:`AHPResult.consistent` or use :func:`ahp_weights_checked`.
    """
    a = np.asarray(matrix, dtype=float)
    _validate_reciprocal(a)
    n = a.shape[0]
    if n == 1:
        return AHPResult((1.0,), 1.0, 0.0, 0.0, 1)

    eigenvalues, eigenvectors = np.linalg.eig(a)
    principal = int(np.argmax(eigenvalues.real))
    lambda_max = float(eigenvalues[principal].real)
    vector = np.abs(eigenvectors[:, principal].real)  # Perron vector is single-signed
    weights = vector / vector.sum()

    consistency_index = (lambda_max - n) / (n - 1)
    random_index = SAATY_RI.get(n)
    if random_index is None:
        raise ValueError(f"no Saaty RI for order {n} (max {max(SAATY_RI)})")
    # CI >= 0 in theory (lambda_max >= n); clamp away tiny negative float noise on a
    # perfectly consistent matrix so the reported CR is never a confusing -4e-16.
    consistency_ratio = 0.0 if random_index == 0 else max(0.0, consistency_index / random_index)
    return AHPResult(
        weights=tuple(float(w) for w in weights),
        lambda_max=lambda_max,
        consistency_index=consistency_index,
        consistency_ratio=consistency_ratio,
        order=n,
    )


def ahp_weights_checked(matrix: Sequence[Sequence[float]]) -> AHPResult:
    """AHP weights, but **reject** judgements with ``CR > 0.10`` (spec fail-safe)."""
    result = ahp_weights(matrix)
    if not result.consistent:
        raise InconsistentComparisons(
            f"AHP consistency ratio {result.consistency_ratio:.4f} exceeds {CR_THRESHOLD}"
        )
    return result


def bwm_weights(
    best_to_others: Sequence[float],
    others_to_worst: Sequence[float],
    *,
    best_index: int,
    worst_index: int,
) -> BWMResult:
    """Best-Worst-Method weights via the linearized min-max LP (Rezaei 2015).

    ``best_to_others[j]`` = preference of the best criterion over ``j`` (best-to-best
    is 1); ``others_to_worst[j]`` = preference of ``j`` over the worst criterion
    (worst-to-worst is 1). Solves ``min xi`` s.t. every ``|w_B - a_Bj w_j| <= xi`` and
    ``|w_j - a_jW w_W| <= xi``, ``sum w = 1``, ``w >= 0``.
    """
    a_b = np.asarray(best_to_others, dtype=float)
    a_w = np.asarray(others_to_worst, dtype=float)
    n = a_b.shape[0]
    if a_w.shape[0] != n:
        raise ValueError("best_to_others and others_to_worst must have equal length")
    if not (0 <= best_index < n and 0 <= worst_index < n):
        raise ValueError("best_index / worst_index out of range")
    if best_index == worst_index:
        # Same criterion cannot be both best and worst — this makes a_BW=1, which would
        # otherwise silently force CI=0 and mask a genuinely inconsistent input.
        raise ValueError("best_index and worst_index must differ")
    if np.any(a_b <= 0) or np.any(a_w <= 0):
        raise ValueError("comparison values must be positive")
    if abs(float(a_b[best_index]) - 1.0) > _UNIT_TOL or abs(float(a_w[worst_index]) - 1.0) > _UNIT_TOL:
        raise ValueError("best-to-best and worst-to-worst preferences must be 1")

    # Decision vector x = [w_0, ..., w_{n-1}, xi]; minimize xi.
    num_vars = n + 1
    xi_col = n
    cost = np.zeros(num_vars)
    cost[xi_col] = 1.0

    # Linearize each |.| <= xi into two <= rows. Best-to-others: |w_B - a_Bj w_j| <= xi;
    # others-to-worst: |w_j - a_jW w_W| <= xi.
    rows: list[list[float]] = []
    rhs: list[float] = []
    for j in range(n):
        for sign in (1.0, -1.0):
            row = np.zeros(num_vars)
            row[best_index] += sign
            row[j] -= sign * a_b[j]
            row[xi_col] = -1.0
            rows.append(list(row))
            rhs.append(0.0)
        for sign in (1.0, -1.0):
            row = np.zeros(num_vars)
            row[j] += sign
            row[worst_index] -= sign * a_w[j]
            row[xi_col] = -1.0
            rows.append(list(row))
            rhs.append(0.0)

    a_eq = [list(np.concatenate([np.ones(n), [0.0]]))]  # sum w = 1
    b_eq = [1.0]
    bounds = [(0.0, None)] * n + [(0.0, None)]  # w >= 0, xi >= 0

    result = linprog(cost, A_ub=rows, b_ub=rhs, A_eq=a_eq, b_eq=b_eq, bounds=bounds, method="highs")
    if not result.success:
        raise ValueError(f"BWM LP did not solve: {result.message}")

    weights = result.x[:n]
    weights = weights / weights.sum()  # guard against tiny drift
    lp_xi = float(result.x[xi_col])

    # Consistency on the RATIO scale that Rezaei's CI table lives on. The LP objective ξ
    # measures |w_B - a_Bj·w_j| (an ABSOLUTE weight-difference: since Σw=1 it is typically
    # << 1), whereas BWM_CI[a_BW] is the max ξ* of the ratio-based model |w_B/w_j - a_Bj|
    # (0.44..5.23). Dividing the small absolute ξ by the large ratio-scale CI made near-
    # maximally inconsistent judgements pass the CR>0.10 gate. Recompute ξ as the max ratio
    # deviation from the optimal weights so numerator and denominator share one scale.
    w_b, w_w = float(weights[best_index]), float(weights[worst_index])
    xi = 0.0
    for j in range(n):
        w_j = float(weights[j])
        if w_j > 0:
            xi = max(xi, abs(w_b / w_j - float(a_b[j])))
        if w_w > 0:
            xi = max(xi, abs(w_j / w_w - float(a_w[j])))

    # Clamp the best-to-worst judgement into the CI table's 1..9 domain before lookup.
    a_bw = min(max(round(float(a_b[worst_index])), 1), max(BWM_CI))
    ci = BWM_CI[a_bw]
    # a_BW==1 => CI==0: only ξ≈0 is consistent; any positive ξ is a contradiction (CR=inf).
    consistency_ratio = (xi / ci) if ci != 0 else (0.0 if xi <= _UNIT_TOL else float("inf"))
    return BWMResult(
        weights=tuple(float(w) for w in weights),
        xi=xi,
        consistency_ratio=consistency_ratio,
        lp_xi=lp_xi,
    )


def weight_agreement(a: Sequence[float], b: Sequence[float]) -> float:
    """Max absolute difference between two weight vectors (sensitivity cross-check).

    0 = identical rankings/weights; larger = more divergence between AHP and BWM.
    """
    va, vb = np.asarray(a, dtype=float), np.asarray(b, dtype=float)
    if va.shape != vb.shape:
        raise ValueError("weight vectors must have equal length")
    return float(np.max(np.abs(va - vb)))
