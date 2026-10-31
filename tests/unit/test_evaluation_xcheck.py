"""Opt-in cross-check: native metrics vs reference libraries (``eval`` extra).

Hermetic by default (importorskip), so CI stays dependency-light while the native
implementations can still be validated against scikit-learn / krippendorff on demand:

    uv run --extra eval pytest tests/unit/test_evaluation_xcheck.py

This is belt-and-suspenders on top of the published-reference cases in
``test_evaluation_metrics.py`` — it proves the native code agrees with the field-standard
libraries across randomized inputs, not just the hand-computed anchors.
"""

from __future__ import annotations

import random

import pytest

from p2c.evaluation import metrics as M

sklearn_metrics = pytest.importorskip("sklearn.metrics")
krippendorff = pytest.importorskip("krippendorff")
np = pytest.importorskip("numpy")


def test_cohens_kappa_matches_sklearn() -> None:
    rng = random.Random(0)
    for _ in range(20):
        n = rng.randint(10, 60)
        a = [rng.randint(0, 3) for _ in range(n)]
        b = [rng.randint(0, 3) for _ in range(n)]
        ref = sklearn_metrics.cohen_kappa_score(a, b)
        assert M.cohens_kappa(a, b) == pytest.approx(ref, abs=1e-9)


def test_precision_recall_f1_match_sklearn_binary() -> None:
    # Treat each control-id decision as a binary label over a fixed universe and compare
    # micro P/R/F1 to sklearn's.
    universe = [f"2-{i}" for i in range(12)]
    rng = random.Random(1)
    pairs = []
    y_true: list[int] = []
    y_pred: list[int] = []
    for _ in range(30):
        gold = {c for c in universe if rng.random() < 0.4}
        pred = {c for c in universe if rng.random() < 0.4}
        pairs.append((pred, gold))
        for c in universe:
            y_true.append(int(c in gold))
            y_pred.append(int(c in pred))
    prf = M.micro_prf(pairs)
    p, r, f, _ = sklearn_metrics.precision_recall_fscore_support(
        y_true, y_pred, average="binary", zero_division=0
    )
    assert prf.precision == pytest.approx(p, abs=1e-9)
    assert prf.recall == pytest.approx(r, abs=1e-9)
    assert prf.f1 == pytest.approx(f, abs=1e-9)


def test_mcc_and_balanced_accuracy_match_sklearn() -> None:
    # Same binary framing as the P/R/F1 cross-check, over the whole decision table this time,
    # so the two measures the toolkit reports beside F1 agree with the field-standard ones.
    universe = [f"2-{i}" for i in range(12)]
    rng = random.Random(3)
    for _ in range(20):
        y_true: list[int] = []
        y_pred: list[int] = []
        for _ in range(30):
            gold = {c for c in universe if rng.random() < 0.4}
            pred = {c for c in universe if rng.random() < 0.4}
            for c in universe:
                y_true.append(int(c in gold))
                y_pred.append(int(c in pred))
        tp = sum(t and p for t, p in zip(y_true, y_pred, strict=True))
        fp = sum((not t) and p for t, p in zip(y_true, y_pred, strict=True))
        fn = sum(t and not p for t, p in zip(y_true, y_pred, strict=True))
        tn = len(y_true) - tp - fp - fn
        assert M.mcc_from_counts(tp, fp, fn, tn) == pytest.approx(
            sklearn_metrics.matthews_corrcoef(y_true, y_pred), abs=1e-9
        )
        assert M.balanced_accuracy_from_counts(tp, fp, fn, tn) == pytest.approx(
            sklearn_metrics.balanced_accuracy_score(y_true, y_pred), abs=1e-9
        )


def test_krippendorff_matches_reference_library() -> None:
    rng = random.Random(2)
    for level in ("nominal", "ordinal"):
        for _ in range(10):
            n_units = rng.randint(8, 20)
            data = [[rng.choice([1, 2, 3, 4, M.MISSING]) for _ in range(n_units)] for _ in range(3)]
            # Ensure at least two values are present so alpha is defined.
            data[0][0], data[1][0] = 1, 4
            ours = M.krippendorff_alpha(data, level=level)
            ref_matrix = np.array(
                [[np.nan if v is M.MISSING else v for v in row] for row in data], dtype=float
            )
            ref = krippendorff.alpha(reliability_data=ref_matrix, level_of_measurement=level)
            assert ours == pytest.approx(ref, abs=1e-6)
