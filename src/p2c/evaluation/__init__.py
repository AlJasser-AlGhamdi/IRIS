"""Evaluation harness: synthetic profiles, metrics, reproducible outputs.

The toolkit's results come from **100 synthetic SME profiles** run through the identical
SYNTHETIC-mode pipeline. This package holds the tested library code:

- :mod:`p2c.evaluation.metrics` — precision/recall/F1, fuzzy@70 control-id match,
  Cohen's kappa, Krippendorff's alpha (nominal + ordinal), SUS, latency, bootstrapped
  95% CIs + Cohen's d. Implemented natively (numpy) and validated against published
  reference values, so they run hermetically in CI (no scikit-learn/krippendorff at
  runtime — those are opt-in cross-check deps in the ``eval`` extra), mirroring the
  native AHP/BWM decision (ADR-0006).
- :mod:`p2c.evaluation.synthetic` — the seeded, threat-intel-weighted profile
  generator and its **leakage-guarded** ground-truth labels (the mapping engine never
  receives the answer key).
- :mod:`p2c.evaluation.harness` — runs the pipeline over every case, computes all
  metrics, and writes deterministic tables to ``evaluation/outputs/``; ``reproduce()``
  regenerates every toolkit number identically.

Dropped at the port from the upstream research code: ``faithfulness`` (the RAG grounding
gate; it imported the retrieval stack this repo does not carry, so the harness no longer
computes it and ``evaluation/outputs/faithfulness.json`` is no longer written) and
``annotation`` (the Label Studio expert-panel export).
"""

from __future__ import annotations
