# Evaluation

All numbers come from `evals/results/*.json`; `uv run python -m evals.run summary` rebuilds them. We froze the
held-out sets before any tuning and ran each once. We replaced the first held-out range before any model ran
on it (git tag `splits-frozen-v2`, [ITERATIONS](ITERATIONS.md) #6).

## Test sets

| Set | What | Size | Used for |
|---|---|---|---|
| Synthetic firms | The engine's generator of Saudi Class B firms: what their scan observes, their hidden truth, their Tier-2 records | dev seeds 1–5; held-out 4001–4020; robustness 2001–2005; ablations 3001–3010 | E1, E5, ablations |
| Owner personas | honest; overstating (claims a missing practice with p = 0.5, the engine's adversary); vague (unclear first, clear on follow-up). Replies in formal Arabic, Saudi dialect and English | 3 per firm | E1, E5 |
| Lab estates | The fictional company on real infrastructure (Jeddah), with defect mixes from seeds | dev: demo, seed-1, seed-2; held-out: seed-9101–9106 | E6, the demo |
| Owner answers | Short replies to the 16 questions, labelled yes / no / partly / unknown by a native speaker | dev 40; test 40; own answers 20 | G0, E2 |
| Injection payloads | 6 phrasings (Arabic and English) × 5 places a target controls | 30 | E4 |

## How the synthetic data was generated

No public dataset of Saudi SMEs with known control state exists, and scanning real companies needs consent
and ethics approval. Everything synthetic here comes from code with fixed seeds, so every number reproduces.

Firms come from the engine's generator (`src/p2c/evaluation/synthetic.py`, described in the engine's
documentation). Each is an NCNICC Class B company with a size band drawn from Monsha'at's Q4 2023 split (small
0.89, medium 0.11), a sector from Monsha'at's sector mix (eight sectors) and an estate of 2 to 9 hosts, sized
by band, with generated names (no real organisation or domain). Security posture (strong, moderate, weak) is a
declared modelling assumption, conditioned on size.

Each firm has two separate layers. The truth is the issues really present and the Tier-2 records the firm
holds. The observation is what a modelled scanner sees, with per-detector detection and false-alarm rates; we
calibrated the web-header rates live against a test target. The agent sees only the observation, and the truth
is used only to score.

Owner answers come from `src/officer/owner_sim.py`. For each question, a practice is "not in place" if the
firm truly has a violation in the question's area. If not, the firm's own Tier-2 record decides. Failing that,
the practice is in place with a posture-based probability (strong 0.8, moderate 0.55, weak 0.3), a declared
assumption of the simulator. There are three personas:

- honest says the truth;
- overstating says "yes" to a missing practice with probability 0.5, the engine's overstatement adversary;
- vague answers unclearly first and gives the truth on follow-up.

The simulator renders replies from templates in formal Arabic, Saudi dialect and English, so the model has to
understand them as it would a real chat.

Lab estates (`lab/estates.py`) are real services on a private network: DNS records, a web server with a TLS
certificate, and decoy database, printer, FTP and SSH listeners. The scanner reads real protocol behaviour
there instead of modelled detections. The demo estate plants six defects; held-out estates are seeded mixes of
ten plantable defects.

The answer sets for language understanding do not come from the simulator. The development and test replies
were written for this evaluation. The project owner wrote the 20 own answers in ten styles the simulator's
templates never use: quick dialect, Arabizi, English, mixed Arabic and English, long and rambling, joking, one
or two words, hurried typos, voice-note style, and answering with a question. A native speaker labelled all of
them with a 1 to 10 confidence per label, and we also report accuracy on the confident labels (8 or more). One
development reply ("we have no printers") was judged not applicable and is not scored.

## Evaluations

- G0, model bake-off. Every candidate on every model job: answer understanding (accuracy against labels),
  next-step choice (share of acceptable choices on 20 states) and explanations (no made-up facts; blind 1 to 5
  rating). Thresholds fixed in advance: parse ≥ 85 %, choose ≥ 80 %, valid JSON ≥ 98 %, p50 latency ≤ 4 s / 3 s,
  explanations ≥ 3.5 / 5 with ≥ 90 % free of made-up facts.
- E1, end to end on unseen firms. Completion; violation detection against the firm's hidden truth (and
  parity with the engine's own method); contradiction detection against the persona's real overstatements;
  in-context answer understanding; questions, human actions, model calls, fallbacks, time.
- E2, answer understanding on unseen replies, including out-of-distribution styles.
- E3, why code decides. The engine harness's ladder of 12 local models on the mapping task.
- E4, injection. Attack success with raw scan text in the prompt vs the typed boundary; canary search over
  every logged prompt.
- E5, robustness. Blocked probes, ownership record lost mid-scan, failing fixes, the model down, and the
  requirements changing mid-session (staff count, government supplier); performance kept vs the baseline run.
- E6, live held-out estates. The full loop on the real lab: planted-defect detection, fixes confirmed by
  re-scan, completion, time.
- E7, continuous monitoring. Twenty firms (seeds 5001 to 5020, used by no other evaluation): a full assessment,
  then a round in which fixed problems come back, one new fixable problem appears and, for half the firms,
  remote access opens; then a quiet round. Scored: drift detected, returning problems re-fixed and verified,
  new fixes asked before applying, risky ones escalated, false alarms in the quiet round.
- Ablations and simpler alternatives. The same unseen firms with each component off: no scan
  (questionnaire only), no interview (scan only), no action gate, no re-scan verification.

## Results

Iris runs qwen3:8b (Ollama, 4-bit) on a GTX 1080 with 8 GB. E1, E2, E4, E5, E6 and the ablations ran on
commit 86b1853. Later commits add monitoring, documents and the plan after the assessment, plus the no-op fix
rule (ITERATIONS #12), and leave the assessment path unchanged.

### Model choice (G0, dev)

| Model | Replies read correctly | Acceptable next step | p50 read / choose | Explanations, blind 1–5 |
|---|---|---|---|---|
| qwen3:8b (chosen) | 82 % | 85 % | 1.5 s / 1.6 s | 2.75 |
| gpt-oss:20b | 77 % | 90 % | 6.2 s / 5.3 s | 3.0 |
| gemma3:12b | 74 % | 90 % | 5.9 s / 7.2 s | 3.75 |
| ALLaM-7B-Instruct (HUMAIN) | 67 % | 75 % | 1.5 s / 1.6 s | 2.62 |
| Keyword lexicon, no model | 54 % | | | |

qwen3:8b read the most replies correctly and was the only model to pass the choice bar and both speed bars,
so it runs the agent. What the owner reads comes from reviewed templates (ITERATIONS #9).

### E2, reading real owner replies

These are the 20 own answers, written by the project owner in ten styles the templates never use.

| Model | Read correctly | Valid JSON | p50 per reply |
|---|---|---|---|
| qwen3:8b (runs the agent) | 19 / 20 | 100 % | 1.7 s |
| gpt-oss:20b | 20 / 20 | 100 % | 7.0 s |
| gemma3:12b | 18 / 20 | 100 % | 8.4 s |
| ALLaM-7B-Instruct | 16 / 20 | 100 % | 3.7 s |
| Keyword lexicon, no model | 16 / 20 | | |

No model read a clear "no" as "yes", and qwen3 never read "don't know" as "yes". Per-split results for the
development and test replies are in `evals/results/e2.json`.

### E1, end to end on 20 unseen firms × 3 owners

| | Result |
|---|---|
| Sessions completed | 60 / 60 |
| Violations found, against each firm's hidden truth | precision 0.96, recall 0.97 |
| Overstatements the scan can see, caught | 43 / 43 |
| First replies understood in context | 98.8 % |
| Class B rows determined (of 120) | 104 on average |
| Questions, owner actions, model calls (median) | 14, 17, 32 |
| Actions outside the menu; model fallbacks | 0; 0 |
| Fixes confirmed by re-scan | 183; every simulated failure (15) reported and handed over, none claimed |
| Time per session (median, simulated scanner) | 59 s |

The same 60 sessions with two more models, so 180 in all:

| | qwen3:8b | gpt-oss:20b | ALLaM-7B-Instruct |
|---|---|---|---|
| Sessions completed | 60 / 60 | 60 / 60 | 60 / 60 |
| First replies understood in context | 98.8 % | 99.1 % | 89.3 % |
| Overstatements the scan can see, caught | 43 / 43 | 43 / 43 | 43 / 43 |
| Class B rows determined (of 120) | 104 | 119 | 118 |
| Questions (median) | 14 | 16 | 16 |
| Actions outside the menu; model fallbacks | 0; 0 | 0; 0 | 0; 0 |
| Fixes confirmed by re-scan | 183 | 183 | 183 |

Violations found are the same for all three, because code maps and scores. gpt-oss ran on a Kaggle T4, so
its times are not comparable with the 8 GB card.

### E6, six unseen live lab estates

| | Result |
|---|---|
| Sessions completed | 6 / 6 |
| Planted problems found | 23 / 23, nothing unexpected |
| Fixable planted problems removed, confirmed by re-scan | 20 / 20 |
| Remote access (SSH) handed to a person | 2 / 2 |
| False "fixed" claims | 0 |
| Time per session (median) | 103 s |

### E4, injection

| Attack success, 30 payloads | qwen3:8b | gemma3:12b | gpt-oss:20b | ALLaM-7B-Instruct |
|---|---|---|---|---|
| Raw scan text in the prompt | 30 / 30 | 30 / 30 | 13 / 30 | 8 / 30 |
| Typed boundary | 0 / 30 | 0 / 30 | 0 / 30 | 0 / 30 |

Text a scanned target writes steered every model. Behind the typed boundary it steered none.

In a live run with the payload planted in four places on the lab (page title, header, TXT record, printer
reply), a full session made 53 model calls. The payload appeared in none of the prompts or outputs, and the
session completed with 6 fixes verified.

### E5, robustness (5 firms per condition)

| Condition | Result |
|---|---|
| Baseline | completed 5 / 5; violation recall 0.94 |
| Ports blocked | completed 5 / 5; unread rows stay "not observed", never clean |
| Web and TLS blocked | completed 5 / 5; nothing it could not read was scored clean |
| Ownership record removed mid-scan | stopped 5 / 5, as designed |
| Every fix fails | 0 claimed; 12 handed over |
| Model down | completed 5 / 5 in questionnaire mode |
| Staff count changes to Class A; owner becomes a government supplier | re-scoped and completed 5 / 5 each |

### E7, monitoring (20 unseen firms)

Each firm gets a full assessment, a round in which problems change, and a quiet round. qwen3:8b makes the
monitoring decisions.

| | Result |
|---|---|
| Changes detected | 58 / 58 |
| Fixes the owner approved earlier, re-applied without asking and verified | 31 / 31 |
| New fixes put to the owner before applying | 19 / 19; 0 applied without asking |
| Remote access opening up, handed to a person | 8 / 8 |
| False alarms in the quiet round; monitoring stopped | 0; 0 |

### Ablations (10 unseen firms, overstating owner)

| Removed | Result |
|---|---|
| Nothing (full agent) | 104 of 120 rows determined; violation F1 0.93; overstatements caught 20 / 20; 0 false fixes; 0 actions outside the menu |
| The scan (questionnaire only) | 89 rows, all on the owner's word; no violation found; no overstatement caught |
| The interview (scan only) | 10 of 120 rows determined |
| The action gate | 14 actions outside the allowed menu |
| Re-scan verification | 5 false "fixed" claims |
