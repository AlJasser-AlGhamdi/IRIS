# Design decisions

Each decision names the simpler alternative we rejected and the evidence for the choice.

## 1. The model reads and picks; code decides

Deterministic code (the vendored engine) maps findings to controls, computes scores, flags contradictions, decides
which fixes are allowed and checks whether a fix worked. The model has two narrow jobs: read the owner's reply and
pick the next step from a menu. Explanations to the owner are reviewed templates, chosen after blind ratings of
model-written ones (ITERATIONS #9).

The simpler alternative is to let an LLM read the scan output and decide compliance per control. The engine's
evaluation harness measured twelve local models on this mapping task against the curated mapping Iris uses
(`evaluation/baseline_ladder_results.json`, eval E3). The best reached micro-F1 0.66 (gpt-oss:20b, gemma3:12b);
Arabic-specialised 7 to 9B models scored 0.00 to 0.20. A wrong mapping is a wrong compliance statement, so the
model never makes one.

## 2. A menu instead of free tool use

In every phase, code lists the legal actions (no scan before ownership is proven, no "fixed" before a re-scan),
ordered by a priority rule, and the model picks one. JSON-schema decoding on the model server limits its output to
that enum, and a pick outside the menu is refused and replaced by the priority rule.

We rejected giving the model all tools and trusting its plan. Ablation `no_action_gate` offers every action; the
illegal-pick rate it records is what the gate prevents. Small local models are far more reliable choosing among
three options than planning freely.

## 3. Nothing a scanned target writes reaches the model

The private worker returns only detector ids, host names, integers and hashes, and `src/officer/contract.py`
validates them. The boundary drops banners, page titles, TXT records and service replies.

We rejected passing the raw scan output to the model "for context". Eval E4 plants 30 instructions in five places
a target controls. With raw text in the prompt, the payload can make a model end the interview or declare the
company compliant. Behind the typed boundary the payload never appears in any prompt (canary search over every
logged prompt). Our earlier work on recovery agents that read attacker-written logs follows the same principle.

## 4. Green means "no violation observed", never "compliant"

A clean outside read is labelled "no violation observed". Iris shows two scores side by side and never merges
them: what the scan shows, and what the answers document.

We rejected a single compliance percentage: a missing finding does not prove compliance, and a self-declaration
must not inflate what was observed (the engine's evidence-precedence rule).

## 5. Human actions only where law or safety needs a person

Iris asks the owner for the staff count (it sets which controls apply), one published DNS record (proof they own
the domain; it refuses to scan otherwise), the answers no scan can give, and approval for changes to their
systems. Everything else is automatic. It never closes remote management (SSH) itself: a wrong move locks the
owner out, so it escalates to a person.

Scanning any domain typed in would be simpler, but unlawful and unsafe. Applying every fix automatically would
make irreversible changes without consent.

## 6. Sixteen questions instead of a 120-row questionnaire

Each plain-language question covers one area's NCNICC Class B rows, and together they cover all 120. A "yes" with
proof is Tier-2 evidence, "yes" alone is a Tier-3 declaration, and "no" is a self-reported gap. Areas follow the
engine's claim relation: a control that only says "the requirements of X are implemented" sits with the question
about X. The detectors that can contradict a question are derived from the engine instead of listed by hand.

Sixteen plain questions instead of 120 rows keep the interview short, and the report lists exactly which rows each
answer stands for.

## 7. Local open models, chosen by measurement

Everything runs through Ollama on an 8 GB gaming GPU with no API keys: the hackathon provides none and a sovereign
deployment needs none. Gate G0 picks the model for each job on our own tasks. We measured HUMAIN's ALLaM-7B
alongside three other open models and report it as measured.

## 8. The live scanner stays private

The engine's public-release rules withhold the live-scan orchestrator, the ownership gate and the pilot runner,
and this repository follows them. Iris calls those through a typed API on a private worker next to the lab (Oracle
Cloud, Jeddah). Every live run is recorded and hash-chained, so you can check it without access to the worker.

## 9. A lab, never a real company

The demo company is fictional (`wahat-alramal.test`, a reserved top-level domain). Iris never scans real
third-party domains: the ownership gate refuses them, and the lab is reachable only on a private network.

## 10. Monitoring re-applies only what was approved and proven

After the report, Iris keeps watching. It re-applies a fix to a returning problem without asking only if the owner
approved that same fix earlier and a re-scan verified it. Anything new needs approval, risky changes go to a
person, and a missing ownership record stops monitoring. Each round, the model chooses from that menu.

Re-applying every known fix automatically would make changes the owner never agreed to. Sending an alert and
stopping would put the owner back to doing the work. In E7, Iris re-fixed and verified returning problems, never
applied a new fix without asking, and raised no false alarms in the quiet round.

## 11. Drafts for the gaps never change a score

For each gap the owner admits (no incident plan, no written policy, untested backups), Iris drafts the document
with the company's details and leaves blanks for what only the owner knows. The draft does not change a score. The
control counts once the owner adopts the draft and declares it.

We rejected letting the model write the documents freely and mark the gaps closed. Drafts come from reviewed
templates filled with the session's facts, and a document nobody adopted is not a control.
