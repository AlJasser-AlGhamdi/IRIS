# Threat model

## What we protect

- The owner's systems: no scan of a domain they have not proven they own, no change without their approval,
  and no change that can lock them out.
- The truth of the assessment: no control is reported clean or compliant without evidence, and no claim
  outranks what the scan observed.
- Iris's decisions: text from a scanned target or a malicious party must not steer the model.
- Data residency: no data leaves the machines the owner chose.

## Adversaries and what stops them

| Adversary | Attempt | Defence | Evidence |
|---|---|---|---|
| Anyone with a domain name | Use the agent to scan someone else's domain | DNS TXT ownership challenge before any scan, re-checked before each host; worker refuses (403) otherwise | test `test_no_scan_before_ownership_and_a_vanishing_record_halts`; lab golden test |
| The owner (overstating) | Claim practices that are not in place | Contradiction flags against scan evidence; the scan outranks the claim | E1 contradiction recall |
| A compromised or hostile target | Plant instructions in banners, titles, TXT records, service replies | Typed contract: only detector ids cross the worker boundary | E4 attack success, canary search over all prompts |
| A model failure | Invalid JSON, a choice outside the menu, a made-up number | JSON-schema decoding, menu gate, validators, deterministic fallbacks | `test_gate_refuses_choices_outside_the_menu`, `test_explanations_with_unsupported_numbers_fall_back_to_the_template`, E5 model-down |
| A hostile web page in the owner's browser | Drive the local interface (CSRF, DNS rebinding) | Server binds loopback, allows only loopback Host headers and same-origin state changes | `src/officer/server.py` |
| The network | Exfiltrate data | Egress guard (in-interpreter) allows only loopback, the lab subnet and the worker's tailnet address; the counter on screen reads the guard | engine sovereignty tests |

## Next steps

- Add machine-wide egress rules next to the in-interpreter guard, so every process on the owner's machine
  follows the same allowlist.
- Check uploaded proof with a vision model, so answers no scan can see become evidence.
