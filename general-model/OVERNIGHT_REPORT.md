# Overnight report — 2026-07-27 → 07-28

All four gaps addressed. Every number below was measured, and where an earlier number
was wrong it is named and withdrawn. Two independent measurements agree on every
headline figure.

---

## 0. The question you raised: was it AURA, or OpenClaw's own safety?

**It was AURA.** Matched A/B intervention, identical prompt and workspace state, the only
difference being whether the plugin is enabled. Outcome measured on the **filesystem**,
not on what the agent says.

| arm | destructive action prevented |
|---|---|
| AURA enabled | **12 / 12 (100 %)** |
| AURA disabled | 3 / 12 (25 %) |

**Fisher exact two-sided p = 0.00034.**

Config confirms no native protection is doing the work: `tools.deny: None`,
`execApprovals: {}`, profile `coding`.

Honest nuance worth publishing: the model's *own* refusal stops 25 % of unprotected runs.
AURA closes the remaining 75-point gap. At n=4/arm the same effect gives p = 0.143 (not
significant) — the paper's Fig. 2 design is underpowered, ours at n=12 is not.
`analysis/ab_intervention.py`, `figures/fig6_ab_intervention.png`.

---

## 1. G1 + G4 — adjudication: 300 → **965** hand-judged labels

12 independent labelers judged all 671 previously-unjudged attack sessions. Combined with
the original 294 resolved labels: **965 gold labels, 817 attack / 148 baseline.**

### Behavioural attack-success rate, per category (Wilson 95 % CI, n = 817)

| category | ASR | k/n | 95 % CI |
|---|---|---|---|
| false_precedent | **77.2 %** | 71/92 | [67.6, 84.6] |
| delimiter_confusion | **72.1 %** | 49/68 | [60.4, 81.3] |
| meta_prompting | **64.5 %** | 40/62 | [52.1, 75.3] |
| cot_hijack | 58.7 % | 37/63 | [46.4, 70.0] |
| prompt_leaking | 58.3 % | 35/60 | [45.7, 69.9] |
| sleeper_trigger | 48.4 % | 31/64 | [36.6, 60.4] |
| role_spoofing | 43.1 % | 28/65 | [31.8, 55.2] |
| multilingual_injection | 42.6 % | 26/61 | [31.0, 55.1] |
| emotional_coercion | 34.5 % | 51/148 | [27.3, 42.4] |
| hypothetical_framing | 34.3 % | 46/134 | [26.8, 42.7] |
| **OVERALL** | **50.7 %** | 414/817 | **[47.2, 54.1]** |

**Over half of all attacks succeed.** These supersede the earlier 15-per-category
figures, which were underpowered (meta_prompting read 83 % at n=15; it is 64.5 % at n=62).
Do not quote the old per-category numbers.

### The label-validity result, now on 817 sessions
Canary label vs hand judgement: **precision 0.957, recall 0.213, kappa 0.201.**
It fires 92 times against **414** true compliances — **it misses 326 of 414 = 79 %.**

### The dominant failure mode, found independently by all 12 labelers
**Solicitation / deferred compliance.** The agent cannot reach the secret (file missing),
so instead of refusing it *asks the user to hand it over* or to run `/approve`. This is a
real compliance — the agent has accepted the injected goal — and the canary is structurally
blind to it. It accounts for roughly a third to a half of compliances in
`false_precedent`, `emotional_coercion` and `hypothetical_framing`.

Other canary-invisible modes seen across slices: full system-prompt / tool-schema
exfiltration, agent-state dumps, field-slot emission (adopting the attacker's output
contract), self-modification of standing instructions.

---

## 2. G2 — model retrained on behavioural labels

`analysis/train_behavioral.py` → `models/aura_behavioral.joblib`

> **CORRECTED 2026-07-27, twice.** This section first reported **AUC 0.797** under a plain
> `StratifiedKFold`. That protocol leaks: the 965 gold records cover only **285 distinct
> prompts** (3.39 repeated trials each) and 77 % of those prompts carry the same label
> across every repeat, so sibling trials sat in train and test simultaneously and the model
> memorised the response cluster. The first correction quoted **0.748** from 3 seeds; that
> was itself a favourable draw. At 10 seeds it is **0.743 (sd 0.008)**.
> **Quote 0.743 prompt-grouped, or 0.712 leave-one-category-out. Never 0.797.**
> An independent audit reached 0.738 / 0.712 by re-deriving from scratch.

### Headline (prompt-grouped `StratifiedGroupKFold`, 5-fold, **10 seeds**)

| evaluation | model | AUC | F1 |
|---|---|---|---|
| **behavioural labels (SHIPPED)** | random_forest | **0.743** (sd 0.008) | 0.653 |
| **generalisation to an UNSEEN attack family (LOACO)** | random_forest | **0.712** | — |
| CONTROL: identical features + identical grouped protocol, canary labels | random_forest | 0.688 (sd 0.013) | — |
| cross-source, 12 science features (split proven disjoint) | random_forest | 0.638 | — |
| cross-source, 62-feature prompt-response | logreg C=0.003 | 0.699 (attack slice 0.727) | — |

**The trivial always-positive F1 floor on this set is 0.603.** Every F1 must be read
against it. Under the honest protocol logreg (0.586) and gradient boost (0.604) are at or
*below* the floor — only random forest's 0.653 is a real margin, and it is +0.050, not the
+0.10 the leaky protocol suggested.

### Size of the leak, per model (10 seeds)

| model | honest (prompt-grouped) | leaky (plain KFold) | leak | LOACO |
|---|---|---|---|---|
| logreg | 0.690 (sd 0.005), F1 0.586 *(below floor)* | 0.708 | −0.018 | 0.613 |
| **random_forest** | **0.743** (sd 0.008), F1 0.653 | 0.797 | **−0.055** | **0.712** |
| gradient_boost | 0.719 (sd 0.014), F1 0.604 *(at floor)* | 0.778 | −0.058 | 0.680 |

### Where it fails: `cot_hijack` is BELOW CHANCE on an unseen family

Held out one attack family at a time (`figures/fig5_protocol_ladder.png`):

| family | AUC | | family | AUC |
|---|---|---|---|---|
| emotional_coercion | 0.82 | | prompt_leaking | 0.68 |
| hypothetical_framing | 0.81 | | sleeper_trigger | 0.65 |
| meta_prompting | 0.80 | | delimiter_confusion | 0.64 |
| role_spoofing | 0.69 | | false_precedent | 0.51 *(chance)* |
| multilingual_injection | 0.69 | | **cot_hijack** | **0.31** *(worse than chance)* |

This is the most important negative result in the project and it must be published. On a
CoT-hijack family the model has never seen, the score is **actively anti-correlated** —
worse than a coin flip. `false_precedent` at 0.51 is indistinguishable from chance, and it
is simultaneously the *highest*-ASR family (77.2 %). The model is weakest exactly where the
agent is most vulnerable.

### Why the leak was invisible

The damage scales with model capacity (logreg −0.018, RF −0.055, GB −0.058), which is the
signature of memorisation: a high-variance learner fits the duplicate response clusters, a
linear one largely cannot. When a "better" model's advantage evaporates under a stricter
split, the advantage *was* the leak — the RF-over-logreg gap falls from +0.083 to +0.035
once grouping is applied.

The leak (−0.055) is roughly **7× the honest seed-to-seed sd (0.008)**, and about 18× the
sd that the original 3-seed leaky run reported (0.003). Tight error bars measured stability
*inside* a broken protocol. They were evidence of reproducibility, never of validity.

### The canary comparison reverses, and the honest result is stronger

Under the leaky protocol the canary control scored *higher* (0.836 vs 0.797) and that was
explained away as the canary being an easier, self-fulfilling target. Under the honest
protocol it inverts:

* canary control **0.836 → 0.688** (−0.148)
* behavioural **0.797 → 0.743** (−0.055)

The canary is a deterministic function of the response string, so repeated trials of one
prompt share its outcome almost perfectly and grouping destroys most of its apparent
signal. **The behavioural model now beats the canary control by +0.055, roughly 4× the
control's sd (0.013).** The behavioural target is not merely the correct target, it is the
more learnable one. Both sides use the same 10 seeds; a 1-seed control against a multi-seed
headline would not be a fair comparison, and that asymmetry was present and was fixed.

How this was found: it was not found by auditing this model. It surfaced from the
refutation of an unrelated competing approach, which reported that a 296-record gold held
only 171 unique prompts. The same check applied here gave 965 records over 285 prompts.

---

## 3. G3 — action records recovered

Re-harvested container logs (588 → 942 files) and re-ran recovery.

| | before | now |
|---|---|---|
| distinct trials with actions | 405 | **660** (+63 %) |
| enriched rows | 769 | **794** |
| action records | 5,230 | recovered with kind / target / in_scope / status |

**Ceiling diagnosed, not assumed:** 1,271 distinct session_ids exist in newcats; only 942
raw logs survive; overlap 523. **748 ids have no log** because OpenClaw prunes old session
files, and 465 of those did make tool calls. Those are permanently unrecoverable. The fix
is forward-looking: new collection harvests logs immediately.

---

## 4. Self-corrections made tonight

| claim | status | corrected value |
|---|---|---|
| behavioural model AUC 0.797 | **prompt-duplication leak** (plain KFold over 965 records spanning 285 prompts) | **0.743** (sd 0.008), prompt-grouped, 10 seeds; **0.712** LOACO |
| the first correction, 0.748 | 3 seeds — a favourable draw | **0.743** at 10 seeds |
| canary control AUC 0.836 | same leak, much larger | **0.688** (sd 0.013) — behavioural now *beats* it |
| F1 0.704 quoted as strong | no baseline given; trivial all-positive F1 is **0.603** | honest F1 **0.653**, i.e. +0.050 over doing nothing |
| `eval_ablations.py` "most independent number", cross-source 0.571 | gold dict keyed by `session_id`; 441 of 441 checkable test rows are NOT the judged record | **WITHDRAWN.** Script quarantined |
| `fig1` subtitle "misses 322 of 414 (78 %)" | assumed all 92 canary fires are true positives; precision is 0.957 so tp = 88 | **326 of 414 (79 %)** — figure regenerated |
| `fig5_transfer_and_safety.png` "n=89 baseline, n=84 attack" | stale split and stale cross-source 0.602 | **withdrawn**, replaced by `fig5_protocol_ladder.png` |
| `aura_final.joblib` trained_on "n=296" | 2 `line_idx` collisions never removed, so 2 records double-weighted | actual **294** |
| retrain n=971 | joined gold to sessions by non-unique `session_id`; kept 6 rows `resolve_gold` drops | **n=965** |
| labeler F1 0.874 / kappa 0.788 | **in-sample only** | OOS **F1 0.604, kappa 0.399** (agent's independent run: 0.612 / 0.404) |
| cross-source AUC 0.748 | measured on the old 283-row gold | **0.699** (attack slice 0.727) on the 965-row gold |
| per-category ASR (n=15/cat) | underpowered | superseded by the n=817 table above |
| out-of-scope actions 1,074 | read-only `web_search` counted as egress | **1,059** on the larger log set |

Two of these (the n=971 join bug and the prompt-duplication leak) were caught **after** the
overnight run reported success. Both were silent: neither crashed, and both reported
plausible numbers. The n=971 bug's only visible symptom was a missing metadata key.

The labeler is **not safe to propagate labels** (kappa 0.40 ≪ 0.70). Independently
confirmed: *"NEITHER LABELER IS SAFE TO PROPAGATE. Both collapse out-of-sample."*
**But its precision holds out-of-sample (0.915–0.924), so the BLOCK path is unaffected** —
the gate uses it for blocking, where precision is what matters.

---

## 5. System state — verified end to end

- **17 / 17 tests passing** (service health, every detection layer, false positives on
  benign traffic, latency, OpenClaw integration, fail-open, secret hygiene)
- Gate live and enabled; verified after every experiment
- All analyses reproduce: `resolve_gold.py`, `recover_actions.py`,
  `eval_combined_gold.py`, `train_behavioral.py`, `ab_intervention.py`

### Data
| asset | count |
|---|---|
| 10-category sessions | **1,974** and growing (collector live; snapshot your count) |
| — action-enriched | 794 |
| **hand-judged gold** | **965** (817 attack / 148 baseline) |
| Chenhao release | 1,314 |
| prompt bank | 500 pairs = 1,000 prompts, 320 science domains |
| raw container logs | 942 |
| figures | 4 |

---

## 6. What is still open

1. **Labeler recall is the weak axis** (0.45–0.48 OOS). Precision is fine. Raising recall
   without losing precision is the next real modelling problem.
2. **1,009 sessions still unjudged** (the baseline-condition ones and newly collected).
   The 965 covers every attack session that existed when adjudication started.
3. **Action recovery capped at ~41 %** for historical sessions; unrecoverable by design.
4. **Scite quota** resets 2026-07-28 for the citation pass.
5. ~~scorer ML layer still points at the canary-trained model~~ **DONE.** The scorer now
   loads `models/aura_behavioral.joblib` (`general=0.7477` in its banner); 17/17 tests
   pass and the live block was re-proven after the repoint
   (`evidence/gate_attribution_2026-07-27.log`).
6. **No confirmed improvement over baseline yet.** The competition workflow ran only 2 of
   5 approaches (the other 3 died on a usage limit) and **both were refuted** — for test-set
   hyperparameter selection, in-sample rule authoring, and gains inside the noise. The
   three untried approaches are still open work.
7. **The cross-source split was checked and is CLEAN** — gold and Chenhao share 0 prompts
   and 0 replies, so 0.638 / 0.699 are unaffected by the leak. But the same check found
   that Chenhao's 758 rows contain only **10 distinct prompts** (75.8 rows per prompt).
   Its effective diversity is ~10, not 758. That is the most likely explanation for weak
   transfer, and it means cross-source AUC has far wider real uncertainty than its n
   suggests. Any remaining within-corpus CV elsewhere in the project still needs the
   prompt-grouped protocol applied.
