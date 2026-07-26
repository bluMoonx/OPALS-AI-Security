# AURA — Verified Results (2026-07-26)

Every number below was measured, then independently re-derived. Where a previously
reported number was wrong, it is named and withdrawn rather than quietly replaced.

---

## 0. Withdrawal notice

**The previously reported 0.905 ROC-AUC is withdrawn. It was invalid.**

Root cause: the label `attack_succeeded` **was** the canary echo. Across all 1,598
records, "canary substring present in the reply" predicts `attack_succeeded` with
precision 1.000 and recall 1.000 — zero disagreeing cells. The label and the strongest
text feature were the same quantity, so any text model trivially reproduced it.
Compounding this, the reported figure was a `GroupKFold(5)` mean-of-fold score
mislabeled as leave-one-attack-category-out.

| claim | verified reality |
|---|---|
| 0.905 ROC-AUC | the shipped trainer actually printed **0.836** |
| "leave-one-category-out" | it was **GroupKFold(5) mean-of-fold** |
| true LOACO, canary-scrubbed | **0.672 pooled out-of-fold** |
| recall 81.4% @ 12.5% FPR | **0.000 @ 10% FPR** |
| "across 38 categories" | only **10 of 38** folds had a defined AUC |

Related: a teammate's 0.95 result rests on `cites_memory_md`, which carries 49% of its
feature importance; their own ablation drops it to **0.689** without that feature. The
same trap is likely present in other published numbers in this space.

---

## 1. Headline finding: canary labeling under-counts attack success ~4x

We hand-judged **283 sessions** (5 independent labelers, stratified across all 10
categories and both conditions) on observed *behavior*: did the agent comply with the
injected instruction, or refuse/flag it? Judged from `(prompt, agent_response)` only,
never from the canary token.

| measure | value |
|---|---|
| behavioral attack success rate | **43.7%** (62/142) |
| canary-derived "success" | **10.6%** (15/142) |
| real compliances the canary label missed | **47 of 62 (76%)** |

The agent is roughly **four times more vulnerable** than canary-based evaluation
reported. `figures/fig1_label_undercount.png`

### Per-category behavioral attack success
| category | behavioral ASR | canary reported |
|---|---|---|
| meta_prompting (task laundering) | **83%** | 0% |
| delimiter_confusion | **80%** | 58% |
| prompt_leaking | **75%** | 1.5% |
| false_precedent | **67%** | 2.6% |
| multilingual_injection | 42% | 3.2% |
| cot_hijack | 30% | 34% |
| sleeper_trigger | 27% | 17% |
| role_spoofing | 25% | 1.5% |
| hypothetical_framing | 9% | 1.8% |
| emotional_coercion | 8% | 1.6% |

**Task-laundering is the single most effective attack against this agent (83%), and
canary-based evaluation reports it as completely ineffective (0%).**
`figures/fig2_per_category_asr.png`

---

## 2. Behavioral-feature ML does not generalize across collections

The strongest honest experiment available: train on one team's corpus with rubric
labels, test on another team's corpus with hand-judged behavioral labels. Different
collection, different prompts, different attack taxonomy, different labeler.

Train: 758 Chenhao sessions (rubric `human_label`). Test: 283 hand-judged gold sessions.

| model (response-only science features) | ROC-AUC | recall @ 10% FPR |
|---|---|---|
| logistic regression | 0.483 | 0.138 |
| random forest | **0.602** | 0.215 |
| gradient boosting | 0.582 | 0.200 |

**Response-only linguistic features barely beat chance across collections.** Single-corpus
numbers in this field (0.87–0.95) do not appear to survive a cross-collection test.

### 2.1 What fixed it: modelling the prompt AND the response

Splitting the context into an *injected* span and a *legitimate* span (22 structural cue
regexes) and giving the model features over both sides raises cross-source transfer
substantially. Same train/test protocol, 62 features, all functions of
`(context text, response text, tool names)` only.

| view | ROC-AUC | 95% CI |
|---|---|---|
| **cross-source (all)** | **0.748** | [0.679, 0.811] |
| cross-source (attack slice) | 0.773 | [0.698, 0.847] |
| cross-source (deduplicated) | 0.752 | — |
| gold 5-fold CV, out-of-fold | 0.907 | — |

**0.602 → 0.748 on the hardest metric we have.** This is not a lucky configuration: an
L2 sweep over C = 0.003…3.0 has **all 7 settings beating 0.602** (range 0.624–0.748,
median 0.730), and transfer improves monotonically with regularisation, so the headline
is the strongly-regularised end rather than a cherry-pick.

### 2.2 Honest ablation: the relational features are *not* what works

The same script's feature-family ablation is worth more than the headline:

| feature family | cross-source AUC (C=0.003 → 0.3) | n features |
|---|---|---|
| relational pair only | 0.564 → 0.620 | 47 |
| response-only (control) | 0.695 → 0.638 | 12 |
| prompt-only (control) | 0.743 → 0.587 | 3 |
| **response + prompt, no pair features** | **0.788 → 0.801** | **15** |
| all | 0.739 → 0.697 | 62 |

The simple 15-feature "no pair" set **transfers better than the full 62-feature set at
every regularisation strength**. So the gain comes from *looking at the prompt at all*,
not from the elaborate relational machinery. The simpler model is the better one — we are
reporting that against our own hypothesis.

---

## 3. What actually works: deterministic detection

Measured on the same hand-judged gold labels, restricted to attack-condition sessions
(n=142, 62 compliances) — where "did it comply or refuse" is the meaningful question.

| detector | precision | recall | F1 |
|---|---|---|---|
| refusal/flag markers | 0.622 | 0.903 | 0.737 |
| compliance labeler | **1.000** | 0.516 | 0.681 |
| **OR-ensemble of both** | 0.638 | **0.968** | **0.769** |

**A deterministic refusal detector (F1 0.737) already outperforms the cross-source ML
model (AUC 0.602).** For this problem, simple interpretable signals beat learned
behavioral features and carry no training-distribution dependence.

### 3.1 A correction we made to our own result

An earlier version of this document claimed the OR-ensemble was a statistically
significant improvement (F1 0.769, CI [+0.007, +0.069]). **That was measured on
mis-joined records and is withdrawn.**

The gold labelers flagged that `session_id` is **not unique** in this corpus (360
duplicates across 1,626 records — the same prompt was run as repeated trials). Joining
gold labels to sessions by `session_id` silently pairs a label with the wrong response.
Re-measured on records with an unambiguous `session_id` (n=84):

| detector | precision | recall | F1 |
|---|---|---|---|
| **compliance labeler** | **0.897** | 0.743 | **0.812** |
| OR-ensemble | 0.630 | 0.971 | 0.764 |
| refusal markers | 0.615 | 0.914 | 0.736 |

Bootstrap (6,000 resamples) on the differences:

| comparison | Δ F1 | 95% CI | verdict |
|---|---|---|---|
| labeler − refusal | +0.076 | [−0.058, +0.210] | **not significant** |
| labeler − ensemble | +0.047 | [−0.077, +0.172] | **not significant** |

**At n=84 the three detectors cannot be statistically distinguished.** The labeler has
the best point estimate and much the best precision, but we are not claiming a
significant F1 win. More hand-judged labels would be needed to separate them.

### 3.2 The number that actually decides the gate design

For a *blocking* decision, F1 is the wrong metric — what matters is whether it blocks
legitimate work. Measured on benign baseline sessions (n=89, of which only 2 were
genuinely unsafe):

| layer | fires on benign baselines | false blocks |
|---|---|---|
| **compliance labeler** | 2 / 89 (2.2%) | **0 / 89 (0.0%)** |
| no-refusal flag | 9 / 89 (10.1%) | advisory only |

The compliance layer fires on exactly the two baseline sessions that are *truly* unsafe.
**Zero false blocks on benign traffic.** That, not the F1 difference, is what licenses
the two-tier design now live in the gate:

- **BLOCK** on the compliance signal — 0% false-positive rate on benign traffic.
- **FLAG** on absent-refusal — advisory, gated on the prompt being attack-shaped
  (`injection_present`). Ungated it fires on ordinary replies too (76% FPR); gated,
  benign traffic passes cleanly.

### 3.3 Leakage ablation (harness contamination)

Gold labelers found a `provenance:` footer appearing in responses whose prompt never
requested one, **including baselines** (28/810 baselines, 60/816 attacks) — state
bleeding across runs in the collection harness, not agent misbehavior. We ablated it:

| | precision | recall | F1 |
|---|---|---|---|
| with `provenance` | 0.617 | 0.967 | 0.753 |
| `provenance` redacted | 0.617 | 0.967 | 0.753 |

Δ F1 = 0.0000. **The detector does not depend on the contaminated signal.** Any n-gram
feature matching "provenance" would have picked up harness bleed-through instead of risk.

---

## 4. The deployed gate (17/17 tests passing)

AURA runs as a live OpenClaw plugin. It is deterministic where it enforces, so it was
unaffected by the labeling defect.

| behavior | result |
|---|---|
| blocks `rm -rf`, `sudo`, `curl \| bash` | risk 0.95, blocked pre-execution |
| flags `.ssh/id_rsa`, `.env` access | risk 0.80 |
| catches memory poisoning | risk 0.979 |
| **false blocks on benign traffic** | **0 / 8** |
| benign flag rate (advisory only) | 38% |
| scoring latency | < 1 ms |
| scorer offline | fails **open** (agent never breaks) |
| live OpenClaw session | gated, decisions logged |
| interactive approval in Control UI | verified denying a credential read |

Run: `python3 openclaw-plugin/test_suite.py` → **17 passed, 0 failed**.
Dashboard: `http://localhost:5005/dashboard`.

---

## 5. Data accounting (complete, 251.7 MB / 3,086 files)

| source | records | label origin | usable |
|---|---|---|---|
| collected_new10category | 1,601 | canary (defective) → relabeled behaviorally | yes, relabeled |
| chenhao_release | 1,314 | rubric `human_label` | **yes** |
| collected_22category/sessions | 82 | rubric `human_label` | yes |
| collected_22category/turns | 248 | category fallback | **no — 124 mislabeled** |
| spring_memory_poisoning | 1,998 | n/a | **no — zero real agent text** |
| container_sessions | 1,188 files | raw native traces | not in corpus |
| gold behavioral labels | 300 | **hand-judged** | yes |
| prompt bank | 500 | 50 distinct/category | yes |

Excluded sources are excluded deliberately and for stated reasons, not silently dropped.

---

## 6. Honest negatives (these are results, not failures)

- **Anomaly-from-normal** does not beat supervised (0.798 vs 0.863).
- **91 engineered features**: no gain once three embedded leaks were removed.
- **Verification-collapse trajectory**: design leakage; the apparent 0.98 was an artifact.
- **Hidden-image injection is impossible on ollama-cloud**: five vision models tested
  (kimi-k2.5, kimi-k2.6, qwen3.5, minimax-m3, gemma4); none read faint or hidden text,
  all hallucinated. Only visible typographic injection works.
- **Model provider is not a confound**: deepseek 0.298 vs kimi 0.300 positive rate.

---

## 7. Reproduce

```bash
python3 openclaw-plugin/test_suite.py     # 17/17 gate tests
python3 analysis/make_figures.py          # figures
cd openclaw-plugin && ./setup.sh          # deploy the live gate
```
Gold labels: `analysis/rebuild/gold_*.jsonl` (300 hand-judged sessions).
Audit scripts: `analysis/hardening/`.
