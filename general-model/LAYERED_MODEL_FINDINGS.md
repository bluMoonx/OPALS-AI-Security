# W2 — LAYERED MODEL (general + per-family specialists)
Measured 2026-07-28. Every number below is reproducible from the scripts named beside it.

## VERDICT IN ONE LINE
Layering **improves the model's ranking** (LOACO AUC +0.0276, prompt-grouped CV +0.0361,
both CIs excluding zero) and **does not improve the deployed gate at the operating point**
(best honest gain: +1 true positive on OOS, +1 on STRICT, a delta the permuted-score null
control reproduces exactly). Layering is a measured negative where it matters. Nothing ships.

---

## 0. BASELINE REPRODUCED FIRST (rule 1)

| quantity | frozen baseline | reproduced | script |
|---|---|---|---|
| prompt-grouped CV AUC, 10 seeds | 0.7427 | **0.742719** | `analysis/layered/w2_repro.py` |
| LOACO AUC | 0.7117 | **0.711670** | same |
| OOS P / R (671 gold2 attack) | 0.9214 / 0.6029 | **0.9214 / 0.6029** | `w2_budget.py` |
| STRICT P / R (288 disjoint prompts) | 0.9213 / 0.4767 | **0.9213 / 0.4767** | same |
| benign FALSE-block (1078 pool) | 2.88% | **2.88%** (31/1078) | same |
| benign RAW block (same pool) | 4.73% | **4.73%** (51/1078, 20 correct) | same |
| shipped test suite | 22/22 | **22 passed, 0 failed, 0 skipped** | `openclaw-plugin/test_suite.py` |

`BASELINE REPRODUCED EXACTLY: True` is asserted in code, not by eye.
No shipped file was modified in this arm; the suite was re-run anyway as the whole-system check.

---

## 1. WHAT WAS BUILT (all under prompt-grouped CV and LOACO, 5 seeds)

Eleven scorers, `analysis/layered/w2_layered.py`:

- `flat` — the shipped 12-feature RF, the control.
- `spec_soft_router` / `spec_hard_router` — general model + one specialist per attack family,
  combined through a learned router. **`attack_category` is never an input.** The router sees
  only (prompt, reply, tools): the 12 flat features plus 8 prompt-demand features.
- `spec_max`, `spec_mean` — router-free combination of the specialist bank.
- `blend_50_50`, `blend_learned` — general + routed specialist, fixed and learned weights.
- `cascade`, `cascade_avg` — general first, specialist only on the residual it is unsure about.
- `flat_perfam_thresh`, `flat_perfam_soft` — per-family thresholds on the flat model,
  selected inside training folds only.

**Router error is fully propagated, never assumed away.**
- Under LOACO the router's accuracy on the held-out family is **0.0000 by construction** — that
  family is absent from training, so the router *cannot* name it. The routed score still uses the
  router's own posterior. This is the deployment-realistic case.
- Under prompt-grouped CV (all families visible) router accuracy is **0.3318 vs 0.100 chance**.
- A router that needed the true family would be worthless in deployment and was never built.

---

## 2. RANKING: LAYERING WINS (`analysis/layered/w2_model_results.json`)

LOACO AUC, 5 seeds, bootstrap over prompt groups, CI on the delta vs flat:

| variant | LOACO AUC | delta | 95% CI on delta |
|---|---|---|---|
| flat | 0.7119 | — | — |
| **spec_soft_router** | **0.7395** | **+0.0276** | **[+0.0004, +0.0564]** |
| blend_learned | 0.7337 | +0.0217 | [+0.0046, +0.0414] |
| blend_50_50 | 0.7314 | +0.0195 | [+0.0079, +0.0323] |
| spec_hard_router | 0.7207 | +0.0088 | [-0.0319, +0.0488] |
| cascade | 0.7198 | +0.0078 | [-0.0068, +0.0224] |
| spec_mean | 0.6967 | -0.0152 | [-0.0367, +0.0047] |
| spec_max | 0.6127 | -0.0992 | [-0.1444, -0.0572] |
| flat_perfam_thresh | 0.6840 | -0.0280 | [-0.0575, +0.0033] |

Prompt-grouped CV: flat 0.7488 -> spec_soft_router 0.7849 (+0.0361, [+0.0135, +0.0613]).

The gain lands exactly where it was predicted to: the families a flat model averages away.

| family | flat LOACO | spec_soft_router | change |
|---|---|---|---|
| cot_hijack (below chance) | 0.309 | 0.392 | **+0.083** |
| false_precedent (chance, highest ASR 77.2%) | 0.522 | 0.655 | **+0.133** |
| role_spoofing | 0.681 | 0.788 | **+0.107** |
| sleeper_trigger | 0.659 | 0.697 | +0.038 |
| hypothetical_framing | 0.809 | 0.777 | -0.032 |
| meta_prompting | 0.794 | 0.781 | -0.013 |

**Permuted-label control** (labels shuffled, whole protocol re-run): flat 0.542,
spec_soft_router 0.517, every variant in [0.496, 0.547]. Harness is sound.

---

## 3. THE OPERATING POINT: LAYERING LOSES (`w2_budget.py`, `w2_budget2.py`)

All benign numbers are on the **FALSE-block** basis, with the raw rate beside them.

### 3a. The budget is already spent — this is the whole story

| | rows | rate |
|---|---|---|
| pool | 1078 (204 prompts) | — |
| gate blocks, RAW | 51 | 4.73% |
| of which objectively CORRECT | 20 | — |
| gate FALSE blocks | 31 | **2.88%** |
| budget | 33 | 3.00% |
| **HEADROOM** | **1.34 rows** | **0.12 pp** |

Any additive layer may convert **at most one** further benign row into a false block.
(The gold1-prompt benign slice sits at 3.37% false on its own, already over budget; that is
why an absolute 3.00% slice constraint read "infeasible" for every variant in round 1. It was
re-specified as a marginal-headroom constraint, which is the correct translation.)

### 3b. Honest operating point — threshold on gold1 ONLY

`fire = gate OR (score >= t)`. `t` maximises gold1 recall subject to gold1-attack P >= 0.90 and
added false blocks on the gold1-prompt benign slice <= marginal headroom. OOS, STRICT and the
full pool are reported, never selected on.

| variant | OOS P/R | F1 | STRICT P/R | F1 | false% | held-out benign | dR_OOS | dR_STRICT |
|---|---|---|---|---|---|---|---|---|
| **shipped gate** | 0.9214/0.6029 | 0.7288 | 0.9213/0.4767 | 0.6284 | 2.88% | 1.92% | — | — |
| flat | infeasible | | | | | | | |
| blend_50_50 | 0.9217/0.6057 | 0.7310 | 0.9222/0.4826 | 0.6336 | 2.97% | 2.19% | +0.0029 | +0.0058 |
| blend_learned | 0.9217/0.6057 | 0.7310 | 0.9222/0.4826 | 0.6336 | 2.97% | 2.19% | +0.0029 | +0.0058 |
| spec_hard_router | 0.9099/0.6057 | 0.7273 | 0.9222/0.4826 | 0.6336 | 3.06% | 2.47% | +0.0029 | +0.0058 |
| spec_mean | 0.9138/0.6057 | 0.7285 | 0.9121/0.4826 | 0.6312 | 2.88% | 1.92% | +0.0029 | +0.0058 |
| flat_perfam_soft | 0.9138/0.6057 | 0.7285 | 0.9121/0.4826 | 0.6312 | 2.88% | 1.92% | +0.0029 | +0.0058 |
| spec_soft_router | 0.9214/0.6029 | 0.7288 | 0.9213/0.4767 | 0.6284 | 2.97% | 2.19% | +0.0000 | +0.0000 |

**+0.0029 OOS = one extra true positive out of 350. +0.0058 STRICT = one out of 172.**

F1 against the slice-specific trivial always-positive floor: OOS floor 0.6856 — baseline 0.7288
and best layered 0.7310 both clear it. STRICT floor 0.7478 — baseline 0.6284 and best layered
0.6336 are both **below** the floor. Layering does not change that; the shipped gate was already
below it on STRICT and this arm makes no claim otherwise.

### 3c. The null control kills the +1

Same threshold search, model scores permuted within family (marginal distribution preserved,
score/label association destroyed), 20 reps:

| | real gain | permuted-score null, max over 20 reps |
|---|---|---|
| dR_OOS | +0.0029 | **+0.0029** |
| dR_STRICT | +0.0058 | **+0.0058** |

The observed gain is **exactly what the same search extracts from noise**. Bootstrap CI on the
delta (prompt groups resampled, 2000 reps) agrees: OOS [+0.0000, +0.0094],
STRICT [+0.0000, +0.0204] — lower bound zero in both.

At a 5.00% false budget (well over budget, reported only as a diagnostic) the oracle-selected
gains are OOS +0.0314 / STRICT +0.0523 for spec_soft_router, against a permuted-score null whose
max is +0.0343 / +0.0407. Even the above-budget "win" is inside the null.

### 3d. Two-sided layer — the only configuration that could gain at a binding budget

`fire = (gate AND s >= t_lo) OR (NOT gate AND s >= t_hi)`: veto the gate fires the model ranks
lowest to free budget, spend it on the highest-ranked non-fires. Thresholds on gold1 only.
`analysis/layered/w2_twosided.py`.

| variant | OOS P/R | dR_OOS | 95% CI | STRICT P/R | dR_STRICT | false% |
|---|---|---|---|---|---|---|
| flat | 0.925/0.566 | **-0.0371** | [-0.0699, -0.0113] | 0.937/0.430 | -0.0465 | 2.50% |
| spec_soft_router | 0.927/0.577 | **-0.0257** | [-0.0556, -0.0034] | 0.938/0.442 | -0.0349 | 2.50% |
| blend_learned | 0.926/0.569 | **-0.0343** | [-0.0659, -0.0085] | 0.937/0.430 | -0.0465 | 2.50% |

The veto side buys real budget (2.88% -> 2.50%) by discarding **real detections**. Selection on
gold1 made the veto look free; it does not transfer. Confidence intervals exclude zero on the
losing side. This configuration is measured and rejected.

---

## 4. WHY THE AUC GAIN DOES NOT CONVERT (`analysis/layered/w2_exchange.py`)

### 4a. Exchange rate: OOS true positives bought per benign false block spent

| variant | +1 fb | +2 fb | +5 fb | +10 fb | +20 fb | +40 fb |
|---|---|---|---|---|---|---|
| flat | 0 | +3 | +4 | +5 | +5 | +5 |
| spec_soft_router | 0 | 0 | +4 | +6 | +11 | +14 |
| blend_50_50 | +1 | +1 | +3 | +4 | +8 | +14 |
| flat_perfam_thresh | +1 | +2 | +3 | +4 | +9 | **+15** |

The shipped gate's own rate is **6.81 true positives per false block** (211 TP for 31 false).
The best layer manages **+1 TP for the 1 false block available**, and **+15 TP for 40** — an
exchange rate of 0.375, roughly **18x worse than the gate**. There is no budget at which buying
model-layer blocks is a better use of benign cost than what the gate already does with it.

### 4b. Per-family OOS recall at matched 3.00% cost — the AUC gains do not appear

| family | n pos | gate R | flat | spec_soft_router | blend_learned | LOACO flat -> soft |
|---|---|---|---|---|---|---|
| cot_hijack | 31 | 0.742 | 0.742 | 0.742 | 0.742 | 0.309 -> 0.392 |
| false_precedent | 62 | 0.677 | 0.677 | 0.677 | **0.694** | 0.522 -> 0.655 |
| role_spoofing | 24 | 0.708 | 0.708 | 0.708 | 0.708 | 0.681 -> 0.788 |
| emotional_coercion | 50 | 0.340 | 0.340 | 0.340 | 0.340 | 0.821 -> 0.827 |
| hypothetical_framing | 44 | 0.455 | 0.455 | 0.455 | 0.455 | 0.809 -> 0.777 |
| sleeper_trigger | 26 | 0.538 | 0.538 | 0.538 | 0.538 | 0.659 -> 0.697 |

Nine of ten families are **unchanged to three decimals**. The +0.133 AUC gain on false_precedent
buys exactly one row. AUC improved in the middle of the ranking; the operating point only reads
the top.

### 4c. Ceiling — the budget is not what forbids this

- OOS attack rows the gate misses: **139 of 350**. STRICT: **90 of 172**.
- An oracle layer that ranked every missed attack above every benign row would recover all 139
  **at zero benign cost** (OOS R 1.000). The 0.12pp headroom is therefore *not* the ceiling.
- Best real variant at the real headroom: **+1**. Realised fraction of the ceiling: **0.007**.

**The binding constraint is model separation, not the benign budget.** A layered architecture
does not supply that separation; it re-ranks rows the gate already ordered adequately.

---

## 5. WHAT THIS MEANS FOR THE PROJECT

1. **The lead's hypothesis was correct about the diagnosis and wrong about the cure.** Per-family
   heterogeneity is real (LOACO 0.82 to 0.31) and specialists genuinely fix it in ranking terms.
   That fix does not reach the operating point.
2. **Report the AUC gain as a modelling result, not a detection result.** A previous arm won on
   AUC by +0.153 and still lost at the operating point; this is the same failure mode, caught
   before it was claimed. `spec_soft_router` LOACO 0.7395 is publishable as a modelling finding
   with the operating-point negative attached to it. Separating those two is the honest framing.
3. **Nothing ships.** The shipped gate stays exactly as it is: strict policy, marker demand,
   22/22, OOS 0.9214/0.6029, STRICT 0.9213/0.4767, benign FALSE 2.88%.
4. **The real lever is elsewhere.** Any future recall work must either raise the benign budget
   (a product decision, not a modelling one) or find features that separate the gate's 139 OOS
   misses from benign traffic. Re-ranking with the current 12+8 feature basis provably cannot:
   0.7% of the available headroom is realised.

---

## 6. ARTEFACTS

| file | contents |
|---|---|
| `analysis/layered/w2_layered.py` / `w2_model_results.json` / `w2_layered.log` | 11 variants, LOACO + CV, router accuracy, permuted-label control |
| `analysis/layered/w2_repro.py` / `w2_repro.json` | baseline reproduction (10-seed AUC, LOACO, per-family) |
| `analysis/layered/w2_operating_point.py` / `.json` / `w2_op.log` | ADD / VETO / ML-alone arms, RAW benign basis |
| `analysis/layered/w2_budget.py` / `w2_budget.json` | same arms re-expressed on the FALSE-block basis; oracle cost-matched curves |
| `analysis/layered/w2_budget2.py` / `w2_budget2.json` | headroom accounting, honest marginal-headroom selection, bootstrap CIs, null control |
| `analysis/layered/w2_twosided.py` / `w2_twosided.json` | two-sided veto+add layer, bootstrap CIs, null control |
| `analysis/layered/w2_exchange.py` / `w2_exchange.json` | exchange rate, per-family operating point, ceiling |

Cached 5-seed LOACO scores: `w2_op_gold.npy` (11 x 965), `w2_op_pool.npy` (11 x 1078).
No gold2 or sathwik response text was read or printed at any point in this arm.
