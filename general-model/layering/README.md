# The layering system

Eleven scorers, built to answer one question: **does layering a general model with
per-attack-family specialists beat the flat model at the point where the gate actually
makes decisions?**

Short answer: **it wins on ranking and loses at the operating point.** That is a real
result and it is why nothing here ships. The measurement is the deliverable.

---

## The eleven scorers

| scorer | shape |
|---|---|
| `flat` | one model over all families (the shipped baseline) |
| `spec_soft_router` | general + per-family specialists, soft-routed by predicted family |
| `spec_hard_router` | same, hard argmax routing |
| `spec_max` | max over general and the matching specialist |
| `spec_mean` | mean over general and the matching specialist |
| `blend_50_50` | fixed 50/50 blend |
| `blend_learned` | learned blend weight |
| `cascade` | general first, specialist only on the uncertain band |
| `cascade_avg` | cascade, averaging where both fire |
| `per_family_thresh_hard` | one threshold per family, hard |
| `per_family_thresh_soft` | one threshold per family, soft |

Protocol: 5 seeds, `StratifiedGroupKFold` grouped on `md5(prompt)`, specialists require
at least 25 rows in a family. 12 features, listed in `w2_model_results.json`.

---

## What it won

**Ranking improves, and exactly where predicted.** LOACO AUC **0.7117 -> 0.7395**
(delta +0.0276, CI [+0.0004, +0.0564]), independently reproduced at **0.7402** on different
seeds (100-104 against the original 0-4).

Per-family LOACO on the flat baseline shows where the headroom was:

| family | flat LOACO | after layering |
|---|---|---|
| `cot_hijack` | 0.3065 | **0.392** |
| `false_precedent` | 0.5145 | **0.655** |
| `role_spoofing` | 0.6875 | **0.788** |
| `emotional_coercion` | 0.8223 | — |
| `hypothetical_framing` | 0.8115 | — |
| `meta_prompting` | 0.7953 | — |

`cot_hijack` and `false_precedent` were at or near chance. Layering moved both. That is
the honest case for the approach.

---

## Why it does not ship

**The gain at the operating point is +1 true positive per slice.**

| | OOS (671) | STRICT (288) |
|---|---|---|
| baseline P / R | .9214 / .6029 | .9213 / .4767 |
| best layer P / R | .8898 / .6229 | .8980 / .5116 |

Recall rises, but **precision falls below the 0.90 bar on both slices**, and once you
re-threshold to hold precision, the gain collapses to +1 tp.

Four things kill it, and each is measured, not argued:

1. **A permuted-SCORE null through the identical threshold search reproduces the gain
   exactly** (max +0.0029 OOS, +0.0058 STRICT). The gain *is* the search finding noise.
2. **Benign headroom is 1.34 rows.** The gate spends 2.87% of a 3.00% false-block budget on
   a 1081-row pool. An additive layer can afford roughly one more false block.
3. **Exchange rate.** The existing gate buys **6.81 true positives per false block**. The
   best layer buys **0.375** (15 tp for 40 false blocks). 18x worse. See `w2_exchange.json`.
4. **The two-sided veto+add variant is actively negative** (OOS -0.026 to -0.037, CIs
   excluding zero on the losing side). Its veto side buys budget by discarding real
   detections. See `w2_twosided.json`.

An oracle layer would recover all 139 gate-missed OOS positives at zero benign cost, so the
ceiling is model separation, not budget. The realised fraction of that ceiling is **0.007**.

---

## When this would become useful

Only if the benign budget widened. At a 5.00% budget the layer does gain
(+0.0171 OOS, +0.0291 STRICT) — but that breaks the only safety budget the project has
written down, so it is not a trade to take on an upper-bound measurement.

---

## Files

| file | what it does |
|---|---|
| `w2_layered.py` | builds and cross-validates all eleven scorers |
| `w2_operating_point.py` | evaluates them at the gate's actual thresholds |
| `w2_exchange.py` | true positives bought per false block, per scorer |
| `w2_twosided.py` | the veto+add variant, the only shape that can gain under a binding budget |
| `w2_repro.py` | independent reproduction on different seeds |
| `w2_budget.py`, `w2_budget2.py` | behaviour as the benign budget is varied |

`*.json` alongside each script is its recorded output.

**Note on `w2_budget`:** an earlier run of this arm declared the gate over budget at 4.73%
and built a replacement policy on it. **4.73% is the RAW block rate; the budget is on FALSE
blocks, which is 2.87%.** That policy was measured, found strictly worse (STRICT R .3837),
and rejected. The mistake is recorded here rather than deleted because the raw-versus-false
distinction is the single easiest thing to get wrong in this project.
