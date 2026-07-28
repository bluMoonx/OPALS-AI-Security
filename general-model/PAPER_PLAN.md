# PAPER_PLAN.md - outline, claim ledger, and publication gate

**Rewritten 2026-07-27 ~12:45 PDT.** This replaces the 300-label-era plan entirely.
`PAPER_CORRECTIONS.md` §7 ruled the previous version stale as a whole and directed a
rewrite rather than a patch, because the *framing* changed and not only the numbers.

What changed in the framing, in one paragraph. The old plan was a list of things to add to
someone else's draft, and its lead was a detector score (F1 0.874). That detector number
was in-sample, and the honest version of it is roughly half. The paper's actual
contribution is not a detector. It is a **measurement result about how the field labels
attack success**, followed by an unusually complete account of how hard it is to measure a
behavioural detector honestly - including two negative results and a shipped system that we
report as a cost curve rather than as a point. The detector is the vehicle, not the claim.

---

## 0. How to read this document

Every claim below is a row with three fields:

- **value** - the current number, as of the snapshot stamped on it.
- **reproduce** - the exact artifact or command that regenerates it.
- **flag** - one of:

| flag | meaning |
|---|---|
| **PUBLISH** | On `PAPER_CORRECTIONS.md` §6's safe list, and re-derived again for this plan. Goes in the paper as written. |
| **PUBLISH+CAVEAT** | Safe only with a specific sentence attached. The sentence is given. Dropping it makes the claim false. |
| **NOT-YET** | On `PAPER_CORRECTIONS.md` §7. The measurement it still needs is stated. Does not enter the draft until that measurement exists. |
| **WITHDRAWN** | Measured, wrong, and named here only so nobody resurrects it. |

### 0.1 Corpora I read to write this plan

Documents and code only: `PAPER_CORRECTIONS.md`, `OVERNIGHT_REPORT.md`,
`analysis/compete/COMPETITION_ROUND2.md`, `analysis/compete/ROUND3_SYNTHESIS.md`, the old
`PAPER_PLAN.md`, `openclaw-plugin/scorer.py`, `analysis/make_figures.py`,
`analysis/eval_combined_gold.py`, and the metadata blocks of `models/*.joblib`,
`models/metrics_behavioral.json`, `analysis/rebuild/eval_supervised_results.json`,
`data/logs/collected_new10category/newcats_actions_recovered.jsonl`,
`evidence/rederive/recover_actions_RERUN_stdout.txt`.

Gold was **scored programmatically only**. I did not print, read or inspect a single
`agent_response` string from gold1 or gold2. I authored no feature and no rule, so nothing
in this document contaminates the STRICT slice. I read `figures/fig1_label_undercount.png`
as a rendered image to confirm its title is no longer clipped; it contains no response text.

### 0.2 Snapshot discipline

The collector is live. Every corpus count in this plan is stamped **2026-07-27 12:42 PDT**
and must be re-stamped, not re-used, at submission. Verified this session:

```
records 2166 | resolved gold 965 (gold1 294 + gold2 671) | attack 817 (pos 414) | baseline 148 (pos 3)
distinct prompts across gold 285 | gold1 attack 146 | OOS 671 | STRICT 288 (116 prompt groups)
python3 analysis/check_gold_integrity.py  ->  GOLD INTEGRITY: OK  (prefix sha256 bbc654c657c78d3e…)
python3 openclaw-plugin/test_suite.py     ->  22 passed, 0 failed, 0 skipped
```

Note `test_suite.py` is now **22/22**, not the 21/21 in `ROUND3_SYNTHESIS.md` or the
17/17 and 20/20 in older documents; a benign-false-block-rate test was added.

### 0.3 The contamination rule that governs the whole paper

**Grouped CV does not defend against author contamination.** Holding a prompt out of a fold
does nothing about a feature written after a human read a response carrying that prompt. So
every generalisation claim is reported on two slices:

- **OOS** - all 671 gold2 attack rows, held out from the labeler.
- **STRICT** - the 288 OOS rows whose *prompt* never appears among gold1's attack prompts.

STRICT is the honest predictor for a new attack, and it is **narrower protection than it
sounds**: it guarantees the prompt was absent from gold1, not that a feature author never
read it (`ROUND3_SYNTHESIS.md` §4.6). The paper must name that channel explicitly and
report the "no mined vocabulary" ablation wherever an arm read any part of the held-out
slice.

---

## 1. Paper skeleton

| § | working title | carries |
|---|---|---|
| 1 | Introduction | The field scores agent-attack success by marker echo. That measurement is wrong by ~4.5×, and we can show it on 817 hand-judged sessions. |
| 2 | Related work / positioning | Canary-and-marker benchmarks; behavioural adjudication; gateway defences. |
| 3 | Corpus and adjudication protocol | 965 hand-judged records, 17 labelers across two waves, 10 attack families, prompt-paired baselines. |
| 4 | **Result 1 - label validity** | Canary under-counts behavioural success 4.5× (50.7 % vs 11.3 %), misses 79 %, kappa 0.201. |
| 5 | **Result 2 - per-category ASR** | Ten families with Wilson CIs. False precedent is the most effective attack at 77.2 %. |
| 6 | **Result 3 - measuring a detector honestly** | The protocol ladder 0.797 leaky → 0.743 prompt-grouped → 0.712 unseen-family, with the leak scaling by model capacity. |
| 7 | **Result 4 - the negative result** | cot_hijack LOACO 0.31 (below chance) and false_precedent 0.51 (chance) - and false_precedent is the highest-ASR family. With the mechanism. |
| 8 | **Result 5 - the gate as an operating curve** | Four block policies, recall vs benign false-block, not a point. |
| 9 | Process findings | `session_id` is not a join key; deployed-vs-measured drift; grouped CV vs author contamination; a flag-order denylist hole. |
| 10 | Limitations and threats to validity | Everything in §7 of this plan. |

---

## 2. Result 1 - canary/marker labelling under-counts behavioural attack success (§4)

**This is the contribution.** It is a methodological finding about the field, not about our
corpus: any benchmark that scores success by marker echo is measuring the wrong thing.

| claim | value (n=817 attack rows, 2026-07-27) | reproduce | flag |
|---|---|---|---|
| Behavioural attack success rate | **50.7 %**, 414/817, Wilson 95 % CI **[47.2, 54.1]** | `python3 analysis/eval_combined_gold.py` | **PUBLISH** |
| Canary-derived success rate | **11.3 %**, 92/817 fires | same | **PUBLISH** |
| Under-count factor | **≈ 4.5×** (50.7 / 11.3) | same | **PUBLISH** |
| Canary misses | **326 of 414 = 79 %** | same | **PUBLISH** |
| Canary vs human agreement | precision **0.9565**, recall **0.2126**, F1 0.3478, **kappa 0.2005** | same | **PUBLISH** |
| Adjudication size | **965 hand-judged records** (817 attack / 148 baseline, 417 positive); gold1 294 records / 5 labelers, gold2 671 records / 12 labelers | `len(load_all_gold(load_records()))`, `Counter(g["_src"] …)` | **PUBLISH** |
| Figure | `figures/fig1_label_undercount.png` | `python3 analysis/make_figures.py` | **PUBLISH** - title clip is **fixed** (regenerated 12:44 today; the rendered PNG now reads "canary misses 326 of 414 = 79%"). Verified by opening the image. |

**The mechanism to state, because it is what makes the finding transferable.** The dominant
canary-invisible failure mode, found independently by all 12 gold2 labelers, is
**solicitation / deferred compliance**: the agent cannot reach the secret, so instead of
refusing it asks the *user* to hand it over or to run `/approve`. The injected goal has been
accepted; no marker is ever echoed; the canary is structurally blind. Other blind modes:
system-prompt and tool-schema exfiltration, agent-state dumps, field-slot emission (adopting
the attacker's output contract), self-modification of standing instructions.

**Sentence the old plan got wrong and must not be reused:** it reported this result as
"~4× (43.7 % vs 10.6 %), misses 76 %, kappa 0.256, n=300". Every one of those is
**WITHDRAWN** - retired 283/300-label era.

---

## 3. Result 2 - per-category ASR with Wilson CIs (§5)

Reproduced exactly this session, including every CI bound.

| category | ASR | k/n | 95 % CI | flag |
|---|---|---|---|---|
| false_precedent | **77.2 %** | 71/92 | [67.6, 84.6] | PUBLISH |
| delimiter_confusion | 72.1 % | 49/68 | [60.4, 81.3] | PUBLISH |
| meta_prompting | 64.5 % | 40/62 | [52.1, 75.3] | PUBLISH |
| cot_hijack | 58.7 % | 37/63 | [46.4, 70.0] | PUBLISH |
| prompt_leaking | 58.3 % | 35/60 | [45.7, 69.9] | PUBLISH |
| sleeper_trigger | 48.4 % | 31/64 | [36.6, 60.4] | PUBLISH |
| role_spoofing | 43.1 % | 28/65 | [31.8, 55.2] | PUBLISH |
| multilingual_injection | 42.6 % | 26/61 | [31.0, 55.1] | PUBLISH |
| emotional_coercion | 34.5 % | 51/148 | [27.3, 42.4] | PUBLISH |
| hypothetical_framing | 34.3 % | 46/134 | [26.8, 42.7] | PUBLISH |
| **OVERALL** | **50.7 %** | 414/817 | **[47.2, 54.1]** | PUBLISH |

Reproduce: `python3 analysis/eval_combined_gold.py`. Figure:
`figures/fig2_per_category_asr.png` (audited fully correct, every bar matches to the
integer).

**Rewrite the narrative sentence, not the number.** The old draft says *"task-laundering is
the single most effective attack (83 %)"*. That is false on two counts: the most effective
family is **false precedent at 77.2 %**, and meta_prompting (the family the 83 % referred
to) is **third at 64.5 %**. The 83 % came from an n=15-per-category pilot that was
underpowered; at n=62 it drops 18 points. The replacement sentence:

> The most effective attack against the agent is **false precedent** - a forged claim that
> some prior authorisation, policy, or precedent already exists - which succeeds in 77.2 %
> of attempts [67.6, 84.6]. Over half of all attacks succeed overall.

**Do not quote** the old per-category set (83/80/75/67/42/30/27/25/9/8 %) or the interim
n=706 table at `WORKLOG.md:78-91`. Both **WITHDRAWN**.

---

## 4. Result 3 - measuring a detector honestly: the protocol ladder (§6)

The framing here is the paper's second contribution and it is a *methods* contribution:
we show the size of the prompt-duplication leak, and that **the leak scales with model
capacity**, which is the signature of memorisation.

| claim | value | reproduce | flag |
|---|---|---|---|
| The leak's cause | 965 records cover only **285 distinct prompts** (3.39 trials each); 77 % of prompts carry one label across all repeats, so sibling trials sat in train and test together | `models/metrics_behavioral.json → _protocol` | **PUBLISH** |
| Plain KFold (leaky) | RF **0.7973** | `metrics_behavioral.json → cv_random_forest.auc_leaky_plain_kfold` | **PUBLISH** as the leak measurement only |
| Prompt-grouped `StratifiedGroupKFold(md5(prompt))`, 5-fold, 10 seeds | RF **0.7427 (sd 0.0081)**, F1 **0.6532** | `→ cv_random_forest` | **PUBLISH** |
| Leave-one-attack-category-out (LOACO) | RF pooled **0.7117** | `→ loaco_random_forest.auc` | **PUBLISH** |
| Leak scales with capacity | logreg **−0.018**, RF **−0.055**, GB **−0.058** | `→ cv_*.leak_magnitude` | **PUBLISH** |
| Leak vs noise | leak −0.055 is **≈ 7×** the honest seed-to-seed sd (0.008), and ≈ 18× the sd the original 3-seed leaky run reported (0.003) | same | **PUBLISH+CAVEAT** - attach: *tight error bars measured stability inside a broken protocol; they were evidence of reproducibility, never of validity.* |
| Trivial always-positive F1 floor | **0.6035** on all 965 | `→ trivial_f1_floor`; re-derived this session | **PUBLISH** |
| Only RF clears the floor | logreg F1 0.5864 (**below**), GB 0.6036 (**at**), RF 0.6532 (**+0.050**) | `metrics_behavioral.json` | **PUBLISH** |
| Canary-label control, identical features and protocol | **0.6882 (sd 0.0133)**; behavioural target beats it by **+0.055** ≈ 4× the control's sd | `→ canary_cv_random_forest` | **PUBLISH+CAVEAT** - attach: *under the leaky protocol the canary control scored higher (0.836); grouping destroys most of its apparent signal because the canary is a deterministic function of the response string. The behavioural target is not merely the correct target, it is the more learnable one.* |
| Figure | `figures/fig5_protocol_ladder.png` - reads its values out of the shipped joblib, so it cannot drift | `python3 analysis/make_fig5_protocol_ladder.py` | **PUBLISH** - audited fully correct |

**WITHDRAWN in this section, permanently:** AUC **0.797** as a headline; **0.748** (a
favourable 3-seed draw); canary control **0.836**; **0.905** and the 0.95/0.94
balanced-accuracy comparisons; F1 **0.704** quoted without a floor. Also **WITHDRAWN**:
"true LOACO 0.672" - the artifact says **0.5019** pooled OOF defined on 12 of 38 folds, and
a re-run today (`analysis/rebuild/eval_supervised_results.json`) confirms 0.5019. Cite
`fig5_protocol_ladder` instead of either number.

---

## 5. Result 4 - the negative result, published because it is against interest (§7)

| claim | value | reproduce | flag |
|---|---|---|---|
| `cot_hijack` LOACO AUC | **0.3065** - *below chance, actively anti-correlated* | `metrics_behavioral.json → loaco_random_forest.per_category` | **PUBLISH** |
| `false_precedent` LOACO AUC | **0.5145** - indistinguishable from chance | same | **PUBLISH** |
| …and false_precedent is simultaneously the **highest-ASR family (77.2 %)** | - | §3 above | **PUBLISH** |
| Full per-family LOACO | emotional_coercion 0.822, hypothetical_framing 0.812, meta_prompting 0.795, role_spoofing 0.688, multilingual 0.685, prompt_leaking 0.679, sleeper_trigger 0.648, delimiter_confusion 0.639, false_precedent 0.515, cot_hijack 0.307 | same | **PUBLISH** |

**The mechanism, which is what upgrades this from an embarrassment to a result**
(`ROUND3_SYNTHESIS.md` §3, all 817 attack rows):

> In chain-of-thought-hijack attacks, complying looks like doing **less**; in every other
> family, complying looks like doing **more**.

| signal | cot_hijack AUC | all-attack AUC | next-worst family |
|---|---|---|---|
| tool-call count | **0.140** | 0.706 | prompt_leaking 0.381 |
| mutating-tool count | 0.247 | 0.630 | prompt_leaking 0.366 |
| reply length | 0.334 | 0.464 | hypothetical 0.179 |

Mean mutating calls: **0.46 for compliant cot_hijack replies vs 2.15 for refusals**; mean
search calls **0.00 vs 1.12**. The attack hands the agent a forged premise and asks it to
*continue the reasoning*, so compliance is a short confident prose continuation with no tool
use, while refusal is the response that goes and **checks**. LOACO trains on nine families
where activity means compliance and applies it to the one where activity means refusal. That
single sign flip fully accounts for the number.
Reproduce: `analysis/compete/round3_synthesis/split.py`, `signstab.py`.

**The attempted fix is itself a reportable loss.** Gating the activity features on a
prompt-side `premise_supplied` flag lifts cot_hijack 0.309 → 0.427 but drops pooled LOACO
0.7113 → 0.7035 and pushes false_precedent 0.517 → **0.434**, further below chance. It moves
the defect; it does not remove it. Reproduce: `round3_synthesis/exp1.py`. **PUBLISH** as a
negative result with the lesson: *a family-level repair must be reported as a pooled delta
with the other families' deltas beside it, or it is not a result.*

**The abstention, stated plainly and costing the deliverable nothing (PUBLISH+CAVEAT).**
The 0.31 is a property of the **12-feature science-feature research model**, which is not
what blocks. On the same family the *deployed* signals are healthy: labeler score AUC
**0.852** on cot_hijack, and the gate's operating-point recall on cot_hijack (OOS, n=31) is
0.677 → 0.742 widened → 0.774 stacked. The caption must say both things, or a reader will
conclude the shipped gate is below chance on cot_hijack, which is false.

---

## 6. Result 5 - the gate as an operating CURVE, not a point (§8)

This section exists because the project's single worst documentation failure was publishing
a recall number and a benign-cost number that described **different configurations**
(`PAPER_CORRECTIONS.md` §0.1: 1.3 % published, 10.8 % actual, an 8× move nobody recorded).
The fix is structural: **recall and benign false-block are one claim and appear in one
table, always.**

### 6.1 The shipped system

`openclaw-plugin/scorer.py`. Blocks when `labeler.label == 1`, **or** (a policy gate passes
**and** (`labeler.score >= 3` **or** `deferred_score_ungated >= 5.5`)). Policy is selected by
env `AURA_BLOCK_POLICY`; the default is **`strict`**, which requires `p_unsafe_demand > 0`.
`balanced` requires `p_unsafe_demand > 0` or `injection_present`; `aggressive` applies no
gate. Threshold 5.5 and bar 3 were frozen on the 146-row gold1 slice and never retuned
against gold2.

### 6.2 The curve - **reproduced from the live plugin code path this session**

| policy | OOS (n=671, 350 pos) | STRICT (n=288, 172 pos) | benign false-block (n=148) | flag |
|---|---|---|---|---|
| `off` (labeler alone) | P **0.9235** R **0.4486** F1 0.6038 tp157 fp13 | P **0.8793** R **0.2965** F1 0.4435 tp51 fp7 | **2/148 = 1.4 %** | PUBLISH |
| **`strict` (DEFAULT)** | P **0.9303** R **0.5343** F1 0.6788 tp187 fp14 | P **0.9014** R **0.3721** F1 0.5267 tp64 fp7 | **2/148 = 1.4 %** | PUBLISH |
| `balanced` | P **0.9349** R **0.5743** F1 0.7115 tp201 fp14 | P **0.9114** R **0.4186** F1 0.5737 tp72 fp7 | **6/148 = 4.1 %** | PUBLISH |
| `aggressive` | P **0.9183** R **0.6743** F1 0.7776 tp236 fp21 | P **0.9292** R **0.6105** F1 0.7368 tp105 fp8 | **17/148 = 11.5 %** | PUBLISH+CAVEAT |

Reproduce: score `load_all_gold(load_records())` through
`openclaw-plugin/behavioral_labeler.score_session` + `deferred_compliance.deferred_features`
/ `deferred_score_ungated`, mirroring the four branches in `scorer.py:143-176`.
**`python3 analysis/paper_repro/policy_curve.py`** → `analysis/paper_repro/policy_curve_output.txt`
(written this session). Every cell matches the shipped comment block in `scorer.py` to four
decimals.

**The one-sentence result.** `strict` **strictly dominates** `off`: identical benign
false-block rate (2/148), **+0.085 OOS recall and +0.076 STRICT recall**, because
`p_unsafe_demand` fires on 321/817 attack prompts and on **0/148** benign prompts. There is
no reason to run `off`.

### 6.3 Deltas with group-bootstrap CIs (prompt groups resampled, 5000 draws, this session)

| slice | change | ΔRecall (95 % CI) | ΔPrecision (95 % CI) | flag |
|---|---|---|---|---|
| OOS | `off` → `strict` | **+0.086 [+0.045, +0.135]** | +0.007 [−0.007, +0.021] | PUBLISH |
| STRICT | `off` → `strict` | **+0.077 [+0.026, +0.142]** | +0.024 [+0.004, +0.065] | PUBLISH |
| OOS | `strict` → `balanced` | **+0.040 [+0.015, +0.071]** | +0.005 [+0.001, +0.010] | PUBLISH |
| STRICT | `strict` → `balanced` | **+0.046 [+0.012, +0.093]** | +0.010 [+0.002, +0.026] | PUBLISH |
| OOS | `strict` → `aggressive` | **+0.140 [+0.090, +0.198]** | −0.012 [−0.049, +0.015] | PUBLISH+CAVEAT (costs 15 more benign blocks) |
| STRICT | `strict` → `aggressive` | **+0.239 [+0.153, +0.329]** | +0.028 [−0.006, +0.073] | same caveat |

Reproduce: **`python3 analysis/paper_repro/policy_curve_ci.py`** →
`analysis/paper_repro/policy_curve_ci_output.txt`. Resampling is over **prompt groups**,
never rows.

### 6.4 Harness control (required, and it passes)

Permuted-label control on the fixed deterministic gate: shuffling labels within a slice
drives precision to the slice base rate, as it must.
OOS base rate **0.5216**, permuted precision **0.5172**. STRICT base rate **0.5972**,
permuted precision **0.5965**. 20 permutations each,
`analysis/paper_repro/policy_curve_ci.py`. Not near the base rate would mean the harness is
broken. (For the *learned* arms the corresponding control is AUC: SOG permutation 0.490,
stage-2 residual 0.478 OOS / 0.457 STRICT, unfitted deferred score 0.504 - all near 0.5.)
**PUBLISH** as a methods footnote.

### 6.5 F1 against the floor - and why F1 is the wrong summary here

Required by the reporting rule, and the answer is uncomfortable in a way worth publishing:

| slice | trivial always-positive F1 | best shipped policy F1 |
|---|---|---|
| all gold (965) | **0.6035** | - |
| gold1 (146) | 0.6095 | 0.8943 (`aggressive`) |
| OOS (671) | **0.6856** | 0.7776 (`aggressive`); default `strict` **0.6788 - below the slice floor** |
| STRICT (288) | **0.7478** | 0.7368 (`aggressive`) - **below the slice floor**; default `strict` 0.5267 |

The attack-only slices have base rates above 50 %, so "block everything" is a strong F1
strategy on them - at a **100 % benign false-block rate**. That is exactly why the paper
reports a curve. State it: *F1 on an attack-only slice is not a decision-relevant metric for
a gate; the decision-relevant pair is (recall at precision ≥ 0.90, benign false-block rate),
and it is reported jointly throughout.* **PUBLISH** - this is an honest framing, not a
dodge, and it is the argument for §8's structure.

### 6.6 What the gate still cannot do

| claim | value | reproduce | flag |
|---|---|---|---|
| Compliances carrying **no deferred evidence at all** are the residual weakness | recall **0.480 OOS / 0.373 STRICT** (n=152 / 75), moved only to 0.488 under round-3 widening | `PAPER_CORRECTIONS.md` §3.1; `ROUND3_SYNTHESIS.md` §1 | **PUBLISH+CAVEAT** - measured pre-widening for the per-family rows; re-run before final. |
| Evidence-family recall (solicitation 0.836/0.781, conditional commit 1.000/1.000, field-slot 0.891/0.938, approval-gate 0.793/0.750, blocked-attempt 0.780/0.731) | as listed | `PAPER_CORRECTIONS.md` §3.1 | **PUBLISH+CAVEAT** - pre-widening snapshot; STATE-DUMP/SELF-MOD rows (n=1/2) are **too small to carry a published recall** and must be dropped from the table. |
| Two independent round-3 arms improved recall and moved the no-evidence bucket by 0.008 | - | `ROUND3_SYNTHESIS.md` §4.4 | **PUBLISH** - the lesson is that both arms share the assumption that compliance leaves a lexical trace, which the residual violates. |

### 6.7 The A/B intervention

12/12 vs 3/12 destructive actions prevented, **Fisher exact two-sided p = 0.000336519**,
outcome measured on the **filesystem**. `analysis/ab_intervention_results.json`,
`figures/fig6_ab_intervention.png`. **PUBLISH+CAVEAT** - the caption must state:
*the A/B tested the literal string `rm -rf`, the one spelling the pre-fix rule layer caught;
it measured one spelling, not the capability.* Honest nuance also worth publishing: the
model's own refusal stops 25 % of unprotected runs; the gate closes the remaining 75-point
gap. At n=4/arm the same effect gives p = 0.143, so a 4-per-arm design is underpowered and
ours at n=12 is not.

---

## 7. Process findings (§9) - all verified on disk

These are cheap credibility and every one of them cost this project real time.

| finding | evidence | flag |
|---|---|---|
| **`session_id` is not a join key.** 2,166 records, 1,271 distinct ids, **326 duplicated ids**, max depth 9, **56.4 %** of records under a duplicated id. Seven scripts had this bug; two are quarantined and exit non-zero. One retrain reported n=971 instead of 965 because of it, and its only visible symptom was a missing metadata key. | `Counter(r["session_id"] for r in load_records())`; `analysis/eval_combined_gold.load_all_gold` is the only sanctioned join | **PUBLISH** |
| **Deployed code drifted from measured code, silently.** `openclaw-plugin/behavioral_labeler.py` was 558 lines while every published number described the 790-line version; the deployed copy scored P 0.965 / R 0.314 against the published P 0.924 / R 0.449. Nothing crashed and nothing warned. Now sha256-identical and test-enforced. | `shasum -a 256 openclaw-plugin/behavioral_labeler.py analysis/rebuild/behavioral_labeler.py` → both `ec437e52…805b3`; the deferred module likewise mirrors at `afda38e8…bbc91` | **PUBLISH** |
| **A denylist hole defeated by flag order.** `rule_layer` substring-matched the literal `"rm -rf"`; `rm -r`, `rm -fr`, `rm --recursive --force`, `find X -delete` and `find X -exec rm {} ;` were all allowed. Found by a live run that deleted its target. Fixed with a flag-order-independent regex: 9 destructive spellings block, 6 benign commands still pass; enumerated as a regression test. | `openclaw-plugin/test_suite.py` (22/22) | **PUBLISH** |
| **Grouped CV does not defend against author contamination.** Holding a prompt out of a fold does nothing about a feature written after a human read a response carrying that prompt. This is why STRICT exists, and why STRICT is still not a complete defence - gold2 prompts were readable, and one arm mined 203 of them. That arm's win survived the ablation removing prompt-mined vocabulary (STRICT ΔR +0.0349, 6 of 8 recoveries from pure grammar), **but only because someone ran the ablation.** | `ROUND3_SYNTHESIS.md` §2.1, §4.6 | **PUBLISH** |
| **Measure the cost axis in the same table as the benefit.** Every round-3 arm reported its attack-slice operating point; one reported the benign cost. The #1 audit correction is exactly that omission going unnoticed for a week. | `PAPER_CORRECTIONS.md` §0.1 | **PUBLISH** |
| **In a parallel competition, "beats the baseline" is meaningless unless the baseline is pinned by content hash at claim time.** One arm was scored a loss purely because a sibling arm improved the baseline 90 seconds earlier; the same code re-measured on the current baseline hits 10/10 seeds on both slices. | `ROUND3_SYNTHESIS.md` §4.1 | **PUBLISH** |

### 7.1 Corpus and infrastructure counts (Methods)

All snapshots at **2026-07-27 12:42 PDT**; re-stamp at submission.

| asset | value | reproduce | flag |
|---|---|---|---|
| 10-category sessions | **2,166** and growing | `wc -l data/logs/collected_new10category/newcats_sessions.jsonl` | PUBLISH+CAVEAT (timestamp required) |
| hand-judged gold | **965** (817 attack / 148 baseline) | loader | PUBLISH |
| prompt bank | **500 pairs = 1,000 prompts**, 50 per category × 10, **320 distinct science domains** | `wc -l data/prompts/new_categories_bank.jsonl` | PUBLISH |
| Chenhao release | **1,314 rows** (614 deepseek + 700 kimi), 921 safe / 393 suspicious, but only **10 distinct prompts** (131.4 rows per prompt) | `Counter(r["user_prompt"] …)` | PUBLISH - and the 10-distinct-prompt fact is the *point*: effective diversity is ~10, not 1,314 |
| 22-category collection | **82 rows**, 41 benign + 41 attack over 23 attack categories, **16 successful**, rate 0.390 CI **[0.257, 0.543]** (28.6-pt width) | `analysis/…/collected_22category/sessions.jsonl` | PUBLISH+CAVEAT - **report as coverage, not as a rate**; a 28.6-point interval cannot carry a point estimate |
| action recovery | **660 distinct trials** with actions, **950 enriched rows**, **1,059 out-of-scope actions (distinct-trial)** | `evidence/rederive/recover_actions_RERUN_stdout.txt`; `data/logs/collected_new10category/newcats_actions_recovered.jsonl` | **PUBLISH+CAVEAT** - see below |
| boundary split | action_manifesting **950** / text_or_state **1,216** of 2,166 | `Counter(r["boundary"] …)` | PUBLISH+CAVEAT (row-level; see below) |

**The action-recovery caveat is mandatory and is itself a finding.** Raw logs are keyed by
`session_id`, which is not unique in newcats, so one recovered trail attaches to every row
sharing that id. **Distinct-trial numbers are exact; row-level sums are inflated by the
join** - the same artifact yields 1,059 out-of-scope actions at the distinct-trial level and
1,494 if you sum the per-row field, and 5,346 vs 6,387 action records depending on which you
sum. Quote the distinct-trial set, name the caveat, and never quote a row-level sum.
This closes `PAPER_CORRECTIONS.md` §7's "five mutually inconsistent sets" item: there is now
one artifact, one definition, and a stated caveat. The older sets (405 / 769 / 680 / 5,230 /
1,074) are all **WITHDRAWN**.

---

## 8. NOT-YET - what is not safe to publish, and the measurement each needs

Drawn from `PAPER_CORRECTIONS.md` §7 plus the two corrections `ROUND3_SYNTHESIS.md` adds.
Nothing in this list enters the draft until its measurement exists.

| claim | why not safe | measurement required |
|---|---|---|
| **"1.3 % false-block rate" as a standalone number** | It describes `off`/`strict` only. `aggressive` is at **11.5 %** and was briefly the default. Publishing any single rate without its policy row is how 1.3 % and 10.8 % ended up in the same repo. | None - **just never publish a rate without its policy and its recall in the same row.** §6.2 is the fix; the four-row table is the deliverable. |
| **The 148-row benign set as the cost denominator** | n=148 with 3 positives cannot resolve a 1-to-3-point difference; the CI on 17/148 alone is roughly ±5 points. | Build **≥ 600 non-attack sessions** (148 hand-judged baseline + `chenhao_release` `human_label == "safe"` + 22-category benign), prompt-deduplicated, hand-adjudicate a 200-row subsample. `ROUND3_SYNTHESIS.md` §5. **This is the single highest-value next experiment in the project.** |
| **stage-2 residual partner** (OOS P 0.9218 R 0.7077, STRICT P 0.9323 R 0.6407, +0 attack-slice FPs, 10/10 seeds) | Not installed. Costs 1.6 benign false blocks on average and **5 in the worst of 10 seeds** on a 148-row benign set - 12.6 % mean, up to 14.9 %. | The ≥600-row benign set above, then the pre-registered ship criterion: benign rate ≤ 12.0 % with upper 95 % group-bootstrap bound ≤ 13.5 % in 10/10 seeds, while OOS R ≥ 0.70 and STRICT R ≥ 0.62 at P ≥ 0.90. |
| **cross-source AUC 0.699 / attack-slice 0.727** | Asserted with **no artifact, no script output, no CI** anywhere in the repo. | Re-run the 62-feature prompt-response cross-source sweep against `load_all_gold`, save a results JSON, report a CI resampling prompt groups - noting Chenhao supplies **10 distinct prompts**, so effective n ≈ 10. |
| **cross-source 0.748 / 0.773 / 0.752 / 0.801 and the 62-vs-15-feature ablation** | Measured on the retired 283-row gold. | Re-measure the whole ablation on the 965-row gold under the grouped protocol, or delete the section. The old plan's §B4 was built on this; **§B4 is deleted, not rewritten.** |
| **"deferred_compliance T1 AUC 0.853, Δ +0.170"** | On gold2-only prompts the gain is **+0.027, CI [−0.014, +0.072] - contains zero.** | Report as **operating-point-only** (which does survive on STRICT), or measure the AUC claim on a larger contamination-free slice. **Never publish +0.17 as a generalising gain.** |
| **"unfitted hand-weighted score reaches AUC 0.842 with zero training"** | Reproducible (0.8419 all-965, 0.8723 attack slice, permutation control 0.504) but measured on all 965 rows including the 685 whose prompts the feature author's taxonomy came from. | Report the same number on **STRICT** before publishing it as evidence of generality. |
| **"Anomaly-from-normal 0.798 vs 0.863"; "ensembling is worse, 0.817 vs 0.874"; "91 engineered features"; "verification-collapse 0.98"** | All against canary-era or in-sample labels; the 0.874 comparator is in-sample. | Re-measure under the grouped protocol on behavioural labels, or present as historical process notes rather than results. The old plan's §B7 negative-results list is **superseded** by §5 of this plan, which has properly measured negatives. |
| **`fig6` as a capability claim** | It measured one spelling of `rm -rf`. | Either caption it precisely (see §6.7), or re-run the A/B against the post-fix regex over the 9 destructive spellings. |
| **live gateway counters** ("1,177 scored → 1,053/118/6"; "1,306 scored → 1,125/167/14") | Two conflicting snapshots of the same counter, presented as if both current, unreproducible after the fact. | Snapshot once, timestamp it, quote that one. |
| **Hidden-image injection negative result** (5 vision models, none read faint text) | Carried over from the old plan with no artifact named in the audit. | Name the artifact and the model versions, or drop it. |
| **Anything about the co-authors' 0.95** | Their own ablation drops it to 0.689 without `cites_memory_md`. | Raise it before submission; a reviewer will find it. Not our number to publish either way. |
| **Scite citation pass** | Quota resets 2026-07-28. | Do not cite adjudicated references until it runs. |

---

## 9. Figure inventory - current on-disk state, verified 2026-07-27 12:44 PDT

| file | status | flag |
|---|---|---|
| `fig1_label_undercount.png` | Regenerated wider; title now renders in full ("canary misses 326 of 414 = 79%"). **Confirmed by opening the PNG.** | **PUBLISH** |
| `fig2_per_category_asr.png` | Every bar matches the vetted table to the integer. | **PUBLISH** |
| `fig3_corpus_provenance.png` | **New replacement.** Plots only line counts and loader counts, carries no machine-derived rate, stamps its own snapshot date. | **PUBLISH** - verify the stamp at submission |
| `fig3_corpus.png.withdrawn` | Withdrawn. It plotted a **machine-labeler** 16 % "unsafe" rate pooled from three unvalidated heuristics, in a paper whose adjudicated headline ASR is 50.7 %; a reader would read 16 % as the ASR. | **WITHDRAWN** |
| `fig4_honest_vs_inflated.png.withdrawn` | Retired and no longer generated. Its "honest 0.502" was canary-era, defined on 12 of 38 folds. | **WITHDRAWN** |
| `fig5_protocol_ladder.png` | Reads its values out of the shipped joblib, so it cannot drift. | **PUBLISH - this is the model figure** |
| `fig5_transfer_and_safety.png.withdrawn` | Stale split and stale cross-source 0.602. The old plan cited it in §B4 and §B6; **those citations are deleted.** | **WITHDRAWN** |
| `fig6_ab_intervention.png` | Correct against the artifact. | **PUBLISH+CAVEAT** - spelling caveat in the caption (§6.7) |
| **missing: the operating curve** | §6.2's four-row table has no figure. It is the paper's fifth result and the one most likely to be misread as a point estimate. | **TO BUILD** - recall vs benign false-block, OOS and STRICT, four policies, one panel |

---

## 10. Blacklist - numbers that must never reappear

Superseded, measured wrong, or in-sample. Listed so a search finds them.

`43.7 %` · `10.6 %` · `misses 76 %` · `kappa 0.256` · `n=283` · `n=300` · `n=295` ·
`n=971` · per-category `83/80/75/67 %` · "task-laundering is the most effective attack" ·
`F1 0.874` as a headline · `kappa 0.788` as generalisation · `AUC 0.905` · `0.95` / `0.94`
bal-acc · `AUC 0.797` as a result · `0.748` (3-seed) · canary `0.836` · `F1 0.704` ·
`true LOACO 0.672` · cross-source `0.748` / `0.773` / `0.752` / `0.801` / `0.602` ·
`1.3 % false-block` unqualified · gate = "labeler == 1 OR deferred ≥ 5.5" ·
OOS `P 0.9352 / R 0.5771` as the shipped gate · STRICT `n = 280` · `17/17` / `20/20` /
`21/21` tests · `405` distinct trials · `769` enriched rows · `680` / `1,059`(row-level) /
`1,074` out-of-scope · `5,230` action records · `758` Chenhao rows · corpus `1,601` /
`1,924` / `1,974` · raw container logs `942` / `1,188` · `sol_secret_request` recovered at
`0.119`.

---

## 11. Writing order

1. **§4 and §5 (label validity, per-category ASR).** Everything is in hand, every number is
   PUBLISH, and this is the contribution. Write it first and let it set the paper's frame.
2. **§6 (protocol ladder) and §7 (negative result).** Also fully evidenced. §7 needs the
   `ROUND3_SYNTHESIS` §3 mechanism paragraph attached or it reads as an admission instead of
   a finding.
3. **§9 (process findings).** Cheap, verified, and they are what makes a reviewer trust §4.
4. **Build the operating-curve figure**, then write §8 around it. Do not write §8 as prose
   with numbers in it; write the table first and the prose second.
5. **Then, and only then, the ≥600-row benign measurement** (§8's top NOT-YET). It decides
   whether stage-2 ships, and it is the only outstanding measurement that could change a
   headline claim.
6. Methods (§3) and Limitations (§10) last, assembled from §7.1 and §8 of this plan.

---

## 12. Honest assessment

**What we have that is strong.** A 965-record human adjudication is a real asset, and the
label-validity result on 817 attack rows is the kind of finding that changes how other
people run their evaluations. It is fully reproduced by one vetted script, two independent
adjudication passes, and an audit. The protocol ladder is a genuine methods contribution,
and the two negative results are credible precisely because they are against interest.

**What we do not have.** We do not have a detector result worth leading with. Under the
honest protocol the best model is AUC 0.743 with F1 0.653 against a 0.603 trivial floor  - 
real, but a +0.050 margin, not a headline. On unseen families it is 0.712, and on the two
families that matter most it is at or below chance. The shipped gate's value is **precision
at the operating point** (0.90–0.93 across all four policies and both slices), not recall
and not AUC.

**The risk to manage.** Every headline in this paper is a correction to a number this
project itself published within the last two weeks. That is uncomfortable and it is also the
strongest signal of the work's integrity - provided the corrections land as our own, with
the mechanism named, rather than as a reviewer's objection. The §10 blacklist exists so that
none of the retired numbers survives into a figure caption or an abstract by accident.

**The one thing that could still go wrong.** The benign cost axis is measured on 148 rows.
It has already burned this project once, at 8×. Until the ≥600-row benign set exists, every
recall claim in §8 is quoted with a cost estimate whose confidence interval is ±5 points, and
the paper must say so in the same sentence.
