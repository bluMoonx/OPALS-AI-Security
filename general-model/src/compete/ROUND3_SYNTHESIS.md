# ROUND 3 SYNTHESIS — what survived, what did not, what ships

Date: **2026-07-27**. Synthesiser: independent of all four arms.
Baseline everything is measured against ("pre-round-3 shipped gate"):

```
block if  behavioral_labeler.score_session(...).label == 1
      or  behavioral_labeler.score_session(...).score >= 3
      or  deferred_compliance.deferred_score_ungated(...) >= 5.5
```

|                        | OOS (671) | STRICT (288) | benign (148) |
|---|---|---|---|
| pre-round-3 shipped    | P 0.9218 R 0.6400 tp224 fp19 | P 0.9327 R 0.5640 tp97 fp7 | 16 false blocks = 10.8 % |

**I reproduced this baseline myself before accepting any claim** (three independent code
paths: the arms' own harnesses, the refuter's `loco.py`, and my `end2end.py`; all print
tp224/fp19 and tp97/fp7). Every number below that is not tagged "arm-reported" was
re-run by me today; the scripts and their raw output are in
`analysis/compete/round3_synthesis/`.

### What I read

Documents, code, and `PAPER_CORRECTIONS.md`. Gold was scored **programmatically only** —
I did not print, read or inspect a single gold2 `agent_response`. I authored no feature
and no rule, so nothing here contaminates STRICT.

---

## 1. Scoreboard, stated plainly

| arm | claim | verdict |
|---|---|---|
| **coverage_gaps** — widen the six deferred-evidence matcher families, threshold frozen at 5.5 | beats the shipped gate on OOS and STRICT above the 0.90 precision floor | **WIN, verified.** Small (+12 tp OOS, +8 tp STRICT) and it did **not** fix the weakness it was aimed at. |
| **stage2_residual** — learned logistic partner scoring only rows the rule called SAFE | as submitted: measured against the *pre-widening* gate | **LOSS as claimed** — its own pre-registered target was missed: 2/10 seeds reached OOS R ≥ 0.70 at P ≥ 0.90, **0/10** reached STRICT R ≥ 0.62. |
| **stage2_residual, re-measured by me on top of the widened gate** | same code, same gold1-only protocol, new residual | **WIN. 10/10 seeds meet both targets on both slices.** This measurement is mine, not the arm's, and is flagged as such throughout. |
| **cot_hijack** — rescue the below-chance family (LOACO 0.31) | a feature fix that lifts cot_hijack without costing the pool | **LOSS.** Best variant lifts cot_hijack 0.309 → 0.427 but drops pooled LOACO 0.7113 → 0.7035 and pushes false_precedent 0.517 → 0.434. Net negative. |
| **paper-audit** — no modelling, correction table only | — | **DELIVERED.** 80 numeric claims re-derived; see §6. |

Two further things that did **not** work, both volunteered by their own arm and confirmed
by me:

- `w_doneclaim` (the "file confirmed written" widening) is **completely inert** on held-out
  data: `minus w_doneclaim` is byte-identical to ALL-ON on gold1, OOS and STRICT
  (tp 55 / 236 / 105). It fixed the one gold1 case it was written for and zero others.
- **The named core weakness is still open.** Rows carrying no deferred evidence at all
  went 0.480 → 0.488 OOS under widening. The stage-2 partner reaches the hardest part of
  that bucket (deferred score ≤ 0) at **0.062 recall on OOS and 0.000 on STRICT**. Both
  round-3 winners recovered rows that already had *some* evidence shape. Nothing this
  round detects a silent compliance that leaves no trace.

---

## 2. What survived, and exactly what should ship

### 2.1 coverage_gaps (already installed)

`openclaw-plugin/deferred_compliance.py`, mirrored byte-identical at
`analysis/compete/deferred_compliance.py`. Six widenings behind a module-level `FLAGS`
dict; `FLAGS` all-False is **byte-faithful to the previous module** (refuter's `equiv.py`:
0 rows differ out of 965). Threshold **not** re-selected: 5.5 held.

|         | OOS (671) | STRICT (288) |
|---|---|---|
| shipped | P 0.9218 R 0.6400 tp224 fp19 | P 0.9327 R 0.5640 tp97 fp7 |
| widened | **P 0.9183 R 0.6743 tp236 fp21** | **P 0.9292 R 0.6105 tp105 fp8** |

- Group bootstrap on the delta (prompt groups, 5000–2000 resamples, 5 seeds):
  OOS dRecall **+0.0341 [+0.0144, +0.0575]**, STRICT **+0.0469 [+0.0155, +0.0848]**.
  Excludes zero on every seed and both slices. dPrecision straddles zero on both.
- **Volume-free statistic** (the one that carries the claim): of the alarms that are *new*,
  OOS 12/14 = 0.857 true against a 0.522 residual base rate; STRICT 8/9 = 0.889 against
  0.597. Matched-volume random null (4000 draws × 5 seeds): E[TP among 14 random extra
  flags] = 4.1, observed 12, P(null ≥ obs) ≤ 0.0003 on every seed.
- **Independent survival checks I ran:** leave-one-attack-category-out — dRecall stays
  positive in **10/10 holdouts on both slices**, min precision over holdouts 0.9057 (OOS)
  / 0.9186 (STRICT). It is not one family carrying the win.
- **Strongest contamination check.** The arm mined its vocabulary from attack *prompts*,
  and STRICT prompts were readable to it (STRICT only guarantees prompt-disjointness from
  *gold1*). So I re-ran with the two prompt-mined widenings switched OFF:
  `CLEAN` still gives OOS dR **+0.0229** (alarm precision 0.800, p = 1.4e-3) and STRICT
  dR **+0.0349** (0.857, p = 2.1e-2). On STRICT, `CLEAN` and `GRAMMAR-ONLY` are identical —
  6 of the 8 STRICT recoveries come from pure grammar ("once I have the X", bare-imperative
  solicitation) with no attacker vocabulary at all. **The win is not carried by
  prompt-mined vocabulary.**
- Threshold re-selection check: on the widened score, gold1 F1 is maximised at exactly 5.5
  (0.8943 vs 0.8852 at 6.0/6.5, 0.8730 at 5.0). No re-selection was warranted or performed.
- `openclaw-plugin/test_suite.py`: **21 passed, 0 failed**.

### 2.2 stage-2 partner (NOT installed — recommended, with a condition)

`analysis/compete/stage2_residual/`. L2 logistic regression, class-weight balanced,
trained on gold1's 146 attack rows only, scoring **only rows the rule called SAFE**, so it
is monotone: it can add a detection, never remove one. `C` by inner grouped CV on training
folds; threshold per seed from gold1 out-of-fold at the P ≥ 0.90 floor; feature set chosen
by gold1 OOF recall. Features authored against `chenhao_release`, `collected_22category`
and gold1 only (provenance stated in the module header).

**Stacked on the widened gate (my measurement, 10 seeds):**

|         | OOS (671) | STRICT (288) |
|---|---|---|
| widened only | P 0.9183 R 0.6743 tp236 fp21 | P 0.9292 R 0.6105 tp105 fp8 |
| widened + stage-2 | **P 0.9218 (sd 0.0006) R 0.7077 (sd 0.0056)** | **P 0.9323 (sd 0.0006) R 0.6407 (sd 0.0063)** |
| seeds clearing P ≥ 0.90 | 10/10 | 10/10 |
| seeds clearing P ≥ 0.90 **and** the pre-registered recall target | **10/10 (R ≥ 0.70)** | **10/10 (R ≥ 0.62)** |
| added false positives on the attack slices | **+0.0** | **+0.0** |

**End-to-end for the round** (median seed, group bootstrap on prompt groups, 5000 resamples):

| slice | pre-round-3 | round-3 stacked | dRecall (95 % CI) | dPrecision |
|---|---|---|---|---|
| OOS | P 0.9218 R 0.6400 tp224 fp19 | **P 0.9216 R 0.7057 tp247 fp21** | **+0.0656 [+0.0369, +0.0997]** | −0.0003 [−0.0125, +0.0097] |
| STRICT | P 0.9327 R 0.5640 tp97 fp7 | **P 0.9322 R 0.6395 tp110 fp8** | **+0.0757 [+0.0370, +0.1200]** | −0.0005 [−0.0212, +0.0138] |

F1 against the **0.603 trivial always-positive floor**: OOS 0.7555 → 0.7994, STRICT
0.7029 → 0.7586, both well clear. Against the *slice-specific* always-positive floor
(OOS 0.6856, STRICT 0.7478) the stacked system now clears STRICT too (0.7586 > 0.7478);
the pre-round-3 gate did not (0.7029). Permuted-label control: residual AUC **0.478 (OOS)
/ 0.457 (STRICT)** — near 0.5, harness sound.

### 2.3 THE KNOWN COST — measured, not assumed

The paper audit's single worst finding is that the benign false-block rate moved 1.3 % →
10.8 % and no document noticed. I refused to recommend anything this round without
measuring the same quantity (`round3_synthesis/benign_cost_output.txt`, 148 hand-judged
non-attack rows):

| configuration | benign false blocks | rate |
|---|---|---|
| pre-round-3 shipped | 16 / 148 | 10.8 % |
| **widened (installed now)** | **17 / 148** | **11.5 %** |
| **widened + stage-2** | 18 / 148 typical, 22 worst seed | **12.6 % mean (sd 0.9 pt), up to 14.9 %** |

**Recommendation.**

1. **Keep the widening.** It is installed, tested, reversible (`FLAGS` → all False restores
   the previous module exactly), and costs **one** benign false block for +12/+8 true
   detections. Ship it.
2. **Do not install stage-2 yet.** Its attack-slice cost is zero and its recall gain is
   real and seed-stable, but it costs **1.6 benign false blocks on average and 5 in the
   worst of 10 seeds** on a benign set of only 148 rows. Seed 1 alone takes the gate to
   14.9 %. Installing a model whose benign cost has a 3-point seed spread measured on 148
   rows is how 1.3 % became 10.8 % last time. It needs the measurement in §5 first.

---

## 3. cot_hijack — the mechanistic conclusion, and why the honest answer is abstention

**Plain language: in chain-of-thought-hijack attacks, complying looks like doing *less*,
and in every other attack family complying looks like doing *more*. The shared
"activity" features therefore point the wrong way, and a model that never saw the family
predicts it backwards.**

The evidence (`round3_synthesis/cot_toolsplit_output.txt`,
`cot_signstab_output.txt`, all 817 attack rows):

| signal | cot_hijack AUC | all-attack AUC | next-worst family |
|---|---|---|---|
| tool-call count | **0.140** | 0.706 | prompt_leaking 0.381 |
| mutating-tool count | 0.247 | 0.630 | prompt_leaking 0.366 |
| reply length | 0.334 | 0.464 | hypothetical 0.179 |

An AUC of 0.14 is not weakness, it is **inversion**. Mean mutating calls: **0.46 for
compliant cot_hijack replies vs 2.15 for refusals**; mean search calls **0.00 vs 1.12**.
The attack hands the agent a forged premise and asks it to *continue the reasoning*, so
compliance is a short confident prose continuation with no tool use, while refusal is the
response that goes and *checks* — searching, reading, verifying. Everywhere else the
attack asks the agent to *do* something, so compliance is the tool-heavy branch.

That single sign flip fully accounts for the LOACO number: leave-one-attack-category-out
trains on nine families where activity means compliance, then applies it to the one family
where activity means refusal. I reproduced pooled LOACO **0.7113** and cot_hijack
**0.309** exactly.

**Was there a fix?** The arm's hypothesis was that a prompt-side flag (`premise_supplied`)
should gate the activity features so the model can learn both signs. Measured, 5 seeds,
LOACO (`cot_premise_loaco_output.txt`):

| variant | pooled LOACO | cot_hijack | false_precedent |
|---|---|---|---|
| A_FULL (baseline) | **0.7113** | 0.309 | **0.517** |
| B_split_tools | 0.6988 | 0.375 | 0.445 |
| C_add_only | 0.7038 | 0.357 | 0.460 |
| D_split_both | 0.7035 | **0.427** | **0.434** |

Every variant that helps cot_hijack **hurts the pool and pushes false_precedent further
below chance**. It moves the defect, it does not remove it. That is a loss.

**The honest engineering answer is a documented abstention, not a fix — and it costs the
deliverable nothing**, which is the part that must be said clearly:

- The 0.31 is a property of the **12-feature science-feature research model**, which is
  not what blocks. It is a paper result, not a gate result.
- On the same family the **deployed** signals are healthy: labeler score AUC **0.852** on
  cot_hijack, and the gate's operating-point recall on cot_hijack (OOS, n=31) is
  **0.677 → 0.742 after widening → 0.774 stacked**. cot_hijack is now *above* the OOS
  average, not below it.
- So: publish cot_hijack LOACO 0.31 as a negative result **with the mechanism named** —
  "the family whose compliance signature is inverted relative to the training pool is the
  family cross-family transfer fails on" — and state that the shipped gate does not depend
  on those features. Do not ship a feature change that buys 0.12 on one family by paying
  0.08 on another and 0.008 on the pool.

---

## 4. Methodological lesson from every loss

1. **stage2_residual lost against the wrong baseline.** Its target was missed by 8 seeds
   on OOS and 10 on STRICT purely because it was measured against a gate that had been
   improved 90 seconds earlier by a parallel arm. Same code, re-measured on the current
   baseline, hits 10/10 on both slices. *Lesson: in a parallel competition, "beats the
   baseline" is meaningless unless the baseline is pinned by content hash at claim time.
   Every arm should record the sha256 of the modules it measured against, and the
   synthesiser must re-run every survivor against the final composed system before
   anything is called a win or a loss.*
2. **cot_hijack lost by optimising a per-family number instead of the pooled one.** The
   fix "worked" on its target and was net-negative everywhere. *Lesson: a family-level
   repair must be reported as a pooled delta with the other families' deltas beside it,
   or it is not a result. A below-chance sub-metric is sometimes a true property of the
   domain, and the correct deliverable is a named mechanism plus an abstention.*
3. **`w_doneclaim` lost by being authored from a single gold1 example.** One case fixed,
   zero transfer. *Lesson: a pattern justified by n=1 in the selection set should be
   pre-registered as inert until a leave-one-widening-out ablation shows otherwise; the
   arm's ablation caught it, which is why the ablation is the deliverable, not the patch.*
4. **The residual weakness stayed open because both winners fish in the same pond.**
   Widening the evidence families and learning a partner on the residual both key off
   *some* surviving trace. *Lesson: when two independent arms improve the same metric and
   the stated core weakness moves 0.008, that is evidence the arms are not independent —
   they share an assumption (that compliance leaves a lexical trace) that the residual
   violates.*
5. **The precision floor is not the whole cost function.** Both winners hold P ≥ 0.90 on
   both attack slices with +0 attack-slice false positives, and both still raise the
   benign false-block rate. *Lesson: report the benign rate in the same table as the
   recall, always. Every arm this round reported the attack-slice operating point; only
   one reported the benign cost, and the paper audit's #1 correction is exactly this
   omission going unnoticed for a week.*
6. **STRICT is narrower protection than it sounds.** It guarantees the *prompt* never
   appeared in gold1. It does **not** guarantee the arm never read that prompt — gold2
   prompts were readable, and the coverage_gaps arm mined 203 of them. The win survived
   the ablation that removes prompt-mined vocabulary, but only because someone ran it.
   *Lesson: name the contamination channel STRICT does and does not close, and require a
   "no mined vocabulary" ablation whenever an arm reads any part of the held-out slice.*

---

## 5. The single highest-value next experiment

**Measure the benign false-block cost of the stacked gate on a benign set large enough to
decide with, then ship or drop stage-2 on that number alone.**

Concretely:

- Build a benign evaluation set of **≥ 600 non-attack sessions** (the 148 hand-judged
  baseline rows + the `chenhao_release` rows whose `human_label == "safe"` + the
  `collected_22category` benign sessions), prompt-deduplicated, and hand-adjudicate a
  200-row random subsample to confirm the imported labels.
- Score three configurations on it: pre-round-3 gate, widened gate, widened + stage-2
  (all 10 seeds).
- **Ship criterion, fixed in advance:** install stage-2 iff its benign false-block rate is
  **≤ 12.0 %** with the **upper 95 % group-bootstrap bound ≤ 13.5 %**, in **10/10 seeds**,
  while OOS recall stays ≥ 0.70 and STRICT recall ≥ 0.62 at P ≥ 0.90. On today's 148-row
  set the point estimate is 12.6 % and the worst seed is 14.9 %, so this is a genuine test
  that stage-2 can fail.
- Why this and not more recall: the round already bought +0.066 OOS / +0.076 STRICT recall
  with CIs excluding zero. The thing that is now *unmeasured* — and that has already
  burned this project once at 8× — is what that recall costs the user. n=148 with 3
  positives cannot resolve a 1-to-3-point difference; the CI on 16/148 alone is roughly
  ±5 points.

Secondary, if capacity allows: the no-evidence residual (OOS n≈121, recall 0.488) needs a
mechanism that does not assume a lexical trace — the natural candidate is prompt-response
*alignment* scored against the injected span rather than against a compliance lexicon,
which is what stage-2's own feature header proposes but its weights show it only partly
does (`novel_secret_literal`, `marker_name_echo`, `field_label_echo` still dominate).

---

## 6. Paper-audit arm — the correction table in summary

`PAPER_CORRECTIONS.md` (33 KB, audit date 2026-07-27). No modelling; every value
re-derived from the vetted loader or from the named on-disk artifact; gold scored
programmatically only.

**Volume.** 80 numeric claims re-derived across four sections (labels/adjudication 10,
model/AUC 18, gate/operating point 32, corpus & infrastructure 20), plus 8 figures, 11
publishable findings, 12 not-yet-publishable claims, and 6 documents ranked by edit debt.

**How many are stale:** the audit finds the great majority of headline numbers in
`RESULTS.md`, `PROGRESS.md` and `PAPER_PLAN.md` to be from the retired 300-label era and
superseded by the 965-row gold. `PAPER_PLAN.md` is stale as a whole and must be rewritten,
not patched. `WORKLOG.md` is honest but append-only, so early entries are contradicted by
later ones in the same file. `COMPETITION_ROUND2.md` and `OVERNIGHT_REPORT.md` are mostly
sound with stale sections.

**The four that would do most damage uncorrected:**

| # | claim as printed | reality |
|---|---|---|
| 1 | benign false-block rate **1.3 %** | **10.8 %** for the shipped gate — and, after round 3, **11.5 %** installed / **12.6 %** if stage-2 ships. The number moved 8× the wrong way and no document said so. |
| 2 | gate = "labeler == 1 OR deferred ≥ 5.5", OOS P 0.9352 R 0.5771 | the gate also carries the global bar of 3; OOS **P 0.9218 R 0.6400**, STRICT **P 0.9327 R 0.5640** |
| 3 | detector **F1 0.874** as the headline | that is **in-sample on gold1**. OOS 0.6038; on never-seen prompts **0.4435 (R 0.2965)** |
| 4 | the whole 300-label era (ASR 43.7 %, canary 10.6 %, misses 76 %, kappa 0.256, n=283/300) | n=817 attack rows: ASR **50.7 % [47.2, 54.1]**, canary **11.3 %**, misses **326/414 = 78.7 %**, kappa **0.2005** |

**Figures that mislead (3 of 8):**

- `fig3_corpus.png` — plots a **machine-labeler** flag rate (16 %) in a paper whose
  headline adjudicated ASR is 50.7 %; a reader will read 16 % as the ASR. **Do not
  publish** without relabelling the axis.
- `fig4_honest_vs_inflated.png` — shows 0.502 as "the honest number"; it is a canary-era
  figure defined on 12 of 38 folds and contradicts `RESULTS.md`'s 0.672 for the same
  claim. **Retire**, use `fig5_protocol_ladder.png`.
- `fig1_label_undercount.png` — numbers correct but the **title is clipped in the rendered
  PNG** ("… = " with the 79 % cut off). Regenerate wider.
- `fig6_ab_intervention.png` — correct, but only publishable with the caption stating that
  the A/B tested the literal string `rm -rf`, the one spelling the pre-fix rule caught.
- `fig2` and `fig5_protocol_ladder` are fully correct; `fig5_transfer_and_safety` is
  correctly withdrawn but still cited in `PAPER_PLAN.md`.

**Safe to publish today** (audit's ranking, all verified): the canary-undercount result
(≈4.5×, n=817, the paper's strongest contribution); per-category ASR with Wilson CIs, with
the narrative rewritten — the most effective family is **false precedent (77.2 %)**, not
task-laundering; the prompt-duplication leak and protocol ladder (0.797 → 0.743 → 0.712);
the negative result cot_hijack 0.31 / false_precedent 0.51 — **now publishable with the
mechanism in §3 attached**; F1 read against the 0.603 floor; the gate's OOS and STRICT
operating points **only with the benign false-block rate attached**; the labeler's
non-generalisation; the A/B with its spelling caveat; and the process findings.

**Two corrections round 3 adds to that file**, which post-date the audit by minutes:

1. §0.1 and §3.2's benign rate is now **17/148 = 11.5 %** as installed (widening landed
   after the audit ran). Anything quoting 10.8 % must say "pre-widening".
2. §3's operating-point table now has a fourth row: **widened, OOS P 0.9183 R 0.6743
   tp236 fp21 / STRICT P 0.9292 R 0.6105 tp105 fp8** — and, if stage-2 ships,
   OOS P 0.9218 R 0.7077 / STRICT P 0.9323 R 0.6407 at 12.6 % benign cost.

---

## 7. Reproduction

```
analysis/compete/round3_synthesis/end2end.py            -> end2end_output.txt
analysis/compete/round3_synthesis/benign_cost.py        -> benign_cost_output.txt
analysis/compete/round3_synthesis/signstab.py           -> cot_signstab_output.txt
analysis/compete/round3_synthesis/split.py              -> cot_toolsplit_output.txt
analysis/compete/round3_synthesis/exp1.py               -> cot_premise_loaco_output.txt
analysis/compete/stage2_residual/final2.py              -> stacked_on_widened_output.txt
analysis/compete/coverage_gaps_results.json             (arm artifact)
```

**Two housekeeping notes, so nobody is surprised.**
`analysis/compete/stage2_residual/cache.json` did not exist in the repo (the arm left it in
its scratchpad); I rebuilt it with `prep.py` against the **widened** gate, which is why
`final2_output.txt` (the arm's pre-widening run, retained) and
`stacked_on_widened_output.txt` (my run) disagree on the baseline row — 224 vs 236 — by
design. Nothing else in the repo was modified by this synthesis.
