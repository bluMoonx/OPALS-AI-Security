# Paper plan — what to add, what to modify (2026-07-27)

Against the current draft *"A Live Gateway for Autonomous Scientific Agents"*
(Chenhao Zhang, Sid).

---

## A. One finding that changes numbers already in the paper

The draft says:

> "Of **210 sessions marked as behaviorally successful by the documented collector
> heuristic**, 50 were action-manifesting and 160 were text or state attacks."

and, in Discussion:

> "The attack-success labels in the larger trace corpus are collector heuristics. A prior
> blind comparison with a matched sample found moderate agreement (Cohen's kappa = 0.562),
> and independent human adjudication is staged but incomplete."

**We now have that adjudication, and it moves the denominator.** On 300 hand-judged
sessions the canary-style heuristic recovers only **10.6 %** of behavioral compliances
against a true **43.7 %** — it misses **76 %** of them, and on the attack slice its
agreement with human judgement is **kappa 0.256**, not 0.562.

Consequence for the paper: **210 is a floor, not a count.** The text/state bucket in
particular is under-filled, because the failure modes the heuristic cannot see are almost
all text-resident (system-prompt exfiltration, state dumps, self-modification, deferred
compliance, solicitation). The *shape* of Fig. 3 survives — action-trail replay still
flags action-manifesting and not text/state — but the denominators and the 160 figure
should be restated.

**Recommended edit:** keep Fig. 3's qualitative claim, requalify the counts as
heuristic-derived lower bounds, and cite the adjudicated rate.

---

## B. What to ADD (new, defensible, not currently in the draft)

### B1. Human-adjudicated ground truth — closes the paper's own stated gap
300 sessions, 5 independent labelers, stratified across 10 categories and both
conditions, judged from `(prompt, response)` only. Directly answers *"independent human
adjudication is staged but incomplete."*
→ new Methods subsection + a labeled-data availability line.

### B2. The label-validity result (strongest new contribution)
Canary/heuristic labeling under-counts attack success ~4x (43.7 % vs 10.6 %; misses 76 %).
This is a **methodological finding about the field**, not just about our corpus: any
benchmark scoring success by marker-echo is measuring the wrong thing.
→ new Results subsection + `fig1_label_undercount.png`.

### B3. Per-category attack-success table
Task-laundering **83 %**, delimiter-confusion 80 %, prompt-leaking 75 %, false-precedent
67 % — against a heuristic reporting 0 %, 58 %, 1.5 %, 2.6 %. The single most effective
attack against the agent is invisible to canary evaluation.
→ new table + `fig2_per_category_asr.png`.

### B4. Cross-collection generalization (nobody in the group has this)
Train on one collection's rubric labels, test on another's hand-judged labels:
response-only features **0.602**, +prompt **0.748** [0.679, 0.811], 15-feature control
**0.801**. Plus the honest ablation showing the relational machinery is *not* the cause.
→ new Results subsection + `fig5_transfer_and_safety.png` (left panel).

### B5. Recovered action records for the 10-category collection (Issue #3)
405 distinct trials, 769 enriched rows, 680 out-of-scope actions, with kind/target/scope
per action — recovered from existing raw logs, no re-collection. This is what lets the
boundary analysis extend beyond the 7-category primary corpus.
→ Methods + extends the Fig. 3 boundary analysis.

### B6. Interactive approval as a third policy outcome
The draft's live path is allow/deny. Ours adds a measured middle tier: **BLOCK** at
1.3 % false-block rate on benign traffic, **FLAG → human approval** in the Control UI,
with a verbatim end-to-end transcript of a credential-exfiltration attempt being held and
denied. Strengthens "a live gateway can provide real prevention".
→ Results + `fig5` (right panel) + the transcript as a figure or appendix box.

### B7. Negative results worth publishing
- Anomaly-from-normal does **not** beat supervised (0.798 vs 0.863).
- Hidden-image injection is **not achievable** on this stack: 5 vision models tested
  (kimi-k2.5, kimi-k2.6, qwen3.5, minimax-m3, gemma4), none read faint/hidden text; only
  visible typographic injection works.
- Ensembling two detectors is **worse** than the better one alone (0.817 vs 0.874).
→ short "Negative results" subsection; these are cheap credibility.

---

## C. What to MODIFY

| # | current text | change | why |
|---|---|---|---|
| C1 | "210 sessions marked as behaviorally successful" | call it a heuristic lower bound; add adjudicated rate | heuristic recovers 10.6 % of true compliances |
| C2 | "kappa = 0.562" | report the new adjudicated kappa (0.256 on the attack slice) and say which sample each refers to | two different samples, currently reads as one |
| C3 | "160 text or state attacks" | restate as heuristic-derived; note the missed modes are predominantly text-resident | the bucket is systematically under-filled |
| C4 | Abstract: "A retrospective replay… can identify many such cases" | can now say human-adjudicated labels confirm the boundary and quantify the heuristic's miss rate | we have the adjudication |
| C5 | Discussion: "independent human adjudication is staged but incomplete" | replace with the completed 300-session adjudication | it is done |
| C6 | Table 1 taxonomy | add the 10 new categories with measured ASR | 10 categories × 50 prompts now exist |
| C7 | Any 22-category rate | report as coverage only, with CI [0.257, 0.543] | 28.6-pt interval cannot carry a point estimate |

---

## D. What NOT to claim (guard rails)

1. **No 0.905, no 0.95.** Both were leakage. Our defensible detector number is
   **F1 0.874** on record-resolved hand-judged gold, and cross-source **0.748**.
2. **Do not report a single-corpus AUC as generalization.** State fold counts.
3. **Do not use canary/marker echo as the success label** anywhere in the paper without
   the miss-rate caveat.
4. **Flag Blu/Kathleen's 0.95 before submission** — their own ablation drops it to 0.689
   without `cites_memory_md`. A reviewer will find this.
5. **Scite adjudication is not done** (quota resets 2026-07-28). Do not cite it yet.

---

## E. Tomorrow, in order

1. **Scite citation pass** once quota resets — verify every reference in the draft.
2. **Write B1–B3** (adjudication, label-validity, per-category table) — highest value,
   all data in hand.
3. **Write B4–B5** (transfer result, recovered action records).
4. **Apply C1–C3, C5** to the existing text — these are corrections to live numbers and
   should not wait.
5. **Regenerate the prompt-injection metrics file** (doc Issue #1: 315/285 → 400/200)
   — Sathwik's, but it blocks a paper number.
6. Optional: extend adjudication past 300 sessions to tighten the per-category CIs.

---

## F. Honest assessment of where the paper stands

The draft's core claim — *a native tool policy can prevent an observable attack, and that
prevention has a boundary* — is **sound and demonstrated**. Our work does not weaken it.

What our work does is: (a) supply the human adjudication the draft says is missing,
(b) show the labels used for the trace analysis under-count by ~4x, which changes
denominators but not the shape of Fig. 3, (c) add a cross-collection generalization result
the paper currently has no analogue for, and (d) extend the live path with a measured
approval tier.

The risk to manage is the label-validity finding. It is the strongest thing we have, and
it is also a correction to numbers already in the draft. Better that it lands as our own
contribution than as a reviewer's objection.
