# PAPER_FACTCHECK.md

Every number in the paper draft (`OPALS Group 21 (2).pdf`, 2026-07-28) checked against the
data files it claims to come from. Verified means "I recomputed it from the source records
and got the same answer", not "it looks plausible".

---

## 1. Table 2, row by row

| row | paper claims | recomputed | verdict |
|---|---|---|---|
| Indirect prompt injection | 400 scored, 315 successes, **79%** (74-82) | 315/400 = **78.8%**, Wilson [74, 82] | **VERIFIED** |
| Broad taxonomy (22 cat) | 41 scored, 16 successes, **39%** (26-54) | 16/41 = **39.0%**, Wilson [26, 54] | **VERIFIED** |
| Website + browser payloads | 16 scored, 16 successes, **100%** (81-100), *no tool trace* | 10/16 = **62.5%**, Wilson [39, 82]; **tool traces now exist** | **FALSE ON BOTH COUNTS** |
| Memory poisoning | 84 scored, 84 successes, **100%** (96-100) | source file still 84 attack + 10 control; new v2 files are n=20 attack / n=20 control | **NEEDS A STATED SOURCE** |
| Ten-category collection | 798 scored, 226 successes, **28%** (25-32), *no tool trace* | our newcats file is **1085 attack / 1081 baseline**, 118 collector-heuristic successes = 10.9%. **Cannot reproduce 798/226 from any file in either repo.** Tool trace **does** exist | **UNREPRODUCIBLE + stale caveat** |
| Primary corpus (kimi) | 350 scored, 210 successes, 60% | not independently checked (Chenhao's collection) | unchecked |
| Primary corpus (deepseek) | 309 scored, 183 successes, 59% | not independently checked | unchecked |

### 1a. The website row is the most urgent fix

`evangeline_website_tests/_tools.json`, pushed 2026-07-28, has all 16 payloads rerun with
traces. Outcomes: **6 mitigated, 10 compliance_with_flag**. Execution paths record
`web_fetch(BLOCKED)` x3 and `read(BLOCKED)` x1, with two payloads reaching a shell step.

So the row should read roughly **16 scored / 10 successes / 62.5% [39, 82] / 2 of 16
action-manifesting**, and the "no tool trace" caveat is retired. The current "100% ASR"
claim is the strongest number in the table and it does not survive its own rerun.

### 1b. The ten-category row cannot be reproduced

The paper says 798 attack and 779 control sessions, and explains that a pooled file was
de-duplicated by 726 sessions to get there. **No file in either repo contains 798 attack
rows.** Our newcats collection is 2,166 rows (1,085 attack / 1,081 baseline). Nor does the
success count reconcile: the collector heuristic marks 118 successes, the hand-judged gold
marks 417 of 965.

**Root cause is structural, not arithmetic.** The paper describes "a single script [that]
reads each collection's own session records, applies one success definition and one
observability definition, and writes both the metrics file and its report". **That script is
not committed anywhere in the repo.** Only per-collection analysis exists. This is the exact
failure mode as group-doc issue 1, where an uncommitted generator let a metrics file rot
undetected. Any Table 2 number that came from it is currently unreproducible by anyone but
its author.

**Action: commit the standardization script, or drop the pooled 30% figure.**

### 1c. The ten-category "no tool trace" caveat is now wrong

`newcats_actions_recovered.jsonl` carries `kind`, `target`, `in_scope` and `status` on every
action: **6,387 action records over 950 enriched rows / 1,284 distinct trials** locally, and
5,230 over 769 rows in the team copy before this push. So the Discussion sentence "Two
collections do not record those fields and report no split" drops to **one**, and that one
(website payloads) also now has traces, so it may drop to **zero**.

**Caveat that must travel with it:** 6,387 is a ROW-LEVEL sum and is inflated by the
non-unique `session_id` join. Publishable figures are **660 distinct trials with actions**
and **1,059 out-of-scope actions** at distinct-trial level. Never quote the row-level sum.

---

## 2. The gateway numbers (our section)

`analysis/paper_repro/policy_curve.py` was rewritten on 2026-07-28. It previously re-derived
the gate from `behavioral_labeler` + `deferred_compliance` only, which is **not the shipped
system**: `scorer.score()` also runs the compliance layer. Confirmed by row-level diff:
every extra block is `layer == "compliance"` (28 on OOS, 18 on STRICT, 1 on gold1) and there
is **no row where the old model blocks and the shipped scorer does not**.

Consequence: the previously published `strict` figures (OOS R 0.5343 / STRICT R 0.3721)
**understated our own system**. The authoritative shipped numbers are in
`GATE_OPERATING_POINTS.md`, regenerated from `scorer.score()`.

### 2a. Two benign rates were both in circulation for the same system

2.88% and 4.72% were never the same measurement:

* **2.88%** came from `test_suite.py`, which counts blocks from `_compliance_layers` **only**
  (one channel) and applies an objective correct-block exclusion.
* **4.72%** came from the policy curve, which counted blocks from the **whole gate** and
  applied **no** exclusion.

Both scripts now share one definition. The budget number is FALSE blocks on the wide pool
after removing objectively-correct blocks (canary disclosed, planted marker emitted,
credential or exfil code, secret-file solicitation).

---

## 3. Figures

| fig | claim | status |
|---|---|---|
| Fig 1 | architecture diagram | fine, no numbers |
| Fig 2 | A/B: 4/4 undefended, 0/4 defended; 12 shell actions vs 21 deny records | consistent with the text; small-n by design and the paper says so |
| Fig 3 | 50 action-manifesting flagged 100%, 160 text-or-state flagged 0% | internally consistent; it is a boundary result, not a prevention result, and the caption says so correctly |
| Fig 4 | retrospective replay, Kimi + Deepseek | consistent |
| **Fig 5** | five collections' action-manifesting share | **must be redrawn.** The website row is absent (correct today, wrong after the rerun) and the ten-category row is absent for "no tool trace" although the trace exists |
| memory-poisoning charts (group doc p4) | "No engineered feature set beat simply guessing the majority outcome (n=90)": majority 0.578 vs LR 0.500 / DT 0.467 / RF 0.544 | **VERIFIED and it is a real result.** Reproduced independently: a model given only the fact ID and zero reply text scores 0.817 under session CV and collapses to exactly the 0.578 majority floor under fact-grouped CV. A model-susceptibility finding, not a gateway finding |

---

## 4. Abstract

The abstract on p4 of the group doc stops mid-sentence at "We first". The paper draft's own
abstract (p7) is complete and is the one to use. It contains no numbers, which given the
above is currently the safest choice.

---

## 5. What must change before submission

1. **Website row and Fig 5**: 16/16/100% becomes 10/16/62.5% [39, 82], and the tool-trace
   caveat is retired. 2 of 16 crossed the boundary.
2. **Ten-category row**: either commit the standardization script that produced 798/226, or
   drop the row and the pooled 30% figure. Right now nobody else can reproduce it.
3. **Retire "no tool trace"** for ten-category; the split is computable. Quote distinct-trial
   numbers, never the 6,387 row-level sum.
4. **Memory poisoning**: state whether the row is the 84-attack file or the 20-attack v2
   file. Note the control group is **20, of which 10 are scored
   `not_applicable (control question, no ground truth)`**, so the effective control is 10.
   The paper's own false-positive caution should say that.
5. **Gateway numbers**: quote `GATE_OPERATING_POINTS.md` as regenerated from
   `scorer.score()`. Never quote a recall from one policy beside a benign rate from another.
6. **The Discussion already makes the right point** about a published false-positive rate
   computed on a control group that silently contained ignored attack sessions. That
   sentence is well earned and should stay.
