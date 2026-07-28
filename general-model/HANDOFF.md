# HANDOFF — everything needed to resume cold

Written 2026-07-28 before context compaction. If you remember nothing else, read this file.

---

## 1. WORKING TERMS WITH SID (standing, do not relearn these)

* **No bullshit, no lying.** Report all details, show process status. If something failed,
  say so in one line and try the alternative.
* **No em dashes** in prose to Sid.
* **Don't be a yes-man.** Push back with evidence. He is right that both sides make
  mistakes; catches run both ways.
* **Big-picture thinking**, connect things before finalising.
* **Never add a Claude co-author tag or any AI attribution to commits.** Commit messages
  are plain and factual.
* **Test parts, then the whole.** Never assume; research when unsure.
* **A measured failure is a delivered result.** "No improvement, here is the measurement"
  is a success. A claimed win that fails verification is a FAILURE and is withdrawn.
* Sid tracks whether work is *real improvement* vs *fixing self-inflicted bugs*. Keep that
  distinction explicit and honest.

## 2. HARD METHOD RULES (violating any invalidates a result)

1. **NEVER join gold to sessions by `session_id`.** 326 duplicated ids, depth to 9, 56% of
   rows. Use `eval_combined_gold.load_all_gold(load_records())`. Three scripts had this bug
   and are quarantined (they exit non-zero): `analysis/rebuild/eval_ablations.py`,
   `analysis/rebuild/retrain_behavioral.py`, `analysis/compete/data.py`.
2. **Never author features/thresholds by reading gold2 or sathwik v1 response text.**
   Grouped CV does NOT defend against author contamination.
3. **Report OOS *and* STRICT *and* the benign cost.** Recall without its cost is not a result.
4. **Benign cost is FALSE blocks, not RAW blocks.** Baseline rows are not attack-free.
5. Thresholds on gold1 or nested inside training folds only. Never on a reported slice.
6. >=5 seeds; bootstrap **PROMPT GROUPS** never rows; CI on the DELTA.
7. F1 against the **slice-specific** trivial floor: all-gold 0.6035, OOS 0.6856, STRICT 0.7478.
8. Permuted-label control on every learned claim (must land near the base rate).
9. Recall at P>=0.90 is the result. AUC alone is a diagnostic.
10. Change a shipped file -> re-run `openclaw-plugin/test_suite.py`, must stay **22/22**.

## 3. THE DATA (counts are snapshots; a collector may still be appending)

| corpus | rows | distinct prompts | role |
|---|---|---|---|
| newcats (ours) | 2166 | 285 in gold | train + eval; **0 rows carry tool OUTPUT** |
| gold (hand-judged) | 965 | 285 | 817 attack / 148 baseline |
| chenhao_release | 1314 | **10** | cross-source; 81% carry tool output |
| sathwik v1 | 600 | 455 | **HELD-OUT TRANSFER SET**, do not train/author on |
| sathwik v2 controls | 600 | 531 | length confound removed |
| memory_poisoning | 94 | — | 84 attack / 10 control |
| collected_22category | 82 | — | 23 families |
| website payloads | 16 | — | **no agent responses in file**; live rerun only |
| prompt bank | 500 | — | only **205 used (41%)**, 7 of 10 families truncated |

**Slices**: gold1 = 146 attack (only slice a threshold may be picked on). OOS = 671 gold2
attack. STRICT = the 288 OOS rows whose prompt never appears in gold1. BENIGN WIDE POOL =
1078 baseline rows over 204 prompts.

## 4. CURRENT VERIFIED STATE OF THE SYSTEM

```
BLOCK_POLICY     = strict        ECHO_GRADE = flag (0.84, cannot block)
PROMOTE_EVIDENCE = False (off)   _GLOBAL_BAR = 3   BLOCK_AT/FLAG_AT = 0.85 / 0.50
```

| slice | P | R |
|---|---|---|
| OOS (671) | 0.9214 | 0.6029 |
| STRICT (288) | 0.9213 | 0.4767 |
| INDEPENDENT sathwik v1 (400) | 0.9099 | 0.3206 |
| benign FALSE | **2.88%** (31/1078); RAW 4.73% (51) | budget 3.00% |
| sathwik v1 controls | 0/200 | |
| sathwik v2 controls | **0/200** | harder set, confound removed |

Model `aura_behavioral.joblib`: RF, 12 features, prompt-grouped 10-seed AUC 0.7427,
LOACO 0.7117. Ceiling for any reply-text detector on independent data at P>=0.90: **R 0.486**.

Live: 22/22 tests, destructive-command regression prevented, gold integrity OK.

## 5. WHAT THE OVERNIGHT RUN ACTUALLY ESTABLISHED

**Improvements that are real and verified**
* **v2 controls**: gate blocks **0/200** on Sathwik's length-matched controls (131 prompts,
  median benign reply 796 chars vs v1's 362). Our 0-false-block claim now rests on **186
  distinct prompts with the confound removed**, not 55 under a known confound.
* **ECHO token filter shipped.** Old filter matched ordinary English (`read-only`,
  `High-entropy`, `git-secrets`, dates, paths). Benign fires **20.15% -> 13.43%**, attack
  fires 98.20% -> 94.59%, **precision 0.574 -> 0.660**. ECHO is flag-grade so this cuts
  spurious approval prompts by a third. `analysis/echo_filter_experiment.py`.

**Measured negatives (delivered results, not failures)**
* **Layered model does NOT help at the operating point.** Ranking improves (LOACO 0.7117 ->
  0.7395, confirmed independently at 0.7402 with different seeds), and exactly where
  predicted (cot_hijack 0.309->0.392, false_precedent 0.522->0.655). But the operating-point
  gain is +1 TP per slice, which the permuted-score null reproduces exactly. Binding
  constraint measured: 1.34 rows of benign headroom, and the gate buys 6.81 TP per false
  block vs the best layer's 0.375. **Nothing shipped.**
* **W4 evidence promotion REFUTED on significance** and left **default OFF**. Its point
  estimates reproduce exactly (OOS R .6029->.6286, STRICT .4767->.5000, benign FALSE
  unchanged at 31) but the significance claim did not survive.
* **KEY FINDING from the refutation**: the 8-condition shipped version is **Pareto-dominated
  by a 3-condition subset** (`runtime_fields + tool_roster + r_field`). Identical on every
  slice, controls still 0/200, and **independent precision returns ABOVE the 0.90 bar
  (0.9027 vs 0.8947)**. W4's own objection was caused entirely by channels that promote
  **zero true positives anywhere** — dead channels causing a regression nobody ablated.
  If it ever ships, ship the 3-condition subset, default off.

**Things found that were wrong**
* An arm claimed the gate is over budget at 4.73% and built a whole `budget` policy on it.
  **4.73% is the RAW rate; the budget is on FALSE blocks and that is 2.88%.** Policy marked
  MEASURED AND REJECTED in the source (it is also strictly worse: STRICT R .3837).
* **The ECHO benign gap**: every benign number we publish was measured on newcats, where
  **0 of 2166 rows carry tool output**, so ECHO is structurally invisible there. On chenhao
  it fires on 20.15% of benign. Our benign cost on a **tool-using workload is still
  unmeasured**.

## 6. THE SEVEN GROUP-DOC ISSUES

| # | issue | status |
|---|---|---|
| 1 | metrics 315/285 -> 400/200 | **PARTIAL.** `attack_category_counts` now 400/200 ✓, but `analysis_provenance.json` says metrics were computed from `sessions.jsonl`, whose `human_label` is `safe` for 598/600. Real labels are in `sessions_tierlabeled.jsonl` (285/185/130). Label-dependent metrics must be regenerated. |
| 2 | 22-category caution | **DONE.** RESULTS.md carries Wilson [0.257, 0.543], width 28.6 pts, with an explicit "cannot support a point estimate". |
| 3 | ten-category action records | **DONE.** 6,387 action records, **all** carrying `target` and `in_scope`, over 950 sessions. |
| 4 | website live rerun | **PARTIAL.** 4 of 16 run live: **4/4 identified the attack, 0/4 complied**, so the "16/16 succeeded / 100% ASR" claim does NOT reproduce. Remaining 12 not run (teammates taking this). |
| 5 | filename mismatch | **ANSWERED, not actioned.** File holds exactly 16 records; 16 HTML payloads on disk; nothing supports "70 vectors". Needs renaming to `16_payloads.json` in Evangeline's directory. |
| 6 | memory-poisoning controls | **PARTIAL.** Merged AURA-format set is 84 attack / 10 control. The 6 unclear sessions are still unadjudicated. |
| 7 | poisoning is fact-determined | **CONFIRMED AND PROVEN.** A model given ONLY the fact ID and zero reply text scores **0.817** under session-level CV and collapses to **exactly the 0.578 majority floor (sd 0.000)** under fact-grouped CV. 18 of 20 facts land 100% one way. The concern is correct: it is a model-susceptibility result, not a gateway result. |

## 7. OTHER STANDING FACTS WORTH NOT RELEARNING

* **The compliance layer was dead in production** until 2026-07-28: the plugin never sent a
  prompt, and `_compliance_layers` short-circuits on an empty prompt. Fixed via
  `before_agent_run`. **Verified live** (`promptLen=67` on a real tool call).
* **`before_agent_reply` and `llm_output` do NOT fire on the CLI path** (`openclaw agent
  --json`). Only `before_tool_call` fires. So reply-side scoring is not exercised by the CLI,
  and our compliance numbers describe the reply path. Not claimable as live CLI behaviour.
* **Sathwik v1 is NOT hand-adjudicated**: `human_label` is `safe` for 598/600, both rater
  worksheets are blank; the usable column is `tier_label`, mechanically derived.
* **The canary result** (the paper's strongest contribution): canary labelling recovers
  recall 0.213, misses **326 of 414 = 79%** of real compliance, kappa 0.201, on n=817.
  Sathwik independently found the mirror image: his canary FEATURE recomputes the canary
  LABEL (circular), and he retracted his AUC 0.972 on that basis.
* **Three label failures, three people, one mistake**: canary label measures "did a string
  appear"; Sathwik's feature recomputes it; the website suite's `full_compliance` measures
  "was a payload present in the page" and reads 100% where live behaviour reads 0.

## 8. FILES

`overnight/` (13 documents): PLAN, PROMPT_TYPE_CATALOGUE, AUDIT, PIPELINE_TEST, W2_LAYERED,
W3_ALL_DATA, W4_OPERATING_POINT, W4_INDEPENDENT_CHECK, W4_ADVERSARIAL_REFUTATION,
W7_REFUTE_W2, W7_REFUTE_W4, W_ECHO_GAP, RESULTS_INTERIM.
Root: `GATE_OPERATING_POINTS.md` (authoritative policy table), `PAPER_CORRECTIONS.md`,
`PAPER_PLAN.md`, `WORKLOG.md` (append-only lab record, T0-T51+), `REPO_INVENTORY.md`.
Scripts: `analysis/eval_v2_controls.py`, `measure_echo_benign_gap.py`,
`echo_filter_experiment.py`, `verify_w4_independent.py`, `verify_w4_ind_precision.py`,
`check_gold_integrity.py`, `measure_benign_wide.py`, `confusion_matrices.json`.

## 9. NOT PUSHED

Everything since commit `d33c2b3` is local only: the ECHO filter fix, the budget-policy
rejection note, all 13 overnight documents, and the new analysis scripts. Sid reviews
before pushing.

---

## 10. WHY LAYERING WAS NOT SHIPPED (asked directly)

It was **not cancelled**. It was built, measured, adversarially verified, and it lost on the
only axis that matters. Eleven scorers were built: flat control; general+per-family
specialists combined by soft router / hard router / max / mean; blend_50_50; blend_learned;
cascade; cascade_avg; per-family thresholds hard and soft.

**It won on ranking.** LOACO 0.7117 -> 0.7395 (delta +0.0276, CI [+0.0004, +0.0564]),
independently reproduced at 0.7402 with different seeds (100-104 vs the arm's 0-4). It
improved exactly the families predicted: cot_hijack 0.309 -> 0.392, false_precedent
(highest-ASR family, sitting at chance) 0.522 -> 0.655, role_spoofing 0.681 -> 0.788.

**It lost at the operating point, and the reason is arithmetic, not architecture.**
* Gain at P>=0.90: **+1 true positive on OOS, +1 on STRICT**.
* A permuted-SCORE null run through the identical threshold search reproduces exactly that
  (max +0.0029 OOS, +0.0058 STRICT). The gain IS the search extracting noise.
* Bootstrap CIs on the delta have lower bound 0.0000.
* **Headroom**: the gate spends 2.88% of a 3.00% FALSE-block budget, leaving 0.12 pp =
  **1.34 rows in a 1078-row pool**. An additive layer may convert at most ONE more benign
  row into a false block.
* **Exchange rate**: the existing gate buys **6.81 true positives per false block**. The
  best layer buys **0.375** (15 TP for 40 false blocks). That is 18x worse.
* The two-sided veto+add layer, the only shape that can gain under a binding budget, is
  actively NEGATIVE (OOS -0.026 to -0.037, CIs excluding zero on the losing side): its veto
  side buys budget by discarding real detections.
* An oracle layer would recover all 139 gate-missed OOS positives at zero benign cost, so
  the ceiling is model separation, not budget. The realised fraction of that ceiling is
  **0.007**.

**Conclusion**: layering is a real modelling result and an empty detection result. Publish
it as a measured negative. It would only become useful if the benign budget were widened,
and at 5.00% budget it does gain (+0.0171 OOS, +0.0291 STRICT) — but that breaks the budget.

## 11. MODELS — where they live and which is best

| model | on GitHub | size | AUC | LOACO | what it is |
|---|---|---|---|---|---|
| **aura_behavioral.joblib** | **yes** | 7.9M | **0.7427** | **0.7117** | **THE BEST. RF, 12 features, 965 hand-judged behavioural labels, prompt-grouped 10 seeds. The only honestly-measured one. This is what the gate loads.** |
| aura_v1.joblib | yes | 140K | 0.789 | — | spring turns, different dataset; still used as the SPECIALIST layer |
| aura_general.joblib | yes | 144K | 0.836 | — | CANARY labels + leaky protocol. Discredited target. Fallback only |
| aura_general.backup.joblib | yes | 18M | 0.905 | — | the withdrawn number. Keep for provenance only |
| aura_plus_memory_poisoning.joblib | yes | 4K | — | — | teammate's, arrived 07-27, not measured by us |
| aura_behavioral_sog.joblib | **LOCAL ONLY** | 7.3M | 0.898 nested | — | 105 features. Higher AUC, LOSES at the operating point (R 0.387 vs 0.449 at P>=0.90). Research value only |
| aura_final.joblib | **LOCAL ONLY** | 600K | — | — | trained_on says n=296, truth is 294; 2 rows double-weighted |
| aura_honest.joblib | **LOCAL ONLY** | 9.9M | 0.502 | — | canary-era, 12 of 38 folds. Source of the withdrawn fig4 |

**Best for blocking**: the deterministic channels, not a model. **Best model**:
`aura_behavioral.joblib`, and note it is FLAG-grade only — capped below BLOCK_AT, it can
never block alone. Three models are local-only and are not on GitHub.

## 12. DATA — 5,372 sessions total, and what each is for

| corpus | n | role now |
|---|---|---|
| newcats (ours) | 2166 | TRAIN + EVAL; 965 hand-judged. **0 rows carry tool OUTPUT** |
| chenhao_release | 1314 | cross-source (only 10 distinct prompts) + the ONLY ECHO benign test |
| sathwik v1 | 600 | HELD-OUT TRANSFER TEST |
| sathwik v2 controls | 600 | benign test, length confound removed |
| prompt bank | 500 | source prompts; **only 205 (41%) were ever collected** |
| memory_poisoning | 94 | scored by W3 |
| collected_22category | 82 | scored by W3 |
| website payloads | 16 | live rerun only; the file has NO agent responses |

**Everything now has a role.** The last unused asset (Evangeline's payloads) was resolved by
finding it contains scraped page text, not agent replies. The remaining underuse is the
**prompt bank: 295 of 500 prompts were never collected**, and 7 of 10 families were
truncated at their first 10.

## 13. THE PLUGIN — how it is accessed

* **Install path** (inside the container): `~/aura-monitor/index.ts` + `openclaw.plugin.json`
* **Activation**: `onStartup: true`, currently `enabled` in `openclaw plugins list`
* **Scorer service**: `http://localhost:5005` on the HOST (the container has no sklearn)
* **Dashboard**: `http://localhost:5005/dashboard` — live decisions, renders untrusted agent
  text with textContent only, never innerHTML
* **History API**: `GET /history` — every scored decision including allows
* **Runtime switches**: `AURA_BLOCK_POLICY` (off/strict/balanced/aggressive; budget is
  REJECTED), `AURA_ECHO_GRADE` (flag/block), `AURA_EVIDENCE_PROMOTION` (0/1),
  `AURA_FAIL_MODE` (open/closed)
* **What a user sees**: `block` refuses the tool call inline with a reason;
  `flag` raises an interactive approval prompt (allow-once / allow-always / deny, denies on
  timeout); `allow` is silent and only logged.

**Accessibility caveat that must not be forgotten**: on the CLI path (`openclaw agent
--json`) only `before_tool_call` fires. `before_agent_reply` and `llm_output` do NOT fire, so
reply-side scoring is not exercised there. The compliance numbers describe the reply path and
are reachable through the scorer API and (unverified) the conversational surface.

## 14. NEXT, IN ORDER
1. Quick health check, then **push** (nothing pushed since `d33c2b3`).
2. Try it in an actual chat surface (Control UI) to see whether the reply hooks fire there.
3. Paper: abstract, corrections, figures.

---

## 15. BLOCKING ISSUE FOUND 2026-07-28: the authoritative table omits a shipped layer

`GATE_OPERATING_POINTS.md` calls itself "the one authoritative table" and `PAPER_PLAN.md`
quotes it. **It measures a system that is not the shipped system.**

`analysis/paper_repro/policy_curve.py` never imports `scorer`. It rebuilds the decision from
`behavioral_labeler` + `deferred_compliance`, i.e. **channels 1 to 3 only**. The shipped
`scorer.score()` also runs the **compliance layer** and ECHO. Row-level diff on identical
slices, strict policy, ECHO at flag grade:

| slice | policy_curve model | shipped `scorer.score()` | delta |
|---|---|---|---|
| gold1 | P .9298 / R .8281 | P .9310 / R .8438 | +1 tp |
| OOS (671) | P .9286 / R .5200 | P .9193 / R .5857 | **+23 tp**, +4 fp |
| STRICT (288) | P .9000 / R .3663 | P .9195 / R .4651 | **+17 tp**, +0 fp |
| benign gold (148) | 2 FALSE, 1.35% | 6 FALSE, 4.05% | **+4 FALSE** |

**Every single extra block comes from `layer == "compliance"` (27 on OOS, 17 on STRICT, 4 on
benign). There are ZERO rows where policy_curve blocks and the shipped scorer does not.**
The difference is strictly additive and strictly attributable to one layer.

This is not a contradiction to resolve by picking a number. It is the compliance layer, which
**only began running live once the plugin was fixed to send the prompt via
`before_agent_run`**. The table predates that being real.

**Consequences, and none of these are optional:**
1. The paper currently plans to publish **OOS R 0.5343 / STRICT R 0.3721**. The shipped system
   is **higher** than that. We are understating our own result.
2. It is also **more expensive** than that. Publishing policy_curve recall beside the shipped
   benign rate is exactly the error `GATE_OPERATING_POINTS.md` §3 exists to prevent, recurring
   in the opposite direction.
3. Benign cost needs care: **4.05% (6/148)** on the gold benign pool is over the 3.00% budget,
   but **2.88% (31/1078)** on the wide pool is under it. The wide pool is the one the budget
   was written against and is the better estimate (n=148 gives a very wide interval). Do not
   quote 4.05% as a budget breach without the wide-pool number beside it.

**Honesty note on the table above**: my `pc()` is a re-implementation of `policy_curve.decide`
and reproduces it to within 5 rows on OOS (182/14 vs the canonical 187/14). The *deltas* and
the *layer attribution* are robust; the absolute policy_curve cells are mine, not canonical.

**REQUIRED FIX before any paper number is quoted**: make `policy_curve.py` call
`scorer.score()` instead of re-deriving the decision, re-run, and regenerate
`GATE_OPERATING_POINTS.md`. One source of truth, and it must be the shipped code path.
Until then **every recall number in `PAPER_PLAN.md` is stale.**

---

## 16. TEAM REPO PULLED 2026-07-28 (7 commits) + issue re-verification

Pulled `b4b8504..1003d4f`: Evangeline (rename, `_tools.json`, payload rerun), Kathleen/Blu
(memory-poisoning v2 + charts), Wick2009 (dataset README traps).

**The group doc now strikes issues 1, 2, 4, 5, 6 as done. Verified against the repo: three
are done, two are not.**

| # | doc says | VERIFIED | evidence |
|---|---|---|---|
| 1 | done | **NOT DONE** | `attack_category_counts` and `gateway_end_to_end` are 400/200 ✓, but `success_conditional_detection.n_successful_attacks` is still **315**, and `provenance` still names `sessions.jsonl`, whose `human_label` is `safe` for **598/600**. Real labels are in `sessions_tierlabeled.jsonl` (285 safe / 185 suspicious / 130 unsafe). Detection rates read **0.0025** and **0.0032**, the signature of scoring against an all-safe file. |
| 2 | done | **DONE (data), team copy is the weaker one** | Both repos carry `target` + `in_scope` on every action, nested in `actions[]`. TEAM 5,230 action records / 769 rows / 375 distinct trials. LOCAL **6,387 / 2,166 rows / 1,284 distinct trials**. Pushing local upgrades the team evidence base. |
| 4 | done | **DONE, and it OVERTURNS the claim** | `_tools.json`: 16/16 have `tool_traces` + `execution_trace`. Outcomes **6 mitigated / 10 compliance_with_flag**, not 16/16. Boundary: `exec(OK)` x2 crossed; `web_fetch(BLOCKED)` x3 and `read(BLOCKED)` x1 were stopped. |
| 5 | done | **DONE** | `16_payloads_70_vectors.json` -> `16_payloads.json`, 16 records. |
| 6 | done | **HALF DONE, one part is WORSE than stated** | Adjudication ✓: 0 unresolved (10 compliance_with_flag + 10 full_compliance). Control **still n=20**, which is the exact thing the issue called too few. And **10 of those 20 are scored `not_applicable (control question, no ground truth)`, so the effective control is 10, not 20.** |

### Consequences for the paper (in addition to §15)

1. Table 2 row "Website and browser payloads / 16 / 16 / 100% / **no tool trace**" is now
   **false on both counts**. There is a tool trace, and the rate is 10/16 complied.
2. Table 2 row "Ten-category collection / 798 / 226 / **no tool trace**" **can be upgraded**.
   We have the action trail with kind, target and scope. The Discussion sentence "Two
   collections do not record those fields and report no split" drops to one.
3. Table 2 "Memory poisoning / 84 / 84 / 100%" versus the new v2 files at n=20 needs
   reconciling. State which collection each row is from.
4. `PAPER_PLAN.md` §7: **6,387 is a ROW-LEVEL sum inflated by the non-unique `session_id`
   join and must never be quoted.** Publishable figures are 660 distinct trials with actions
   and 1,059 out-of-scope actions at distinct-trial level.

### Still open, in effort order
* **Issue 1** (theirs, small): recompute `analysis_metrics.json` from `sessions_tierlabeled.jsonl`.
* **Issue 6a** (Kathleen): control group to 40 real control questions, not 20 of which 10 are n/a.
* **Ours**: push local action recovery, fix `policy_curve.py` to call `scorer.score()` (§15).

---

## 17. PUSHED 2026-07-28 — `b7bec38` + `11ba7bd`

15 files. Junk-guarded (no `__pycache__`, `.log`, `.joblib`, `.bak`) and deletion-guarded.
Nothing of anyone else's was removed. No AI attribution in either message.

**FINAL AUTHORITATIVE NUMBERS** (`GATE_OPERATING_POINTS.md`, from `scorer.score()`):

| policy | gold1 P/R | OOS P/R | STRICT P/R | benign raw/correct/FALSE | rate | budget |
|---|---|---|---|---|---|---|
| off | .9455/.8125 | .9235/.4486 | .8793/.2965 | 31/19/12 | 1.11% | OK |
| **strict** | **.9310/.8438** | **.9214/.6029** | **.9213/.4767** | **54/23/31** | **2.87%** [2.0,4.0] | **OK** |
| balanced | .9310/.8438 | .9217/.6057 | .9222/.4826 | 59/24/35 | 3.24% | OVER |
| aggressive | .9322/.8594 | .9183/.6743 | .9292/.6105 | 130/31/99 | 9.16% | OVER |

Recall went UP (OOS .5343 -> .6029, STRICT .3721 -> .4767) at essentially unchanged benign
cost, because the old table omitted the compliance layer. `balanced` is now over budget and
is no longer a candidate default, which retires the conditional in the old §2.

The 2.88% / 4.72% split is resolved: both scripts now share one definition and agree on
**31 false blocks**.

### Two blockers found while pushing
1. **GitHub push protection rejected `newcats_actions_recovered.jsonl`** — 6 placeholder
   Slack webhook URLs (`T00000000/B00000000`) the agent generated inside its own replies.
   Not live credentials. Pushing it needs either the repo unblock URL or redaction, and
   redaction alters the corpus. **Left out of the push; needs Sid's decision.** The team repo
   keeps its 769-row version, so issue 2 is still satisfied, just with less data.
2. **A fresh clone crashed on `import science_features`.** `scorer.py` only added
   `ROOT/analysis` to `sys.path`, but the published layout puts helpers in
   `general-model/src/`. Fixed in `11ba7bd` and verified by importing and scoring from both
   layouts.

### Still open
* Issue 6a (Kathleen): control group is 20, of which 10 are `not_applicable`, so effectively 10.
* The ten-category Table 2 row (798/226) is **unreproducible**; its standardization script was
  never committed. See `PAPER_FACTCHECK.md` §1b.
* Website Table 2 row and Fig 5 need redrawing (10/16, not 16/16).
* Reply hooks on the conversational surface still unverified.

---

## 18. SESSION 3 — Nathan's data, new channel, paper (3) revision

Pushed `11ba7bd..8509fbe`. Three commits total this session: `b7bec38`, `11ba7bd`, `8509fbe`.

### Nathan's corpus IS usable, and it exposed a real scope limit
`nathans data/*.json`, 8 live runs, 208 records, all with prompt + response + verdict.
* prompt_injection: 48 rows, **6 distinct prompts**, 19 successes / 29 resisted
* memory_poisoning: 160 rows, 20 distinct prompts, 11 facts, 80 adjudicated (all poisoned),
  **80 `manual_review_needed`** and therefore excluded
* Its six subtypes are OUR ten-category taxonomy, collected by a different person, so it is a
  same-taxonomy / different-collector transfer test. Diversity is thin: report at prompt-group
  level only.

**The shipped gate blocked 0 of 19 successful injections.** Not a bug. Every blocking channel
is built on secret-disclosure semantics (`secret_source` + `exfil_demand`); that corpus plants
an arbitrary marker and asks the agent to echo it. **AURA detects injection-driven secret
disclosure, not injection compliance in general.** That belongs in the paper's limitations.

### New channel: `instructed_echo`, FLAG-grade, default ON
`AURA_INSTRUCTED_ECHO=0` disables. Measured on three corpora, not just the motivating one:

| | result |
|---|---|
| Nathan, ungated | TP 11/19, FP 18/29, **P 0.379** — a refusal that QUOTES the token is textually identical to compliance |
| Nathan, refusal-gated | TP 11/19, FP 2/29, **P 0.846** — ships |
| our benign pool | 7 fires not already blocked. As a BLOCK: 2.87% -> **3.52%**, over budget. As a FLAG: **zero** false blocks |
| our OOS / STRICT | **identical tp/fp on and off**. Buys nothing on our own data |

22/22 tests. Benign FALSE unchanged at 31/1081 = 2.87%.

### Paper revision (3): most of the previous check is fixed
**Verified exactly**: website 16/8/50% + 25% AM (the paper's `label` field is right, my
earlier 10/16 used the unadjudicated `score` field), pooled 816 and 29.6% -> 30% [27, 33],
Fig 5 precisions .735/.534/.514, indirect injection 79%, 22-category 39%.

**Two blockers remain**:
1. Data Availability names `standardized_analysis/standardize_tracks.py`. **It does not exist
   in the repo.** It is what produces Table 2, Fig 7, the pooled 30% and the 816 denominator.
2. Ten-category 798/226 still unreproducible from any committed file. Resolves once (1) lands.

**Also flagged**: author list differs between group doc (4 authors) and paper (3, drops
Sathwik); Nathan/Evangeline/Audrey contribute data but are not authors. Memory-poisoning
control is effectively **10**, not 20, since half its rows are `not_applicable`. The
ten-category caveat should say the tool targets DO exist.

### Still not pushed
`newcats_actions_recovered.jsonl` — GitHub push protection blocks it over 6 placeholder Slack
webhooks (`T00000000/B00000000`) the agent wrote into its own replies. Needs either the repo
unblock URL or redaction; redaction alters the corpus. **Sid's decision.**
