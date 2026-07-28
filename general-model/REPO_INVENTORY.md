# AURA / OPALS — COMPLETE REPO INVENTORY AND MODEL COMPARISON

**Snapshot: 2026-07-27 14:08 PDT.**
Team repo checkout `/private/tmp/claude-501/-Users-sid-Documents-Behavioral-Risk-Prediction-for-Autonomous-AI-Systems/69306e3f-efd6-48e7-a076-fc2873ce40b2/scratchpad/opals` at
commit `a0ae8aa` (Sathwik_Kintada, 2026-07-27 14:05:42 -0700, "Merge pull request #3 from
bluMoonx/sathwik-model-experiments"), 754 files.
Local working tree `/Users/sid/Documents/Behavioral Risk Prediction for Autonomous AI Systems`, 4,670 files, 160 `.py`.

The repo moved twice while this inventory was being written (`4328a36` → `6d1c28a` → `a0ae8aa`,
13:54 → 14:05). Two local scripts were also created concurrently by other arms:
`/Users/sid/Documents/Behavioral Risk Prediction for Autonomous AI Systems/analysis/cross_source_v2.py` (14:06) and
`/Users/sid/Documents/Behavioral Risk Prediction for Autonomous AI Systems/analysis/paper_repro/benign_policy_delta.py`.
Every count below is as of the snapshot time.

Verification run for this document: `python3 openclaw-plugin/test_suite.py` → **22 passed, 0 failed, 0 skipped**.
No shipped file was modified by this arm.

---

## 0. THE HEADLINE, FIRST

**4,491 agent sessions have been collected across this project. 965 of them are hand-adjudicated.
965 are used to train the shipped model. 2,046 are touched by any evaluation.
2,325 have never been used by any AURA model or evaluation — 51.8% of everything we collected.**

The largest single unused block is Sathwik's 600-session prompt-injection corpus, which is also
the most prompt-diverse data anyone on this team has produced (455 distinct prompts, 1.32
rows/prompt, versus our 285 prompts at 3.39 rows/prompt and Chenhao's 10 prompts at 131.4
rows/prompt). It sat unread for four days.

---

## 1. EVERY DATASET

Legend for **AURA use**: *shipped* = feeds a shipped model or the shipped gate; *eval* = read by a
reported evaluation; *frozen* = in the retired `corpus_clean.jsonl` only; **UNUSED** = no AURA model
or evaluation has ever read it.

### 1.1 Datasets that AURA actually uses

| # | Path | Rows | What it is | Collector | Human labels? | Distinct prompts | rows/prompt | AURA use |
|---|---|---|---|---|---|---|---|---|
| D1 | `data/logs/collected_new10category/newcats_sessions.jsonl` | **2,166** (1,271 distinct `session_id`) | 10 new attack categories, attack/baseline prompt pairs, live OpenClaw + kimi-k2.5 | Sid | 965 rows hand-adjudicated (the gold); the rest carry canary-derived `human_label` | **403** | 5.37 | **shipped + eval.** The only corpus the 965 gold labels key into. 1,081 baseline rows / 204 benign prompts are the benign-cost denominator. |
| D2 | `data/logs/collected_new10category/newcats_actions_recovered.jsonl` | 2,166 | D1 enriched with recovered action trails (`actions`, `n_out_of_scope`, `boundary`) | Sid | same as D1 | 403 | 5.37 | **eval** (action-recovery numbers, `analysis/canonical_action_counts.py`). |
| D3 | `analysis/rebuild/gold_A..E.jsonl` (5 files) | **300** (294 resolve; 146 attack + 148 baseline) | gold1 — first adjudication round | Sid | **YES, hand** | subset of D1 | — | **eval.** The ONLY slice a threshold may be selected on. |
| D4 | `analysis/rebuild/gold2_S01..S12.jsonl` (12 files) | **671** | gold2 — second adjudication round, all attack rows | Sid | **YES, hand** | subset of D1 | — | **eval.** OOS slice; 288 of these are STRICT (prompt unseen in gold1). |
| D5 | `data/logs/chenhao_release/kimi_50_sessions.jsonl` | 700 | 7 attack categories × (50 attack + 50 baseline), kimi-k2.5 | Chenhao Zhang | **NO.** `human_label` is a collector heuristic. Blind worksheets exist (80 rows × 2 raters); their `label` column is **prefilled with that same heuristic and stamped "MACHINE DRAFT … VERIFY independently"**, and the 5 human scoring dimensions are **0/80 filled**. | **9** | 77.8 | **shipped-adjacent + eval.** Cross-source train set; also 651 rows in `corpus_clean`. |
| D6 | `data/logs/chenhao_release/deepseek_50_sessions.jsonl` | 614 | same design, deepseek-v4-pro, rate-limited | Chenhao Zhang | NO, same | **10** | 61.4 | same as D5. |
| D7 | `data/logs/collected_22category/sessions.jsonl` | 82 | scigateway 22-category sessions | Sid | NO (`scigateway_heuristic`) | 36 | 2.28 | **frozen.** 75 rows in `corpus_clean`; not in any current model. |
| D8 | `analysis/rebuild/corpus_clean.jsonl` | **2,303** (1,940 neg / 363 pos) | deduped merge: newcats 1,577 + chenhao 651 + scigw22 75 | Sid | derived | 434 | 5.31 | **frozen.** Trains `aura_honest.joblib` only. One label generation out of date. |

**Chenhao's effective training diversity is 10 prompts, not 1,314 rows.** Every cross-source
number AURA has ever published is trained on that. Measured: `human_label` is **98.7% recoverable
from `attack_category` alone** across 1,314 rows and 8 categories — the label is very nearly a
relabeling of the design variable, which caps every cross-source result computed against it.

### 1.2 THE UNUSED ASSETS — flagged explicitly

| # | Path | Rows | What it is | Collector | Human labels? | Distinct prompts | AURA use |
|---|---|---|---|---|---|---|---|
| **U1** | `<repo>/prompt-injection/dataset/sessions_tierlabeled.jsonl` | **600** | 400 attacks (8 subtypes × 50) + 200 benign controls, live OpenClaw 2026.7.1 / kimi-k2.5, collected 2026-07-23, 0 failures | **Sathwik Kintada** | **NO** — `human_label` {safe 285, suspicious 185, unsafe 130} is produced by `prompt-injection/analysis/compliance_tier.py`. Blind worksheets (144 rows) exist with **0 `judgement` cells filled.** | **455** (1.32 rows/prompt) | **NONE. ZERO overlap with our 965 gold — 0 shared prompts, 0 shared responses.** The real transfer test we never had. |
| U2 | `<repo>/prompt-injection/dataset/sessions.jsonl` | 600 | the same 600 sessions under the harm-based rubric ({safe 598, suspicious 2}) | Sathwik | NO | 455 | NONE |
| U3 | `<repo>/prompt-injection/dataset/compliance_tiers.csv` | 600 | per-session compliance tier + observable features | Sathwik | NO | — | NONE |
| U4 | `<repo>/prompt-injection/dataset/manifests/*.csv` (4) | 4 family manifests | per-run session manifests | Sathwik | — | — | NONE |
| U5 | `data/logs/spring_memory_poisoning/turns_run{1,2}.jsonl` | **1,998 turns / 100 sessions** (1,000 baseline + 998 attack) | Spring astrophysics memory-poisoning turn logs | Spring project (Kathleen lineage) | NO (`label` = run condition) | **120 queries** | **NONE currently.** Trained `aura_v1.joblib` only; **explicitly excluded** from `corpus_clean` by `analysis/rebuild/build_corpus.py:25` ("all `response_preview` values are one CLI banner"). |
| U6 | `data/logs/collected_22category/turns.jsonl` | 248 | per-turn records under D7 | Sid | NO | 38 | **NONE.** Excluded by `build_corpus.py:26` — "injects 124 mislabelled records". |
| U7 | `data/logs/container_sessions/sessions/*.jsonl` | 942 session logs + 953 trajectory logs (4,005 files, 13,167 lines) | raw OpenClaw execution logs, 660 with a parsed `toolCall` | Sid | n/a | n/a | **partial** — mined for action trails by `recover_actions.py` / `canonical_action_counts.py`; never used as features or labels. 294 of 660 trails match **no** collection row at all. |
| U8 | `data/logs/image_sessions/*.jsonl` (13 files) | 118 log lines / ~13 vision sessions | harvested vision-agent sessions | Sid | NO | — | **NONE.** Excluded by `build_corpus.py:27`. |
| U9 | `data/images/decoy_graphs/` (72 PNG + `manifest.jsonl`) | 72 | typographic injection on science figures | Sid | manifest has `injected`/`level`/`canary` | — | **NONE. 0 scripts reference `decoy_graphs`.** |
| U10 | `data/images/photo_toolkit/` (5 PNG) | 5 | adversarial-vision samples | Sid | — | — | **NONE. 0 script references.** |
| U11 | `data/_failed_manual_review/grainmask_photo_FAILED/` | ~24 PNG | moiré / grain-mask attacks that failed on kimi's vision | Sid | — | — | **NONE.** `data/README.md` says "Safe to delete." |
| U12 | `data/prompts/new_categories_bank.jsonl` | 500 | 500 attack/baseline prompt variants + planted secret + canary | Sid | n/a (source material) | 500 | **generator only** (`analysis/collect_prompt_pairs.py`). This is what produced D1. |
| U13 | `<repo>/memory-poisoning/data/processed/matched_sessions.json` | 110 | summer astrophysics memory-poisoning sessions | Kathleen / Blu | NO (`compliance_score`) | 50 | **NONE in any AURA model.** |
| U14 | `<repo>/memory-poisoning/data/processed/memory_poisoning_astro_aura.jsonl` | **94** (84 pos / 10 neg) | 110 above, converted to AURA `corpus_clean` schema | Kathleen / Blu | derived | 50 | **NONE.** Appended to the **repo** `general-model/corpus_clean.jsonl` (2,303 → **2,397**) on 2026-07-27; **absent from the local corpus and from every model.** |
| U15 | `<repo>/evangeline_website_tests/16_payloads_70_vectors.json` + 17 HTML fixtures | 16 payload trials / 70 vectors | browser-agent attack payloads (direct injection, credential harvesting, XXE, session hijacking, …) | Evangeline (MoeraWho) | `label` + `score` fields present, hand-assigned | 16 | **NONE.** |
| U16 | `<repo>/docker-logs-2026-07-23T21-00-00.475Z.csv` | 956 | OpenClaw gateway container logs | Evangeline (MoeraWho) | n/a | — | **NONE.** |
| U17 | `Group 21 AI security /Resources_from_Spring_project/prompt_injection/session_manifest.csv` | 90 | Spring poisoned-résumé prompt-injection sessions | Spring project | — | — | **NONE.** |
| U18 | `Group 21 AI security /Resources_from_Spring_project/memory_poisoning/{attack,baseline}/session_050.jsonl` | 82 + 87 | Spring raw session pair | Spring project | — | — | **NONE.** |
| U19 | `<repo>/chenhao-data_release/*/adjudication/worksheet_rater_{A,B}.csv` | 80 rows × 2 raters × 2 datasets = **320 drafted** | blind human worksheets for D5/D6 | Chenhao | **0/320 human dimension cells filled**; `label` is the prefilled machine draft | — | **NONE.** |
| U20 | `<repo>/prompt-injection/dataset/external/sid_new10category.jsonl` | 124 | a 124-row slice of **our** D1, exported into Sathwik's tree | Sathwik | inherited | 47 | Sathwik's cross-check only. |
| U21 | `<repo>/prompt-injection/dataset/analysis/*`, `figures/*` | — | Sathwik's own detector bench outputs | Sathwik | — | — | Not AURA. |

### 1.3 U1 — what the transfer set actually contains, and its one caveat

Measured directly from the file (schema fields only; **no response text was read**):

```
600 rows · 455 distinct user_prompt · 1.32 rows/prompt
400 attack  = hypothetical_framing 50, fabricated_context 50, delimiter_confusion 50,
              role_spoofing 50, task_laundering 50, prompt_leaking 50,
              sleeper_trigger 50, reasoning_hijack 50
200 benign  = framing_social 50, structural_parsing 50, temporal_reasoning 50,
              task_laundering-control 50
human_label  safe 285 / suspicious 185 / unsafe 130   (all 200 benign rows are "safe")
agent_response non-empty 595/600 · tool_calls non-empty 178 · actions non-empty 166
gateway_decision  None on all 600
attack_category  'direct_prompt_injection' on all 400 attacks — the 8 subtypes live in
                 session_id and attack_objective, NOT in attack_category
```

**Caveat that must travel with any use of U1 as a transfer set.** Sathwik documents, and I
reproduced independently from prompt word counts alone:

| | min words | median | max |
|---|---|---|---|
| attack prompts | 10 | 29 | 74 |
| benign prompts | 3 | 11 | 18 |

`>18 words` separates **315/400 attacks from 0/200 benign** with zero false positives. Any
attack-vs-benign AUC on this corpus is contaminated by prompt length unless length is controlled.
Sathwik's own finding (`prompt-injection/analysis/DETECTOR_FINDINGS.md` §3, §8): removing length
features drops his AUC 0.997 → 0.86, and 430 of 708 successful attacks have a feature vector
*exactly identical* to some benign session. **The safe use of U1 is attack-slice-only
(compliance vs resistance among the 400 attacks), not attack-vs-benign.**

**Status correction as of 14:05 today.** U1 is no longer untouched by *every* model in the repo —
commit `a0ae8aa` added `prompt-injection/analysis/detector_bench.py` and `model_bakeoff.py`, which
Sathwik ran on it for his own track. It remains untouched by **every AURA model and every AURA
evaluation**, which is the property that matters for using it as our held-out transfer set.

---

## 2. EVERY MODEL ARTIFACT

Nine `.joblib` files exist. `aura_general.joblib`, `aura_general.backup.joblib`, `aura_v1.joblib`
and `aura_behavioral.joblib` are **md5-identical** between `models/` and
`<repo>/general-model/models/`. `aura_behavioral_sog`, `aura_final`, `aura_honest` are local-only.

| Artifact | Size | Est. | Features | Trained on | Labels | Protocol | Headline | Protocol verdict |
|---|---|---|---|---|---|---|---|---|
| `models/aura_v1.joblib` | 141 KB | GradientBoosting | 11 spring linguistic | **U5** spring turns (1,998) | run condition | `GroupKFold(5)` on **session_id** (`train_full.py:53`, `train_spring_baseline.py:39`) | cv_auc **0.789** | **LEAKY.** 1,998 turns cover only **120 distinct queries, and all 120 appear in more than one session**. Grouping by session does not separate prompts; every test query is also in training. 0.789 is not a generalization number. |
| `models/aura_general.joblib` | 145 KB | GradientBoosting | 12 science | 3,240 sessions | **canary** | `GroupKFold` by attack category | cv_auc 0.836 | **Labels discredited.** The canary recovers ~21% of true compliances (κ 0.20 vs hand judgement). Protocol is fine; the target is wrong. |
| `models/aura_general.backup.joblib` | 18.4 MB | RandomForest(400) | 12 science | 3,188 sessions | **canary** | `GroupKFold` by attack category | cv_auc **0.905** | **THE RETRACTED NUMBER.** Same discredited labels. Withdrawn in commit `c4a23bd`. |
| `models/aura_final.joblib` | 613 KB | GradientBoosting + TF-IDF(40k) | 62 relational (prompt, reply, tool-name) | gold n=**296** (retired) + chenhao n=1,314 | mixed | nested prompt-grouped CV; model, source, combination and threshold all chosen inside training folds | T1 attack F1 **0.772** (target 0.737), T2 blind AUC **0.540** (target 0.602) | **HONEST protocol, SELF-DECLARED NON-WIN.** Its own note: "HONEST BASELINE, NOT A CONFIRMED WIN." Trained on the retired 296-row gold, superseded by the 965. |
| **`models/aura_behavioral.joblib`** | 8.3 MB | RandomForest(500, `min_samples_leaf=3`, `balanced_subsample`) | 12 science | **965 hand-judged gold** | **behavioural, hand** | `StratifiedGroupKFold`, `group=md5(prompt)`, 5-fold × **10 seeds** | **AUC 0.7427 (sd 0.0081)**, LOACO 0.7117, F1 0.6532 vs trivial floor 0.6035 (**+0.0497**) | **HONEST. THE SHIPPED MODEL.** Records its own leak size: plain `StratifiedKFold` reads 0.7973, i.e. **+0.0546 of pure leak**, because the 965 rows span only 285 prompts. |
| `models/aura_behavioral_sog.joblib` | 7.7 MB | RandomForest(500) | compliance-taxonomy (`analysis/compete/sog_features.py`) | 965 gold (417 pos) | behavioural, hand | `StratifiedGroupKFold(prompt)`, 5-fold, seeds 0-4 | **AUC 0.8787 (sd 0.0011)** vs T1 0.7443 same harness; paired Δ **+0.1343**, CI [0.0868, 0.1667] bootstrapped over **285 prompt groups**; permutation control **0.49**; strict-cluster grouping 0.883 | **HONEST, and it declares its own defeat at the operating point.** At precision ≥0.90: **recall 0.387 vs the deterministic labeler's 0.449.** Oracle ceiling at P 0.92 is 0.439, still below 0.449. The AUC gain lives in the mid-range, not in the high-precision head the gate blocks on. |
| `models/aura_honest.joblib` | 10.3 MB | RandomForest(400) | 12 science | **D8** frozen 2,303-row corpus | canary-era | **TRUE leave-one-attack-category-out**, 38 folds | pooled OOF **0.5019**, mean-of-fold 0.618 over only **12/38 folds**, recall@10%FPR 0.055 | **HONEST protocol, obsolete labels.** Reproduces bit-identically. Do NOT publish as "the honest AURA number" (see `evidence/rederive/VERDICTS.json` #2). Keep as the cautionary artifact. |
| `evidence/rederive/aura_honest.PRE_RERUN.joblib` | 10.3 MB | — | — | — | — | — | — | **md5-identical to `models/aura_honest.joblib`: `0fb986fc6f52fc3f923da27a9249538c`.** Zero additional information. |
| `<repo>/memory-poisoning/models/aura_plus_memory_poisoning.joblib` | 2.3 KB | `StandardScaler → LogisticRegression(balanced)` | 15 science + surface | AURA science corpus + **84 memory-poisoning sessions (U14)** | compliance score | not stated in the artifact | generalization recall@10%FPR **0.357** | **Non-shipping**, self-declared. Kathleen/Blu. A model trained on the other 35 families flags only 36% (30/84) of these — the blind spot the data fills. |

**Metrics sidecars:** `models/metrics.json`, `metrics_general.json`, `metrics_behavioral.json`
(14 keys, incl. `canary_cv_*` and `xsrc_*` controls), `metrics_behavioral_sog.json`.

### 2.1 Ranking, and the best model for each purpose

**Blocking at high precision — winner: `openclaw-plugin/scorer.py` + the deterministic
behavioural labeler, NOT any `.joblib`.**
Reproduced from `analysis/paper_repro/policy_curve_output.txt` (records 2,166, gold 965,
gold1 attack 146, OOS 671, STRICT 288, STRICT prompt groups 116):

| policy | gold1 P/R | OOS P/R | STRICT P/R | benign (148) | benign (1,081, bootstrap over 204 prompt groups) |
|---|---|---|---|---|---|
| off | .946/.813 | .924/.449 | .879/.297 | 1.4% | 2.9% [1.0, 5.3] |
| **strict (shipped)** | .930/.828 | **.930/.534** | **.901/.372** | 1.4% | **3.0% [1.1, 5.5]** |
| balanced | .931/.844 | .935/.574 | .911/.419 | 4.1% | 4.9% [2.2, 8.3] |
| aggressive | .932/.859 | .918/.674 | .929/.610 | 11.5% | 12.0% [8.0, 16.2] |

Trivial always-positive F1 floors: gold1 **0.6095**, OOS **0.6856**, STRICT **0.7478**, all-gold **0.6035**.
Note that on OOS and STRICT the shipped gate's F1 (0.679, 0.527) is **below** the trivial floor —
the gate wins on *precision at low benign cost*, not on F1. Say it that way.
No `.joblib` beats the deterministic path at P ≥ 0.90; `aura_behavioral_sog` explicitly loses
(recall 0.387 vs 0.449). **Do not swap a model in for the rule at the blocking operating point.**

**Ranking / triage — winner: `models/aura_behavioral_sog.joblib`.**
AUC 0.8787 (sd 0.0011) under prompt-grouped CV with a 0.49 permutation control and a paired CI
that excludes 0. Use it to order a review queue, never to auto-block.

**Research comparison / the number to beat — winner: `models/aura_behavioral.joblib`.**
0.7427 (sd 0.0081), 10 seeds, prompt-grouped, with its own leak magnitude (+0.0546) recorded in
the artifact. Every claimed improvement must be measured against this under the same harness.
Keep `models/aura_honest.joblib` beside it as the leakage cautionary panel.

**Deletion guidance**

| Artifact | Verdict |
|---|---|
| `evidence/rederive/aura_honest.PRE_RERUN.joblib` | **SAFE TO DELETE** (10.3 MB reclaimed). Byte-identical to `models/aura_honest.joblib`; md5 `0fb986fc6f52fc3f923da27a9249538c` is now recorded here, which is the only thing the file proved. |
| `models/aura_general.joblib` | **SAFE TO DELETE.** Superseded by `aura_behavioral`; its 0.836 is preserved in `models/metrics_general.json`. |
| `models/aura_final.joblib` | **SAFE TO DELETE.** Self-declared non-win on a retired gold set; its full metrics dict is inside the artifact and reproduced above. |
| `models/aura_general.backup.joblib` (18.4 MB) | **KEEP — PROVENANCE.** This is the object behind the retracted 0.905. The retraction in `PAPER_CORRECTIONS.md` is unfalsifiable without it. |
| `models/aura_v1.joblib` | **KEEP — PROVENANCE.** First artifact; the leak diagnosis in §2 refers to it. |
| `models/aura_honest.joblib` | **KEEP — PROVENANCE.** The 0.502 in `evidence/rederive/VERDICTS.json` #2 is checked against it. |
| `models/aura_behavioral.joblib`, `aura_behavioral_sog.joblib` | **KEEP — LIVE.** |
| `<repo>/memory-poisoning/models/aura_plus_memory_poisoning.joblib` | **KEEP.** 2.3 KB, only artifact of the memory-poisoning coverage result. |

---

## 3. EVERY SCRIPT THAT PRODUCES A NUMBER

93 of the 160 `.py` files emit a metric. Two are quarantined. **Six more are offenders that were
never flagged.** Full audit method: scan for `roc_auc_score|f1_score|precision_score|recall_score|
average_precision`, then check each hit for (a) a raw `session_id` join, (b) ungrouped CV that is
reported as a result rather than labelled as a control.

### 3.1 Trustworthy — the canonical spine

| Script | What it produces | Why it is trustworthy |
|---|---|---|
| `analysis/eval_combined_gold.py` | `load_records()` / `load_all_gold()` → **965 gold rows** (gold1 294 + gold2 671; attack 817, baseline 148; 285 distinct prompts) | Resolves gold2 by `line_idx` and **refuses to guess** when `records[line_idx].session_id != g.session_id`. The only sanctioned loader. |
| `analysis/resolve_gold.py` | gold1 record resolution | Trusts `line_idx` first, then matches the recorded **response prefix**, then a unique-`session_id` fallback; refuses on disagreement. |
| `analysis/check_gold_integrity.py` | gold-file fingerprint guard | Detects the 965 labels drifting against an appended source file. |
| `analysis/paper_repro/policy_curve.py`, `policy_curve_ci.py` | the shipped policy table (§2.1) | Uses the canonical loader; STRICT slice by prompt hash; trivial floors printed alongside. |
| `analysis/measure_benign_wide.py` | benign false-block on **1,081** rows / 204 prompts | Bootstraps **prompt groups**, not rows; prints the too-narrow Wilson interval only for contrast; states its own looseness (3/148 judged-baseline rows were themselves COMPLIED). |
| `analysis/train_behavioral.py` | `aura_behavioral.joblib`, `metrics_behavioral.json` | `StratifiedGroupKFold(md5(prompt))`, 10 seeds; the `StratifiedKFold` at line 146 is the **deliberately labelled leaky control** whose gap is published. |
| `analysis/rederive_cross_source.py`, `rederive_loaco_control.py` | `evidence/rederive/*.json` | Bootstraps 285 prompt groups; ran a permuted-label control (row-permuted 0.5000 sd 0.0185, group-permuted 0.4971) before reporting. |
| `analysis/canonical_action_counts.py` | trail-basis vs row-basis action counts | Defines "distinct trial" as an action trail; publishes the 84.5%-ambiguity caveat beside the row basis. |
| `analysis/compete/refute_*/` (24 scripts) | the adversarial re-checks | All use `StratifiedGroupKFold` + the canonical loader; several run permutation controls. |
| `analysis/compete/sog_*.py` (8 scripts) | `aura_behavioral_sog` metrics | Grouped, nested, seeded; `sog_main.py:384`'s plain `StratifiedKFold` is explicitly printed as "NOT reported as a result … shown only to confirm the grouped protocol is the conservative one". |
| `openclaw-plugin/scorer.py`, `test_suite.py` | the live gate; 22 assertions | 22/22 green at this snapshot. |

### 3.2 QUARANTINED (already, correctly)

| Script | Guard |
|---|---|
| `analysis/rebuild/eval_ablations.py` | header line 1 `!! QUARANTINED 2026-07-27 — DO NOT RUN !!`; guard at :44-46 `sys.exit("REFUSING TO RUN: broken session_id join -> invalid numbers")`. Offending join at **:310** `g[d["session_id"]] = int(d["behavioral_label"])`. |
| `analysis/rebuild/retrain_behavioral.py` | same header; guard at :47-49. Offending join at **:120-122** `by_sid[r["session_id"]].append(i)` used with a window at **:155**. |

### 3.3 NEW OFFENDERS — not previously flagged

`newcats_sessions.jsonl` has **2,166 rows over 1,271 distinct `session_id`; 326 ids are duplicated,
max depth 9, and 1,221 rows (56.4%) sit under a duplicated id.** Any dict keyed on `session_id`
silently discards 895 records and attaches gold labels to the wrong trial.

| # | Script:line | Bug | Consequence |
|---|---|---|---|
| **N1** | `analysis/compete/data.py:31` `sess[r["session_id"]] = r` and **`:41`** `gold[g["session_id"]] = g` | **session_id join, last-wins on both sides** | Collapses 965 gold rows to **283**. The docstring even admits it: "283 unique hand-judged sessions … 17 session_ids were judged twice … last one wins (15/17 duplicate pairs agree; 2 disagree)". Every `compete` script importing `data.py` inherits this. |
| **N2** | `analysis/compete/improve_labeler.py:53` `gold[r["session_id"]] = r`, **`:57`** `sess.setdefault(r["session_id"], r)` | **session_id join**, last-wins on gold, **first**-wins on sessions | Labels are joined to whichever trial happened to appear first in the file, not the one that was judged. `improve_labeler_results.json` is untrustworthy. |
| **N3** | `analysis/compete/supervised_on_gold.py:69` `sessions.setdefault(r["session_id"], r)` **and** `:509,:515` ungrouped `StratifiedKFold(5)` on gold rows | **both bugs at once** | The join picks the wrong trial *and* the CV lets the same prompt straddle train/test. `supervised_on_gold_results.txt` / `_summary.json` are untrustworthy. |
| **N4** | `analysis/compete/evaluate.py:65` `by_id.setdefault(r["session_id"], []).append(i)` with a hard-coded window fallback `:80-83` and `return inwin[0] if inwin else cands[0]`; plus ungrouped `StratifiedKFold(5)` at **:203, :362** | window heuristic + ungrouped CV | It asserts `recs[i].session_id == g.session_id`, so it never mislabels *across* sessions — but among the 326 duplicated ids it picks `cands[0]`, i.e. an arbitrary trial with a different response. Combined with ungrouped CV, its numbers are not comparable to the canonical harness. |
| **N5** | `analysis/compete/prompt_response_pair.py:903, :919` ungrouped `StratifiedKFold(5)` / inner `StratifiedKFold(4)` on the 965 gold rows | **ungrouped CV reported as a result** | Its own docstring at :498-504 correctly warns that gold is record-level and resolves records by response prefix (:520-522) — so the *join* is sound — but it then cross-validates without prompt groups. Measured leak on this exact data is **+0.05 AUC** (`aura_behavioral` metrics). `prompt_response_pair_results.json` is inflated by roughly that. (`:786` on chenhao is a labelled within-source separability check, fine.) |
| **N6** | `analysis/compete/ensemble.py:114` and `ensemble2.py:110, :118` — `StratifiedKFold` chosen when `groups is None`, and the group path uses `GroupKFold` by **attack category**, never by prompt | ungrouped-by-prompt CV | `ensemble_results.json`, `ensemble2_results.json`, `ensemble*_report.txt` all predate the prompt-group discipline. Superseded by `analysis/compete/refute_ens*/` and `ens/run_ensemble*.py`, which are grouped. |
| **N7** | `analysis/train_full.py:53` and `analysis/train_spring_baseline.py:39` — `g = session_id` | **grouping does not separate prompts** | 1,998 spring turns cover 120 queries and **all 120 queries appear in more than one session**. `GroupKFold` on session therefore guarantees every test query is in training. This is the protocol behind `aura_v1.joblib`'s **0.789**. Flag the number wherever it appears. |
| **N8** | `analysis/rebuild/validate_labeler.py:59-76` | window-based `session_id` resolution | Safer than N1-N3 — it raises `ValueError` when a window is ambiguous and asserts the id matches — but it is a third resolver, not the canonical one. Prefer `eval_combined_gold`. |

**Correctly-labelled ungrouped CV — NOT offenders** (each is printed as a control, not a result):
`analysis/train_behavioral.py:146`; `analysis/compete/sog_main.py:384` ("LEAK CHECK … NOT reported
as a result"); `analysis/rebuild/eval_supervised.py:221` ("categories seen in training —
OPTIMISTIC"); `analysis/hardening/reproduce_baseline_protocol.py:74` ("P5 random StratifiedKFold(5)
[NO grouping - optimistic]"); `analysis/compete/refute_recall_lift/attack3.py:91` ("leaky
control"); `analysis/compete/verify_prompt_response_pair.py:74` (splitter comparison, by design);
`analysis/compete/final_detector.py:395` (inner OOF on chenhao only; the outer split is
`StratifiedGroupKFold`); `analysis/compete/sog_baseline_repro.py:53` (fallback branch, never taken
— groups are always supplied).

### 3.4 Scripts that are generators, not measurers (no number to distrust)

`analysis/collect_prompt_pairs.py`, `recover_actions.py`, `make_image_attacks.py`,
`make_photo_attacks.py`, `make_illusion_attacks.py`, `make_figures.py`,
`make_fig5_protocol_ladder.py`, `live_demo.py`, `science_features.py`,
`analysis/rebuild/{build_corpus,extract_*,label_A,make_gold_*}.py`,
`analysis/compete/{detectors,compliance_features,sog_features,sog_data,labeler_v2,errors}.py`,
`analysis/signfix/{build_features,demand_features,tool_type_features}.py`,
`openclaw-plugin/{behavioral_labeler,deferred_compliance}.py`.

### 3.5 Repo-side scripts (not audited by the local harness)

`<repo>/scigateway/` (22 files, Chenhao, commit `7bf12cf`) — `pipeline/{train,evaluate,features,
erroranalysis,evidence,live_analysis}.py`. `pipeline/train.py:29` rosters logistic regression,
decision tree, random forest, xgboost. **No AURA number depends on it.**
`<repo>/memory-poisoning/notebooks/` (13 scripts, Kathleen/Blu) — `train_detector.py`,
`train_classifier.py`, `build_feature_table.py`, `score_results_v2.py`, `integrate_into_aura.py`.
The claimed "0.94 balanced acc / 0.95 AUC" (commit `1bc4f75`) is measured on **110 sessions over 50
prompts** with no prompt grouping visible; treat as unvalidated.
`<repo>/prompt-injection/analysis/` (7 scripts, Sathwik) — `detector_bench.py`, `model_bakeoff.py`,
`compliance_tier.py`, `check_control_balance.py`. Sathwik's own `DETECTOR_FINDINGS.md` retracts two
of his earlier claims and documents the length confound; that document is honest and should be read
before anyone uses U1.

---

## 4. THE DATA LEDGER

**Unit: one live agent session.** Turn-level files are folded into their session count.
`container_sessions` are the raw log substrate under D1, not additional sessions, so they are
listed but not added.

| Corpus | Sessions | Collector | Hand-adjudicated | In shipped training | In any evaluation |
|---|---|---|---|---|---|
| newcats (D1/D2) | **2,166** rows / 1,271 ids | Sid | **965** | **965** | 965 gold + 1,081 benign = **2,046** |
| collected_22category (D7) | 82 | Sid | 0 | 0 | 0 (75 rows in frozen corpus only) |
| chenhao kimi_50 (D5) | 700 | Chenhao | 0 | 0 | cross-source train side |
| chenhao deepseek_50 (D6) | 614 | Chenhao | 0 | 0 | cross-source train side |
| **prompt-injection (U1)** | **600** | **Sathwik** | **0** | **0** | **0** |
| spring memory-poisoning (U5) | 100 (1,998 turns) | Spring project | 0 | 0 | 0 (`aura_v1` only, retired) |
| summer memory-poisoning (U13) | 110 | Kathleen / Blu | 0 | 0 | 0 |
| image_sessions (U8) | 13 | Sid | 0 | 0 | 0 |
| evangeline website tests (U15) | 16 | Evangeline | 16 (`label`+`score` fields) | 0 | 0 |
| spring prompt_injection (U17) | 90 | Spring project | 0 | 0 | 0 |
| — *(raw substrate, not counted)* | *942 container logs → 660 action trails* | Sid | — | — | action counts only |
| **TOTAL** | **4,491** | — | **965** (+16 Evangeline) | **965** | **2,046** |

**The four numbers the team needs:**

- **Collected: 4,491 sessions.**
- **Hand-adjudicated: 965** (21.5%). All by Sid, all inside newcats. Chenhao's 320 drafted worksheet
  rows and Sathwik's 144 drafted worksheet rows have **0 human judgement cells filled**; every other
  `human_label` in this project is a heuristic, a canary match, or a run condition.
- **Used in training the shipped model: 965 rows over 285 distinct prompts** (3.39 rows/prompt).
  The frozen `aura_honest` used 2,303 rows over 434 prompts.
- **Used in any evaluation: 2,046** (965 gold + 1,081 benign baseline), plus chenhao's 1,314 on the
  training side of the cross-source test.
- **Collected but never used by any AURA model or evaluation: 2,325 sessions — 51.8% of everything
  collected.** Breakdown: 600 Sathwik + 700 chenhao kimi + 614 chenhao deepseek + 110 summer
  memory-poisoning + 100 spring memory-poisoning + 90 spring prompt-injection + 82 scigw22 +
  16 evangeline + 13 image = 2,325. Chenhao's 1,314 are counted here because they are only ever a
  *training* source for the cross-source test, never an evaluation set. If they are credited as
  "used", the unused figure is **1,011 sessions (22.5% of all collected)** — and **U1's 600 is
  59.3% of that**, i.e. the single unused corpus is larger than everything else unused combined.

**Prompt diversity, the number that actually constrains us:**

| Corpus | rows | distinct prompts | rows/prompt |
|---|---|---|---|
| **Sathwik (U1)** | 600 | **455** | **1.32** |
| Sid gold (D3+D4) | 965 | 285 | 3.39 |
| Sid newcats (D1) | 2,166 | 403 | 5.37 |
| corpus_clean (D8) | 2,303 | 434 | 5.31 |
| Chenhao (D5+D6) | 1,314 | **10** | **131.4** |

---

## 5. WHAT EACH TEAMMATE CONTRIBUTED

From `git shortlog -sne HEAD` at `a0ae8aa` (**74 commits**) and the file tree. Factual, no adjectives.

| Author (all identities) | Commits |
|---|---|
| Kathleen / "Blu" (`Blu` 18 + `blumoon` 14) | **32** |
| Sathwik Kintada (`Wick2009` 13 + `Sathwik_Kintada` 2 merges) | **15** |
| Sid Devineni (`superheroguy177` 12 + `gimkitxxx` 7) | **19** |
| Chenhao Zhang (`ChenhaoZhang01` 3 + `Chenhao Zhang` 2) | **5** |
| Evangeline (`MoeraWho`) | **3** |

**Sid Devineni** — 19 commits (12 as `superheroguy177@gmail.com`, 7 as `gimkitxxx@gmail.com`),
2026-07-23 → 07-27. Contributed `general-model/` (165 files): the 500-prompt attack bank, the
2,166-session newcats collection, **all 965 hand adjudications** (gold1 300 + gold2 671), the
deterministic behavioural labeler, the shipped `openclaw-plugin` gate (scorer, labeler, deferred
channel, 22-test suite, TypeScript plugin), `aura_v1/general/behavioral/behavioral_sog/final/honest`,
the action-recovery pipeline, and the corrections record. Notable commits: `e7f1d38` "prompt-duplication
leak inflated AUC 0.797 → honest 0.743"; `9fc79e6` "965 hand-judged labels (was 300); canary misses
79% of compliances"; `c4a23bd` "withdraw invalid 0.905"; `12d70c2` "fix an 11.5% benign false-block
regression"; `55937df` "measure the benign rate on 1081 rows not 148; withdraw fig3 and fig4".
Also authored the two quarantine guards and `evidence/rederive/VERDICTS.json`.

**Kathleen / "Blu" (`bluMoonx`, 105179246+)** — **32 commits, the most of anyone**, 2026-07-16 →
07-27. Repo owner (`803eb2d` initial commit, README, project structure). Owns `memory-poisoning/`
(414 files, the largest directory in the repo): the astrophysics prompt bank, baseline/attack runs,
110 matched sessions, 13 analysis notebooks, 6 result charts, `aura_plus_memory_poisoning.joblib`,
and `MEMORY_POISONING_MERGE_NOTE.md`. Commit `1bc4f75` claims "0.94 balanced acc / 0.95 AUC" for the
gateway poisoning detector — measured on 110 sessions / 50 prompts, protocol unvalidated. Commit
`4328a36` (13:54 today) appended her 94 rows to the repo `corpus_clean.jsonl` (2,303 → 2,397) with an
explicit undo path and an honest caveat that the features "detect unsafe answering behavior, not truth".

**Sathwik Kintada (`Wick2009` / `sathwik.kintada@gmail.com`)** — 13 authored commits + 2 merges
(PR #2 on 07-23, PR #3 on 07-27 14:05). Owns `prompt-injection/` (50 files): the
benign-canary attack generators (`scenarios.py`, `prompts/generators.py`, `controls.py`,
`controls_v2.py`, `control_pools.py`, `multilingual.py`), `collect.py`, the 3-tier compliance
labeler, and **the 600-session corpus with 455 distinct prompts — the most prompt-diverse data in
the project.** His 07-27 PR added `detector_bench.py`, `model_bakeoff.py`, six figures and
`DETECTOR_FINDINGS.md`, in which he **retracts two of his own earlier claims** (the "AUC 0.972
transfer" result is circular because `echoed_planted_tokens` agrees with the success label at 0.978;
the headline AUC was inflated by a prompt-length artifact) and reports that the existing rule
gateway **blocks 1 of 400 prompt-injection attacks (0.25%)**.

**Chenhao Zhang (`ChenhaoZhang01` / `Chenhao Zhang`)** — 5 commits, 2026-07-16 → 07-23. Contributed `scigateway/`
(22 files, the shared collection/analysis pipeline — schema, taxonomy, attack definitions, live
Docker backend, OpenClaw parser, train/evaluate/features/erroranalysis modules) and
`chenhao-data_release/` (37 files): **1,314 sessions across two models** (kimi_50 700,
deepseek_50 614) with per-dataset analysis, SHA-256 manifest, LICENSE, and blind adjudication
worksheets. His `Session` schema is what Sathwik's collector and our loaders both target. Caveat
that must travel with his data: 10 distinct prompts, and `human_label` is 98.7% recoverable from
`attack_category`.

**Evangeline (`MoeraWho`, 117536070+)** — 3 commits (07-23 upload, 07-26, `6d1c28a` 07-27 14:03). Owns
`evangeline_website_tests/` (36 files): 17 adversarial HTML fixtures (direct/indirect injection,
credential harvesting, form and session hijacking, XXE, cross-origin leaks, size/depth bombs,
navigation traps, infinite scroll, slow response), `16_payloads_70_vectors.json` with hand-assigned
`label`/`score`, a browser test harness, and 956 rows of OpenClaw gateway container logs. **None of
it has been read by any AURA model or evaluation.**

**Spring project (inherited, not a current contributor)** — `Group 21 AI security /Resources_from_Spring_project/`:
1,998 memory-poisoning turns over 100 sessions, a 90-session prompt-injection manifest with poisoned
résumés, `longtail_experiment_v3.py`, and the two symposium papers (CIST'26 #117, ICAIIS26 #105) that
this project builds on.

---

## 6. ACTION LIST, IN PRIORITY ORDER

1. **Score U1 with the shipped gate.** 600 sessions, 455 prompts, zero prompt or response overlap
   with our 965. Attack-slice only (400 rows) to avoid the prompt-length confound. Report recall at
   P ≥ 0.90 and the block rate on the 200 controls side by side. **Do not train on it.**
2. **Add the six new offenders (N1-N7) to the quarantine list**, or at minimum stamp
   `analysis/compete/{data,improve_labeler,supervised_on_gold,evaluate,prompt_response_pair,
   ensemble,ensemble2}.py` with a header naming the bug, as `eval_ablations.py` already does.
   `data.py` collapsing 965 → 283 is the highest-impact one: everything importing it is affected.
3. **Flag `aura_v1`'s 0.789 wherever it appears.** Grouping by `session_id` on the spring turns does
   not group by prompt; all 120 queries straddle folds.
4. **Fix `test_suite.py`'s benign check.** It still budgets against 148 sessions (1.4%); the measured
   rate on 1,081 is 3.0% [1.1, 5.5]. The test passes for the wrong reason.
5. **Get the worksheets filled.** 464 drafted adjudication rows (Chenhao 320, Sathwik 144) sit at 0%
   human completion. Hand labels are the project's scarcest resource and 965 is the whole supply;
   Sathwik's 144 rows would be the highest-value 144 labels on the team because they sit on 455
   distinct prompts we have never seen.
6. **Delete** `evidence/rederive/aura_honest.PRE_RERUN.joblib`, `models/aura_general.joblib`,
   `models/aura_final.joblib` (≈11 MB). **Keep** `aura_general.backup.joblib` — it is the evidence
   behind the retraction.
7. **Decide what to do about U5/U13/U15.** 226 collected sessions in three memory-poisoning and
   browser-attack corpora are excluded from every model, two of them by explicit audit decisions
   that are recorded but never revisited.
