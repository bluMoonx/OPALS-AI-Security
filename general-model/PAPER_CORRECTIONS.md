# PAPER_CORRECTIONS.md — authoritative correction table

Audit date: **2026-07-27**. Arm: paper-readiness audit. No modelling, no new claims.

Everything below was re-derived from the vetted loader
(`analysis/eval_combined_gold.load_all_gold`) or from the on-disk artifact that the claim
names. Where a document number could not be reproduced, that is stated rather than
patched over.

### Corpora I read while doing this

- **Documents and code only**: `OVERNIGHT_REPORT.md`, `WORKLOG.md`, `PROGRESS.md`,
  `RESULTS.md`, `PAPER_PLAN.md`, `analysis/compete/COMPETITION_ROUND2.md`,
  `analysis/make_figures.py`, `analysis/eval_combined_gold.py`,
  `analysis/resolve_gold.py`, `openclaw-plugin/scorer.py`,
  `analysis/compete/deferred_compliance.py` (signatures only), and the metadata blocks of
  `models/*.joblib`, `models/metrics_behavioral.json`,
  `analysis/compete/deferred_arm_results.json`, `analysis/ab_intervention_results.json`.
- **Gold**: scored **programmatically only**. I did not print, read or inspect a single
  `agent_response` string from gold1 or gold2. No feature or rule was authored here, so
  the STRICT slice is uncontaminated by this audit.
- I did **not** read `chenhao_release` or `collected_22category` response text either; I
  only counted rows, labels and distinct prompts in them.

### Reproduction preamble used by every "evidence command" below

```python
import sys, hashlib
sys.path.insert(0, "analysis"); sys.path.insert(0, "openclaw-plugin")
from eval_combined_gold import load_records, load_all_gold, metrics
gold = load_all_gold(load_records())
h = lambda g: hashlib.md5((g["_rec"].get("prompt") or "").strip().encode()).hexdigest()
g1p    = {h(x) for x in gold if x["_src"]=="gold1(orig)" and x["condition"]=="attack"}
oos    = [x for x in gold if x["_src"]=="gold2(new)"  and x["condition"]=="attack"]
strict = [x for x in oos if h(x) not in g1p]
```
Referred to below as **[PRE]**.

---

## 0. The four corrections that matter most

Ranked by how much damage they would do if they reached a reviewer uncorrected.

| # | claim | where | reality |
|---|---|---|---|
| **0.1** | "false-block rate on benign traffic **1.3 %**" | `RESULTS.md:281,283`, `PROGRESS.md:112`, `PAPER_PLAN.md:72` | **10.8 % (16/148)** for the gate as currently shipped. 1.3 % describes the labeler-only gate that has not been the shipped configuration since T25. **This number moved 8x in the wrong direction and no document says so.** |
| **0.2** | gate = "labeler ==1 OR deferred ≥ 5.5", OOS **P 0.9352 / R 0.5771** | `OVERNIGHT_REPORT.md:282,286-289` | Shipped gate also carries the global bar of 3 (`scorer.py:65 _GLOBAL_BAR = 3`). OOS **P 0.9218 / R 0.6400 (tp224 fp19)**; STRICT **P 0.9327 / R 0.5640 (tp97 fp7)**. The report's §7 table is one revision stale. |
| **0.3** | "detector **F1 0.874** / P 0.945 / R 0.812 / kappa 0.788" presented as *the* headline | `RESULTS.md:266`, `PROGRESS.md:92,223`, `PAPER_PLAN.md:104` | **In-sample on gold1 (n=146) only.** Out-of-sample: F1 0.6038 (671 rows). On prompts never seen: **F1 0.4435, R 0.2965** (288 rows). `WORKLOG.md:140` and `OVERNIGHT_REPORT.md:200` already withdraw it; RESULTS/PROGRESS/PAPER_PLAN still print it as the headline. |
| **0.4** | 300-label era everywhere: **43.7 % / 10.6 % / misses 76 % / kappa 0.256 / n=283 / n=300** | `RESULTS.md:134,141,142`; `PROGRESS.md:40,45,46`; `PAPER_PLAN.md:21-23,41,47,91,124` | Superseded by **n=817 attack rows of 965 gold**: ASR **50.7 % [47.2, 54.1]**, canary-derived **11.3 %**, canary **misses 326 of 414 = 78.7 %**, kappa **0.2005**, precision **0.9565**. |

---

## 1. Label / adjudication numbers

| claim as written | file:line | correct current value | evidence |
|---|---|---|---|
| "behavioral attack success rate **43.7%** (62/142)" | `RESULTS.md:141`, `PROGRESS.md:45` | **50.7 % (414/817)**, Wilson 95 % CI **[47.2, 54.1]** | [PRE] `atk=[g for g in gold if g["condition"]=="attack"]; sum(g["behavioral_label"] for g in atk)/len(atk)` |
| "canary-derived success **10.6%** (15/142)" | `RESULTS.md:142`, `PROGRESS.md:46` | **11.3 % (92/817)** fires; 88 of those are true positives | [PRE] `sum(1 for g in atk if g["_rec"].get("attack_succeeded"))` |
| "real compliances the canary missed **47 of 62 (76 %)**" | `RESULTS.md:143`, `PROGRESS.md:47`, `PAPER_PLAN.md:23,47` | **326 of 414 = 78.7 %** (report as 79 %) | `python3 analysis/eval_combined_gold.py` |
| "kappa = **0.256** on the attack slice" | `PAPER_PLAN.md:26,92` | **kappa 0.2005**, canary precision **0.9565**, recall **0.2126**, F1 0.3478 | `python3 analysis/eval_combined_gold.py` |
| "We hand-judged **283 sessions**" / "**300** hand-judged" / "5 independent labelers" | `RESULTS.md:134,359`; `PROGRESS.md:40,148`; `PAPER_PLAN.md:41` | **965 hand-judged records** (817 attack / 148 baseline), 417 positive; gold1 294 records from 5 labelers **plus** gold2 671 records from 12 labelers | [PRE] `len(gold)`, `Counter(g["_src"] for g in gold)` |
| per-category ASR: meta_prompting 83 %, delimiter 80 %, prompt_leaking 75 %, false_precedent 67 %, multilingual 42 %, cot_hijack 30 %, sleeper 27 %, role_spoofing 25 %, hypothetical 9 %, emotional 8 % | `RESULTS.md:149-160`; `PROGRESS.md:54-63`; `PAPER_PLAN.md:53-54` | **false_precedent 77.2 % (71/92), delimiter_confusion 72.1 % (49/68), meta_prompting 64.5 % (40/62), cot_hijack 58.7 % (37/63), prompt_leaking 58.3 % (35/60), sleeper_trigger 48.4 % (31/64), role_spoofing 43.1 % (28/65), multilingual_injection 42.6 % (26/61), emotional_coercion 34.5 % (51/148), hypothetical_framing 34.3 % (46/134)** | `python3 analysis/eval_combined_gold.py` (reproduced exactly, incl. every Wilson CI) |
| "**Task-laundering is the single most effective attack** (83 %)" | `RESULTS.md:162`, `PROGRESS.md:52` | **False precedent is (77.2 %).** meta_prompting is third at 64.5 %. The narrative sentence has to be rewritten, not just the number. | as above |
| "the ASR table supersedes the earlier 15-per-category figures" (interim n=706 table) | `WORKLOG.md:78-91` | Superseded again by the final n=817 table at `WORKLOG.md:117-130`. Do not quote the T6 block. | — |
| "297/300 resolved, 3 dropped → **295 records**" | `RESULTS.md:257-258` | `resolve_gold.py` reads **296** rows, resolves to **294** records, drops **4**. Positives 67; attack slice 146 with 64 positives. `PROGRESS.md:215` has this right. | `python3 analysis/resolve_gold.py` |
| "session_id duplication: **360 duplicates in 1,626 records**" | `PROGRESS.md:211` | Current corpus: **2,166 records, 1,271 distinct ids, 326 duplicated ids, max depth 9, 1,221 records (56.4 %) under a duplicated id** | `Counter(r["session_id"] for r in load_records())` |

---

## 2. Model / AUC numbers

| claim as written | file:line | correct current value | evidence |
|---|---|---|---|
| "5-fold CV behavioural labels RF **AUC 0.797** (sd 0.003) F1 0.704" | `WORKLOG.md:150,207` | **0.7427 (sd 0.0081)**, F1 **0.6532**, prompt-grouped `StratifiedGroupKFold(md5(prompt))`, 5-fold, 10 seeds. 0.797 is the leaky plain-KFold value and is retained only as the leak measurement. | `models/metrics_behavioral.json` → `cv_random_forest.auc` |
| "the first correction, **0.748**" (3 seeds) | `WORKLOG.md:239`, `OVERNIGHT_REPORT.md:90,192` | **0.7427**. 0.748 was a favourable 3-seed draw. Already withdrawn in-place, but it is still the number every competition arm names as "the T1 baseline". | same |
| competition target quoted as "**T1 AUC 0.748**" | `COMPETITION_ROUND2.md:24,28,129,252` | The live baseline is **0.7427 (sd 0.0081)**. `sog_main` measured it in-harness at **0.7443 (sd 0.0087)**. Any Δ against 0.748 is ~0.005 too small. | `models/metrics_behavioral.json`; `models/aura_behavioral_sog.joblib['metrics']['baseline_T1_same_harness']` |
| "canary control AUC **0.836**" | `WORKLOG.md:151,207,246`; `RESULTS.md:120` | **0.6882 (sd 0.0133)** under the same grouped protocol. 0.836 is the leaked figure. | `models/metrics_behavioral.json` → `canary_cv_random_forest.auc` |
| "logreg 0.691 / GB 0.721 (3 seeds)" | `WORKLOG.md:239-241` | logreg **0.6903 (sd 0.0050)** F1 0.5864 (below the 0.6035 floor); gradient_boost **0.7194 (sd 0.0136)** F1 0.6036 (at the floor) | `models/metrics_behavioral.json` |
| LOACO per-family table | `OVERNIGHT_REPORT.md:124-128` | Reproduces exactly from the artifact: emotional_coercion 0.8223, hypothetical_framing 0.8115, meta_prompting 0.7953, role_spoofing 0.6875, multilingual 0.6852, prompt_leaking 0.6786, sleeper_trigger 0.6484, delimiter_confusion 0.6393, false_precedent 0.5145, **cot_hijack 0.3065**; pooled **0.7117** | `models/metrics_behavioral.json` → `loaco_random_forest` |
| "trivial always-positive F1 floor **0.603**" | `OVERNIGHT_REPORT.md:106` | **0.60347** ✔ | `models/metrics_behavioral.json` → `trivial_f1_floor` |
| "cross-source **0.748** [0.679, 0.811]", "attack slice 0.773", "dedup 0.752", "gold 5-fold OOF 0.907" | `RESULTS.md:194-197`; `PROGRESS.md:79`; `PAPER_PLAN.md:60,104` | **0.699 (attack slice 0.727)** on the 965-row gold. The 0.748 family was measured on the retired 283-row gold. | `WORKLOG.md:163-175`; `OVERNIGHT_REPORT.md:201`. **No standalone artifact re-derives 0.699 — see §5.2.** |
| "response-only cross-source **0.602**" | `RESULTS.md:179,199,235`; `PROGRESS.md:78`; `PAPER_PLAN.md:60` | 12-science-feature cross-source RF is **0.6383** (recall@10%FPR 0.2014) on the 965-row gold | `models/metrics_behavioral.json` → `xsrc_random_forest` |
| "15-feature no-pair control **0.801**" and the whole ablation table | `RESULTS.md:210-214`; `PROGRESS.md:80` | Measured on the retired 283-row gold. **Not re-measured on the 965-row gold.** Unsupported at present. | — |
| "Train: **758 Chenhao sessions**" | `RESULTS.md:174` | `chenhao_release` is **1,314 rows** and contains **10 distinct `user_prompt` values** (max 374 rows on one prompt), 921 safe / 393 suspicious. Its effective diversity is ~10, not 758 or 1,314. | `wc -l data/logs/chenhao_release/*.jsonl`; `Counter(r["user_prompt"] for r in rows)` |
| "Chenhao's **758 rows** contain only 10 distinct prompts (75.8 rows per prompt)" | `OVERNIGHT_REPORT.md:255-256` | The 10-distinct-prompt finding is **confirmed**, but on **1,314 rows (131.4 per prompt)**. The 758 denominator is wrong. | as above |
| "true LOACO, canary-scrubbed **0.672 pooled out-of-fold**" | `RESULTS.md:122` | The artifact says **0.5019** pooled OOF (12 of 38 folds defined), and this is what `fig4` plots. **0.672 has no supporting artifact anywhere in the repo.** | `joblib.load("models/aura_honest.joblib")["pooled_oof_auc"]` |
| "recall **0.000** @ 10 % FPR" | `RESULTS.md:124` | Artifact says **recall@10%FPR = 0.0551**, recall@5%FPR = 0.050 | same bundle |
| "`aura_final.joblib` trained_on n=296; vetted is 294" | `WORKLOG.md:316`, `OVERNIGHT_REPORT.md:198` | Confirmed — bundle still records `trained_on: 'gold hand-judged records n=296 (pos 67) + chenhao n=1314'`. Model is not in the live path. | `joblib.load("models/aura_final.joblib")["trained_on"]` |
| SOG: "**0.8787** (sd 0.0016, 10 seeds)", "Δ +0.133, CI [+0.094, +0.174]", "permutation 0.478/0.490" | `COMPETITION_ROUND2.md:115-116,126` | Bundle records **0.8787 (sd 0.0011, seeds 0-4)**, paired Δ **0.1343, CI [0.0868, 0.1667]**, permutation **0.490**. Seed count and CI as printed do not match the artifact. | `models/aura_behavioral_sog.joblib["metrics"]` |
| "n=971 retrain" | `WORKLOG.md:190-209` | **965.** Already fixed; listed so nobody resurrects it. | `len(load_all_gold(load_records())) == 965` |
| "**0.905** ROC-AUC" and "0.95 / 0.94 bal-acc" comparisons | `RESULTS.md:109,120`; `PROGRESS.md:202,225`; `PAPER_PLAN.md:103,107` | Correctly withdrawn everywhere. Keep the withdrawal; do not resurrect the numbers as anything but a cautionary example. | — |

---

## 3. Gate / operating-point numbers

All of the following reproduce **exactly** against the live plugin code path
(`openclaw-plugin/behavioral_labeler.score_session` + `deferred_compliance.deferred_score_ungated`).

| configuration | OOS (n=671, 350 pos) | STRICT (n=288, 172 pos) | gold1 (n=146, 64 pos) |
|---|---|---|---|
| labeler alone | P 0.9235 R 0.4486 F1 0.6038 tp157 fp13 | P 0.8793 R 0.2965 F1 0.4435 tp51 fp7 | P 0.9455 R 0.8125 F1 0.8739 |
| + global bar 3 | P 0.9151 R 0.5543 F1 0.6904 tp194 fp18 | P 0.9176 R 0.4535 F1 0.6070 tp78 fp7 | P 0.9464 R 0.8281 F1 0.8833 |
| + deferred ≥ 5.5 | P 0.9352 R 0.5771 F1 0.7138 tp202 fp14 | P 0.9205 R 0.4709 F1 0.6231 tp81 fp7 | P 0.9298 R 0.8281 F1 0.8760 |
| **BOTH (SHIPPED)** | **P 0.9218 R 0.6400 F1 0.7555 tp224 fp19** | **P 0.9327 R 0.5640 F1 0.7029 tp97 fp7** | P 0.9310 R 0.8438 F1 0.8852 |

| claim as written | file:line | correct current value | evidence |
|---|---|---|---|
| gate = "labeler ==1 OR deferred ≥ 5.5"; OOS P 0.9352 R 0.5771 tp202 fp14 | `OVERNIGHT_REPORT.md:282,286-289` | Shipped gate is **labeler ==1 OR score ≥ 3 OR deferred ≥ 5.5** → **P 0.9218 R 0.6400 tp224 fp19** | `scorer.py:65,111` + table above |
| "**45 extra true detections for one extra false positive**" | `OVERNIGHT_REPORT.md:291-292` | True for the deferred-only revision (157→202 tp, 13→14 fp). For the **shipped** gate vs labeler alone it is **+67 tp for +6 fp** on OOS, and **+46 tp for 0 fp** on STRICT. | table above |
| "recovers **39** true compliances for 1 new false positive" | `OVERNIGHT_REPORT.md:303` | Internally inconsistent with the 45 on `:291` in the same section. Neither describes the shipped gate. Use **+67 / +6 (OOS)** or **+46 / +0 (STRICT)**. | table above |
| "SHIP: change the no-injection threshold 6 → 3. Takes the gate from P 0.924/R 0.449 to P 0.915/R 0.554" | `COMPETITION_ROUND2.md:37-101,302-306` | Correct as measured, but **superseded**: the shipped gate is the union of the bar-3 rule *and* the deferred channel. Quoting §2.1/§5.1 as "what shipped" understates recall by 0.086 (OOS) and 0.111 (STRICT). | table above |
| "STRICT slice **n = 280** (172 pos)" | `COMPETITION_ROUND2.md:65,69,201,206,226,334` | **n = 288** (172 pos), 116 prompt groups. Positives are right; the row count is not. `WORKLOG.md:485` and the current brief use 288. | [PRE] `len(strict)` |
| "T3's honest baseline for prompt-level generalisation is **0.297**" | `COMPETITION_ROUND2.md:288-292` | Confirmed: labeler STRICT recall **0.29651** at precision 0.8793. | table above |
| "`sol_secret_request` is recovered at **0.119** vs a 0.155 base rate — nothing detects it" | `COMPETITION_ROUND2.md:279-286` | **Superseded.** Under the shipped gate, solicitation recall is **0.836 OOS / 0.781 STRICT**. | reproduced independently; see §3.1 |
| "canary on the same 671: P 0.948 / R 0.209" | `COMPETITION_ROUND2.md:294-296` | Not separately re-derived here. On all 817 attack rows the canary is P 0.9565 / R 0.2126. Consistent. | `analysis/eval_combined_gold.py` |
| "**17 / 17 tests passing**" | `RESULTS.md:301,355`; `PROGRESS.md:193,248`; `OVERNIGHT_REPORT.md:218,246` | **21 passed, 0 failed, 0 skipped** | `python3 openclaw-plugin/test_suite.py` |
| "**20/20 tests pass**" | `OVERNIGHT_REPORT.md:332` | **21/21** | same |
| "false-block rate on benign traffic **1.3 % (2/149)**" | `RESULTS.md:281,283`; `PROGRESS.md:112`; `PAPER_PLAN.md:72` | Labeler alone: **2/148 = 1.4 %**. **Shipped gate: 16/148 = 10.8 %.** Attribution of the 16: bar-3 only 6, deferred only 7, both 1, labeler+bar 2. | see §3.2 |
| "no false BLOCKS on benign traffic — 0/8" / "0/5 false positives on benign work" | `test_suite.py` output | True but on **8 and 5 synthetic benign prompts**. It is not a substitute for the 148 hand-judged baseline sessions, and it is what has been masking correction 0.1. | `python3 openclaw-plugin/test_suite.py` |
| "deployed labeler drifted, 558 lines vs 790" | `WORKLOG.md:413-424`; `OVERNIGHT_REPORT.md:314-318` | **Fixed and verified**: both files are 790 lines and sha256 `ec437e52…805b3`. | `shasum -a 256 openclaw-plugin/behavioral_labeler.py analysis/rebuild/behavioral_labeler.py` |
| "Residual after the shipped rule on OOS: **455 rows called SAFE**" | (competition brief, not a repo file) | **428** rows called safe (671 − 224 tp − 19 fp), of which **126** are true compliances. The 126 is right. | table above |
| precision arithmetic: R 0.70 → recover 21, FP budget 8.2, residual P ≥ 0.72; R 0.75 → recover 38, budget 10.1, ≥ 0.79 | `WORKLOG.md:515-517` | **Arithmetic verified** at tp224/fp19 against a 0.90 floor. | `(224+a)/(224+a+19+b) ≥ 0.90` |

### 3.1 Evidence-family recall (WORKLOG T27) — independently reproduced

| failure mode | n (OOS) | OOS recall | STRICT n | STRICT recall |
|---|---|---|---|---|
| SOLICITATION (`r_solicit_target`) | 61 | 0.836 | 32 | 0.781 |
| CONDITIONAL COMMIT | 24 | 1.000 | 12 | 1.000 |
| FIELD-SLOT emission | 46 | 0.891 | 16 | 0.938 |
| APPROVAL-GATE pushing | 29 | 0.793 | 20 | 0.750 |
| BLOCKED ATTEMPT (env accident) | 132 | 0.780 | 67 | 0.731 |
| STATE DUMP / SELF-MOD | 1 / 2 | 1.000 | 0 | — |
| **NO deferred evidence at all** | **152** | **0.480** | **75** | **0.373** |

`WORKLOG.md:527-535` reproduces to three decimals. One correction: it prints
"STATE DUMP / SELF-MODIFICATION n=3"; the split is **1 state-dump and 2 self-mod**, both
too small to carry a published recall.

### 3.2 The benign false-block regression, in full

```python
# [PRE], then:
base = [g for g in gold if g["condition"] != "attack"]          # 148 rows, 3 truly unsafe
import behavioral_labeler as BL
from deferred_compliance import deferred_score_ungated as D
fp = lambda pred: sum(1 for g,p in zip(base,pred) if p and g["behavioral_label"]==0)
```

| gate configuration | fires on 148 benign | false blocks | rate |
|---|---|---|---|
| labeler alone (the published 1.3 %) | 5 | 2 | **1.4 %** |
| + global bar 3 | — | 9 | 6.1 % |
| + deferred ≥ 5.5 | — | 10 | 6.8 % |
| **BOTH (shipped)** | 19 | **16** | **10.8 %** |

This is the only place in the project where the shipped configuration is **worse** than
the published one, and no document currently records it.

---

## 4. Corpus, action-recovery and infrastructure counts

Every count below is a **snapshot**; the collector appends to
`newcats_sessions.jsonl` continuously. Gold `line_idx` remains valid only because all
labelled rows sit at index ≤ 1923 and everything since is a pure append
(`python3 analysis/check_gold_integrity.py` → `GOLD INTEGRITY: OK`, prefix hash
`bbc654c657c78d3e…` unchanged).

| claim as written | file:line | correct value (2026-07-27) | evidence |
|---|---|---|---|
| 10-category sessions **1,601** | `RESULTS.md:327` | **2,166** | `wc -l data/logs/collected_new10category/newcats_sessions.jsonl` |
| 10-category sessions **1,924** | `PROGRESS.md:144,223` | **2,166** | same |
| 10-category sessions **1,974** "and growing" | `OVERNIGHT_REPORT.md:227` | **2,166** | same |
| "distinct trials with actions **405**" | `RESULTS.md:42`; `PROGRESS.md:174,250`; `PAPER_PLAN.md:65` | Not reproducible. The recovered artifact has **366 distinct `session_id`s carrying actions** over **794 enriched rows**. `OVERNIGHT_REPORT.md:176` claims 660 — also not reproducible from the artifact. **Define "distinct trial" or drop the number.** | `data/logs/collected_new10category/newcats_actions_recovered.jsonl` |
| "rows enriched **769**" | `RESULTS.md:43`; `PROGRESS.md:145,175`; `PAPER_PLAN.md:65` | **794** (matches `OVERNIGHT_REPORT.md:177`) | same file, `sum(1 for r in rows if r["actions"])` |
| "out-of-scope actions **680**" | `RESULTS.md:45,50`; `PROGRESS.md:176,206,250`; `PAPER_PLAN.md:65` | **1,297 out-of-scope action records**, spread over **417 enriched rows**. `OVERNIGHT_REPORT.md:203` says 1,059 — also stale. | `sum(r["n_out_of_scope"] for r in rows)` |
| "action records **5,230**" | `OVERNIGHT_REPORT.md:178` | **5,346** | `sum(len(r["actions"]) for r in rows)` |
| action kinds "file_read 318, shell 212, file_write 132, memory_read 108, other 89, network 52, file_delete 2" | `RESULTS.md:44`; `PROGRESS.md:177` | **shell 1745, file_read 1365, network 801, other 623, file_write 587, memory_read 221, file_delete 4** | `Counter(a["kind"] for r in rows for a in r["actions"])` |
| boundary split | (implied by Fig. 3 discussion) | **action_manifesting 794 / text_or_state 1,139** of 1,933 recovered rows | `Counter(r["boundary"] for r in rows)` |
| raw container logs **1,188** | `PROGRESS.md:150` | **4,008 files** | `find data/logs/container_sessions -type f \| wc -l` |
| raw container logs **942**; "re-harvested 588 → 942" | `OVERNIGHT_REPORT.md:172,180,232` | **4,008 files** | same |
| "1,271 distinct session_ids exist in newcats" | `OVERNIGHT_REPORT.md:180` | **Still exactly 1,271** ✔ (of 2,166 records) | `len({r["session_id"] for r in load_records()})` |
| Chenhao release **1,314** | `RESULTS.md:328`; `PROGRESS.md:146`; `OVERNIGHT_REPORT.md:230` | **1,314** ✔ (614 deepseek + 700 kimi), labels safe 921 / suspicious 393 | `wc -l data/logs/chenhao_release/*.jsonl` |
| 22-category **82 sessions, 41 attack, 16 successful, 0.390, CI [0.257, 0.543] width 28.6 pts, 23 categories** | `RESULTS.md:13-18`; `PROGRESS.md:163` | **All confirmed exactly.** 82 rows, 41 `benign` + 41 attack across 23 attack categories, 16 `suspicious`. | `Counter(r["attack_category"] for r in rows)` |
| prompt bank **500 (50/category × 10)** / "500 pairs = 1,000 prompts" | `PROGRESS.md:149`; `OVERNIGHT_REPORT.md:231` | **Confirmed**: 500 lines, each with `attack_prompt` + `baseline_prompt`, exactly 50 per category × 10 categories, and **exactly 320 distinct `domain` values** ✔ | `wc -l data/prompts/new_categories_bank.jsonl`; `len({r["domain"] for r in rows})` |
| clean corpus **2,303** | `PROGRESS.md:154` | **2,303** ✔ but it is a **frozen rebuild** (`analysis/rebuild/corpus_clean.jsonl`, newcats 1,577 / chenhao 651 / scigw22 75, 363 positives) whose newcats labels come from the deterministic labeler, not from gold. It is ~600 newcats rows behind the live corpus. | `wc -l analysis/rebuild/corpus_clean.jsonl` |
| Spring turns **1,998**, 22-cat turns **248** | `RESULTS.md:331,330`; `PROGRESS.md:151,152` | **Confirmed** (1,000 + 998; 248). Both correctly excluded. | `wc -l` |
| "**3 figures**" / "figures | **4**" | `PROGRESS.md:156`; `OVERNIGHT_REPORT.md:233` | **5 live PNGs** + 1 `.withdrawn` | `ls figures/` |
| live gateway counters "1,177 scored → 1,053/118/6" and "1,306 scored → 1,125/167/14" | `RESULTS.md:85`; `PROGRESS.md:32,136` | Two different snapshots of the same counter presented as if both current, in the same repo state. Neither is reproducible after the fact. **Attach a timestamp or drop.** | — |
| A/B intervention 12/12 vs 3/12, Fisher p = 0.00034 | `OVERNIGHT_REPORT.md:16-20`; `WORKLOG.md:61-67` | **Confirmed exactly** (p = 0.000336519) | `analysis/ab_intervention_results.json` |

---

## 5. Figure audit — re-derived, one at a time

> The table below is the audit **as found**. All three defects it names were fixed on
> 2026-07-27; see **§5.1** for what was done and the numbers re-derived off each
> regenerated PNG. Do not act on the "must be regenerated" / "do not publish" verdicts
> without reading §5.1 first.

| figure | claims on the face of it | verdict |
|---|---|---|
| `fig1_label_undercount.png` | n=817; canary 11.3 % (92/817) vs behavioral 50.7 % (414/817); title "canary misses 326 of 414 = …" | **Numbers correct.** **But the title is CLIPPED** — the rendered PNG cuts off at "= " and the reader never sees "79 %". `make_figures.py:74-76` builds a two-line title too wide for `figsize=(4.6, 3.4)`. **Misleading as rendered; must be regenerated with a wider figure or a shorter title.** |
| `fig2_per_category_asr.png` | all ten k/n pairs and percentages | **Fully correct.** Every bar matches the vetted per-category table to the integer. No action. |
| `fig3_corpus.png` | "Rebuilt corpus: 2303 sessions, 363 unsafe (16 %)"; newcats ~1,577 | **MISLEADING — do not publish.** (a) It plots the frozen `corpus_clean.jsonl`, ~600 newcats rows behind the live corpus. (b) The "16 % unsafe" is a **machine-labeler** rate on a corpus whose newcats labels are not gold, and it sits in the same paper as a headline saying the true adjudicated ASR is **50.7 %**. A reader will read 16 % as the attack-success rate. Either relabel the axis "sessions flagged by the deterministic labeler" or withdraw. |
| `fig4_honest_vs_inflated.png` | 0.905 "reported (invalid)" / 0.836 "canary-leaked protocol" / **0.502 "honest (true LOACO)"** | **MISLEADING — do not publish as-is.** The 0.502 is `aura_honest.joblib`'s pooled OOF over a **canary-era 38-category corpus**, defined on only 12 of 38 folds. It contradicts `RESULTS.md:122`, which says 0.672 for the same claim (0.672 has no artifact). It also invites the reader to take 0.502 as "the honest AURA number", when the current honest numbers are **0.7427 grouped / 0.7117 LOACO on behavioural labels**. The whole panel is one label generation out of date. Replace with `fig5_protocol_ladder.png`, which tells the same story correctly. |
| `fig5_protocol_ladder.png` | left: 0.797 plain KFold / 0.743 prompt-grouped / 0.712 LOACO, "leak −0.055"; right: per-family LOACO 0.82…0.31 | **Fully correct.** Every value matches `models/metrics_behavioral.json` to two decimals (0.7427→0.74, 0.7117→0.71, cot_hijack 0.3065→0.31, false_precedent 0.5145→0.51). Reads its numbers out of the shipped joblib, so it cannot drift. **This is the model figure to publish.** |
| `fig6_ab_intervention.png` | 12/12 vs 3/12, Fisher p = 0.00034, filesystem outcome | **Correct** against `ab_intervention_results.json`. **Caption obligation:** the A/B tested the literal string `rm -rf`, which is the one spelling the pre-`T23` rule layer caught. It measured one spelling, not the capability (`WORKLOG.md:430-453`). Publishing the panel without that sentence overstates what was demonstrated. |
| `fig5_transfer_and_safety.png.withdrawn` | n=89 baseline / n=84 attack, cross-source 0.602 | Correctly withdrawn. **`PAPER_PLAN.md:62,73` still cites it as a deliverable — remove those references.** |

### 5.1 Resolution of the three §5 defects — done 2026-07-27 12:44, re-verified off the rendered PNGs

All three were fixed in `analysis/make_figures.py`; `fig2` regenerated **byte-identical**
(md5 `58c12bc57266c5aba6fcfd3d53c3815c` before and after), confirming the edit touched
nothing it should not. `openclaw-plugin/` was not modified; `test_suite.py` re-run anyway:
**22 passed, 0 failed**. `make_figures.py` is idempotent — a second run is a no-op on the
retired files.

| defect | action taken | verified off the rendered PNG |
|---|---|---|
| **1. `fig1` title clipped** | `figsize` 4.6×3.4 → 6.6×3.8; the second title line is now a separate `ax.text` at `y=1.015` so `tight_layout` reserves room for it. Finding kept verbatim. | The subtitle now reads in full: **"n=817 hand-judged attack sessions; canary misses 326 of 414 = 79%"**. Bars: 11.3 % (92/817), 50.7 % (414/817). Re-derived from `load_all_gold` at 2026-07-27 12:42 — n 817, canary 92 (11.2607 %), behavioural 414 (50.6732 %), canary∧behavioural tp 88, missed 414−88 = 326, 326/414 = 78.744 % → 79 %. Exact. |
| **2. `fig3_corpus.png` misleading** | **Withdrawn** → `fig3_corpus.png.withdrawn`, and replaced by a new **`fig3_corpus_provenance.png`** built from the live source files. Argument for replacing rather than merely relabelling: the "unsafe" series was not one labeler but **three incomparable heuristics pooled under one legend entry** — `deterministic_behavioral_labeler` (newcats, 1577), `chenhao_risk_indicator_or` (chenhao, 651), `scigateway_heuristic` (scigw22, 75); `label_origin` confirms all 2303 rows are machine-labelled and **zero are adjudicated**. An honest axis label would have had to say "three different unvalidated heuristics, pooled", at which point the series carries no interpretable quantity. So the machine-label series was deleted outright and replaced with the one provenance fact the paper actually needs: how much of the evidence base is hand-adjudicated. The new panel plots **only line counts and loader counts** and carries no rate at all. | Face of the new figure: newcats **2166** collected / **965** hand-adjudicated; chenhao_release **1314** / **0**; collected_22category **82** / **0**; stamp "snapshot 2026-07-27 (newcats collector is live; file mtime 2026-07-27 06:43). No machine labels plotted." Re-derived: `wc -l` = 2166 / 1314 / 82; `len(load_all_gold(load_records()))` = 965; the generator asserts every gold `line_idx` falls inside newcats, so the 0/0 are structural, not assumed. Staleness of the old figure quantified: `corpus_clean.jsonl` was frozen at mtime 2026-07-26 15:03 with 1601 raw newcats rows, i.e. **565 raw rows behind** the live 2166. |
| **3. `fig4_honest_vs_inflated.png` misleading** | **Retired** → `fig4_honest_vs_inflated.png.withdrawn`. `fig_honest_vs_inflated()` deleted from `make_figures.py`; it can no longer be regenerated, and the module docstring records why. No replacement panel is generated here — `fig5_protocol_ladder.png` already tells the story from the current artifact. | Confirmed absent from the generator's output list (`generated 3 figures`: fig1, fig2, fig3_corpus_provenance) and the PNG no longer resolves under its published name. |

---

## 6. What is SAFE to publish today, ranked by strength of evidence

1. **Canary/marker-echo labelling under-counts behavioural attack success ~4.5×.**
   n=817 hand-judged attack sessions; canary fires 11.3 %, true ASR 50.7 % [47.2, 54.1];
   canary precision 0.9565, recall 0.2126, kappa 0.2005; misses 326 of 414 = 79 %.
   Reproduced by a single vetted script, two independent adjudication passes, and this
   audit. Figure: `fig2` (clean), `fig1` (after the title is fixed).
   *This is the paper's strongest contribution and it is fully evidenced.*

2. **Per-category behavioural ASR, n=817, with Wilson CIs.** All ten rows verified
   exactly. Publish the table, not the old 15-per-category one, and rewrite the
   "task-laundering is the most effective attack" sentence — it is **false precedent**
   (77.2 %).

3. **The prompt-duplication leak and the protocol ladder.** 965 records over 285 distinct
   prompts (3.39 trials each); plain KFold 0.797 → prompt-grouped 0.743 → LOACO 0.712;
   leak scales with model capacity (logreg −0.018, RF −0.055, GB −0.058). Every number is
   in a machine-written artifact and `fig5_protocol_ladder.png` renders it correctly.

4. **The negative result: cot_hijack LOACO 0.31, false_precedent 0.51.** Verified from
   the artifact. Publish it — it is the most credible thing in the report precisely
   because it is against interest. Pair it with the fact that false_precedent is
   simultaneously the highest-ASR family.

5. **F1 must be read against the 0.603 trivial always-positive floor**, and only random
   forest (0.653) clears it. Verified.

6. **The gate's out-of-sample and never-seen-prompt operating points.** OOS
   P 0.9218 / R 0.6400 (tp224 fp19); STRICT P 0.9327 / R 0.5640 (tp97 fp7); labeler-alone
   baselines P 0.9235/R 0.4486 and P 0.8793/R 0.2965. Every cell reproduced here from the
   live plugin code path. **Publish only with the 10.8 % benign false-block rate attached**
   (§0.1) — the recall claim and the cost claim are the same claim.

7. **The deterministic labeler does not generalise.** In-sample F1 0.874 → OOS 0.604 →
   STRICT 0.444; kappa 0.399 OOS, far below the 0.70 propagation bar. Precision holds
   (0.9235 OOS, 0.8793 STRICT), which is why the block path survives. Verified.

8. **The A/B intervention**, 12/12 vs 3/12, Fisher p = 0.00034, filesystem-measured, with
   the `rm -rf`-spelling caveat stated in the caption (see §5).

9. **22-category collection is coverage, not a rate**: 16/41, CI [0.257, 0.543], 28.6-pt
   width. Verified exactly.

10. **Evidence-family recall of the shipped gate** (§3.1), including the honest weak spot:
    compliances carrying none of the seven evidence families are recovered at 0.480 OOS /
    0.373 STRICT. Reproduced here.

11. **Process findings, all verified on disk**: `session_id` is not a join key (326
    duplicated ids, depth up to 9, 56.4 % of records); deployed-vs-measured labeler drift
    (now sha256-identical, test-enforced); the flag-order denylist hole (regression test
    present, 21/21 passing); grouped CV does not defend against author contamination.

---

## 7. What is NOT safe to publish yet, and what each still needs

| claim | why it is not safe | measurement required |
|---|---|---|
| **"1.3 % false-block rate on benign traffic"** | The shipped gate is at **10.8 %**. Publishing 1.3 % beside R 0.64 misdescribes the system. | Decide the operating point deliberately. Either publish 10.8 % with the recall, or measure a gate variant that keeps the recall at an acceptable benign cost, on a benign set larger than 148. |
| **cross-source 0.699 / 0.727** | Asserted in `WORKLOG.md:163-175` and `OVERNIGHT_REPORT.md:201` with **no artifact, no script output, and no CI** anywhere in the repo. | Re-run the 62-feature prompt-response cross-source sweep against `load_all_gold`, save a results JSON, and report a CI resampling **prompt groups** — noting that Chenhao supplies only 10 distinct prompts, so the effective n is ~10. |
| **cross-source 0.748 / 0.773 / 0.752 / 0.801 / the 62-vs-15-feature ablation** | Measured on the retired 283-row gold. | Re-measure the whole ablation table on the 965-row gold, or delete the section. |
| **"true LOACO 0.672"** | Contradicted by the artifact (0.502). One of the two is wrong and nobody knows which. | Re-run the canary-scrubbed LOACO and keep the output, or withdraw both numbers and cite `fig5_protocol_ladder` instead. |
| **deferred_compliance T1 AUC 0.853, Δ +0.170** (`WORKLOG.md:399`; `OVERNIGHT_REPORT.md:271-275`) | On gold2-only prompts the gain is **+0.027, CI [−0.014, +0.072] — contains zero** (`COMPETITION_ROUND2.md:199-208`). The repo simultaneously calls this arm the round's WINNER and says its generalisation claim does not survive. | Either report it as **operating-point-only** (which does survive on STRICT) or measure the AUC claim on a larger contamination-free slice. Never publish +0.17 as a generalising gain. |
| **"unfitted hand-weighted score reaches AUC 0.842 with zero training"** | I reproduced it (0.8419 all-965; 0.8723 attack slice; permutation control 0.504 — harness sound). But it is measured on all 965 rows, **including the 685 whose prompts the feature author's taxonomy came from**. | Report the same number on STRICT before publishing it as evidence of generality. |
| **action-recovery counts (405 / 660 / 769 / 794 / 680 / 1,059 / 5,230)** | Five mutually inconsistent sets across four documents; only "794 enriched rows" survives contact with the artifact. | Fix the definition of "distinct trial", re-run `recover_actions.py`, and quote one set from one artifact with a timestamp. |
| ~~**`fig3_corpus.png` and `fig4_honest_vs_inflated.png`**~~ | ~~See §5.~~ | **CLOSED 2026-07-27** — both withdrawn to `.withdrawn`, `fig4` no longer generated, `fig3` replaced by `fig3_corpus_provenance.png`. See §5.1. |
| **PAPER_PLAN.md as a whole** | It is a **300-label-era document**. §A, B1, B2, B3, B4, B5, B6, C1, C2, D1 all quote superseded numbers (43.7/10.6/76 %, kappa 0.256, 83 %/80 %/75 %/67 %, 0.602/0.748/0.801, 405/769/680, 1.3 %, F1 0.874), and B4/B6 cite a withdrawn figure. | Rewrite against this file before any of it goes into the draft. Do not edit it number-by-number; the framing changed too. |
| **live gateway counters** | Two conflicting snapshots, unreproducible. | Snapshot once, timestamp it, and quote that one. |
| **"Anomaly-from-normal 0.798 vs 0.863"; "ensembling is worse, 0.817 vs 0.874"; "91 engineered features"; "verification-collapse 0.98"** (`RESULTS.md:340-348`; `PROGRESS.md:207-208`; `PAPER_PLAN.md:78-82`) | All measured against **canary-era or in-sample** labels. The 0.874 comparator is in-sample. | Re-measure under the grouped protocol on behavioural labels, or present them as historical process notes rather than results. |
| **`fig6` A/B as a capability claim** | It measured one spelling of `rm -rf`. | Either caption it precisely, or re-run the A/B against the post-fix regex over the 9 destructive spellings. |

---

## 8. Documents ranked by how much editing they need

| document | state |
|---|---|
| `analysis/compete/COMPETITION_ROUND2.md` | **Mostly sound.** Fix STRICT n 280→288 throughout, note that §2.1/§5.1's ship recommendation was superseded by the union rule, and mark §4's `sol_secret_request` bullet as closed. |
| `OVERNIGHT_REPORT.md` | **Sound in §1–§4, stale in §5 and §7.** Fix the gate rule and its table, 17/17→21/21, 20/20→21/21, corpus/log/figure counts, and the 39-vs-45 inconsistency. |
| `WORKLOG.md` | Append-only and honest; early entries (T8, T9, T13) are superseded **in the same file** by T16/T25. Safe as a lab record, unsafe to quote by line without checking for a later entry. |
| `RESULTS.md` | **Half of it is pre-adjudication.** §1, §2, §3.2, §3.3, §5 all need replacing. §0's withdrawal notice, the 22-category section and the live-transcript section are fine. |
| `PROGRESS.md` | Same as RESULTS.md; F1–F4 are all superseded. |
| `PAPER_PLAN.md` | **Fully stale.** Rewrite, do not patch. |

---

## 9. ADDENDUM 2026-07-27 — the benign false-block rate, measured on 1,081 rows not 148

Correction **0.1** above was derived from the 148 hand-judged baseline sessions, which is
all the audit had. The corpus in fact holds **1,081 baseline-condition rows over 204
distinct benign prompts**; 933 were never hand-judged. A baseline session carries no
injected attack, so a block on one is almost certainly a false block, which makes the raw
block rate over all 1,081 a defensible **upper bound** with no new adjudication. It is
loose by roughly 2.0%, since 3 of the 148 judged baseline rows were themselves judged
COMPLIED.

| policy | blocked / 1081 | rate | bootstrap 95 % (PROMPT groups) | the old 148-row figure |
|---|---|---|---|---|
| off (labeler alone) | 31 | **2.9 %** | [1.0, 5.3] | 1.4 % |
| **strict (shipped default)** | **32** | **3.0 %** | [1.1, 5.5] | 1.4 % |
| balanced | 53 | 4.9 % | [2.2, 8.3] | 4.1 % |
| aggressive | 130 | 12.0 % | [8.0, 16.2] | 11.5 % |

CIs bootstrap the **204 prompt groups**, not the rows. Benign prompts repeat, so a
row-level Wilson interval is too narrow; it is shown in the source output only for
comparison.

### What this changes

1. **A NEW correction, which supersedes 0.1's own replacement value.** The published
   "1.3 % false-block on benign traffic" is wrong *even for the labeler-alone configuration
   it describes*. On 7× more data that configuration is **2.9 % [1.0, 5.3]**. Neither 1.3 %
   nor 1.4 % should appear in the paper.
2. **`strict` is confirmed near-free on real evidence.** It costs exactly **one** extra
   block out of 1,081 over `off` (31 → 32) while buying +0.085 OOS recall and +0.075 STRICT
   recall. On 148 rows the two were indistinguishable; on 1,081 the cost is measurable and
   it is one row.
3. **`aggressive` is confirmed unusable** (12.0 %, CI [8.0, 16.2]) and **`balanced`
   (4.9 %)** is the only defensible step up from the default.

### The methodological point, which is worth publishing

The 148-row sample was not merely noisy, it was **biased low** where it mattered: 1.4 % vs
2.9 % for off/strict, while being roughly right for balanced (4.1 vs 4.9) and aggressive
(11.5 vs 12.0). A 148-row benign set cannot certify a rate near 1 %. Any paper reporting a
low false-positive rate on a benign set of that size is reporting a number its sample
cannot support, and this project did exactly that for weeks.

Attribution over all 1,081 benign rows under `aggressive`: labeler fires 31, global bar
only 40, deferred only 59.

Reproduce: `python3` on the corpus via `load_all_gold`/`load_records`, scoring
`scorer._compliance_layers` with `scorer.BLOCK_POLICY` set per policy; script preserved at
`analysis/measure_benign_wide.py`.
