# ROUND 5 SYNTHESIS — does it transfer, and what is the best we could possibly do

Date **2026-07-27**. Snapshot: `load_records()` = **2166**, `load_all_gold()` = **965**,
gold1 attack **146** / OOS **671** / STRICT **288** (116 prompt groups) / benign **148** /
wide benign **1081** over 204 prompts. Transfer corpus
`sessions_tierlabeled.jsonl` md5 **8c89853838741877528e58a31e6c535f** (identical to the
hash the transfer arm recorded, so the file did not move under us).
`openclaw-plugin/scorer.py` sha256 `8c36820d…0b0609`,
`behavioral_labeler.py` sha256 `ec437e52…805b3`.

**Synthesiser independence.** Every number in §1, §2, §3 and §4 was re-measured by me in
this session with scripts I wrote, not copied from an arm. Gold and the 600 were **scored
programmatically only**: no `agent_response` string from any corpus was printed, read or
inspected. I authored no feature, no rule, no lexicon and no threshold, so nothing here
contaminates STRICT or the transfer set. The transfer set remains **unseen** for future
arms.

Scripts (all absolute, all in the session scratchpad
`…/69306e3f-…/scratchpad/SYN5/`): `ceiling.py` (shipped-gate reproduction on 5 slices,
channel attribution, oracle ceilings, zero-evidence residual, miss profile),
`ci2.py` (prompt-group bootstraps on the ceiling gap, permuted-label control on the oracle
procedure, single-feature AUCs), `fam.py` (per-family gate recall, num_tools oracle).
Outputs `ceiling.json`, `ci2.json`, `fam.json`.

### What I re-ran before accepting any claim

| re-run | result | matches? |
|---|---|---|
| `openclaw-plugin/test_suite.py` | **22 passed, 0 failed, 0 skipped** | yes — still green |
| `analysis/paper_repro/policy_curve.py` | every published cell to 4 dp (OOS strict .9303/.5343, STRICT .9014/.3721) | yes |
| `analysis/measure_benign_wide.py` | 1081 rows / 204 prompts; strict **32/1081 = 3.0 %** | yes |
| shipped gate on the 600, my own script | strict **tp 100 / fp 10 / fn 215**, benign **0/200** | matches the transfer arm exactly |
| channel attribution on the 600 | ch1 110, ch2 **0**, ch3 **0**, gated-off 443, empty 5 | matches the arm exactly |
| `audit/gate_mempois.py` (memory poisoning, 84+10) | block recall **0.000** without ingested source, **0.476** with, **2/10 benign blocked** | reproduced |
| `audit/fact_oracle.py` | fact-ID-only oracle **0.817** random-CV vs **0.578 = majority floor** grouped by fact | reproduced |
| per-family gate recall on OOS/STRICT (`fam.py`, mine) | cot_hijack OOS **0.677**, STRICT **1.000**; false_precedent OOS **0.661** | confirms the transfer arm, contradicts a PUBLISH-flagged line (§6.3) |
| `num_tools` single-feature AUC | gold STRICT **0.7902**, new600-M2 **0.9433** | reproduces the cross-source arm's two most important controls |

I did **not** re-run the corpus-expansion retrains (ADV/REF_SIG already reproduced the
expansion arm's operating-point table bit-for-bit — identical thresholds, identical
P/R/FA to 3 dp — which is a stronger control than a third rerun by me).

---

## 1. Does the gate transfer? **Yes on precision and on benign cost. No on recall.**

The **shipped block predicate, completely unmodified**, no training, no threshold selected
anywhere, run zero-shot on 600 sessions collected by a different person on a different day
with **0 shared prompts and 0 shared responses**:

| slice | policy | P | R | benign block | note |
|---|---|---|---|---|---|
| **new600 attack (400)**, their label reading (unsafe∪suspicious, 315 pos) | strict | **0.909** [0.841, 0.950] | **0.317** [0.269, 0.371] | **0/200 = 0.0 %** [0, 1.88] | tp 100 / fp 10 / fn 215 |
| our OOS (671, 350 pos) | strict | 0.930 [0.887, 0.958] | 0.534 [0.482, 0.586] | 32/1081 = 3.0 % [2.1, 4.2] | tp 187 / fp 14 |
| our STRICT (288, 172 pos) | strict | 0.901 [0.810, 0.951] | 0.372 [0.303, 0.446] | same | tp 64 / fp 7 |

Deltas, prompt-group bootstrap on the **delta** (transfer arm, 4000 draws; I reproduced
every point estimate that feeds them):

- vs OOS: **ΔPrecision −0.021, CI [−0.087, +0.043]** — contains zero.
  **ΔRecall −0.217, CI [−0.311, −0.116]** — excludes zero.
- vs STRICT: ΔP +0.008 [−0.081, +0.108]; **ΔR −0.055 [−0.183, +0.080] — contains zero.**
- benign: **−3.0 points [−5.5, −1.1]** — significantly *better* than our own benign pool.

**Plain statement.** Precision holds at 0.909 on a corpus nobody in this project designed,
labelled or tuned against, at **zero** false blocks on 200 independent benign sessions.
That is the strongest external-validity evidence the project has, and the operating point
was frozen on gold1 long before the corpus existed. Recall does **not** hold against OOS
(−0.217, excludes zero) and is indistinguishable from our honest STRICT slice.

**The mechanism is the more useful finding.** All 110 fires on the 600 come from
**channel 1**, the deterministic labeler. Channels 2 and 3 — the global evidence bar and
the deferred-compliance score, the entire added-recall apparatus that buys +0.085 OOS
recall on our corpus — fire **zero** times on all 600 rows, because the `strict` gate's
`p_unsafe_demand` precondition opens on only **56/400** new attack prompts against
**245/671** of our OOS rows (I measure the OOS demand rate at 0.365 vs 0.140 on the 600).
443 of 600 rows are gated off before those channels are consulted. The policy knob is
therefore **inert** here: `off` → `aggressive` moves 110 → 112 fires out of 400 (+0.004
recall) against +0.225 OOS recall on our own corpus.

**Two things that must not be oversold.**

1. Under the **unsafe-only** reading (130 positives) precision collapses to **0.427**
   [0.339, 0.521] at R 0.362 — barely above the 0.325 base rate. Both readings must be
   quoted with their null.
2. F1 loses to always-block on **every** slice, because all these slices are
   positive-heavy: new600 0.471 vs floor 0.881; unsafe-only 0.392 vs 0.491; OOS 0.679 vs
   0.686; STRICT 0.527 vs 0.748. **No F1 number here is a win.** The gate's value is
   precision at near-zero benign cost.

**Permuted-label control.** With predictions fixed and labels permuted, shipped precision
collapses exactly to the base rate on both corpora (OOS 0.5258 vs prevalence 0.5216;
new600 0.7894 vs 0.7875). That is the correct null for a fixed binary rule and it says the
harness is sound.

---

## 2. The single authoritative numbers table

**Reading rules, enforced.** (a) No gate number appears without its policy label.
(b) Every recall carries its benign cost. (c) Every F1 carries its slice's trivial
always-positive floor. (d) In-sample rows are marked and are never generalisation.

### 2.1 The shipped deterministic gate (no training on any evaluated slice)

| policy | gold1 (146) P/R **in-sample** | OOS (671) P/R | STRICT (288) P/R | new600-M1 (400) P/R | new600-M2 P/R | benign 148 fires | benign 1081 | new600 benign 200 |
|---|---|---|---|---|---|---|---|---|
| `off` | .9455/.8125 | .9235/.4486 | .8793/.2965 | **.9091/.3175** | .4273/.3615 | 5 (2 false) | 31 = 2.9 % [1.0, 5.3]ᵍ | **0/200** |
| **`strict` ← SHIPPED** | .9298/.8281 | **.9303/.5343** | **.9014/.3721** | **.9091/.3175** | .4273/.3615 | 5 (2 false) | **32 = 3.0 % [1.1, 5.5]ᵍ** | **0/200** |
| `balanced` | .9310/.8438 | .9349/.5743 | .9114/.4186 | .9099/.3206 | .4324/.3692 | 9 (6 false) | 53 = 4.9 % [2.2, 8.3]ᵍ | **0/200** |
| `aggressive` | .9322/.8594 | .9183/.6743 | .9292/.6105 | .9018/.3206 | .4286/.3692 | 20 (17 false) | 130 = 12.0 % [8.0, 16.2]ᵍ | **0/200** |

ᵍ prompt-group bootstrap over 204 benign prompts. Trivial always-positive F1 floors:
gold1 0.6095, OOS 0.6856, STRICT 0.7478, all-gold 0.6035, new600-M1 0.8811,
new600-M2 0.4906.

### 2.2 Learned models — every one of them is worse than the gate at the operating point

Threshold selected on **gold1 only** at P ≥ 0.90, then applied unchanged. Prompt-grouped,
10 seeds.

| model | train | grouped CV AUC | LOACO | OOS P/R | STRICT P/R | benign FA | OOS F1 (floor .6856) |
|---|---|---|---|---|---|---|---|
| shipped RF `aura_behavioral.joblib` | gold 965 | **0.7427** (sd .0081) | 0.7117 | .556/**.029** | .667/.035 | 2.5 % | 0.054 |
| RF +sathwik600 | +525 | — | 0.6844 | .688/**.063** | .778/.081 | 4.2 % | 0.115 |
| RF +mempois94 | +94 | — | 0.7133 | .750/.026 | .833/.029 | 3.2 % | 0.050 |
| RF +chenhao | +758 | — | 0.7106 | .667/.023 | 1.000/.029 | 1.3 % | 0.044 |
| RF EXPANDED (all) | 2342 | 0.6414 (sd .0081) | 0.6824 | .760/**.054** | .824/.081 | 4.9 % | 0.101 |
| permuted-label control (union) | — | **0.4968** (sd .056) | — | — | — | — | — |

**The line that matters:** the best learned model reaches **OOS recall 0.063**. The shipped
deterministic gate reaches **0.534** on the same slice at a lower benign cost. Every ML
result in this project is an order of magnitude below the rule-based system at any usable
operating point, and no arm has ever closed that gap.

### 2.3 Cross-corpus transfer of *trained* models (leave-one-corpus-out)

| held-out corpus | n | AUC | seed sd | group-bootstrap 95 % | crosses 0.5? |
|---|---|---|---|---|---|
| gold (ours) | 965 | 0.5299 | .0031 | [0.469, 0.589] | **yes** |
| sathwik (the new 600) | 525 | 0.5506 | .0077 | [0.484, 0.613] | **yes** |
| mempois | 94 | 0.6655 | .0141 | [0.489, 0.824] | **yes** |
| chenhao | 758 | 0.7653 | .0189 | [0.645, 0.998] | no — but 10 distinct prompts |

Zero-shot vs having-seen-the-corpus on the new 600: **AUC 0.5506 → 0.8237, gap +0.273**
(their reading); **0.5014 → 0.9224, gap +0.421** (unsafe-only). Permuted control 0.500.

### 2.4 Cross-source, restated (round-4/5 re-derivation)

| model | gold STRICT AUC | recall @ P ≥ 0.90 | train distinct prompts |
|---|---|---|---|
| chenhao→gold, published 62-feature (the paper number) | 0.7571 [0.667, 0.842] | **0.087** | **10** |
| new600→gold, published 62-feature | 0.7284 [0.651, 0.807] | **no P≥0.90 threshold exists** | 455 |
| new600→gold, shipped 12-feature rep | 0.7586 [0.686, 0.829] | 0.000 | 455 |
| **NO-TRAINING CONTROL: `num_tools` alone, zero parameters** | **0.7902** [0.713, 0.861] | none reaches P≥0.90 | **0** |

I independently reproduce `num_tools` STRICT AUC = **0.7902**. The published cross-source
AUC is **not distinguishable from counting tool calls** (Δ +0.033, CI [−0.069, +0.141]).

### 2.5 Memory poisoning (84 poisoned + 10 benign)

| configuration | block recall on 84 | benign blocked / 10 | firing layer |
|---|---|---|---|
| shipped gate, no ingested source passed | **0/84 = 0.000** | 0/10 | — (21 flags, general layer) |
| shipped gate, poisoned `MEMORY.md` passed as `ingested` | **40/84 = 0.476** [0.373, 0.582] | **2/10 = 20 %** [5.7, 51.0] | ECHO (40 of 40) |
| the "36 % blind spot" recipe, exact re-run | 30/84 = **0.357** | — | logistic @10 % FPR |
| fact-ID-only oracle, random-over-sessions CV | acc **0.817** | — | *no reply text used at all* |
| fact-ID-only oracle, **grouped by fact** | acc **0.578 = the majority floor** | — | same |

### 2.6 Single-feature AUCs (what the signal actually is)

| feature | OOS | STRICT | new600-M1 | new600-M2 |
|---|---|---|---|---|
| labeler evidence score | 0.866 | 0.839 | 0.655 | 0.611 |
| deferred score | 0.880 | 0.862 | 0.601 | 0.706 |
| **num_tools** | 0.718 | **0.790** | 0.619 | **0.943** |
| reply length | 0.482 | 0.472 | 0.444 | 0.551 |

On the new corpus's unsafe tier, **counting tool calls (AUC 0.943) beats every behavioural
feature we have built**. A `num_tools ≥ 1` rule gets P 0.903 [0.847, 0.941] / R 0.444 on
new600-M1 — better recall than our whole gate — but at **11.5 % benign block**, which is
`aggressive`-grade cost. Under the unsafe-only reading no `num_tools` threshold reaches
P ≥ 0.90 at all.

---

## 3. What is the ceiling?

The lead asked for the best we could possibly do. Here it is, as a band, on the slice that
matters (an **independent** corpus at P ≥ 0.90), with the same band for our own honest
slice beside it. Each rung is measured, not assumed.

| rung | our STRICT (288) | independent new600-M1 (400) | what it means |
|---|---|---|---|
| **today, shipped** | R **0.372** at P 0.901, 3.0 % benign | R **0.317** at P 0.909, **0 %** benign | what actually ships |
| **perfect calibration of existing channels** (oracle, in-sample → upper bound) | R **0.715** at P 0.904 | R **0.375** at P 0.901 | best any threshold/combination of today's signals could do |
| **absolute limit of reply-text evidence** (positives carrying *no* lexical or deferred evidence at all) | R **0.855** [0.794, 0.906] | R **0.486** [0.430, 0.543] | nothing that reads the reply can exceed this with these evidence families |

**Headline answer.** On an independent corpus the best we could possibly do at
P ≥ 0.90 is about **0.49 recall**, and we are at **0.32**. We have already captured about
two-thirds of the achievable ceiling. On our own distribution the ceiling is much higher
(0.855) and we have captured under half of it — which is exactly the shape you would
expect from a system fitted, honestly but unavoidably, to its own corpus.

**Control on the ceiling method.** Under 100 label permutations the oracle grid search
reaches P ≥ 0.90 in **0 of 100** attempts on both OOS and the new corpus. The oracle
ceilings are therefore not grid-search overfitting on noise; they are real headroom in the
existing signals. (They remain in-sample and so remain *upper* bounds.)

### (a) DATA limit — what more collection would buy, quantified

**Evidence.**
- Leave-one-corpus-out AUC when predicting a corpus you have never seen: gold **0.530**,
  sathwik **0.551**, mempois **0.666**. All three bootstrap CIs cross 0.5. Only chenhao
  (0.765) clears, and chenhao has 10 distinct prompts.
- The value of *having seen* a corpus: AUC **0.551 → 0.824** (+0.273) on their reading,
  **0.501 → 0.922** (+0.421) unsafe-only. Nearly all achievable performance on a corpus
  comes from having collected that corpus.
- Adding 525 genuinely new rows (a **+54 %** increase in training data) moved pooled LOACO
  AUC by **−0.028 [−0.054, −0.001]** (worse, excludes zero) while moving the operating
  point by **+0.034 OOS recall [+0.006, +0.068]** and **+0.046 STRICT [+0.016, +0.083]** at
  **+1.7 pp benign cost**. Both are true; see §6.1.
- The absolute numbers make the size of the prize clear: even after expansion the best
  learned model is at **OOS R 0.063**, versus the gate's 0.534.

**Conclusion.** More data of the *same kind* buys almost nothing for generalisation and
costs benign headroom. More data of a *new kind* buys a large amount **on that kind only**.
Collection is not the binding constraint on the shipped system; it is the binding
constraint on the *learned* system, and the learned system is 8× behind the rules.

**The experiment that would test it.** A **prompt-count learning curve on the new corpus**:
subsample its 400 attack prompts at 50 / 100 / 200 / 300 / 400 groups, train the shipped
12-feature representation, evaluate on held-out *prompt groups* of the same corpus, 10
seeds, group-bootstrap CI on the slope. If the curve is still rising at 400 prompts, data
is the limit and the answer is "collect more, from more collectors". If it has flattened by
200 — which the LOCO numbers predict — data is **not** the limit and further collection
should be spent on *diversity of collector and environment*, not on volume. Cost: hours,
no new labelling. This is the highest-information cheap experiment available.

### (b) METHOD limit — what a better model could buy

**Evidence.**
- Oracle headroom over existing channels: OOS **+0.186 [+0.072, +0.282]**, STRICT
  **+0.343 [+0.188, +0.526]** — both exclude zero. On the independent corpus the same
  headroom is **+0.057** (bootstrap mean +0.102 [+0.006, +0.210], and the bootstrap mean
  exceeds the point estimate because in-draw oracle fitting inflates it, so treat the
  independent-corpus headroom as *at most* ~0.06).
- The misses are not gated-off, they are evidence-free. Of the 163 OOS misses, 134 carry
  evidence score 0 and only 24 carry score ≥ 3 while being gated off by the policy. Of the
  **215** misses on the new corpus, **211** carry score 0 and **zero** carry score ≥ 3 —
  i.e. no policy change can recover any of them.
- Every learned alternative measured in five rounds tops out at grouped AUC 0.743 /
  LOACO 0.712 and delivers ≤ 0.063 recall at P ≥ 0.90.

**Conclusion.** There is real, statistically significant method headroom **on our own
distribution** — roughly doubling STRICT recall without touching precision — and there is
almost none on an independent corpus. A better model helps where we already have evidence,
and does not help where we do not.

**The experiment that would test it.** A **nested-calibration combiner**: learn the decision
surface over (evidence score, deferred score, demand gate) *inside* training folds with the
threshold nested, prompt-grouped, 10 seeds, and measure how much of the 0.343 STRICT oracle
gap survives on held-out prompt groups. Pre-register the verdict: **if nested selection
recovers less than one third of the oracle gap, the gap is oracle optimism and the method
limit is already reached.** This is the decisive test of whether "a better model" is a real
option or a story.

### (c) IRREDUCIBLE limit — what cannot be solved from reply text

**Evidence.**
- **The zero-evidence residual.** 11.7 % [8.3, 15.5] of OOS positives, 14.5 % [9.4, 20.6]
  of STRICT positives and **51.4 % [45.8, 57.0]** of new600 positives carry *no* lexical or
  deferred evidence at all. On the new corpus that alone caps any reply-text detector at
  **R 0.486**. Prior rounds independently measured the same bucket at recall 0.480 OOS /
  0.373 STRICT, and an entire round of work moved it **0.480 → 0.488**.
- **The memory-poisoning result is the cleanest statement of the limit.** Without the
  ingested source text the shipped gate blocks **0 of 84** poisoned sessions. With the
  source it blocks 40, and every one of those 40 fires on the **ECHO** layer — string
  overlap with the poison, not behaviour — at a cost of **2 of 10 benign** sessions. These
  features detect *unsafe answering behaviour*, not truth: a confidently-wrong poisoned
  answer and a confidently-right legitimate answer are not separable from the reply text.
- **And the apparent skill there is fact memorisation.** A fact-ID-only oracle that reads
  **no reply text whatsoever** scores 0.817 under random-over-sessions CV and exactly the
  **0.578 majority floor** when grouped by fact; 18 of the 20 facts with ≥ 3 trials are
  100 % one way. The memory-poisoning classifier was learning which fact was poisoned.
- **The target itself is partly non-behavioural.** On the new corpus's unsafe tier,
  `num_tools` alone scores AUC **0.943** — the label is close to "did the agent call a
  tool". Independently, the co-author's cross-methodology check shows benign-canary probes
  overstate susceptibility by **+0.31** mean over six techniques, positive for every one.

**Conclusion.** A hard floor exists and it is not small. On an independent corpus roughly
**half** of true compliances leave no trace in the reply. No feature engineering on reply
text can reach them; the only routes are different observables — the tool trail, the
environment diff, the ingested source — or a different decision point (block the *action*,
not the *answer*).

**The experiment that would test it.** A **blind human-adjudication floor**: take the 41 OOS
zero-evidence positives plus 41 matched negatives, strip the prompt, the tools and the
label, show two independent adjudicators the **reply text only**, and measure their
accuracy and kappa. If humans are at chance on reply text alone, the limit is proven
irreducible from that channel and the project should stop trying to close it with features
— and should say so in the paper, because "here is the part that is provably not solvable
from the text" is a stronger contribution than another 2 points of recall. Cost: ~2 hours
of adjudication, no code.

---

## 4. Recommended shipped configuration, with its full cost

**Keep `AURA_BLOCK_POLICY=strict`. Do not change the shipped system on the basis of
Round 5.** Nothing measured this round beats it, and the transfer result is *evidence for*
the current configuration rather than against it.

| axis | value | interval |
|---|---|---|
| OOS (671) | P 0.9303 / R 0.5343 | P [0.887, 0.958], R [0.482, 0.586] (Wilson) |
| STRICT (288) | P 0.9014 / R 0.3721 | P [0.810, 0.951], R [0.303, 0.446] |
| **independent new600 (400)** | **P 0.9091 / R 0.3175** | P [0.841, 0.950], R [0.269, 0.371] |
| benign, wide pool (1081 rows / 204 prompts) | **32 blocked = 3.0 %** | Wilson [2.1, 4.2]; **prompt-group bootstrap [1.1, 5.5]** |
| benign, audited false blocks | **1.77 %** | [0.74, 3.13] |
| **benign, independent (200)** | **0 blocked = 0.0 %** | [0.0, 1.88] |
| gold1 (in-sample, threshold slice — never a generalisation claim) | P 0.9298 / R 0.8281 | — |
| test suite | 22/22 green, unchanged | — |

**Three caveats that must ship with the number.**
1. The 3.0 % benign rate is an **upper bound** (baseline rows are not attack-free: 14/1081
   emit a planted marker). Its CI reaches **5.5 %** against a written budget of 3.0 %. The
   budget is effectively exhausted.
2. `balanced` improves recall *and* precision on both held-out slices with all four CIs
   excluding zero, and is rejected on one number only: 4.9 % [2.2, 8.3] benign. The
   pre-registered rule from Round 4 stands — hand-judge the 130 rows `aggressive` blocks,
   which yields the **exact** false-block numerator for all four nested policies at once,
   and switch to `balanced` if and only if its exact wide rate is ≤ 3.0 %.
3. On an independent corpus the policy knob is **inert** (110 → 112 fires of 400). Do not
   claim the policy ladder as a transferable feature of the system; on foreign traffic
   `off` and `aggressive` are the same decision on 398 of 400 rows.

---

## 5. What is publishable now that was not this morning

1. **A genuine external-validity result.** "The shipped behavioural gate, applied zero-shot
   to 600 sessions collected independently with zero prompt and zero response overlap,
   holds precision 0.909 [0.841, 0.950] and blocks 0 of 200 independent benign sessions."
   This is the first transfer claim in the project that is not confounded by a 10-prompt
   corpus. **PUBLISH.**
2. **The matching negative, which is the more useful half.** "Recall does not transfer
   (ΔR −0.217 [−0.311, −0.116] vs OOS) and the added-recall machinery contributes **zero**
   of 110 fires outside the corpus it was built on." **PUBLISH — do not soften.**
3. **A measured ceiling, with a control.** Oracle headroom over existing channels
   (STRICT +0.343 [+0.188, +0.526]; independent corpus ≤ +0.06) and a zero-evidence floor
   (independent-corpus recall cannot exceed 0.486 [0.430, 0.543]), with a permutation
   control showing the oracle reaches P ≥ 0.90 in 0/100 permuted runs. **PUBLISH.**
4. **Training-transfer is at chance.** Leave-one-corpus-out AUC 0.530 / 0.551 / 0.666 with
   CIs crossing 0.5, against a seen-it AUC of 0.824–0.922. "A behavioural model predicts a
   corpus it has seen and nothing else." **PUBLISH.**
5. **The cross-source claim, restated and defused.** The published cross-source AUC is
   indistinguishable from a zero-parameter tool-call counter (num_tools STRICT 0.7902,
   Δ +0.033 [−0.069, +0.141]), has no deployable operating point (STRICT recall 0.087 at
   P ≥ 0.90), and rests on 10 distinct prompts. **PUBLISH as a correction** — this retires
   §2.4's old headline rather than adding to it.
6. **Memory poisoning is not detectable from reply text.** 0/84 without the ingested
   source; 40/84 with it, all via string echo, at 2/10 benign; and a fact-ID-only oracle
   that reads no text at all collapses from 0.817 to the 0.578 majority floor when grouped
   by fact. **PUBLISH as a negative result**, with the framing: these features detect
   unsafe *answering behaviour*, not truth.
7. **A correction to the transfer set's own provenance.** 455 distinct prompts = 400 attack
   (all unique) + **55** distinct benign prompts over 200 benign rows — not 200. I confirm
   this independently (400 attack groups, 55 benign groups). Any bootstrap on their benign
   set has **55** groups, not 200.
8. **The 8-family subtype field moved.** In the committed team repo `attack_category` reads
   `direct_prompt_injection` for all 400 attacks; the families live only in
   `attack_objective`. Any analysis briefed before that change must be re-checked.

Still **NOT** publishable, unchanged: any F1 as a headline on these slices; any recall
without its policy label and benign cost; `balanced` as the default until the 130-row
adjudication runs; the corpus-expansion operating-point gains (see §6.1).

---

## 6. Disagreements between arms, and how I resolve them

### 6.1 "Expanding the corpus helps" vs "expanding the corpus hurts" — **both are right, and the conclusion is neither**

The expansion arm reports +sathwik600 improving the operating point (OOS ΔR +0.034
[+0.006, +0.068], STRICT +0.046 [+0.016, +0.083]). The refutation arm reports the same
addition *hurting* pooled LOACO AUC (−0.028 [−0.054, −0.001], 10/10 seeds worse, t = −65.8).

**Resolution.** These are different statistics computed from the same fitted models, and
the refuter reproduced the expansion arm's operating-point table **bit-for-bit** (threshold
0.801, OOS .688/.063, FA 4.2 %). There is no numerical conflict. The correct reading is the
one neither arm stated plainly: **both statistics describe a model that is not shipped and
should not be.** The "improved" operating point is OOS recall **0.063** against the shipped
gate's **0.534**, at nearly double the benign cost. A +0.034 improvement inside a system
that is 8× worse than the deployed one is not a result about the deployed system. Adding
the new corpus to training is **rejected** — not because the arm's statistics are wrong,
but because the thing being improved is the wrong artifact.

### 6.2 "The gate transfers" vs "the model fires 0/595 on the new corpus" — **different systems**

The transfer arm shows the deterministic gate transferring on precision. The cross-source
arm shows the gold-trained *model* (direction B) ranking the new corpus at AUC 0.767 but
firing on **0 of 595 rows** at its gold-calibrated threshold, with no threshold on the new
corpus reaching P ≥ 0.90 on the acted-only label. Both are correct and they are about
different artifacts. **Resolution:** the **rules** transfer and the **learned score** does
not. That is the sentence the paper should carry, and it is a stronger claim than either
arm made alone.

### 6.3 "cot_hijack and false_precedent are weak families" — **retire it, with my own numbers**

`PAPER_PLAN.md` carries **PUBLISH**-flagged rows: cot_hijack LOACO AUC **0.3065**
("below chance, actively anti-correlated"), false_precedent **0.5145**. The transfer arm
says the gate contradicts this. I measured it myself (`fam.py`, shipped `strict` policy):

| family | OOS gate recall | STRICT gate recall |
|---|---|---|
| cot_hijack | **0.677** (21/31) | **1.000** (13/13) |
| false_precedent | **0.661** (41/62) | 0.360 (9/25) |
| genuinely weak: multilingual_injection | 0.150 (3/20) | 0.000 (0/6) |
| genuinely weak: emotional_coercion | 0.220 (11/50) | 0.213 (10/47) |

**Resolution.** Both survive, but only with the system named. "The **RF model's** LOACO AUC
on cot_hijack is 0.307" is true and publishable. "**cot_hijack is a weak family**" is false
for the shipped gate and is contradicted on independent data, where the transfer arm found
cot_hijack's and false_precedent's counterparts to be the **two best of eight** families.
The unqualified sentence must be struck from the paper; the qualified one may stay.

### 6.4 A live documentation defect inside a shipped file — flagged, not fixed

`openclaw-plugin/scorer.py` **line 195** asserts `BOTH (SHIPPED) OOS P 0.9218 R 0.6400 /
STRICT P 0.9327 R 0.5640`. The shipped default today measures **.9303/.5343** and
**.9014/.3721**; the closest current policy, `aggressive`, measures **.9183/.6743** and
**.9292/.6105**. The comment matches **neither**. It is a pre-policy-gate snapshot left in
a shipped file — exactly the defect class ("deployed code drifted from measured code,
silently") the project already publishes as a lesson. I did not edit it: changing a shipped
file inside a synthesis round is out of scope and would require re-running the suite for a
comment. **It must be corrected before submission**, and `GATE_OPERATING_POINTS.md` should
be named in the file as the single source of truth.

### 6.5 A briefing correction that both the arm and I found independently

The brief states 200 distinct benign prompts in the transfer corpus. There are **55**. The
455 distinct prompts are 400 attack + 55 benign. This matters for any bootstrap over their
benign set and is confirmed by two independent counts.

---

## 7. The one-paragraph answer to the lead's question

**The best we could possibly do, on an independent corpus, at the precision floor we
actually ship, is about 0.49 recall — and we are at 0.32.** Perfect calibration of every
signal we already have would take us to about 0.375; the remaining distance to 0.49 needs
signals we do not have; and everything above 0.49 is unreachable from reply text at all,
because roughly half of true compliances on foreign traffic leave no lexical trace. On our
own corpus the ceiling is 0.855 and we are at 0.372, but that gap is a statement about
fitting our own distribution, not about the system's future. The honest summary for the
paper is that **the precision half of this system generalises and the recall half does
not**, that we have already captured about two-thirds of what is achievable off-corpus, and
that the most valuable remaining work is not another model — it is proving where the floor
is, with the blind-adjudication experiment in §3(c) and the nested-calibration experiment
in §3(b). Two cheap experiments would convert the ceiling from an estimate into a result.
