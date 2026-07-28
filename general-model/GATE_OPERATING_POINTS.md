# GATE_OPERATING_POINTS.md — the one authoritative table

Snapshot **2026-07-27**. Corpus 2,166 records (collector is live, quote counts with a date).
Reproduce with `python3 analysis/paper_repro/policy_curve.py`.

> **NO GATE NUMBER MAY BE PUBLISHED WITHOUT ITS POLICY LABEL.**
> Quoting a recall from one policy beside a benign rate from another describes a system that
> does not exist. That has already happened once in this project, see §3.

## 1. The curve

`AURA_BLOCK_POLICY` selects how the two added channels (global evidence bar, deferred
solicitation score) are gated. Channel 1, the deterministic labeler, always runs and
contributes **zero** false blocks on the benign pool.

| policy | gate on channels 2 and 3 | OOS (671) P / R | STRICT (288) P / R | benign block, wide pool (1081) |
|---|---|---|---|---|
| `off` | disabled, labeler only | .9235 / .4486 | .8793 / .2965 | 2.9 % |
| **`strict`** ← **SHIPPED DEFAULT** | require `p_unsafe_demand` | **.9303 / .5343** | **.9014 / .3721** | **3.0 %** [1.1, 5.5] |
| `balanced` | demand OR `injection_present` | .9349 / .5743 | .9114 / .4186 | 4.9 % [2.2, 8.3] |
| `aggressive` | no gate | .9183 / .6743 | .9292 / .6105 | 12.0 % [8.0, 16.2] |

Counts, for anyone reconciling with an older document:

| policy | OOS tp / fp | STRICT tp / fp |
|---|---|---|
| `off` | 157 / 13 | 51 / 7 |
| `strict` | 187 / 14 | 64 / 7 |
| `balanced` | 201 / 14 | 72 / 7 |
| `aggressive` | 236 / 21 | 105 / 8 |

Benign CIs bootstrap the **204 prompt groups**, not the 1,081 rows. Benign prompts repeat,
so a row-level interval is too narrow.

## 2. Why `strict` and not `balanced`

State the case for `balanced` at full strength before rejecting it: it improves **recall and
precision simultaneously on both held-out slices**, and all four bootstrap CIs exclude zero
(OOS ΔR +0.040 [+0.015, +0.071], ΔP +0.005 [+0.001, +0.010]; STRICT ΔR +0.046
[+0.012, +0.093], ΔP +0.010 [+0.002, +0.026]). That is rare and it is not noise.

It is rejected on one number. `balanced` costs **4.90 %** on the wide benign pool against a
written budget of **3.0 %**. The delta, +1.94 pp [+0.42, +4.04], excludes zero, so the cost
is real. Buying recall by breaking the only safety budget the project has written down is
not a trade to authorise on an upper-bound measurement.

`aggressive` is rejected outright: +9.07 pp [+5.83, +12.72] benign cost for +0.239 STRICT
recall. One in eight benign sessions blocked.

**This decision is conditional.** The benign rate is an upper bound. If the pending 130-row
adjudication (§4) shows `balanced`'s exact rate at or below 3.0 %, `balanced` becomes the
correct default and should be switched immediately.

## 3. The contradiction this file exists to kill

`ROUND3_SYNTHESIS.md` publishes "the shipped gate" as **OOS R 0.6743 / STRICT R 0.6105**.
Round 4 publishes the shipped default as **OOS R 0.5343 / STRICT R 0.3721**.

Both are correct. They describe different policies. Round 3's "widened gate" row is
**exactly today's `aggressive`**, cell for cell (OOS tp236 fp21, STRICT tp105 fp8). Round 4
inserted the policy gate and defaulted it to `strict`, trading **0.239 of STRICT recall** to
bring the benign rate from 12.0 % down to 3.0 %.

That trade is defensible and is endorsed here. But Round 3's recall figures remain the most
quotable numbers in the repository, and **a paper citing Round 3's 0.6743 next to a benign
rate of 1.4 % describes a system that has never existed.**

Equally retired: the "1.3 %" and "10.8 %" benign figures. Neither describes the shipped
default. 1.3 % was labeler-only measured on 148 rows, which reads 2.9 % on 1,081.

## 4. Known limits of these numbers

1. **The benign rate is an UPPER BOUND.** Baseline-condition rows are not attack-free:
   14 of 1,081 (1.29 %) emit a planted environment marker, so some blocks on them are
   correct. The audited `strict` false-block rate is **1.77 % [0.74, 3.13]**.
2. **The exact rates are one experiment away.** The policies are nested by construction
   (`off` 31 ⊆ `strict` 32 ⊆ `balanced` 53 ⊆ `aggressive` 130 fires), so hand-judging the
   130 rows `aggressive` blocks yields the **exact** false-block numerator for all four
   policies at once over a known denominator of 1,081. No sampling, no bound. Roughly two
   hours of work, and it decides a live shipped-default question.
3. **Do not quote F1 as a headline on these slices.** The always-positive trivial F1 is
   0.6035 on all gold, **0.6856 on OOS** (base rate 0.5216) and **0.7478 on STRICT** (base
   rate 0.5972). At the default, OOS F1 0.6788 and STRICT F1 0.5267 are *below* their
   slice floors. That does not mean a trivial classifier is better: always-saying-attack
   blocks **100 %** of benign work. It means F1 is the wrong lens for a gate, because it
   never looks at the benign population. Quote (recall, benign block rate) pairs.
4. **Every count is a snapshot.** The collector appends continuously.
