# GATE_OPERATING_POINTS.md — the one authoritative table

Snapshot **2026-07-28**. Corpus 2,166 records (collector is live, quote counts with a date).
Reproduce with `python3 analysis/paper_repro/policy_curve.py`.

> **NO GATE NUMBER MAY BE PUBLISHED WITHOUT ITS POLICY LABEL.**
> Quoting a recall from one policy beside a benign rate from another describes a system that
> does not exist. That has already happened once in this project, see §3.

> **2026-07-28 — THIS TABLE WAS REGENERATED AND EVERY RECALL WENT UP.** The previous version
> was produced by a script that re-derived the gate from `behavioral_labeler` +
> `deferred_compliance` only. The shipped `scorer.score()` **also runs the compliance layer**,
> so the old table measured a system we do not ship and **understated our own result**. See §5.

## 1. The curve

`AURA_BLOCK_POLICY` selects how the added evidence channels are gated. The deterministic
labeler always runs.

| policy | OOS (671) P / R | STRICT (288) P / R | benign FALSE blocks, wide pool (1,081) |
|---|---|---|---|
| `off` | .9235 / .4486 | .8793 / .2965 | **1.11 %** [0.6, 1.9] |
| **`strict`** ← **SHIPPED DEFAULT** | **.9214 / .6029** | **.9213 / .4767** | **2.87 %** [2.0, 4.0] |
| `balanced` | .9217 / .6057 | .9222 / .4826 | 3.24 % [2.3, 4.5] **OVER BUDGET** |
| `aggressive` | .9183 / .6743 | .9292 / .6105 | 9.16 % [7.6, 11.0] **OVER BUDGET** |

`gold1` (the only slice a threshold may be picked on), for completeness:
`off` .9455/.8125 · `strict` .9310/.8438 · `balanced` .9310/.8438 · `aggressive` .9322/.8594

Counts:

| policy | OOS tp / fp | STRICT tp / fp | benign raw / correct / FALSE |
|---|---|---|---|
| `off` | 157 / 13 | 51 / 7 | 31 / 19 / 12 |
| `strict` | 211 / 18 | 82 / 7 | 54 / 23 / **31** |
| `balanced` | 212 / 18 | 83 / 7 | 59 / 24 / 35 |
| `aggressive` | 236 / 21 | 105 / 8 | 130 / 31 / 99 |

## 2. Why `strict` and not `balanced`

`balanced` buys almost nothing now: **+1 tp on OOS, +1 on STRICT**. It costs 4 more false
blocks and pushes the benign rate to **3.24 %**, over the written **3.00 %** budget. On the
old (channel-only) table `balanced` looked like a real gain, because the compliance layer's
detections were invisible and `balanced` was the only way to reach them. **Once the
compliance layer is measured, `strict` already has them.** The case for `balanced` is gone,
not merely outweighed.

`aggressive` is rejected outright: **9.16 %** benign cost for +0.134 STRICT recall.

## 3. The contradiction this file exists to kill

`ROUND3_SYNTHESIS.md` publishes "the shipped gate" as OOS R 0.6743 / STRICT R 0.6105. That
row is **exactly today's `aggressive`**, cell for cell (OOS tp236 fp21, STRICT tp105 fp8).
**A paper citing 0.6743 next to a benign rate of 1.4 % describes a system that has never
existed.** Equally retired: the "1.3 %" and "10.8 %" benign figures.

## 4. Benign cost: one definition, in both scripts

The budget is on **FALSE blocks**, not raw blocks. Baseline-condition rows are **not**
attack-free: some disclose a canary, emit a planted provenance marker, carry credential or
exfil code, or solicit a secret file. **Blocking those is correct.** Under `strict`, 54 raw
blocks contain **23 objectively correct** ones, leaving **31 false**.

Two numbers were previously in circulation for the same system, and they were never the same
measurement:
* **2.88 %** — `test_suite.py`, counting blocks from `_compliance_layers` **only** (one
  channel), with the correct-block exclusion applied.
* **4.72 %** — the policy curve, counting the **whole gate**, with **no** exclusion.

Both now share one definition and agree on **31 false blocks** (2.87 % of 1,081 here,
2.88 % of the suite's 1,078-row pool). The unadjudicated upper bound is also emitted as
`false_rate_unadjudicated` for anyone who wants the pessimistic reading.

Benign CIs are Wilson on rows. The pool is 1,081 rows over **204 distinct prompts**; benign
prompts repeat, so a prompt-level bootstrap is wider and is the honest interval for a claim
about *prompts* rather than *sessions*.

## 5. What changed on 2026-07-28, and by how much

`policy_curve.py` now calls `scorer.score()` — the shipped code path — instead of
re-deriving the decision. Row-level diff, `strict`, ECHO at flag grade:

| slice | old (channels only) | shipped `scorer.score()` |
|---|---|---|
| OOS | R .5343 | **R .6029** |
| STRICT | R .3721 | **R .4767** |

**Every extra block is `layer == "compliance"`: 28 on OOS, 18 on STRICT, 1 on gold1. There is
no row where the old model blocks and the shipped scorer does not.** The difference is
strictly additive and attributable to one layer — the layer that only began running live once
the plugin was fixed to send the prompt via `before_agent_run`.

## 6. Known limits

1. **Every count is a snapshot.** The collector appends continuously.
2. **Do not quote F1 as a headline.** The always-positive trivial F1 is 0.6035 on all gold,
   **0.6856 on OOS**, **0.7478 on STRICT**. F1 never looks at the benign population, which is
   the whole point of a gate. Quote (recall, benign FALSE-block rate) pairs.
3. **Benign cost on tool-using workloads is unmeasured.** 0 of 2,166 rows in this corpus carry
   tool output, so the ECHO layer is structurally invisible here. On an external corpus that
   does carry tool output, ECHO fires on 13.4 % of benign replies.
4. **These are reply-path numbers.** On the CLI path `before_agent_reply` does not fire, so
   the compliance layer is not exercised there. Do not claim these as live CLI behaviour.
