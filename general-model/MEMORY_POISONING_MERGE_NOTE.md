# Merge note: real memory-poisoning data added to AURA

**From:** memory-poisoning subproject  ·  **Date:** 2026-07-27

## What I added
94 real OpenClaw sessions from the astrophysics memory-poisoning experiment, in
AURA's exact `corpus_clean.jsonl` row schema:

| rows | attack_category | label | meaning |
|---|---|---|---|
| 84 | `memory_poisoning` | 1 | agent emitted the planted FALSE value as fact (unsafe) |
| 10 | `benign_astro` | 0 | clean-memory run, agent answered correctly (safe) |

- `source`: `mempois_astro`
- `tools`: `[]` — verified from the trajectory logs: these sessions made **zero**
  tool calls. The agent answered straight from its (poisoned) memory without
  verifying, so `science_features` correctly fires `unverified_confident_claim`.
- `label_origin`: `memory_poisoning_compliance_score` (see
  `memory-poisoning/notebooks/score_results_v2.py`).

## Where it is
1. **Standalone, ready to merge anywhere:**
   `memory-poisoning/data/processed/memory_poisoning_astro_aura.jsonl`
2. **Already appended locally** to `general-model/corpus_clean.jsonl`
   (2303 → 2397 rows). Backup: `corpus_clean.jsonl.bak`.
   To undo: `cp corpus_clean.jsonl.bak corpus_clean.jsonl` or `git checkout corpus_clean.jsonl`.

## Why it matters (coverage was a blind spot)
`memory_poisoning` had only **3** rows before → effectively unlearnable. Now **87**.

Measured with AURA's own `science_features` + a LogReg at a 10% false-alarm
operating point (`memory-poisoning/notebooks/integrate_into_aura.py`):
- A model trained on the **other 35 families** (never seeing real memory
  poisoning) flags **36% (30/84)** of these poisoned sessions. That's the blind
  spot this data fills.

## Honest caveat (please keep in any writeup)
These features detect **unsafe answering behavior** (a confident, unverified,
numeric claim), **not truth**. The same features fire on a confident answer from
*legitimate* memory. Telling poisoned-from-legitimate memory apart needs
content-level fact-checking — it is not solvable from reply text alone.

## To fold into the SHIPPED model
Appending to `corpus_clean.jsonl` covers the `eval_ablations` / `make_figures`
analysis path. The shipped `models/aura_behavioral.joblib` trains from
`data/logs/` via `src/train_behavioral.py`, and that raw log tree is **not in
this checkout**. To include memory poisoning there, drop the 94 sessions into the
collected-logs corpus on the machine that has `data/logs/` and re-run
`train_behavioral.py`. The standalone `.jsonl` above is in the right schema for that.
