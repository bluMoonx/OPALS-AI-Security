# MODELS.md — what each file is, and which one to use

**Use `aura_behavioral.joblib`.** It is what `scorer.py` loads. Everything else here is
provenance or research.

| model | AUC | LOACO | trained on | status |
|---|---|---|---|---|
| **`aura_behavioral.joblib`** | **0.7427** | **0.7117** | 965 hand-judged behavioural labels | **SHIPPED** |
| `aura_v1.joblib` | 0.789 | — | spring turns, 1,998 rows | used as the specialist layer |
| `aura_general.joblib` | 0.836 | — | CANARY labels, leaky protocol | fallback only, **discredited target** |
| `aura_general.backup.joblib` | 0.905 | — | same, 3,188 rows | **withdrawn number**, kept for provenance |

## Why 0.7427 and not 0.905

The 0.905 was real arithmetic on the wrong protocol. Two defects, both fixed:

1. **Prompt-duplication leak.** Sessions sharing a prompt landed in both train and test.
   Regrouping with `StratifiedGroupKFold` on `md5(prompt)` dropped AUC from 0.797 to 0.743.
2. **CANARY-derived labels.** The target was a planted token rather than judged behaviour,
   so the model learned the canary, not the risk. Retrained on 965 hand-judged labels.

The honest number went down. That is what fixing a leak looks like, and 0.7427 is a number
that survives leave-one-attack-category-out at 0.7117 while 0.905 was never tested that way.

## What the model is allowed to do

**It cannot block.** `scorer.py` caps the general layer below `BLOCK_AT`, so the highest
verdict it can produce alone is `flag`, which raises an approval prompt. Blocking is
reserved for the precise deterministic layers.

This is deliberate and measured: at the operating point the model's precision is not good
enough to refuse a scientist's work, but its coverage is broad enough to be worth surfacing.

## Local-only models, deliberately not published

Three models exist in the working tree and are **not** in this repo:

- `aura_behavioral_sog.joblib` — 105 features, nested AUC 0.898. Higher AUC, **loses at the
  operating point** (R 0.387 against 0.449 at P >= 0.90). Research value only.
- `aura_final.joblib` — metadata claims n=296; the truth is 294, with 2 rows double-weighted.
- `aura_honest.joblib` — canary-era, AUC 0.502 over 12 of 38 folds. Source of the withdrawn
  figure 4.

They are omitted because publishing a model whose headline AUC beats the shipped one, while
losing where decisions are made, invites exactly the misquote this project keeps having to
correct.

## Reproduce

```bash
python3 analysis/paper_repro/policy_curve.py     # the operating-point table
python3 layering/w2_repro.py                     # AUC, LOACO, per-family breakdown
```
