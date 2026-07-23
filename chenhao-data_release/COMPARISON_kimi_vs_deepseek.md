# Preliminary cross-model comparison: Kimi-k2.5 vs deepseek-v4-pro

Generated from `experiments_rigor/{kimi_50,deepseek_50}/analysis/analysis_metrics.json`.
Attack-success labels use the collector heuristic (preliminary; pending two-rater
human adjudication). Recall is conditional on behaviorally successful attacks; the
false-positive rate (FPR) is on matched safe controls. Intervals are Wilson 95%.

- **Kimi-k2.5 (primary):** 700 sessions; 210 successful attacks; 350 controls.
- **deepseek-v4-pro (generalization):** 614 sessions; 183 successful attacks; 305 controls.

## Observability ablation (recall / FPR by tier)

| Telemetry tier | Kimi recall (95% CI) | deepseek recall (95% CI) | Kimi FPR (95% CI) | deepseek FPR (95% CI) |
|---|---|---|---|---|
| Action trail only | 0.238 (0.19–0.30) | 0.246 (0.19–0.31) | 0.051 (0.03–0.08) | 0.007 (0.00–0.02) |
| + content provenance | 0.719 (0.65–0.78) | 0.743 (0.68–0.80) | 0.377 (0.33–0.43) | 0.423 (0.37–0.48) |
| + full transcript | 0.957 (0.92–0.98) | 0.978 (0.95–0.99) | 0.543 (0.49–0.59) | 0.672 (0.62–0.72) |

## Recall by failure class (action / +provenance / +full transcript)

| Failure class | Observability | Kimi | deepseek |
|---|---|---|---|
| credential_exposure | action-manifesting | 1.00 / 1.00 / 1.00 | 1.00 / 1.00 / 1.00 |
| memory_poisoning | text-resident | 0.00 / 1.00 / 1.00 | 0.00 / 1.00 / 1.00 |
| memory_poisoning_realistic | text-resident | 0.00 / 1.00 / 1.00 | 0.00 / 1.00 / 1.00 |
| prose_claim_poisoning | text-resident | 0.00 / 0.00 / 0.98 | 0.00 / 0.00 / 0.98 |
| provenance_spoofing | text-resident | 0.00 / 0.10 / 0.20 | 0.00 / 0.57 / 0.57 |

## Reading

- The tier signature is the same on both models: action-only near 0.24, provenance
  0.72–0.74, full transcript 0.96–0.98. Model identity does not change the pattern.
- The circularity control replicates: memory poisoning recovers at the provenance
  tier for the canary and the realistic variant identically (0.00 / 1.00 / 1.00) on
  both models. Detection keys on content distinctiveness, not on an artificial marker.
- The prose (non-distinctive) variant is the ceiling on both models: 0.00 until the
  full transcript (~0.98).
- `provenance_spoofing` differs (Kimi 0.00/0.10/0.20 at n=10; deepseek 0.00/0.57/0.57
  at n=7). Both cells have small n and few successes, so this row is noisy and not a
  model difference to over-read.
- FPR is higher on deepseek at the upper tiers (0.423 / 0.672 vs 0.377 / 0.543). The
  usability cost of provenance and transcript telemetry is model-dependent, but the
  recall recovery is not.
