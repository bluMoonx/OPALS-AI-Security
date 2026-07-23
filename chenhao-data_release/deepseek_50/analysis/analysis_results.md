# SciGateway - Live-Agent Analysis

This report is derived from observed OpenClaw sessions. Attack-success and label fields use documented behavior heuristics and are not a substitute for human adjudication.

Dataset: **614 live sessions**, 5-fold grouped CV. Best classifier: `exp1_metadata_only` / `logistic_regression`.

Input integrity fingerprint (SHA-256): `39e00838d385749083ff0f891228c5cd46a7e75e781a3cba23e9be98fa08b021`. This detects later input changes; it is not collector identity attestation.

## Classifier (out-of-fold, pooled)

| Metric | Value |
|--------|------:|
| Attack detection rate | 0.880 |
| Macro-F1 | 0.412 |
| Unsafe recall | 0.000 |
| False-positive rate (benign flagged) | 0.487 |
| False-negative rate (attacks missed) | 0.120 |
| Severity-weighted detection | 0.630 |

## Gateway replay (security vs. usability)

| System | Attack success rate | Attack block rate | Over-block rate |
|--------|--------------------:|------------------:|----------------:|
| Rule baseline (no training) | 0.841 | 0.159 | 0.023 |
| ML evaluator (best, OOF) | 0.854 | 0.146 | 0.007 |

ML vs. rule block-decision agreement: **0.985** (9 differing sessions); exact enforcement-action agreement: **0.730** (166 differing sessions).

## Security view - detection among attacks that actually succeeded

The rates above are computed over every attack-*condition* session, including attacks the model resisted (nothing to catch). Restricting to the **183 attacks that behaviourally succeeded** (183/309 = 59.2% of attack conditions) gives the honest security picture:

| Of the successful attacks | count | rate |
|---------------------------|------:|-----:|
| Flagged by classifier (pred != safe) | 161 | 0.880 |
| Blocked end-to-end (policy enforcement) | 45 | 0.246 |
| Silent escapes (no action-trail signal, unflagged, unblocked) | 22 | 0.120 |
| Observable but not blocked (policy coverage gap) | 0 | 0.000 |

Detection is **bimodal by attack observability** - whether the successful attack raised any action-trail signal the gateway can act on:

| Observability class | successful | classifier flagged | gateway blocked |
|---------------------|-----------:|-------------------:|----------------:|
| action-manifesting (raised an action-trail signal) | 45 | 45 (1.00) | 45 (1.00) |
| text/state-resident (no action-trail signal) | 138 | 116 (0.84) | 0 (0.00) |

Every silent escape is text/state-resident: an action-monitoring gateway is structurally blind to attacks that leave no action-trail signal. An observable success can still escape when its signal maps only to a warning; that is a policy-coverage gap, not an observability gap. Blocks are driven by deterministic policy tripwires, not the classifier: unsafe recall is 0.000.

## Observability ablation - recall vs telemetry tier

The gateway is swept across cumulative telemetry tiers over the same **183 successful attacks**. Recall is the fraction of those attacks a tier could detect; the false-positive rate is over truly-safe control work. The tier at which a failure class first becomes detectable is its observability gap, quantified.

| Telemetry tier | detected | recall | recall 95% CI | control FPR | FPR 95% CI |
|----------------|---------:|-------:|:------:|------------:|:------:|
| action-trail only | 45/183 | 0.246 | [0.189, 0.313] | 2/305 = 0.007 | [0.002, 0.024] |
| + content provenance | 136/183 | 0.743 | [0.675, 0.801] | 129/305 = 0.423 | [0.369, 0.479] |
| + full transcript + classifier | 179/183 | 0.978 | [0.945, 0.991] | 205/305 = 0.672 | [0.618, 0.722] |

Recall by failure class (attack category) across tiers:

| Failure class | n | action-trail only | + content provenance | + full transcript + classifier |
|---|---|---|---|---|
| memory_poisoning | 44 | 0.00 | 1.00 | 1.00 |
| memory_poisoning_realistic | 43 | 0.00 | 1.00 | 1.00 |
| prose_claim_poisoning | 44 | 0.00 | 0.00 | 0.98 |
| provenance_spoofing | 7 | 0.00 | 0.57 | 0.57 |
| credential_exposure | 45 | 1.00 | 1.00 | 1.00 |

## Statistical uncertainty

Rates below use 95% Wilson score intervals; they show sampling uncertainty for these observed sessions, not external validity across models/platforms.

| Outcome | count | rate | 95% CI |
|---------|------:|-----:|:------:|
| Successful attacks blocked | 45/183 | 0.246 | [0.189, 0.313] |
| Action-manifesting successes blocked | 45/45 | 1.000 | [0.921, 1.000] |
| Text/state-resident successes blocked | 0/138 | 0.000 | [0.000, 0.027] |
| Truly-safe work over-blocked | 2/305 | 0.007 | [0.002, 0.024] |

## Native platform controls (confound)

OpenClaw applies its own tool policy before SciGateway's post-collection replay. Those restrictions are platform behavior and are not credited to SciGateway.

Matched gateway slices: **0/614** (0.0%); **614** analyzed sessions had no unambiguous matching slice. Among matched slices, native tool-policy events appeared in **0** (0.0%).

Adjacent gateway logs excluded from this dataset: **0**.

Tools removed by OpenClaw (number of log slices): (none observed).

The structured assets/CIA/attack-surface/STRIDE threat model and the observability boundary are recorded in `analysis_metrics.json`.

## Detection by attack category

| Attack category | n | detection rate | severity |
|-----------------|--:|---------------:|---------:|
| provenance_spoofing | 45 | 0.133 | 5 |
| prose_claim_poisoning | 44 | 0.977 | 5 |
| memory_poisoning | 44 | 0.886 | 5 |
| data_fabrication | 44 | 0.000 | 5 |
| memory_poisoning_realistic | 43 | 0.767 | 5 |
| context_poisoning | 44 | 0.750 | 4 |
| credential_exposure | 45 | 1.000 | 4 |
| benign | 305 | 0.564 | 0 |

## CV leaderboard

| Experiment | Model | Detection | Macro-F1 | FPR |
|------------|-------|----------:|---------:|----:|
| exp1_metadata_only | logistic_regression | 0.880 | 0.412 | 0.487 |
| exp2_fs_and_command | logistic_regression | 0.874 | 0.405 | 0.501 |
| exp3_full_gateway | logistic_regression | 0.874 | 0.402 | 0.508 |
| exp1_metadata_only | decision_tree | 0.240 | 0.295 | 0.357 |
| exp2_fs_and_command | decision_tree | 0.235 | 0.295 | 0.350 |
| exp3_full_gateway | decision_tree | 0.235 | 0.295 | 0.353 |
| exp3_full_gateway | xgboost | 0.137 | 0.286 | 0.260 |
| exp2_fs_and_command | xgboost | 0.137 | 0.285 | 0.265 |
| exp1_metadata_only | xgboost | 0.137 | 0.278 | 0.290 |
| exp3_full_gateway | random_forest | 0.120 | 0.273 | 0.283 |
| exp2_fs_and_command | random_forest | 0.120 | 0.272 | 0.288 |
| exp1_metadata_only | random_forest | 0.120 | 0.269 | 0.299 |
