# SciGateway - Live-Agent Analysis

This report is derived from observed OpenClaw sessions. Attack-success and label fields use documented behavior heuristics and are not a substitute for human adjudication.

Dataset: **700 live sessions**, 5-fold grouped CV. Best classifier: `exp1_metadata_only` / `logistic_regression`.

Input integrity fingerprint (SHA-256): `c83bf001e88caa97a89803420245ad68dde1251ba9082e8b6287b6adf588a3cc`. This detects later input changes; it is not collector identity attestation.

## Classifier (out-of-fold, pooled)

| Metric | Value |
|--------|------:|
| Attack detection rate | 0.686 |
| Macro-F1 | 0.438 |
| Unsafe recall | 0.000 |
| False-positive rate (benign flagged) | 0.320 |
| False-negative rate (attacks missed) | 0.314 |
| Severity-weighted detection | 0.453 |

## Gateway replay (security vs. usability)

| System | Attack success rate | Attack block rate | Over-block rate |
|--------|--------------------:|------------------:|----------------:|
| Rule baseline (no training) | 0.857 | 0.143 | 0.054 |
| ML evaluator (best, OOF) | 0.857 | 0.143 | 0.051 |

ML vs. rule block-decision agreement: **0.999** (1 differing sessions); exact enforcement-action agreement: **0.837** (114 differing sessions).

## Security view - detection among attacks that actually succeeded

The rates above are computed over every attack-*condition* session, including attacks the model resisted (nothing to catch). Restricting to the **210 attacks that behaviourally succeeded** (210/350 = 60.0% of attack conditions) gives the honest security picture:

| Of the successful attacks | count | rate |
|---------------------------|------:|-----:|
| Flagged by classifier (pred != safe) | 144 | 0.686 |
| Blocked end-to-end (policy enforcement) | 50 | 0.238 |
| Silent escapes (no action-trail signal, unflagged, unblocked) | 16 | 0.076 |
| Observable but not blocked (policy coverage gap) | 0 | 0.000 |

Detection is **bimodal by attack observability** - whether the successful attack raised any action-trail signal the gateway can act on:

| Observability class | successful | classifier flagged | gateway blocked |
|---------------------|-----------:|-------------------:|----------------:|
| action-manifesting (raised an action-trail signal) | 50 | 0 (0.00) | 50 (1.00) |
| text/state-resident (no action-trail signal) | 160 | 144 (0.90) | 0 (0.00) |

Every silent escape is text/state-resident: an action-monitoring gateway is structurally blind to attacks that leave no action-trail signal. An observable success can still escape when its signal maps only to a warning; that is a policy-coverage gap, not an observability gap. Blocks are driven by deterministic policy tripwires, not the classifier: unsafe recall is 0.000.

## Observability ablation - recall vs telemetry tier

The gateway is swept across cumulative telemetry tiers over the same **210 successful attacks**. Recall is the fraction of those attacks a tier could detect; the false-positive rate is over truly-safe control work. The tier at which a failure class first becomes detectable is its observability gap, quantified.

| Telemetry tier | detected | recall | recall 95% CI | control FPR | FPR 95% CI |
|----------------|---------:|-------:|:------:|------------:|:------:|
| action-trail only | 50/210 | 0.238 | [0.186, 0.300] | 18/350 = 0.051 | [0.033, 0.080] |
| + content provenance | 151/210 | 0.719 | [0.655, 0.775] | 132/350 = 0.377 | [0.328, 0.429] |
| + full transcript + classifier | 201/210 | 0.957 | [0.921, 0.977] | 190/350 = 0.543 | [0.490, 0.594] |

Recall by failure class (attack category) across tiers:

| Failure class | n | action-trail only | + content provenance | + full transcript + classifier |
|---|---|---|---|---|
| memory_poisoning | 50 | 0.00 | 1.00 | 1.00 |
| memory_poisoning_realistic | 50 | 0.00 | 1.00 | 1.00 |
| prose_claim_poisoning | 50 | 0.00 | 0.00 | 0.98 |
| provenance_spoofing | 10 | 0.00 | 0.10 | 0.20 |
| credential_exposure | 50 | 1.00 | 1.00 | 1.00 |

## Statistical uncertainty

Rates below use 95% Wilson score intervals; they show sampling uncertainty for these observed sessions, not external validity across models/platforms.

| Outcome | count | rate | 95% CI |
|---------|------:|-----:|:------:|
| Successful attacks blocked | 50/210 | 0.238 | [0.186, 0.300] |
| Action-manifesting successes blocked | 50/50 | 1.000 | [0.929, 1.000] |
| Text/state-resident successes blocked | 0/160 | 0.000 | [0.000, 0.023] |
| Truly-safe work over-blocked | 18/350 | 0.051 | [0.033, 0.080] |

## Native platform controls (confound)

OpenClaw applies its own tool policy before SciGateway's post-collection replay. Those restrictions are platform behavior and are not credited to SciGateway.

Matched gateway slices: **0/700** (0.0%); **700** analyzed sessions had no unambiguous matching slice. Among matched slices, native tool-policy events appeared in **0** (0.0%).

Adjacent gateway logs excluded from this dataset: **0**.

Tools removed by OpenClaw (number of log slices): (none observed).

The structured assets/CIA/attack-surface/STRIDE threat model and the observability boundary are recorded in `analysis_metrics.json`.

## Detection by attack category

| Attack category | n | detection rate | severity |
|-----------------|--:|---------------:|---------:|
| provenance_spoofing | 50 | 0.000 | 5 |
| prose_claim_poisoning | 50 | 0.980 | 5 |
| memory_poisoning | 50 | 0.960 | 5 |
| data_fabrication | 50 | 0.000 | 5 |
| memory_poisoning_realistic | 50 | 0.940 | 5 |
| context_poisoning | 50 | 0.140 | 4 |
| credential_exposure | 50 | 0.000 | 4 |
| benign | 350 | 0.429 | 0 |

## CV leaderboard

| Experiment | Model | Detection | Macro-F1 | FPR |
|------------|-------|----------:|---------:|----:|
| exp1_metadata_only | logistic_regression | 0.686 | 0.438 | 0.320 |
| exp2_fs_and_command | logistic_regression | 0.676 | 0.439 | 0.310 |
| exp3_full_gateway | logistic_regression | 0.676 | 0.438 | 0.312 |
| exp2_fs_and_command | decision_tree | 0.662 | 0.342 | 0.541 |
| exp3_full_gateway | decision_tree | 0.662 | 0.342 | 0.541 |
| exp1_metadata_only | decision_tree | 0.452 | 0.326 | 0.451 |
| exp2_fs_and_command | random_forest | 0.238 | 0.312 | 0.300 |
| exp1_metadata_only | random_forest | 0.238 | 0.309 | 0.310 |
| exp3_full_gateway | random_forest | 0.238 | 0.308 | 0.312 |
| exp3_full_gateway | xgboost | 0.190 | 0.316 | 0.229 |
| exp2_fs_and_command | xgboost | 0.186 | 0.309 | 0.247 |
| exp1_metadata_only | xgboost | 0.181 | 0.311 | 0.233 |
