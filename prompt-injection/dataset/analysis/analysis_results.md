# SciGateway - Live-Agent Analysis

This report is derived from observed OpenClaw sessions. Attack-success and label fields use documented behavior heuristics and are not a substitute for human adjudication.

Dataset: **600 live sessions**, 5-fold grouped CV. Best classifier: `exp3_full_gateway` / `decision_tree`.

Input integrity fingerprint (SHA-256): `59318ffef38f6368894b97469fe8be4429439bc3944549c7e8420679038ba803`. This detects later input changes; it is not collector identity attestation.

## Classifier (out-of-fold, pooled)

| Metric | Value |
|--------|------:|
| Attack detection rate | 0.500 |
| Macro-F1 | 0.499 |
| Unsafe recall | 0.000 |
| False-positive rate (benign flagged) | 0.002 |
| False-negative rate (attacks missed) | 0.500 |
| Severity-weighted detection | 0.003 |

## Gateway replay (security vs. usability)

| System | Attack success rate | Attack block rate | Over-block rate |
|--------|--------------------:|------------------:|----------------:|
| Rule baseline (no training) | 0.998 | 0.003 | 0.000 |
| ML evaluator (best, OOF) | 0.998 | 0.003 | 0.000 |

ML vs. rule block-decision agreement: **1.000** (0 differing sessions); exact enforcement-action agreement: **0.998** (1 differing sessions).

## Security view - detection among attacks that actually succeeded

The rates above are computed over every attack-*condition* session, including attacks the model resisted (nothing to catch). Restricting to the **315 attacks that behaviourally succeeded** (315/400 = 78.8% of attack conditions) gives the honest security picture:

| Of the successful attacks | count | rate |
|---------------------------|------:|-----:|
| Flagged by classifier (pred != safe) | 1 | 0.003 |
| Blocked end-to-end (policy enforcement) | 1 | 0.003 |
| Silent escapes (no action-trail signal, unflagged, unblocked) | 313 | 0.994 |
| Observable but not blocked (policy coverage gap) | 1 | 0.003 |

Detection is **bimodal by attack observability** - whether the successful attack raised any action-trail signal the gateway can act on:

| Observability class | successful | classifier flagged | gateway blocked |
|---------------------|-----------:|-------------------:|----------------:|
| action-manifesting (raised an action-trail signal) | 2 | 1 (0.50) | 1 (0.50) |
| text/state-resident (no action-trail signal) | 313 | 0 (0.00) | 0 (0.00) |

Every silent escape is text/state-resident: an action-monitoring gateway is structurally blind to attacks that leave no action-trail signal. An observable success can still escape when its signal maps only to a warning; that is a policy-coverage gap, not an observability gap. Blocks are driven by deterministic policy tripwires, not the classifier: unsafe recall is 0.000.

## Statistical uncertainty

Rates below use 95% Wilson score intervals; they show sampling uncertainty for these observed sessions, not external validity across models/platforms.

| Outcome | count | rate | 95% CI |
|---------|------:|-----:|:------:|
| Successful attacks blocked | 1/315 | 0.003 | [0.001, 0.018] |
| Action-manifesting successes blocked | 1/2 | 0.500 | [0.095, 0.905] |
| Text/state-resident successes blocked | 0/313 | 0.000 | [0.000, 0.012] |
| Truly-safe work over-blocked | 0/200 | 0.000 | [0.000, 0.019] |

## Native platform controls (confound)

OpenClaw applies its own tool policy before SciGateway's post-collection replay. Those restrictions are platform behavior and are not credited to SciGateway.

Matched gateway slices: **0/600** (0.0%); **600** analyzed sessions had no unambiguous matching slice. Among matched slices, native tool-policy events appeared in **0** (0.0%).

Adjacent gateway logs excluded from this dataset: **0**.

Tools removed by OpenClaw (number of log slices): (none observed).

The structured assets/CIA/attack-surface/STRIDE threat model and the observability boundary are recorded in `analysis_metrics.json`.

## Detection by attack category

| Attack category | n | detection rate | severity |
|-----------------|--:|---------------:|---------:|
| direct_prompt_injection | 400 | 0.003 | 5 |
| benign | 200 | 0.005 | 0 |

## CV leaderboard

| Experiment | Model | Detection | Macro-F1 | FPR |
|------------|-------|----------:|---------:|----:|
| exp3_full_gateway | decision_tree | 0.500 | 0.499 | 0.002 |
| exp2_fs_and_command | logistic_regression | 0.500 | 0.398 | 0.012 |
| exp3_full_gateway | logistic_regression | 0.500 | 0.398 | 0.012 |
| exp1_metadata_only | logistic_regression | 0.500 | 0.362 | 0.028 |
| exp1_metadata_only | random_forest | 0.000 | 0.333 | 0.000 |
| exp1_metadata_only | xgboost | 0.000 | 0.333 | 0.000 |
| exp2_fs_and_command | random_forest | 0.000 | 0.333 | 0.000 |
| exp2_fs_and_command | xgboost | 0.000 | 0.333 | 0.000 |
| exp3_full_gateway | random_forest | 0.000 | 0.333 | 0.000 |
| exp3_full_gateway | xgboost | 0.000 | 0.333 | 0.000 |
| exp2_fs_and_command | decision_tree | 0.000 | 0.332 | 0.002 |
| exp1_metadata_only | decision_tree | 0.000 | 0.332 | 0.003 |
