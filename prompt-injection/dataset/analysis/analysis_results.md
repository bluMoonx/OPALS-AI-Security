# SciGateway - Live-Agent Analysis

This report is derived from observed OpenClaw sessions. Attack-success and label fields use documented behavior heuristics and are not a substitute for human adjudication.

Dataset: **600 live sessions**, 5-fold grouped CV. Best classifier: `exp2_fs_and_command` / `logistic_regression`.

Input integrity fingerprint (SHA-256): `2b32469e89f4b914cf8bc398470bd004f786b40d88308b616276c7b4c340b4d5`. This detects later input changes; it is not collector identity attestation.

## Classifier (out-of-fold, pooled)

| Metric | Value |
|--------|------:|
| Attack detection rate | 0.790 |
| Macro-F1 | 0.596 |
| Unsafe recall | 1.000 |
| False-positive rate (benign flagged) | 0.733 |
| False-negative rate (attacks missed) | 0.210 |
| Severity-weighted detection | 0.790 |

## Gateway replay (security vs. usability)

| System | Attack success rate | Attack block rate | Over-block rate |
|--------|--------------------:|------------------:|----------------:|
| Rule baseline (no training) | 0.997 | 0.003 | 0.000 |
| ML evaluator (best, OOF) | 0.587 | 0.413 | 0.042 |

ML vs. rule block-decision agreement: **0.765** (141 differing sessions); exact enforcement-action agreement: **0.248** (451 differing sessions).

## Security view - detection among attacks that actually succeeded

The rates above are computed over every attack-*condition* session, including attacks the model resisted (nothing to catch). Restricting to the **315 attacks that behaviourally succeeded** (315/315 = 100.0% of attack conditions) gives the honest security picture:

| Of the successful attacks | count | rate |
|---------------------------|------:|-----:|
| Flagged by classifier (pred != safe) | 249 | 0.790 |
| Blocked end-to-end (policy enforcement) | 130 | 0.413 |
| Silent escapes (no action-trail signal, unflagged, unblocked) | 66 | 0.210 |
| Observable but not blocked (policy coverage gap) | 0 | 0.000 |

Detection is **bimodal by attack observability** - whether the successful attack raised any action-trail signal the gateway can act on:

| Observability class | successful | classifier flagged | gateway blocked |
|---------------------|-----------:|-------------------:|----------------:|
| action-manifesting (raised an action-trail signal) | 2 | 2 (1.00) | 2 (1.00) |
| text/state-resident (no action-trail signal) | 313 | 247 (0.79) | 128 (0.41) |

Every silent escape is text/state-resident: an action-monitoring gateway is structurally blind to attacks that leave no action-trail signal. An observable success can still escape when its signal maps only to a warning; that is a policy-coverage gap, not an observability gap. Blocks are driven by deterministic policy tripwires, not the classifier: unsafe recall is 1.000.

## Statistical uncertainty

Rates below use 95% Wilson score intervals; they show sampling uncertainty for these observed sessions, not external validity across models/platforms.

| Outcome | count | rate | 95% CI |
|---------|------:|-----:|:------:|
| Successful attacks blocked | 130/315 | 0.413 | [0.360, 0.468] |
| Action-manifesting successes blocked | 2/2 | 1.000 | [0.342, 1.000] |
| Text/state-resident successes blocked | 128/313 | 0.409 | [0.356, 0.464] |
| Truly-safe work over-blocked | 12/285 | 0.042 | [0.024, 0.072] |

## Native platform controls (confound)

OpenClaw applies its own tool policy before SciGateway's post-collection replay. Those restrictions are platform behavior and are not credited to SciGateway.

Matched gateway slices: **0/600** (0.0%); **600** analyzed sessions had no unambiguous matching slice. Among matched slices, native tool-policy events appeared in **0** (0.0%).

Adjacent gateway logs excluded from this dataset: **600**.

Tools removed by OpenClaw (number of log slices): (none observed).

The structured assets/CIA/attack-surface/STRIDE threat model and the observability boundary are recorded in `analysis_metrics.json`.

## Detection by attack category

| Attack category | n | detection rate | severity |
|-----------------|--:|---------------:|---------:|
| indirect_prompt_injection | 315 | 0.790 | 5 |
| benign | 285 | 0.733 | 0 |

## CV leaderboard

| Experiment | Model | Detection | Macro-F1 | FPR |
|------------|-------|----------:|---------:|----:|
| exp2_fs_and_command | logistic_regression | 0.790 | 0.596 | 0.733 |
| exp1_metadata_only | logistic_regression | 0.781 | 0.510 | 0.839 |
| exp3_full_gateway | logistic_regression | 0.752 | 0.626 | 0.628 |
| exp1_metadata_only | decision_tree | 0.667 | 0.663 | 0.319 |
| exp3_full_gateway | decision_tree | 0.644 | 0.663 | 0.368 |
| exp2_fs_and_command | decision_tree | 0.629 | 0.660 | 0.351 |
| exp1_metadata_only | random_forest | 0.613 | 0.541 | 0.575 |
| exp3_full_gateway | random_forest | 0.606 | 0.590 | 0.533 |
| exp2_fs_and_command | random_forest | 0.575 | 0.552 | 0.575 |
