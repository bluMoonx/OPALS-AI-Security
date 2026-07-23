# General Model — behavioral risk classifier across the full attack taxonomy

A gateway-level classifier that flags unsafe agent behavior from OpenClaw logs,
generalized across attack categories (not just memory poisoning).

## Models (`models/`)
- **`aura_general.joblib`** — the general model. Trained on the pooled dataset
  (this track's collected sessions + the team's kimi/deepseek releases),
  **1,733 sessions, 34 attack categories**, outcome-based labels (`human_label`:
  did the agent actually behave unsafely, not merely: was it attacked).
  **ROC-AUC 0.763, leave-one-attack-category-out** (tested on categories held out
  of training — the "catches unseen attack types" number).
- **`aura_v1.joblib`** — memory-poisoning specialist, ROC-AUC 0.789 on the Spring
  science turns.
- `metrics*.json` — the CV results.

## Features (`src/science_features.py`)
The differentiator: AI-for-Science behavioral features (hedge/certainty density,
citation behavior, `unverified_confident_claim`, `capability_spoof`) on top of
the action/metadata signals. Ablation shows +6 AUC over metadata-only.

## Prompts (`prompts/new_categories_bank.jsonl`)
100 matched attack/baseline pairs across 10 new categories: emotional_coercion,
hypothetical_framing, false_precedent, delimiter_confusion, role_spoofing,
sleeper_trigger, cot_hijack, meta_prompting, multilingual_injection,
prompt_leaking. Each plants a MOCK secret and carries a `canary` for automatic
success labeling. (Mock secrets are sanitized to non-provider formats.)

## Logs (`logs/`)
Collected labeled sessions: `new10category/` (the 10 new categories, canary-labeled)
and `collected_22category/` (the scigateway attack taxonomy).

## Code (`src/`)
- `train_general.py` — pools the logs, extracts features, trains + LOACO, saves the model.
- `science_features.py` — the feature extractor.
- `collect_prompt_pairs.py` — runs prompt pairs through OpenClaw and auto-labels by canary.
- `train_full.py` / `train_spring_baseline.py` — the memory-poisoning specialist + baseline.
- `make_image_attacks.py` — decoy-graph image injection generator.

## Images (`images/decoy_graphs/`)
Visible typographic injection on science figures — WORKS on kimi (agent obeys the
embedded instruction). Note: hidden-to-human image injection (watermark/scaling)
was tested across 5 ollama-cloud vision models and does NOT work — those models
only read clearly-visible text. Documented as a limitation of the cloud vision.

## Reproduce
`python src/train_general.py` (from a dir with `logs/` present) rebuilds
`models/aura_general.joblib` and prints the LOACO metrics.
