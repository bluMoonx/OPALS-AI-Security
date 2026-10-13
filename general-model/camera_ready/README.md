# Camera-ready reproduction (IEEE BIBM 2026 UGHS, paper S59280)

`camera_ready_numbers.py` recomputes every behavioral-corpus number in the camera-ready paper
*Runtime Gating of Unsafe Tool Use in Autonomous Scientific Agents* from the data in this repository,
and checks each one against the value printed in the paper.

```
python3 general-model/camera_ready/camera_ready_numbers.py
```

It prints one line per number (section, what the paper states, what the script computes) and ends
with `46 of 46 numbers match the paper.` All values are also written to `camera_ready_numbers.json`.
The first run scores 1,752 sessions under four block policies with `openclaw-plugin/scorer.py`;
the verdicts are cached in `verdict_cache.json`. Delete the cache to rescore from scratch.

## What it covers

| Paper | Numbers |
|---|---|
| III-D | corpus size, attack types, biomedical share of distinct prompts, labeled sessions, laboratory keyword rule |
| III-E | canary agreement with the human judges (Cohen's kappa) |
| IV-A | deletion trial from `ab_intervention_results.json`; Fisher and Wilson statistics for the trial counts |
| IV-B, Table III | out-of-fold policy choice and outcomes, per-fold ranges, aggressive and strict settings |
| Table I, IV-C | leave-one-layer-out ablation; out-of-fold refusal of text-resident vs action-manifesting successes, unflagged successes, refusal by attack type |
| IV-D | laboratory vs other (canary and human labels) with Wilson intervals, Mantel-Haenszel adjustment, per-prompt tests, replay refusal by task type |
| Table II | behavioral rows (human-labeled tool-reaching share, canary successes) |

## Inputs

- `logs/new10category/newcats_sessions.jsonl` and `newcats_actions_recovered.jsonl`: the 2,166-session corpus and its action trails
- `gold_labels/gold2_*.jsonl`: second labeling round (the 671 held-out attack sessions)
- `gold_labels/round1/`: first labeling round, added with this folder. `src/resolve_gold.py` needs these
  files, and without them the 817 labeled attack sessions reduce to 671.
- `openclaw-plugin/scorer.py` and `models/aura_behavioral.joblib`: the shipped gateway scorer

`src/eval_combined_gold.py` looks for the second round under `analysis/rebuild/`, which does not exist in
this repository, so the script points it at `gold_labels/` before loading.

## Not reproduced here

- **Tool-denial trial** (credential exfiltration, IV-A): counts are as reported on the team poster. The session logs are
  not in this repository.
- **Table II, non-behavioral rows**: these come from each collection's own outputs:
  `chenhao-data_release/*/analysis` (primary corpora), `prompt-injection/dataset` (direct injection),
  `memory-poisoning/data/processed` (memory poisoning), `logs/collected_22category` (broad taxonomy) and
  `evangeline_website_tests` (web and browser).
