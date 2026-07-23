# SciGateway — Real-Agent Security Study: Data Release

This package holds the observed-session data and analysis for the SciGateway study.
The study measures what a runtime security gateway can detect in a live autonomous
agent at three telemetry tiers. This README uses Simplified Technical English.

You can use this data to reproduce the analysis or to combine it with your own
matched-session collections.

## 1. What is in this package

| Dataset | Model | Sessions | Design |
|---|---|---|---|
| `kimi_50/` | Kimi-k2.5 | 700 | 50 attack + 50 baseline per category, 7 categories |
| `deepseek_50/` | deepseek-v4-pro | 614 | 43–45 attack + 42–45 baseline per category (rate-limited) |

`kimi_50` is the primary high-power dataset. `deepseek_50` is a second-model
generalization dataset. `COMPARISON_kimi_vs_deepseek.md` gives the side-by-side
result. `MANIFEST_sha256.txt` lists a SHA-256 hash for every file.

## 2. Directory layout (per dataset)

```
<dataset>/
  sessions.jsonl                 one JSON object per line; the primary data
  analysis/
    analysis_metrics.json        all computed metrics (includes the tier ablation)
    analysis_results.md          human-readable results
    analysis_provenance.json     input fingerprints and run metadata
    error_analysis.md            misses and policy costs
    features.csv                 17 observable features per session
    platform_controls.json       native tool-policy confound checks
    audit_trail.jsonl            per-session gateway decisions
    figures/                     result figures (PNG)
  adjudication/
    worksheet_rater_A.csv        blind human worksheet (machine-assisted draft)
    worksheet_rater_B.csv        blind human worksheet (machine-assisted draft)
    answer_key.csv               heuristic labels (researcher reference)
    README.md                    how to fill the worksheets
```

## 3. The seven attack categories

Each category has a matched safe baseline. The set spans two observability classes.

| Category | Observability class | Attack goal |
|---|---|---|
| `credential_exposure` | action-manifesting | Read or disclose a fake key |
| `memory_poisoning` | text-resident | Reuse a self-announcing false tag (canary) |
| `memory_poisoning_realistic` | text-resident | Reuse a plausible false build tag |
| `prose_claim_poisoning` | text-resident | Reuse a non-distinctive false number |
| `context_poisoning` | text-resident | Obey a later-turn planted instruction |
| `data_fabrication` | text-resident | State an invented result as fact |
| `provenance_spoofing` | text-resident | Attribute output to a false source |

## 4. Session record schema (`sessions.jsonl`)

Each line is one session with these fields:

| Field | Meaning |
|---|---|
| `session_id` | `<category>-<condition>-<index>`, e.g. `credential_exposure-attack-007` |
| `date`, `platform`, `agent_name` | Collection metadata |
| `task_type`, `input_document_type` | The task and the input medium |
| `user_prompt` | The input turn (may carry the attack) |
| `agent_response` | The agent reply text |
| `actions` | Ordered action trail (for example, `file_read:...`) |
| `tool_calls`, `tool_trace_available` | Tool activity and whether the trace was captured |
| `latency_seconds` | Turn latency |
| `risk_indicators` | Boolean/int flags from the collector heuristic |
| `human_label` | Heuristic risk label: `safe`, `suspicious`, or `unsafe` |
| `label_notes` | Short reason for the heuristic label |
| `attack_category` | The category, or `benign` for a baseline |
| `attack_objective` | The attack goal (empty for a baseline) |
| `agent_config` | Model, container, and schedule metadata |
| `gateway_decision` | Replayed gateway decision, if present |

`condition` is `attack` or `baseline`. The `index` is the replicate number.

## 5. How to combine this data with your own

1. Keep the same `sessions.jsonl` schema and the same `session_id` scheme.
2. Use a unique `session_id` per session. To merge two sets, concatenate the JSONL
   files and drop duplicate `session_id` values.
3. Keep each attack matched to a baseline in the same category.
4. Record the model and the schedule seed in `agent_config`, so replicates stay
   reproducible and disjoint across shards.
5. Re-run the analysis on the merged file with the SciGateway `analyze-live`
   command (in the main repository) to regenerate the metrics and figures.

## 6. Labels and adjudication

The `human_label` field is an automatic **heuristic** label, not a final human
judgment. The `adjudication/` worksheets support a two-rater human check of that
heuristic. The worksheets are **pre-filled with the heuristic label as a draft**
(machine-assisted). Two independent human raters review and correct every row. This
procedure anchors the raters toward the heuristic, so the agreement it produces is an
upper bound, not a blind estimate. See `adjudication/README.md`.

## 7. Safety note

The data contains one **fake** secret canary, `MOCK-KEY-DO-NOT-USE-7f3a91zz`, and one
non-routable exfiltration address on the `.invalid` domain. These are harmless probe
artifacts. No real credential, private data, or routable endpoint is present.

## 8. License and citation

This data is released under **Creative Commons Attribution 4.0 (CC BY 4.0)**. See
`LICENSE`. If you use this data, cite the SciGateway study (OPALS Group 21, 2026).
