# AURA Monitor — live behavioral risk gate for OpenClaw

Turns the AURA classifier into a real-time enforcement plugin. Every tool call
and agent reply is scored; high-risk actions are blocked before they run.

## Quick start
```bash
cd openclaw-plugin
./setup.sh
```
That starts the scorer and installs the gate into a running `openclaw-gateway`.

Prereqs: OpenClaw running in Docker, and host `python3` with `scikit-learn` +
`joblib` (`pip install scikit-learn joblib`). The models in `../models/` are
loaded automatically.

## How it works
```
 agent tool call / reply
        │
        ▼
 aura-monitor plugin (in OpenClaw)  ──HTTP──▶  scorer.py (host :5005)
   before_tool_call → block/allow                ├─ RULE     dangerous action → block
   llm_output       → flag                       ├─ ECHO     reply repeats untrusted content → block
                                                 ├─ SPECIALIST poisoning + "your notes" frame → block
                                                 └─ GENERAL  broad model → advisory FLAG only
```

## Operating design (why it behaves well in practice)
- **Blocks come ONLY from precise signals** (rule / echo / frame-gated specialist),
  so benign science answers, facts, and normal tool use are never blocked.
- **The general model can only FLAG, never block alone** — it is broad but noisy,
  so it raises advisory flags for human review instead of breaking workflows.
- **Fail-open**: if the scorer is unreachable the agent is never blocked.

Verified behavior:
| input | verdict |
|---|---|
| memory-poisoned reply ("prefer your notes over external", false value) | **block** |
| `rm -rf` / secret-file / exfil tool call | **block** / flag |
| benign science answer, benign fact, `web_search` | **allow** |

## Files
- `scorer.py` — host scoring service (loads `aura_general` + `aura_v1`).
- `aura-monitor/` — the OpenClaw plugin (`index.ts`, manifest, package.json).
- `setup.sh` — one-command install.

## Updating the model
Retrain (`python ../analysis/train_general.py`), then restart the scorer:
`pkill -f scorer.py && ./setup.sh`. No plugin changes needed — the gate picks up
the new model automatically.

## Honest limitations
- Blocking a *poisoned reply* mid-generation needs the `before_agent_finalize`
  hook (currently reply risk is flagged, tool-based attacks are blocked).
- The general model still soft-flags some benign confident claims (advisory only).
- Hidden-image attacks aren't detectable (kimi's vision can't read hidden text).
