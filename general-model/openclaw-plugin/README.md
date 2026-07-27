# AURA Monitor — live behavioral risk gate for OpenClaw

Turns the AURA classifier into a real-time control plane inside OpenClaw. Every
tool call and agent reply is scored; dangerous actions are blocked before they
execute, borderline ones raise an **interactive approval prompt in the Control
UI**, and everything is streamed to a live dashboard.

## Quick start
```bash
cd openclaw-plugin
./setup.sh
```
Then open:
- **Dashboard** → http://localhost:5005/dashboard
- **OpenClaw UI** → http://localhost:18789 (get the token from `openclaw.json`)

Prereqs: OpenClaw running in Docker, host `python3` with `scikit-learn` + `joblib`.
Models load automatically from `../models/`.

## Architecture
```
 agent tool call / reply
        │
        ▼
 aura-monitor plugin (in OpenClaw)  ──HTTP──▶  scorer.py (host :5005)
   before_tool_call → block / approve / allow    ├─ RULE        dangerous action
   after_tool_call  → record ingested content    ├─ ECHO        reply repeats untrusted content
   llm_output       → score reply text           ├─ SPECIALIST  poisoning + untrusted-source frame
                                                 └─ GENERAL     broad model (advisory FLAG only)
                                                        │
                                                        ▼
                                                 live dashboard /dashboard
```
The scorer runs on the host because the OpenClaw container has no scikit-learn.

## What the user sees
| verdict | behavior in the Control UI |
|---|---|
| **block** | tool call refused before execution, with the reason in the conversation |
| **flag** | **interactive approval prompt** — allow-once / allow-always / deny. Times out to **deny** after 120s. Approve in chat with `/approve <id>` |
| allow | silent passthrough, logged to the dashboard |

Verified end to end: asking the agent to read a credentials file raises AURA's
approval request, the run pauses, and without approval the read is **denied**.

## Operating design (why it behaves well in practice)
- **Only precise layers can BLOCK** (rule / echo / frame-gated specialist), so
  benign science answers, ordinary facts, and normal tool use are never blocked.
- **The general model can only FLAG** — it is capped below the block threshold
  because it over-fires on borderline-but-legitimate replies. Broad coverage
  without breaking workflows.
- **Fail-open**: if the scorer is unreachable the agent is never blocked. A
  monitoring outage must not take down the user's agent.
- **Untrusted text is never rendered as HTML** — the dashboard builds DOM with
  `textContent`, so a malicious agent reply cannot script the monitoring page.

## Files
- `scorer.py` — host scoring service + dashboard (`/score`, `/dashboard`, `/history`)
- `aura-monitor/` — the OpenClaw plugin (`index.ts`, manifest, package.json)
- `setup.sh` — one-command install
- `try_aura.sh` — hands-on demo; `./try_aura.sh "some text"` scores your own text

## Updating the model
Retrain (`python ../analysis/train_general.py`), then `pkill -f scorer.py && ./setup.sh`.
The gate picks up the new model with no plugin changes.

## Honest limitations
- Blocking a *poisoned reply mid-generation* needs `before_agent_finalize`;
  today replies are flagged and tool-based attacks are blocked.
- The general model still soft-flags some benign confident claims (advisory only).
- Approvals need an approval-capable surface. The **Control UI chat** has one;
  a bare `openclaw agent` CLI run does not, so approvals there auto-deny on timeout.
- Hidden-image attacks are not detectable (no ollama-cloud vision model reads
  faint/hidden text — verified across 5 models).
