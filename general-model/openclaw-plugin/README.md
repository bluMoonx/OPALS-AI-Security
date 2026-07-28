# AURA Monitor — live behavioral risk gate for OpenClaw

Turns the AURA classifier into a real-time control plane inside OpenClaw. Every tool call
and agent reply is scored; dangerous actions are blocked before they execute, borderline
ones raise an **interactive approval prompt**, and everything is streamed to a live
dashboard.

---

## Install

```bash
cd openclaw-plugin
./setup.sh
```

That is the whole install on Docker Desktop or OrbStack with a container named
`openclaw-gateway`. It starts the scorer, copies the plugin into the container, links it,
enables conversation access, and restarts the gateway.

**Prereqs**
- OpenClaw running in Docker
- host `python3` with `scikit-learn` and `joblib` (`pip install scikit-learn joblib`)
- models present in `../models/` (loaded automatically, by path relative to `scorer.py`)

Then open:
- **Dashboard** -> `http://localhost:5005/dashboard`
- **Decision history (JSON)** -> `http://localhost:5005/history`

### The dashboard

Every decision is a row. **Click any row to expand it.** The detail view shows:

| section | what it gives you |
|---|---|
| context strip | session id, event kind, active block policy, echo grade, prompt/reply/ingested sizes |
| **User prompt / Agent reply** | the full conversation for that decision, side by side |
| Tool call | the tool name and the exact params it was about to run |
| **Layer scores** | every layer's score as a bar, sorted, so you can see *why* `risk` is what it is and which layer was the argmax |
| Evidence | the rule/action reason, planted literals found in the prompt, derived paths, tools available, untrusted-source frame |
| Action trail | the ordered tools already called this session, with targets and failures |
| Ingested content | the untrusted text the agent read, which the ECHO layer scores against |

Top bar: live counts, per-layer firing counts, free-text search across prompt/reply/tool/
reason/session, verdict filters (block / flag / allow) and an event-kind filter
(tool calls / replies). Polls every 2s.

**Security:** the dashboard renders untrusted agent text. Every node is built with
`textContent`; there is no `innerHTML`, `outerHTML`, `document.write` or `eval` anywhere in
it, and `test_suite.py` fails if one is ever introduced.

### If your setup differs

Every setting is an environment variable. Nothing is hardcoded to one machine.

| variable | default | when to change it |
|---|---|---|
| `AURA_CONTAINER` | `openclaw-gateway` | your container has another name |
| `AURA_PORT` | `5005` | 5005 is taken |
| `AURA_SCORER_URL` | `http://host.docker.internal:$AURA_PORT/score` | **plain Linux Docker**, where `host.docker.internal` usually does not resolve. Use the bridge gateway, typically `http://172.17.0.1:5005/score` |
| `AURA_COMPOSE_DIR` | unset | you want `docker compose restart` instead of `docker restart` |
| `AURA_FAIL_MODE` | `open` | set `closed` to deny tool calls when the scorer is down |

```bash
AURA_CONTAINER=my-agent AURA_PORT=5099 ./setup.sh
```

**Uninstall**

```bash
docker exec openclaw-gateway openclaw plugins uninstall aura-monitor
pkill -f scorer.py
```

---

## Architecture

```
 agent tool call / reply
        │
        ▼
 aura-monitor plugin (in OpenClaw)  ──HTTP──▶  scorer.py (host :5005)
   before_agent_run  → capture prompt           ├─ RULE        dangerous action
   before_tool_call  → block / approve / allow  ├─ ECHO        reply repeats untrusted content
   after_tool_call   → record ingested content  ├─ COMPLIANCE  agent obeyed an injected instruction
   before_agent_reply→ score reply text         ├─ ACTION      risky action trail   (flag-grade)
   llm_output        → fallback                 ├─ SPECIALIST  poisoning + untrusted frame
                                                └─ GENERAL     broad model          (flag-grade)
                                                        │
                                                        ▼
                                                 live dashboard /dashboard
```

The scorer runs on the **host** because the OpenClaw container has no scikit-learn.
`before_agent_run` is load-bearing: without the prompt, the compliance layer short-circuits
and the entire measured detection stack is dead. That was a real outage in this plugin and
is why the hook exists.

---

## What the user sees

| verdict | behaviour |
|---|---|
| **block** | tool call refused before execution, reason surfaced in the conversation |
| **flag** | **interactive approval prompt** — allow-once / allow-always / deny. Times out to **deny** |
| allow | silent passthrough, logged to the dashboard |

---

## Which hooks actually fire (measured, not assumed)

| hook | CLI (`openclaw agent --json`) |
|---|---|
| `before_agent_run` | fires |
| `before_tool_call` | fires |
| `after_tool_call` | fires |
| `before_agent_reply` | **does not fire** |
| `llm_output` | **does not fire** (declared in the SDK, never delivered) |

**Consequence, and do not paper over it:** on the CLI path only the tool-call side is live,
so RULE, ECHO and ACTION can block and COMPLIANCE cannot. The compliance layer's offline
numbers describe the **reply** path, which is reachable through the scorer API. Whether the
conversational surface delivers the reply hooks is **not yet verified**. Do not quote
reply-path numbers as live CLI behaviour.

---

## Operating design

- **Only precise layers can BLOCK** (rule / echo / compliance / frame-gated specialist), so
  ordinary science answers and normal tool use are not blocked.
- **The general model and the action layer can only FLAG** — both are capped below the block
  threshold. Broad coverage without breaking workflows.
- **Fail-open by default.** A monitoring outage must not take down the user's agent. Set
  `AURA_FAIL_MODE=closed` where the gate is a security control rather than an observability aid.
- **Untrusted text is never rendered as HTML.** The dashboard builds DOM with `textContent`,
  so a malicious agent reply cannot script the monitoring page.
- **The scorer binds `0.0.0.0`** because the container reaches it via `host.docker.internal`,
  which is not the host loopback. That means the port is open on your LAN. Narrow it with
  `AURA_BIND` only if your Docker network gives the container another route to the host.

---

## Tuning

| variable | values | effect |
|---|---|---|
| `AURA_BLOCK_POLICY` | `off` \| `strict` (default) \| `balanced` \| `aggressive` | how aggressively the evidence channels gate. `budget` was measured and **rejected** |
| `AURA_ECHO_GRADE` | `flag` (default) \| `block` | whether an echo alone can block |
| `AURA_EVIDENCE_PROMOTION` | `0` (default) \| `1` | promote multi-channel evidence to block grade |
| `AURA_INSTRUCTED_ECHO` | `1` (default) \| `0` | flag-grade channel for "the reply emits a literal the prompt planted" |

Numbers for each policy are in [`../GATE_OPERATING_POINTS.md`](../GATE_OPERATING_POINTS.md).
**No gate number may be quoted without its policy label.**

---

## Files

- `scorer.py` — host scoring service + dashboard (`/score`, `/dashboard`, `/history`, `/health`)
- `aura-monitor/` — the OpenClaw plugin (`index.ts`, `openclaw.plugin.json`, `package.json`)
- `behavioral_labeler.py`, `deferred_compliance.py` — deterministic detection channels
- `setup.sh` — one-command install
- `try_aura.sh` — hands-on demo; `./try_aura.sh "some text"` scores your own text
- `test_suite.py` — 24 tests. **Run after any change to a shipped file.**

```bash
python3 openclaw-plugin/test_suite.py
```

---

## Honest limitations

- Blocking a *poisoned reply mid-generation* needs `before_agent_finalize`; today replies are
  flagged and tool-based attacks are blocked.
- Approvals need an approval-capable surface. A bare `openclaw agent` CLI run does not have
  one, so approvals there auto-deny on timeout.
- Hidden-image attacks are not detectable (no ollama-cloud vision model reads faint or hidden
  text; verified across 5 models).
- **Benign cost on tool-using workloads is unmeasured.** Our benign corpus has 0 rows
  carrying tool output, so the ECHO layer is structurally invisible there. On an external
  corpus that does carry tool output, ECHO fires on 13.4% of benign replies.
