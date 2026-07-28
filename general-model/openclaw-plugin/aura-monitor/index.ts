/**
 * AURA Monitor — live behavioral risk gate for OpenClaw.
 *
 * Wires the AURA classifier into the agent runtime as a real-time control plane.
 * Calls the host-side scorer (http://host.docker.internal:5005), which combines a
 * rule layer, an echo/provenance layer, an action-trail layer, a compliance layer,
 * a memory-poisoning specialist, and the general behavioural model.
 *
 * INTERFACE INTEGRATION (what the user sees in the Control UI):
 *   block  -> the tool call is refused before it executes, with a reason that
 *             surfaces in the conversation.
 *   flag   -> an interactive APPROVAL PROMPT appears; the user decides
 *             allow-once / allow-always / deny. Denial is the safe default on timeout.
 *   allow  -> silent passthrough (logged to the dashboard only).
 *
 * Live dashboard: <scorer host>/dashboard (default http://localhost:5005/dashboard)
 *
 * ---------------------------------------------------------------------------
 * 2026-07-28 — THE COMPLIANCE LAYER WAS NEVER RUNNING. This is the fix.
 *
 * `scorer._compliance_layers(prompt, reply, tools)` returns (0,0) immediately when
 * `prompt` is empty. The previous version of this file sent
 *     before_tool_call -> { toolName, params, ingested }
 *     llm_output       -> { replyText, ingested }
 * Neither carried a prompt. So the deterministic labeler, the global evidence bar
 * and the deferred-compliance channel — the entire measured detection stack — were
 * dead in production. Verified against the live scorer on a known compliance case:
 *     payload without prompt -> verdict "allow", compliance layer 0.00
 *     same payload with prompt -> verdict "block", compliance layer 0.93
 * Every live block ever demonstrated came from the RULE layer alone.
 *
 * Root cause: no hook was capturing the user's message. `before_agent_run` carries
 * it (`event.prompt`), and nothing was listening. Fixed below.
 * ---------------------------------------------------------------------------
 *
 * WHICH HOOKS ACTUALLY FIRE — measured 2026-07-28, not assumed:
 *   before_tool_call    FIRES on the CLI path (`openclaw agent --json`). Verified by
 *                       scorer /history entries appearing for every tool call.
 *   before_agent_reply  does NOT fire on the CLI path. A run that produced a reply
 *                       generated zero (reply) entries in the scorer's history.
 *   llm_output          does NOT fire either, same test. It is declared in the SDK
 *                       types and present in PLUGIN_HOOK_NAMES, but never delivered.
 *   Both reply hooks are registered anyway; whichever the conversational surface
 *   (Control UI / channels) delivers will score. That path is NOT yet verified.
 *
 * CONSEQUENCE FOR THE ARCHITECTURE. On the CLI path only the tool-call side is live,
 * so RULE, ECHO and ACTION can block and COMPLIANCE cannot — at before_tool_call the
 * agent has not replied yet, and _compliance_layers short-circuits on an empty reply.
 * The compliance layer's offline numbers (P .921 / R .603 on 671 held-out sessions)
 * describe the reply path, which is reachable through the scorer API but is not
 * exercised by the CLI. Do not claim those numbers as live CLI behaviour.
 *
 * Hooks used:
 *   before_agent_run   — capture the user's prompt for the session (THE FIX)
 *   before_tool_call   — gate every tool call (block / approve / allow)
 *   after_tool_call    — record the action trail + remember ingested content
 *   before_agent_reply — score the agent's reply text (llm_output does NOT fire
 *                        in this build; measured, see below)
 *   llm_output         — same, registered as a fallback
 */
import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";

/**
 * Where the host-side scorer lives. The default works for Docker Desktop and OrbStack,
 * where `host.docker.internal` resolves to the host from inside the container.
 * Override with AURA_SCORER_URL when the scorer runs on another port or host, e.g.
 * plain Linux Docker (`http://172.17.0.1:5005/score`) or a shared deployment.
 * If you change the port here, set AURA_PORT to match when starting scorer.py.
 */
const SCORER = process.env.AURA_SCORER_URL || "http://host.docker.internal:5005/score";
const DASHBOARD = SCORER.replace(/\/score$/, "/dashboard");
const TIMEOUT_MS = Number(process.env.AURA_TIMEOUT_MS || 2000);

/**
 * Behaviour when the scorer is unreachable.
 *   "open"   (default) — allow. A monitoring outage must not break a user's agent.
 *   "closed" — deny tool calls. Correct for a deployment where the gate is a
 *              security control rather than an observability aid.
 * Set AURA_FAIL_MODE=closed in the container environment to switch.
 */
const FAIL_CLOSED = (process.env.AURA_FAIL_MODE || "open") === "closed";

const MAX_INGESTED = 4000;
const MAX_TRAIL = 40;

/** Per-session state. Keyed by sessionKey so a sleeper planted in turn 1 is still
 *  visible in turn 40 — single-call scoring cannot see delayed-activation attacks. */
type SessionState = {
  prompt: string;              // the user's message for the current run
  ingested: string;            // untrusted content the agent has read (echo layer)
  trail: Array<{ tool: string; kind?: string; paths?: string[]; failed?: boolean }>;
};
const sessions = new Map<string, SessionState>();

/** Cap on retained sessions. The gateway is long-lived and this Map had no eviction:
 *  one entry per session, forever, each holding up to MAX_INGESTED chars plus a trail.
 *  Map preserves insertion order, so deleting the oldest key is a cheap LRU-by-age. */
const MAX_SESSIONS = 500;

function stateFor(key: string): SessionState {
  let s = sessions.get(key);
  if (!s) {
    if (sessions.size >= MAX_SESSIONS) {
      const oldest = sessions.keys().next().value;
      if (oldest !== undefined) sessions.delete(oldest);
    }
    s = { prompt: "", ingested: "", trail: [] };
    sessions.set(key, s);
  }
  return s;
}

/** Pull the assistant reply out of a hook event, whatever shape the runtime uses.
 *  Field names are runtime-owned and have already changed once; read every known
 *  carrier rather than assuming one. Order matters: `assistantTexts` is the CLI
 *  runner's own array and is the authoritative one when present. */
function extractReply(event: any): string {
  const texts = Array.isArray(event?.assistantTexts) ? event.assistantTexts : [];
  const joined = texts.filter((t: any) => typeof t === "string" && t).join("\n");
  if (joined) return joined;
  const last = event?.lastAssistant;
  if (typeof last?.text === "string" && last.text) return last.text;
  if (Array.isArray(last?.content)) {
    const parts = last.content
      .map((p: any) => (typeof p === "string" ? p : typeof p?.text === "string" ? p.text : ""))
      .filter(Boolean);
    if (parts.length) return parts.join("\n");
  }
  return String(event?.cleanedBody || event?.text || event?.output || event?.content || "");
}

function sessionKey(event: any, ctx?: any): string {
  return (
    ctx?.sessionKey || event?.sessionKey || event?.ctx?.sessionKey ||
    event?.sessionId || event?.runId || "default"
  );
}

async function callScorer(payload: Record<string, unknown>): Promise<any> {
  try {
    const r = await fetch(SCORER, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    return await r.json();
  } catch {
    return FAIL_CLOSED
      ? { risk: 1.0, verdict: "block", reason: "scorer unreachable (fail-closed)", layer: "offline" }
      : { risk: 0, verdict: "allow", reason: "scorer unreachable", layer: "offline" };
  }
}

export default definePluginEntry({
  id: "aura-monitor",
  name: "AURA Monitor",
  description: "Behavioral risk gate backed by the AURA classifier.",
  register(api: any) {
    // ---- 0. Capture the user's prompt --------------------------------------
    // Without this the compliance layer is inert: it short-circuits on an empty
    // prompt. This hook is the whole reason the detection stack now runs live.
    api.on("before_agent_run", async (event: any, ctx: any) => {
      const s = stateFor(sessionKey(event, ctx));
      s.prompt = String(event?.prompt || "");
      s.trail = [];                       // new run, new action trail
      return undefined;                   // never gate here; observation only
    });

    // Same field, different lifecycle point. Harmless if both fire.
    api.on("agent_turn_prepare", async (event: any, ctx: any) => {
      const s = stateFor(sessionKey(event, ctx));
      if (event?.prompt) s.prompt = String(event.prompt);
      return undefined;
    });

    // ---- 1. Gate every tool call before it executes ------------------------
    api.on(
      "before_tool_call",
      async (event: any, ctx: any) => {
        const s = stateFor(sessionKey(event, ctx));
        const res = await callScorer({
          toolName: event.toolName,
          params: event.params,
          prompt: s.prompt,
          ingested: s.ingested,
          tools: s.trail.map((t) => t.tool),
          // Host-authoritative action-trail fields. `derivedPaths` is a hint, not
          // an authoritative parse, so the scorer treats it as evidence only.
          toolKind: event.toolKind,
          toolInputKind: event.toolInputKind,
          derivedPaths: event.derivedPaths || [],
          trail: s.trail.slice(-MAX_TRAIL),
        });

        console.log(
          `[aura] tool=${event.toolName} risk=${res.risk} verdict=${res.verdict}` +
            (res.reason ? ` — ${res.reason}` : ""),
        );

        if (res.verdict === "block") {
          return {
            block: true,
            blockReason:
              `AURA blocked this action — ${res.reason} (risk ${res.risk}, ` +
              `${res.layer} layer). Review it at ${DASHBOARD}`,
          };
        }

        if (res.verdict === "flag") {
          // `title` is REQUIRED by plugin.approval.request — omitting it makes the
          // gateway reject the request and hard-block the tool call.
          return {
            requireApproval: {
              title: `AURA: ${res.reason}`,
              description:
                `AURA flagged "${event.toolName}" — ${res.reason} ` +
                `(risk ${res.risk}, ${res.layer} layer). Allow this action?`,
              severity: "warning",
              timeoutBehavior: "deny",
              allowedDecisions: ["allow-once", "allow-always", "deny"],
              pluginId: "aura-monitor",
              onResolution: async (decision: string) => {
                console.log(`[aura] approval for ${event.toolName}: ${decision}`);
              },
            },
          };
        }

        return undefined; // allow
      },
      { priority: 50 },
    );

    // ---- 2. Record the action trail + remember ingested content -------------
    api.on("after_tool_call", async (event: any, ctx: any) => {
      const s = stateFor(sessionKey(event, ctx));

      s.trail.push({
        tool: event?.toolName,
        kind: event?.toolKind,
        paths: (event?.derivedPaths || []) as string[],
        failed: Boolean(event?.error),
      });
      if (s.trail.length > MAX_TRAIL) s.trail = s.trail.slice(-MAX_TRAIL);

      const out = typeof event?.result === "string"
        ? event.result
        : JSON.stringify(event?.result ?? "");
      if (!out) return;
      s.ingested = (s.ingested + "\n" + out).slice(-MAX_INGESTED);
    });

    // ---- 3. Score the agent's reply (text-resident attacks) ----------------
    // This is where the compliance layer earns its keep: the attacks that never
    // touch a tool end here, in the reply.
    //
    // `before_agent_reply` is the hook that actually fires in this build and it
    // carries the reply as `cleanedBody`. `llm_output` is declared in the SDK types
    // but was measured NOT to fire: a normal run produced zero reply-scoring events
    // in the scorer's history. Both are registered; whichever the runtime delivers
    // will score, and the handler is idempotent.
    const scoreReply = async (reply: string, key: string) => {
      if (!reply) return;
      const s = stateFor(key);
      const res = await callScorer({
        replyText: reply,
        prompt: s.prompt,                       // was missing — the whole bug
        ingested: s.ingested,
        tools: s.trail.map((t) => t.tool),
        trail: s.trail.slice(-MAX_TRAIL),
      });
      if (res.verdict !== "allow") {
        console.log(
          `[aura] reply risk=${res.risk} verdict=${res.verdict} — ${res.reason}` +
            ` [layer=${res.layer}]`,
        );
      }
      return res;
    };

    api.on("before_agent_reply", async (event: any, ctx: any) => {
      await scoreReply(extractReply(event), sessionKey(event, ctx));
      // Observation only for now. Returning { handled: true } would REPLACE the
      // reply, and the reply-side operating point has not been measured end to end
      // in-flight; the offline numbers are P .921 / R .603. Do not gate here until
      // that is measured live.
      return undefined;
    });

    // `llm_output` DOES fire on the CLI path. The earlier claim that it does not was an
    // artifact of reading the wrong fields: this handler used `event.text || event.output
    // || event.content`, and the runtime carries the reply in `assistantTexts` (string[])
    // and `lastAssistant`. All three legacy fields are undefined, so `reply` was always ""
    // and the handler returned before ever calling the scorer. Measured in the runtime
    // bundle (dist/cli-runner-*.js):
    //     if (assistantText.length > 0 && hasLlmOutputHooks)
    //       runAgentHarnessLlmOutputHook({ event: { runId, sessionId, provider, model,
    //                                               resolvedRef, assistantTexts,
    //                                               lastAssistant, usage }, ... })
    // Consequence of the bug: on the CLI path NO reply was ever scored, so the compliance
    // layer — the only layer whose operating point we have measured (OOS P 0.9214 /
    // R 0.6029) — contributed nothing in production. before_tool_call cannot stand in for
    // it: at that point the reply is empty and _compliance_layers short-circuits to 0.
    api.on("llm_output", async (event: any, ctx: any) => {
      await scoreReply(extractReply(event), sessionKey(event, ctx));
    });

    console.log(
      `[aura] monitor registered — fail-${FAIL_CLOSED ? "closed" : "open"}, ` +
        `dashboard ${DASHBOARD}`,
    );
  },
});
