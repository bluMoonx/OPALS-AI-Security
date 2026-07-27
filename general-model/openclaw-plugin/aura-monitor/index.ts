/**
 * AURA Monitor — live behavioral risk gate for OpenClaw.
 *
 * Wires the AURA classifier into the agent runtime as a real-time control
 * plane. Calls the host-side scorer (http://host.docker.internal:5005), which
 * combines a rule layer, an echo/provenance layer, a memory-poisoning
 * specialist, and the general 38-category model.
 *
 * INTERFACE INTEGRATION (what the user sees in the Control UI):
 *   block  -> the tool call is refused before it executes, with a reason
 *             that surfaces in the conversation.
 *   flag   -> an interactive APPROVAL PROMPT appears in the UI; the user
 *             decides allow-once / allow-always / deny. Denial is the safe
 *             default if the prompt times out.
 *   allow  -> silent passthrough (logged to the dashboard only).
 *
 * Live dashboard: http://localhost:5005/dashboard
 *
 * Hooks used:
 *   before_tool_call     — gate every tool call (block / approve / allow)
 *   after_tool_call      — capture what a tool RETURNED, so the echo layer can
 *                          later detect the reply reproducing untrusted content
 *   llm_output           — score the agent's reply text (text-resident attacks)
 */
import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";

const SCORER = "http://host.docker.internal:5005/score";
const TIMEOUT_MS = 2000;

/** Recent untrusted content the agent ingested, per session (for the echo layer). */
const ingestedBySession = new Map<string, string>();
const MAX_INGESTED = 4000;

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
    // Fail OPEN: a monitoring outage must never break the user's agent.
    return { risk: 0, verdict: "allow", reason: "scorer unreachable", layer: "offline" };
  }
}

function sessionKey(event: any): string {
  return event?.sessionKey || event?.ctx?.sessionKey || event?.runId || "default";
}

export default definePluginEntry({
  id: "aura-monitor",
  name: "AURA Monitor",
  description: "Behavioral risk gate backed by the AURA classifier.",
  register(api: any) {
    // ---- 1. Gate every tool call before it executes ----------------------
    api.on(
      "before_tool_call",
      async (event: any) => {
        const key = sessionKey(event);
        const res = await callScorer({
          toolName: event.toolName,
          params: event.params,
          ingested: ingestedBySession.get(key) || "",
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
              `${res.layer} layer). Review it at http://localhost:5005/dashboard`,
          };
        }

        if (res.verdict === "flag") {
          // Interactive: the user decides, in the Control UI.
          // `title` is REQUIRED by plugin.approval.request — omitting it makes
          // the gateway reject the request and hard-block the tool call.
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

    // ---- 2. Remember untrusted content the agent ingested ----------------
    api.on("after_tool_call", async (event: any) => {
      const key = sessionKey(event);
      const out = typeof event?.result === "string"
        ? event.result
        : JSON.stringify(event?.result ?? "");
      if (!out) return;
      const prev = ingestedBySession.get(key) || "";
      ingestedBySession.set(key, (prev + "\n" + out).slice(-MAX_INGESTED));
    });

    // ---- 3. Score the agent's reply (text-resident attacks) --------------
    api.on("llm_output", async (event: any) => {
      const reply = event?.text || event?.output || event?.content || "";
      if (!reply) return;
      const key = sessionKey(event);
      const res = await callScorer({
        replyText: reply,
        ingested: ingestedBySession.get(key) || "",
      });
      if (res.verdict !== "allow") {
        console.log(
          `[aura] reply risk=${res.risk} verdict=${res.verdict} — ${res.reason}`,
        );
      }
    });

    console.log("[aura] monitor registered — dashboard http://localhost:5005/dashboard");
  },
});
