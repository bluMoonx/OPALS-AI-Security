/**
 * AURA Monitor — live behavioral risk gate for OpenClaw.
 *
 * Hooks the typed plugin events and calls the host-side AURA scorer
 * (http://host.docker.internal:5005) which combines a rule layer (inline-
 * blockable dangerous actions) with the aura_general ML model (text-resident
 * risk). This turns the offline classifier into a real-time enforcement gate.
 *
 *   before_tool_call -> block clearly-dangerous tool calls before they run
 *   llm_output       -> score the agent's reply, flag elevated risk
 */
import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";

const SCORER = "http://host.docker.internal:5005/score";

async function callScorer(payload: Record<string, unknown>): Promise<any> {
  try {
    const r = await fetch(SCORER, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(2000),
    });
    return await r.json();
  } catch (e) {
    // fail-open: never break the agent if the scorer is down
    return { risk: 0, verdict: "allow", reason: "scorer unreachable" };
  }
}

export default definePluginEntry({
  id: "aura-monitor",
  name: "AURA Monitor",
  description: "Behavioral risk gate backed by the AURA classifier.",
  register(api: any) {
    // 1) Inline enforcement: block dangerous tool calls BEFORE they execute.
    api.on(
      "before_tool_call",
      async (event: any) => {
        const res = await callScorer({
          toolName: event.toolName,
          params: event.params,
        });
        console.log(
          `[aura] scored tool=${event.toolName} risk=${res.risk} verdict=${res.verdict}`,
        );
        if (res.verdict === "block") {
          console.log(
            `[aura] BLOCK tool=${event.toolName} risk=${res.risk} — ${res.reason}`,
          );
          return {
            block: true,
            blockReason: `AURA blocked this action: ${res.reason} (risk ${res.risk}).`,
          };
        }
        if (res.verdict === "flag") {
          console.log(
            `[aura] FLAG tool=${event.toolName} risk=${res.risk} — ${res.reason}`,
          );
        }
        return undefined; // allow
      },
      { priority: 50 },
    );

    // 2) Reply scoring: flag text-resident risk (poisoned facts, unverified claims).
    api.on("llm_output", async (event: any) => {
      const reply = event.text || event.output || event.content || "";
      if (!reply) return;
      const res = await callScorer({ replyText: reply, tools: [] });
      if (res.verdict !== "allow") {
        console.log(
          `[aura] reply risk=${res.risk} verdict=${res.verdict} — ${res.reason}`,
        );
      }
    });
  },
});
