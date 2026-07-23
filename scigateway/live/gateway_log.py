"""Parse OpenClaw's *gateway* log — the second, richer native log stream.

Alongside each per-session ``<id>.jsonl`` (the agent's own turn log that
:mod:`scigateway.live.openclaw_parser` reads), OpenClaw's gateway writes a daily
structured log at ``/tmp/openclaw/openclaw-*.log`` (enabled with the gateway
token). The collector already harvests it as ``gateway_NNN.log`` but nothing has
parsed it. It records things the session log does NOT:

* **native tool-policy decisions** — the gateway's *own* allow/deny of tools
  (e.g. it removes ``cron`` and the ``gateway``/``message`` tools under the
  "coding" profile). This matters for validity: some capabilities are gated by
  OpenClaw itself, not by SciGateway, and that confound is invisible unless we
  read this log;
* **run lifecycle** — ``[agent] run <id> ended with stopReason=...``;
* **startup facts** — the model in use and the list of loaded plugins;
* **tracing** — ``runId`` / ``traceId`` to correlate events to a turn.

Each line is one JSON record: positional args under ``"0"``/``"1"``/``"2"``, a
flattened ``message``, ``_meta`` (subsystem ``name``, ``logLevelName``, ``date``),
and sometimes ``traceId``/``spanId``. This module turns that into typed events and
a compact per-log summary. It reads only text — no Docker, no tokens.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_RUN_END_RE = re.compile(r"run ([0-9a-fA-F-]{8,}) ended with stopReason=(\w+)")
_RUNID_RE = re.compile(r"runId=([0-9a-fA-F-]{8,})")
_MS_RE = re.compile(r"agent (\d+)ms")
_PLUGINS_RE = re.compile(r"plugins:\s*([^;)]+)")
_MODEL_RE = re.compile(r"agent model:\s*([^\s(]+)")


@dataclass(slots=True)
class GatewayLogEvent:
    """One structured record from the gateway log."""

    kind: str                       # tool_policy | run_end | ws_result | model | startup | log
    subsystem: str
    level: str
    timestamp: str
    message: str
    run_id: str = ""
    trace_id: str = ""
    detail: Any = None              # the structured payload (e.g. the tool-policy dict)


def _subsystem(meta: dict) -> str:
    name = meta.get("name", "")
    if isinstance(name, str) and name.startswith("{"):
        try:
            parsed = json.loads(name)
            return parsed.get("subsystem") or parsed.get("module") or name
        except ValueError:
            return name
    return name if isinstance(name, str) else ""


def _classify(subsystem: str, message: str, arg1: Any) -> tuple[str, Any]:
    if "tool-policy" in subsystem:
        return "tool_policy", arg1 if isinstance(arg1, dict) else {}
    if "agent-command" in subsystem and "stopReason" in message:
        return "run_end", None
    if subsystem.endswith("/ws") and "runId=" in message:
        return "ws_result", None
    if "agent model:" in message:
        match = _MODEL_RE.search(message)
        return "model", (match.group(1) if match else "")
    if "plugins:" in message:
        match = _PLUGINS_RE.search(message)
        return "startup", ([p.strip() for p in match.group(1).split(",")] if match else [])
    return "log", None


def parse_gateway_log(text_or_path: str | Path) -> list[GatewayLogEvent]:
    """Parse a gateway log (path or raw text) into typed events. Bad lines skipped."""
    if isinstance(text_or_path, Path) or (
        isinstance(text_or_path, str) and "\n" not in text_or_path
        and len(text_or_path) < 260 and Path(text_or_path).exists()
    ):
        raw = Path(text_or_path).read_text(encoding="utf-8")
    else:
        raw = str(text_or_path)

    events: list[GatewayLogEvent] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(record, dict):
            continue
        meta = record.get("_meta", {}) or {}
        subsystem = _subsystem(meta)
        message = record.get("message", "") or ""
        kind, detail = _classify(subsystem, message, record.get("1"))

        run_id = record.get("runId", "") or ""
        if not run_id:
            for pattern in (_RUN_END_RE, _RUNID_RE):
                match = pattern.search(message)
                if match:
                    run_id = match.group(1)
                    break
        events.append(GatewayLogEvent(
            kind=kind, subsystem=subsystem,
            level=meta.get("logLevelName", ""),
            timestamp=meta.get("date", record.get("time", "")),
            message=message, run_id=run_id,
            trace_id=record.get("traceId", "") or "",
            detail=detail,
        ))
    return events


def tool_policy_events(events: list[GatewayLogEvent]) -> list[dict]:
    """The native tool-policy allow/deny decisions, as plain dicts."""
    out = []
    for event in events:
        if event.kind != "tool_policy" or not isinstance(event.detail, dict):
            continue
        out.append({
            "rule": event.detail.get("rule", ""),
            "rule_kind": event.detail.get("ruleKind", ""),
            "removed_tools": list(event.detail.get("removedTools", [])),
            "matched_rules": list(event.detail.get("matchedRules", [])),
            "run_id": event.run_id,
            "trace_id": event.trace_id,
        })
    return out


def events_for_run(events: list[GatewayLogEvent], run_id: str) -> list[GatewayLogEvent]:
    """Filter to one turn by runId (the daily log interleaves many runs)."""
    return [e for e in events if e.run_id == run_id]


def gateway_log_summary(text_or_path: str | Path) -> dict:
    """A compact, analysis-ready digest of one gateway log file.

    ``native_removed_tools`` / ``native_denied_tools`` are the key validity output:
    tools OpenClaw's own policy took away, independent of SciGateway.
    """
    events = parse_gateway_log(text_or_path)
    policies = tool_policy_events(events)
    removed: set[str] = set()
    denied: set[str] = set()
    for policy in policies:
        removed.update(policy["removed_tools"])
        if policy["rule_kind"] == "deny":
            denied.update(policy["removed_tools"])

    runs = [{"run_id": e.run_id, "stop_reason": e.message.split("stopReason=")[-1]}
            for e in events if e.kind == "run_end"]
    model = next((e.detail for e in events if e.kind == "model" and e.detail), "")
    plugins = next((e.detail for e in events if e.kind == "startup" and e.detail), [])

    return {
        "n_events": len(events),
        "model": model,
        "plugins": plugins,
        "tool_policy_rules": policies,
        "native_removed_tools": sorted(removed),
        "native_denied_tools": sorted(denied),
        "runs": runs,
    }
