"""Parse a native OpenClaw session log into the project's observable schema.

OpenClaw writes one JSONL file per session at
``/home/node/.openclaw/agents/main/sessions/<id>.jsonl``. Each line is an event:

* ``{"type":"session", ...}``            — header (id, cwd, version)
* ``{"type":"model_change", ...}``       — provider + modelId
* ``{"type":"message", "message":{...}}`` — a user / assistant / toolResult turn

An assistant message's ``content`` is a list of parts; the ones we care about are
``{"type":"text","text":...}`` (the reply) and
``{"type":"toolCall","name":...,"arguments":{...}}`` (a concrete action the agent
took). Tool *results* come back as ``{"role":"toolResult", ...}`` messages.

This module turns that native stream into a :class:`ParsedSession`: the user
prompt, the assistant text, token usage, and — the important part — the ordered
:class:`~scigateway.schema.AgentAction` trail, by mapping each ``toolCall`` onto
one of the six schema action kinds. That trail is exactly what
:mod:`scigateway.pipeline.features` and :mod:`scigateway.gateway` consume, so a
collection and analysis share one observable-action contract.

The tool-name -> action-kind map covers OpenClaw's built-in tools (verified from a
live container: ``read``/``write``/``exec`` plus the ``remove``/``http``/``memory``/
``note``/``ls``/``grep``/``edit``/``bash`` names registered in its dist bundle) and
a handful of common aliases. Unknown tool names are still recorded in
``tool_calls`` but do not fabricate a typed action.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from ..schema import AgentAction

# tool name (lowercased) -> AgentAction kind. Verified built-ins first, then
# common aliases a provider might emit.
TOOL_KIND_MAP: dict[str, str] = {
    # file reads
    "read": "file_read", "cat": "file_read", "ls": "file_read", "list": "file_read",
    "list_dir": "file_read", "glob": "file_read", "grep": "file_read", "find": "file_read",
    "view": "file_read", "open": "file_read", "head": "file_read", "tail": "file_read",
    # file writes
    "write": "file_write", "edit": "file_write", "create": "file_write",
    "append": "file_write", "save": "file_write", "patch": "file_write",
    "mkdir": "file_write", "touch": "file_write",
    # file deletes
    "remove": "file_delete", "rm": "file_delete", "delete": "file_delete",
    "unlink": "file_delete", "rmdir": "file_delete", "trash": "file_delete",
    # shell
    "exec": "shell", "bash": "shell", "shell": "shell", "run": "shell",
    "sh": "shell", "command": "shell", "terminal": "shell",
    # network
    "http": "network", "https": "network", "fetch": "network", "curl": "network",
    "wget": "network", "download": "network", "upload": "network",
    "browse": "network", "browser": "network", "request": "network",
    "tavily": "network", "web_search": "network", "websearch": "network",
    # memory
    "memory": "memory_write", "remember": "memory_write", "note": "memory_write",
    "notes": "memory_write", "store": "memory_write", "remind": "memory_write",
}

# argument keys to try when extracting an action target, per kind.
_TARGET_KEYS = {
    "file_read": ("path", "file", "filepath", "filePath", "target", "dir", "directory", "pattern"),
    "file_write": ("path", "file", "filepath", "filePath", "target"),
    "file_delete": ("path", "file", "filepath", "filePath", "target"),
    "shell": ("command", "cmd", "script", "input", "code"),
    "network": ("url", "uri", "endpoint", "href", "query"),
    "memory_write": ("content", "text", "value", "note", "fact", "key"),
}


@dataclass(slots=True)
class ParsedSession:
    """Observable content extracted from a native OpenClaw session log."""

    session_id: str
    user_prompts: list[str] = field(default_factory=list)
    assistant_text: str = ""
    actions: list[AgentAction] = field(default_factory=list)
    tool_calls: list[str] = field(default_factory=list)
    provider: str = ""
    model: str = ""
    total_tokens: int = 0
    cost_total: float = 0.0
    num_turns: int = 0
    unknown_tools: list[str] = field(default_factory=list)

    @property
    def first_prompt(self) -> str:
        return self.user_prompts[0] if self.user_prompts else ""


def tool_to_action(name: str, arguments: Any) -> AgentAction | None:
    """Map one ``toolCall`` to an :class:`AgentAction`, or ``None`` if unknown.

    ``in_scope`` is left ``True`` here (the parser cannot know task scope); the
    collector rewrites it against each scenario's declared scope.
    """
    kind = TOOL_KIND_MAP.get((name or "").strip().lower())
    if kind is None:
        return None
    args = arguments
    if isinstance(args, str):
        try:
            args = json.loads(args)
        except (ValueError, TypeError):
            args = {"value": args}
    if not isinstance(args, dict):
        args = {}
    target = ""
    for key in _TARGET_KEYS.get(kind, ()):  # first present, non-empty key wins
        val = args.get(key)
        if isinstance(val, str) and val.strip():
            target = val.strip()
            break
    if not target:
        target = (json.dumps(args) if args else name)[:200]
    return AgentAction(kind=kind, target=target[:500], in_scope=True)


def parse_session_events(events: Iterable[dict], session_id: str = "") -> ParsedSession:
    """Build a :class:`ParsedSession` from already-decoded native events."""
    ps = ParsedSession(session_id=session_id)
    assistant_texts: list[str] = []
    for ev in events:
        etype = ev.get("type")
        if etype == "session" and not ps.session_id:
            ps.session_id = str(ev.get("id", ""))
        elif etype == "model_change":
            ps.provider = ev.get("provider", ps.provider) or ps.provider
            ps.model = ev.get("modelId", ps.model) or ps.model
        elif etype == "message":
            _consume_message(ev.get("message", {}) or {}, ps, assistant_texts)
    ps.assistant_text = "\n".join(t for t in assistant_texts if t).strip()
    return ps


def _consume_message(msg: dict, ps: ParsedSession, assistant_texts: list[str]) -> None:
    role = msg.get("role")
    content = msg.get("content")
    if role == "user":
        text = _content_text(content)
        if text:
            ps.user_prompts.append(text)
            ps.num_turns += 1
        return
    if role in ("toolResult", "tool_result", "tool"):
        # What a tool returned to the agent — the ingested content the gateway
        # would see. Attach to the earliest action still missing its result
        # (tool results arrive in call order); best-effort, capped to stay compact.
        text = _tool_result_text(content)
        if text:
            for action in ps.actions:
                if not action.content:
                    action.content = text[:2000]
                    break
        return
    if role in ("assistant", "model"):
        usage = msg.get("usage") or {}
        ps.total_tokens += int(usage.get("totalTokens", usage.get("total", 0)) or 0)
        cost = usage.get("cost")
        if isinstance(cost, dict):
            ps.cost_total += float(cost.get("total", 0.0) or 0.0)
        elif cost:
            ps.cost_total += float(cost)
        if isinstance(content, list):
            for part in content:
                if not isinstance(part, dict):
                    continue
                ptype = part.get("type")
                if ptype == "text" and part.get("text"):
                    assistant_texts.append(part["text"])
                elif ptype in ("toolCall", "tool_use"):
                    name = part.get("name", "")
                    ps.tool_calls.append(name)
                    action = tool_to_action(name, part.get("arguments", part.get("input", {})))
                    if action is not None:
                        ps.actions.append(action)
                    elif name:
                        ps.unknown_tools.append(name)
        elif isinstance(content, str):
            assistant_texts.append(content)


def _content_text(content: Any) -> str:
    """Flatten a message ``content`` (string or list of parts) to plain text."""
    if isinstance(content, str):
        return content.strip()
    if isinstance(content, list):
        out = []
        for part in content:
            if isinstance(part, dict) and part.get("type") == "text" and part.get("text"):
                out.append(part["text"])
            elif isinstance(part, str):
                out.append(part)
        return "\n".join(out).strip()
    return ""


_RESULT_KEYS = ("text", "output", "result", "content", "stdout", "data")


def _tool_result_text(content: Any) -> str:
    """Extract the textual payload of a toolResult message (string / parts / dict)."""
    if isinstance(content, str):
        return content.strip()
    if isinstance(content, dict):
        for key in _RESULT_KEYS:
            val = content.get(key)
            if isinstance(val, str) and val.strip():
                return val.strip()
        return ""
    if isinstance(content, list):
        out = []
        for part in content:
            if isinstance(part, str):
                out.append(part)
            elif isinstance(part, dict):
                for key in ("text",) + _RESULT_KEYS:
                    val = part.get(key)
                    if isinstance(val, str) and val.strip():
                        out.append(val)
                        break
        return "\n".join(out).strip()
    return ""


def parse_session_jsonl(text_or_path: str | Path) -> ParsedSession:
    """Parse native session JSONL from a path or a raw string.

    A value that points at an existing file is read; otherwise it is treated as
    the JSONL text itself. Malformed lines are skipped (native logs occasionally
    interleave a non-JSON banner line).
    """
    raw: str
    if isinstance(text_or_path, Path) or (
        isinstance(text_or_path, str) and "\n" not in text_or_path
        and len(text_or_path) < 260 and Path(text_or_path).exists()
    ):
        raw = Path(text_or_path).read_text(encoding="utf-8")
    else:
        raw = str(text_or_path)
    events = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return parse_session_events(events)
