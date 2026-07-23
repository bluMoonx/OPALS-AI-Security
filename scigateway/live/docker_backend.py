"""Drive a running Dockerized OpenClaw agent and harvest its native logs.

This is the low-level control surface for live collection. Everything it does is
one of three real Docker operations, exactly as the Spring experiment did:

* ``docker exec <c> openclaw agent -m <text> --session-id <id> --json`` — run one
  real agent turn (this is the only thing that spends model tokens);
* ``docker exec <c> bash -lc <cmd>`` — set up / tear down container state
  (drop a mock poisoned file, reset a session, etc.);
* ``docker cp`` — copy files in (scenario setup) and out (native log harvest).

Configuration comes from the environment so nothing is hardcoded:

======================================  ==================================  ==============================
env var                                 meaning                              default
======================================  ==================================  ==============================
``SCIGATEWAY_OPENCLAW_CONTAINER``        container name / id                  ``openclaw-gateway``
``SCIGATEWAY_OPENCLAW_MODEL``            ``--model`` override (provider/id)   "" (use the container default)
``OPENCLAW_GATEWAY_TOKEN``               gateway token, injected as env       "" (omit)
======================================  ==================================  ==============================

The Spring script committed a real gateway token into source; we deliberately
read it from the environment instead and never log its value (CLAUDE.md Rule 12
is about failing loud on *errors*, not leaking secrets).

``dry_run=True`` makes every method operate on in-memory synthetic data instead
of calling Docker, so the whole orchestration — including the real parser running
on realistic native events — is testable offline with zero API spend.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_CONTAINER = os.environ.get("SCIGATEWAY_OPENCLAW_CONTAINER", "openclaw-gateway")
DEFAULT_AGENT_ID = "main"
SESSION_DIR = "/home/node/.openclaw/agents/main/sessions"
WORKSPACE_DIR = "/home/node/.openclaw/workspace"
GATEWAY_LOG_GLOB = "/tmp/openclaw/openclaw-*.log"


def session_dir_for(agent_id: str | None) -> str:
    """The native session directory for a given agent id (default: ``main``).

    OpenClaw's ``agents add`` creates each isolated agent under its own
    ``~/.openclaw/agents/<id>/`` tree. This is only a fallback: a real
    ``openclaw agent --json`` response already reports the exact
    ``sessionFile`` it wrote, so callers should prefer that over guessing.
    """
    return f"/home/node/.openclaw/agents/{agent_id or DEFAULT_AGENT_ID}/sessions"


@dataclass(slots=True)
class LiveTurn:
    """The parsed result of one ``openclaw agent`` turn.

    ``usage`` is OpenClaw's own token accounting for the turn
    (``{"input", "output", "total", "cost"}``); ``cost`` is what the provider
    billed (0.0 on a flat Ollama-Cloud plan). ``session_file`` is the in-container
    path to the native session JSONL, taken from the agent's structured output so
    we never have to guess it.
    """

    response_text: str
    session_id: str
    status: str = "ok"
    run_id: str = ""
    duration_s: float = 0.0
    provider: str = ""
    model: str = ""
    usage: dict = field(default_factory=dict)
    session_file: str = ""

    @property
    def cost(self) -> float:
        c = self.usage.get("cost")
        if isinstance(c, dict):
            return float(c.get("total", 0.0) or 0.0)
        return float(c or 0.0)

    @property
    def total_tokens(self) -> int:
        return int(self.usage.get("total", 0) or 0)


class DockerError(RuntimeError):
    """A docker command failed. Carries stderr so failures are debuggable."""


class OpenClawDockerBackend:
    """Thin, well-bounded driver for a live OpenClaw container."""

    def __init__(
        self,
        container: str | None = None,
        *,
        model: str | None = None,
        gateway_token: str | None = None,
        timeout: int = 240,
        dry_run: bool = False,
    ) -> None:
        self.container = container or DEFAULT_CONTAINER
        self.model = model if model is not None else os.environ.get("SCIGATEWAY_OPENCLAW_MODEL", "")
        self.gateway_token = (
            gateway_token if gateway_token is not None
            else os.environ.get("OPENCLAW_GATEWAY_TOKEN", "")
        )
        self.timeout = timeout
        self.dry_run = dry_run
        # dry-run bookkeeping: synthetic native events accumulated per session.
        self._dry_events: dict[str, list[dict]] = {}

    # -- availability ------------------------------------------------------- #
    def is_available(self) -> bool:
        """True iff the daemon is up and the target container is running."""
        if self.dry_run:
            return True
        try:
            out = subprocess.run(
                ["docker", "ps", "--format", "{{.Names}}"],
                capture_output=True, encoding="utf-8", errors="replace", timeout=30,
            )
        except (OSError, subprocess.SubprocessError):
            return False
        return self.container in (out.stdout or "").split()

    # -- low-level exec / cp ------------------------------------------------- #
    def exec(self, bash_cmd: str) -> str:
        """Run a bash command inside the container; return stdout (stripped)."""
        if self.dry_run:
            return ""
        res = subprocess.run(
            ["docker", "exec", self.container, "bash", "-lc", bash_cmd],
            capture_output=True, encoding="utf-8", errors="replace", timeout=self.timeout,
        )
        if res.returncode != 0:
            raise DockerError(f"exec failed ({res.returncode}): {(res.stderr or '')[:200]}")
        return (res.stdout or "").strip()

    def put_file(self, container_path: str, content: str) -> None:
        """Write ``content`` to ``container_path`` via a host temp file + docker cp.

        Using ``docker cp`` (rather than ``echo`` inside the shell, as Spring did)
        means arbitrary payload text needs no shell escaping — a poisoned document
        can contain quotes, ``$``, backticks, and newlines verbatim.
        """
        self.put_bytes(container_path, content.encode("utf-8"))

    def put_bytes(self, container_path: str, content: bytes) -> None:
        """Write binary content to a container path without shell interpolation."""
        if self.dry_run:
            return
        tmp = Path(tempfile.mkdtemp(prefix="scigw_")) / "payload"
        tmp.write_bytes(content)
        try:
            self.exec(f"mkdir -p $(dirname {shq(container_path)})")
            res = subprocess.run(
                ["docker", "cp", str(tmp), f"{self.container}:{container_path}"],
                capture_output=True, encoding="utf-8", errors="replace", timeout=self.timeout,
            )
            if res.returncode != 0:
                raise DockerError(f"cp-in failed: {(res.stderr or '')[:200]}")
        finally:
            try:
                tmp.unlink()
                tmp.parent.rmdir()
            except OSError:
                pass

    def remove_path(self, container_path: str) -> None:
        """Best-effort ``rm -f`` of an in-container path (setup/teardown)."""
        if self.dry_run:
            return
        self.exec(f"rm -f {shq(container_path)}")

    def reset_session(self, session_id: str) -> None:
        """Delete any prior native log for ``session_id`` so the run is fresh."""
        if self.dry_run:
            self._dry_events.pop(session_id, None)
            return
        self.remove_path(f"{SESSION_DIR}/{session_id}.jsonl")

    # -- the one operation that spends tokens ------------------------------- #
    def send(self, message: str, session_id: str, *, agent_id: str | None = None) -> LiveTurn:
        """Run one real agent turn and return the parsed :class:`LiveTurn`.

        ``agent_id`` routes the turn to a specific isolated OpenClaw agent
        profile (``openclaw agent --agent <id> ...``) instead of the routing
        default. Used by the multi-agent handoff scenarios, which need each
        role to be a genuinely separate agent identity, not the same agent
        talking to itself under a different session id.
        """
        if self.dry_run:
            return self._dry_send(message, session_id, agent_id=agent_id)

        argv = ["docker", "exec"]
        if self.gateway_token:
            argv += ["-e", f"OPENCLAW_GATEWAY_TOKEN={self.gateway_token}"]
        argv += [self.container, "openclaw", "agent",
                 "-m", message, "--session-id", session_id, "--json",
                 "--timeout", str(self.timeout)]
        if agent_id:
            argv += ["--agent", agent_id]
        if self.model:
            argv += ["--model", self.model]

        t0 = time.time()
        res = subprocess.run(
            argv, capture_output=True, encoding="utf-8", errors="replace",
            timeout=self.timeout + 60,
        )
        elapsed = round(time.time() - t0, 3)
        if res.returncode != 0:
            raise DockerError(f"agent turn failed ({res.returncode}): {(res.stderr or '')[:300]}")
        return self._parse_agent_json(res.stdout or "", session_id, elapsed, agent_id=agent_id)

    def agent_exists(self, agent_id: str) -> bool:
        """Read-only check that an isolated agent profile is actually configured.

        Spends no tokens (``openclaw agents list`` never calls a model). Used to
        fail loud before a multi-agent scenario runs, rather than silently
        falling back to the default agent and mislabeling a single-agent result
        as a genuine second-agent one.
        """
        if self.dry_run:
            return True
        out = self.exec("openclaw agents list --json 2>/dev/null || true")
        try:
            agents = json.loads(out) if out else []
        except json.JSONDecodeError:
            return agent_id in out  # tolerate a non-JSON text listing
        names = {
            a.get("id") or a.get("name") for a in agents
            if isinstance(a, dict)
        } if isinstance(agents, list) else set()
        return agent_id in names

    @staticmethod
    def _parse_agent_json(
        stdout: str, session_id: str, elapsed: float, *, agent_id: str | None = None,
    ) -> LiveTurn:
        """Map ``openclaw agent --json`` output onto a :class:`LiveTurn`.

        Defensive about field presence: the CLI wraps the result in
        ``{runId, status, result:{payloads:[{text}], meta:{agentMeta:{...}}}}``.
        """
        data = json.loads(_first_json_object(stdout))
        result = data.get("result", {}) or {}
        payloads = result.get("payloads", []) or []
        text = "\n".join(
            p.get("text", "") for p in payloads if isinstance(p, dict) and p.get("text")
        ).strip()
        meta = (result.get("meta", {}) or {}).get("agentMeta", {}) or {}
        default_dir = session_dir_for(agent_id)
        return LiveTurn(
            response_text=text,
            session_id=session_id,
            status=data.get("status", "ok"),
            run_id=data.get("runId", ""),
            duration_s=float(meta.get("durationMs", 0.0) or 0.0) / 1000.0 or elapsed,
            provider=meta.get("provider", ""),
            model=meta.get("model", ""),
            usage=dict(meta.get("usage", {}) or {}),
            session_file=meta.get("sessionFile", f"{default_dir}/{session_id}.jsonl"),
        )

    # -- native-log harvest -------------------------------------------------- #
    def harvest(self, turn: LiveTurn, dest_dir: str | Path, index: int) -> dict[str, str]:
        """Copy the native session log + gateway log out into ``dest_dir``.

        Returns a map of ``{"session": path, "gateway": path}`` for what was
        written (Spring's layout: ``session_NNN.jsonl`` and ``gateway_NNN.log``).
        """
        dest = Path(dest_dir)
        dest.mkdir(parents=True, exist_ok=True)
        written: dict[str, str] = {}

        session_dst = dest / f"session_{index:03d}.jsonl"
        if self.dry_run:
            session_dst.write_text(
                "\n".join(json.dumps(e) for e in self._dry_events.get(turn.session_id, [])),
                encoding="utf-8",
            )
            written["session"] = str(session_dst)
            gw = dest / f"gateway_{index:03d}.log"
            gw.write_text(json.dumps({"message": "[dry-run] no gateway log"}) + "\n", encoding="utf-8")
            written["gateway"] = str(gw)
            return written

        src = turn.session_file or f"{SESSION_DIR}/{turn.session_id}.jsonl"
        if self._cp_out(src, session_dst):
            written["session"] = str(session_dst)

        gateway_src = self.exec(f"ls -t {GATEWAY_LOG_GLOB} 2>/dev/null | head -1")
        if gateway_src:
            gw_dst = dest / f"gateway_{index:03d}.log"
            if self._cp_out(gateway_src, gw_dst):
                written["gateway"] = str(gw_dst)
        return written

    def read_native_session(self, turn: LiveTurn) -> str:
        """Return the raw native session JSONL text (for parsing)."""
        if self.dry_run:
            return "\n".join(json.dumps(e) for e in self._dry_events.get(turn.session_id, []))
        src = turn.session_file or f"{session_dir_for(None)}/{turn.session_id}.jsonl"
        return self.exec(f"cat {shq(src)}")

    def _cp_out(self, container_path: str, dst: Path) -> bool:
        res = subprocess.run(
            ["docker", "cp", f"{self.container}:{container_path}", str(dst)],
            capture_output=True, encoding="utf-8", errors="replace", timeout=self.timeout,
        )
        return res.returncode == 0

    # -- dry-run synthetic turn --------------------------------------------- #
    def _dry_send(self, message: str, session_id: str, *, agent_id: str | None = None) -> LiveTurn:
        """Fabricate a realistic native event stream so the parser can run offline.

        The synthetic session mimics the real shape observed from the container:
        a ``session`` header, a ``model_change``, the user ``message``, and — when
        the prompt names a file — a ``read`` toolCall + toolResult, then an
        assistant text reply. This is *only* for tests; it never claims to be real.
        """
        events = self._dry_events.setdefault(session_id, [])
        if not events:
            events.append({"type": "session", "version": 3, "id": session_id,
                           "cwd": WORKSPACE_DIR})
            events.append({"type": "model_change", "provider": "dry-run",
                           "modelId": "dry-run"})
        events.append({"type": "message",
                       "message": {"role": "user", "content": message}})
        # If the prompt references a file path, emit a read action so the trail
        # is non-trivial for tests.
        for token in message.replace(",", " ").split():
            if token.endswith((".md", ".txt", ".csv", ".pdf")):
                events.append({"type": "message", "message": {"role": "assistant",
                    "content": [{"type": "toolCall", "id": "t1", "name": "read",
                                 "arguments": {"path": f"{WORKSPACE_DIR}/{token}"}}]}})
                events.append({"type": "message", "message": {"role": "toolResult",
                    "content": [{"type": "text", "text": "[dry-run file contents]"}]}})
                break
        reply = f"[dry-run] acknowledged: {message[:60]}"
        events.append({"type": "message", "message": {"role": "assistant",
            "content": [{"type": "text", "text": reply}],
            "usage": {"input": 100, "output": 10, "totalTokens": 110,
                      "cost": {"total": 0.0}}}})
        return LiveTurn(
            response_text=reply, session_id=session_id, status="ok",
            run_id="dry-run", duration_s=0.1, provider="dry-run", model="dry-run",
            usage={"input": 100, "output": 10, "total": 110, "cost": {"total": 0.0}},
            session_file=f"{session_dir_for(agent_id)}/{session_id}.jsonl",
        )


def shq(s: str) -> str:
    """Minimal single-quote shell quoting for in-container paths."""
    return "'" + s.replace("'", "'\\''") + "'"


def _first_json_object(text: str) -> str:
    """Return the first *parseable* balanced ``{...}`` JSON object in ``text``.

    ``openclaw agent --json`` may print a stray banner line before the JSON; this
    isolates the object so :func:`json.loads` doesn't choke on the prefix. Each
    ``{`` position is tried in turn so a banner that itself contains braces
    (e.g. ``WARN {deprecated}``) can't shadow the real result.
    """
    i = text.find("{")
    while i >= 0:
        candidate = _balanced_object(text, i)
        if candidate is not None:
            try:
                json.loads(candidate)
                return candidate
            except ValueError:
                pass
        i = text.find("{", i + 1)
    raise ValueError("no JSON object in agent output")


def _balanced_object(text: str, start: int) -> str | None:
    """The brace-balanced substring beginning at ``start``, or ``None``."""
    depth = 0
    in_str = False
    esc = False
    for i in range(start, len(text)):
        ch = text[i]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
        else:
            if ch == '"':
                in_str = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return text[start:i + 1]
    return None
