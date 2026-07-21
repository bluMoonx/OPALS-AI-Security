"""Real collection against a Dockerized OpenClaw agent.

The harness sends bounded prompts with ``docker exec``, copies the agent's native
logs with ``docker cp``, and parses those logs into the project's shared Session
schema. The optional dry-run path exists only for offline wiring tests; it marks
its records non-live so analysis cannot mistake them for evidence.
"""

from __future__ import annotations

from .docker_backend import LiveTurn, OpenClawDockerBackend
from .openclaw_parser import ParsedSession, parse_session_events, parse_session_jsonl

__all__ = [
    "OpenClawDockerBackend",
    "LiveTurn",
    "ParsedSession",
    "parse_session_jsonl",
    "parse_session_events",
]
