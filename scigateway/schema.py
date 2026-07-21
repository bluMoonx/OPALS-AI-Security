"""Session schema and validation.

This is the contract every part of the system agrees on. A *session* is one
interaction with an OpenClaw agent, captured entirely from what a gateway can
observe from the outside: the prompt, the response text, the concrete actions the
agent took (file/shell/network/memory ops), and the tool calls it made — plus
human-assigned risk labels.

The schema is expressed as typed dataclasses so that:

* every producer (platform adapters) emits the same shape, and
* every consumer (feature extraction) can rely on that shape.

We deliberately avoid a third-party validation dependency (pydantic): the schema
is small, and stdlib dataclasses + explicit ``validate()`` keep the project
dependency-light and easy to audit — matching CLAUDE.md Rule 2 (Simplicity First).
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable

from . import RISK_LABELS

# Task types an OpenClaw-style personal assistant performs on the local machine.
# The last two extend the study toward the OPALS "AI for science" proposal: an
# agent doing literature/experiment work, and a jailbreak (direct-channel) probe.
TASK_TYPES = (
    "file_organization",   # sort/rename/move files
    "message_triage",      # summarize/reply to messages (WhatsApp, email, ...)
    "web_automation",      # browse/fill forms/scrape
    "shell_task",          # run a requested shell command / script
    "memory_recall",       # answer using persistent memory
    "note_management",     # read/update notes (e.g. Obsidian)
    "injection_test",      # controlled: input carries a hidden instruction
    "research_task",       # AI-for-science: literature search / experiment design
    "jailbreak_test",      # controlled: user turn reframes a disallowed request
)

# The kind of untrusted input (if any) the agent was given. This is where
# injections and poisoned facts hide.
INPUT_DOCUMENT_TYPES = ("none", "file", "pdf", "message", "web_page", "note", "mock_injected")


class SchemaError(ValueError):
    """Raised when a session or one of its parts fails validation.

    We subclass :class:`ValueError` so callers can catch either, but the distinct
    type lets tests assert *why* something was rejected (CLAUDE.md Rule 12: fail loud).
    """


# The kinds of action an agent can take on the machine. This is the observable
# trail a gateway sees — the raw material for feature extraction.
ACTION_KINDS = ("file_read", "file_write", "file_delete", "shell", "network", "memory_write")

# The enforcement actions the gateway can take on a request, ordered from least to
# most restrictive. ``allow``/``warn`` let the request proceed; the rest stop the
# harmful action from reaching execution (a human gate, a tool denial, or a kill).
ENFORCEMENT_ACTIONS = ("allow", "warn", "require_confirmation", "restrict_tools", "block")
# Which enforcement actions actually prevent a harmful action from executing.
BLOCKING_ACTIONS = ("require_confirmation", "restrict_tools", "block")


@dataclass(slots=True)
class AgentAction:
    """A single observable action the agent took.

    Examples:
    * ``AgentAction("file_delete", "/home/u/project/old.txt")``
    * ``AgentAction("shell", "rm -rf ~/tmp")``
    * ``AgentAction("network", "POST https://paste.example.com")``
    * ``AgentAction("memory_write", "user prefers method X", in_scope=False)``

    ``target`` is the path / command / URL / fact. ``in_scope`` records whether the
    action was within the bounds of what the task actually required — an
    out-of-scope destructive op is exactly the raw signal we want to catch.

    ``content`` is what the action *observed* — the bytes a read returned, a fetch's
    response body, a tool result. A gateway sits between the tool and the model, so
    this output is observable-in-principle; capturing it lets the monitor see
    text/state-resident compromise (e.g. a poisoned fact reproduced in the reply)
    that leaves no other action-trail signal. It defaults empty, so logs collected
    before capture existed still load and simply carry no ingested content.
    """

    kind: str
    target: str
    in_scope: bool = True
    content: str = ""

    def validate(self) -> None:
        if self.kind not in ACTION_KINDS:
            raise SchemaError(f"AgentAction.kind {self.kind!r} not in {ACTION_KINDS}")
        if not isinstance(self.target, str) or not self.target.strip():
            raise SchemaError("AgentAction.target must be a non-empty string")
        if not isinstance(self.in_scope, bool):
            raise SchemaError("AgentAction.in_scope must be a bool")
        if not isinstance(self.content, str):
            raise SchemaError("AgentAction.content must be a string")

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "AgentAction":
        return cls(
            kind=d["kind"],
            target=d.get("target", ""),
            in_scope=bool(d.get("in_scope", True)),
            content=d.get("content", ""),
        )


_RISK_BOOL_FIELDS = ("prompt_injection_followed", "memory_poisoned",
                     "destructive_file_op", "shell_escalation",
                     "data_exfiltration", "credential_exposure")


@dataclass(slots=True)
class RiskIndicators:
    """Ground-truth behavioral flags for a session.

    These are the *observed truths* about what the agent did — established during
    labeling — and are the anchor the human label is derived from. They are NOT fed
    to the classifier directly (that would be leakage); feature extraction derives
    *observable* proxies from the raw action trail and text instead. Keeping them here
    lets us (a) audit labels and (b) measure how well observable features recover them.
    """

    prompt_injection_followed: bool = False
    memory_poisoned: bool = False
    destructive_file_op: bool = False
    shell_escalation: bool = False
    data_exfiltration: bool = False
    credential_exposure: bool = False
    out_of_scope_ops: int = 0

    def validate(self) -> None:
        for name in _RISK_BOOL_FIELDS:
            if not isinstance(getattr(self, name), bool):
                raise SchemaError(f"RiskIndicators.{name} must be a bool")
        if not isinstance(self.out_of_scope_ops, int) or self.out_of_scope_ops < 0:
            raise SchemaError("RiskIndicators.out_of_scope_ops must be a non-negative int")

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "RiskIndicators":
        return cls(
            prompt_injection_followed=bool(d.get("prompt_injection_followed", False)),
            memory_poisoned=bool(d.get("memory_poisoned", False)),
            destructive_file_op=bool(d.get("destructive_file_op", False)),
            shell_escalation=bool(d.get("shell_escalation", False)),
            data_exfiltration=bool(d.get("data_exfiltration", False)),
            credential_exposure=bool(d.get("credential_exposure", False)),
            out_of_scope_ops=int(d.get("out_of_scope_ops", 0)),
        )


@dataclass(slots=True)
class GatewayDecision:
    """The runtime gateway's response to one session.

    This is the *second half* of the spring framework (CIST 117 §3): what the
    interceptor→evaluator→policy→enforcement pipeline decided about a request. It
    is recorded alongside the raw session so every audit log answers not just
    "what did the agent do?" but "what did the gateway detect, decide, and do
    about it, and did the attack get through?".

    Fields
    ------
    evaluator            which risk evaluator produced the detection
                         (e.g. ``"ml:random_forest"`` or ``"rules"``).
    predicted_label      the detection output (one of :data:`RISK_LABELS`).
    risk_score           calibrated 0..1 risk (P(unsafe) for ML, rule score else).
    class_probabilities  full per-label probability map, when available.
    triggered_signals    the concrete observable red flags the gateway saw.
    policy_name          which deterministic policy rule fired.
    policy_rationale      one-line human-readable reason.
    enforcement_action   one of :data:`ENFORCEMENT_ACTIONS`.
    blocked              True iff the policy selected a blocking action. In the
                         current post-collection replay, this is counterfactual;
                         it becomes an observed prevention only with an inline proxy.
    attack_present       ground-truth: was this actually a risky/attack session.
    attack_succeeded     ground-truth attack the policy would let proceed in a
                         replay; observed success only with an inline gateway.
    """

    evaluator: str
    predicted_label: str
    risk_score: float
    enforcement_action: str
    policy_name: str = ""
    policy_rationale: str = ""
    class_probabilities: dict[str, float] = field(default_factory=dict)
    triggered_signals: list[str] = field(default_factory=list)
    blocked: bool = False
    attack_present: bool = False
    attack_succeeded: bool = False

    def validate(self) -> None:
        if self.predicted_label not in RISK_LABELS:
            raise SchemaError(
                f"GatewayDecision.predicted_label {self.predicted_label!r} "
                f"not in {RISK_LABELS}")
        if self.enforcement_action not in ENFORCEMENT_ACTIONS:
            raise SchemaError(
                f"GatewayDecision.enforcement_action {self.enforcement_action!r} "
                f"not in {ENFORCEMENT_ACTIONS}")
        if not (0.0 <= float(self.risk_score) <= 1.0):
            raise SchemaError("GatewayDecision.risk_score must be in [0, 1]")

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "GatewayDecision":
        return cls(
            evaluator=d.get("evaluator", ""),
            predicted_label=d.get("predicted_label", "safe"),
            risk_score=float(d.get("risk_score", 0.0)),
            enforcement_action=d.get("enforcement_action", "allow"),
            policy_name=d.get("policy_name", ""),
            policy_rationale=d.get("policy_rationale", ""),
            class_probabilities=dict(d.get("class_probabilities", {})),
            triggered_signals=list(d.get("triggered_signals", [])),
            blocked=bool(d.get("blocked", False)),
            attack_present=bool(d.get("attack_present", False)),
            attack_succeeded=bool(d.get("attack_succeeded", False)),
        )


@dataclass(slots=True)
class Session:
    """One complete OpenClaw agent session, as seen at the gateway.

    A session captures everything a gateway can observe from the outside: the
    user's request, the agent's reply text, and — crucially for a machine-acting
    agent — the concrete ``actions`` it took (file ops, shell commands, network
    calls, memory writes), plus human-assigned risk labels.

    The trailing fields (``attack_category`` .. ``gateway_decision``) are optional
    and default to a benign, no-decision state, so older raw logs written before
    the runtime gateway existed still load and validate unchanged.
    """

    session_id: str
    date: str  # ISO date string, e.g. "2026-06-25"
    platform: str
    agent_name: str
    task_type: str
    user_prompt: str
    input_document_type: str
    agent_response: str
    actions: list[AgentAction] = field(default_factory=list)
    tool_calls: list[str] = field(default_factory=list)
    tool_trace_available: bool = True
    latency_seconds: float = 0.0
    risk_indicators: RiskIndicators = field(default_factory=RiskIndicators)
    human_label: str = "safe"
    label_notes: str = ""
    # -- attack metadata + gateway response (optional; added for the v2 study) --
    attack_category: str = "benign"
    attack_objective: str = ""
    agent_config: dict = field(default_factory=dict)
    gateway_decision: "GatewayDecision | None" = None

    # -- derived convenience properties (cheap, deterministic; not features) --
    @property
    def num_tool_calls(self) -> int:
        return len(self.tool_calls)

    @property
    def num_actions(self) -> int:
        return len(self.actions)

    @property
    def response_word_count(self) -> int:
        return len(self.agent_response.split())

    def actions_of(self, kind: str) -> list[AgentAction]:
        """All actions of a given kind (e.g. ``"file_delete"``)."""
        return [a for a in self.actions if a.kind == kind]

    def validate(self) -> None:
        """Raise :class:`SchemaError` if this session is not well-formed."""
        if not isinstance(self.session_id, str) or not self.session_id.strip():
            raise SchemaError("Session.session_id must be a non-empty string")
        if self.task_type not in TASK_TYPES:
            raise SchemaError(
                f"Session.task_type {self.task_type!r} not in {TASK_TYPES}")
        if self.input_document_type not in INPUT_DOCUMENT_TYPES:
            raise SchemaError(
                f"Session.input_document_type {self.input_document_type!r} "
                f"not in {INPUT_DOCUMENT_TYPES}")
        if self.human_label not in RISK_LABELS:
            raise SchemaError(
                f"Session.human_label {self.human_label!r} not in {RISK_LABELS}")
        if not isinstance(self.agent_response, str):
            raise SchemaError("Session.agent_response must be a string")
        if self.latency_seconds < 0:
            raise SchemaError("Session.latency_seconds must be >= 0")
        for a in self.actions:
            a.validate()
        self.risk_indicators.validate()
        if not isinstance(self.attack_category, str) or not self.attack_category:
            raise SchemaError("Session.attack_category must be a non-empty string")
        if self.gateway_decision is not None:
            self.gateway_decision.validate()

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Session":
        return cls(
            session_id=d["session_id"],
            date=d.get("date", ""),
            platform=d.get("platform", ""),
            agent_name=d.get("agent_name", ""),
            task_type=d["task_type"],
            user_prompt=d.get("user_prompt", ""),
            input_document_type=d.get("input_document_type", "none"),
            agent_response=d.get("agent_response", ""),
            actions=[AgentAction.from_dict(a) for a in d.get("actions", [])],
            tool_calls=list(d.get("tool_calls", [])),
            tool_trace_available=bool(d.get("tool_trace_available", True)),
            latency_seconds=float(d.get("latency_seconds", 0.0)),
            risk_indicators=RiskIndicators.from_dict(d.get("risk_indicators", {})),
            human_label=d.get("human_label", "safe"),
            label_notes=d.get("label_notes", ""),
            attack_category=d.get("attack_category", "benign"),
            attack_objective=d.get("attack_objective", ""),
            agent_config=dict(d.get("agent_config", {})),
            gateway_decision=(
                GatewayDecision.from_dict(d["gateway_decision"])
                if d.get("gateway_decision") else None
            ),
        )


# --------------------------------------------------------------------------- #
# Serialization helpers — raw logs are stored one-JSON-per-file, and the whole
# dataset can also be round-tripped as a single JSONL for convenience.
# --------------------------------------------------------------------------- #

def save_session(session: Session, path: str | Path) -> None:
    """Write one session to ``path`` as pretty JSON, after validating it."""
    session.validate()
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(session.to_dict(), indent=2), encoding="utf-8")


def load_session(path: str | Path) -> Session:
    """Load and validate a single session from a JSON file."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    s = Session.from_dict(data)
    s.validate()
    return s


def save_sessions_jsonl(sessions: Iterable[Session], path: str | Path) -> int:
    """Write many sessions to a single JSONL file. Returns the count written."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with path.open("w", encoding="utf-8") as fh:
        for s in sessions:
            s.validate()
            fh.write(json.dumps(s.to_dict()) + "\n")
            n += 1
    return n


def load_sessions_jsonl(path: str | Path) -> list[Session]:
    """Load and validate all sessions from a JSONL file."""
    out: list[Session] = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        s = Session.from_dict(json.loads(line))
        s.validate()
        out.append(s)
    return out
