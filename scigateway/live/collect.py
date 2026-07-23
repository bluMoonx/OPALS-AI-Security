"""Orchestrate a live run and write the Spring-style ``experiments/`` layout.

For every ``(category, condition, replicate)`` this:

1. asks the scenario to set up container state (:meth:`Scenario.setup`);
2. sends each prompt turn to the real agent (:meth:`OpenClawDockerBackend.send`);
3. harvests the container's native ``session_NNN.jsonl`` + ``gateway_NNN.log``
   with ``docker cp`` into ``<category>/<condition>/`` (the Spring layout);
4. parses the native log into an :class:`~scigateway.schema.Session` and derives
   honest labels from the observed behavior (:meth:`Scenario.evaluate`).

It emits, under ``out_dir``:

* ``<category>/<attack|baseline>/session_NNN.jsonl`` + ``gateway_NNN.log`` — the
  raw native OpenClaw logs (interchangeable with the Spring artifacts);
* ``sessions.jsonl`` — the same runs in the project's :class:`Session` schema, the
  input the analysis pipeline (features -> gateway -> evaluate) consumes;
* ``session_manifest.csv`` — one row per session (category, condition, ground
  truth, tokens, cost, latency, label, native paths);
* ``turns_<timestamp>.jsonl`` — per-turn behavioral features (Spring-style);
* ``run_summary.json`` — totals, including measured token spend and cost.

``dry_run=True`` runs the whole thing against synthetic native logs (no Docker,
no API spend) so it is fully unit-testable.
"""

from __future__ import annotations

import csv
import json
import random
import time
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path

from ..schema import Session, save_sessions_jsonl
from .docker_backend import OpenClawDockerBackend
from .openclaw_parser import parse_session_jsonl
from .scenarios import Scenario, get_scenario, is_out_of_scope

CONDITIONS = ("attack", "baseline")


def _planned_runs(
    categories: list[str] | tuple[str, ...],
    sessions_per_condition: int,
    schedule_seed: int,
) -> list[tuple[str, str, int]]:
    """Return a reproducible, randomized order with matched replicate blocks.

    Each block contains one attack and one baseline for every category at a shared
    replicate index. Shuffling the block avoids running all attacks before all
    controls, while stable session IDs and the seed keep the order auditable.
    """
    if sessions_per_condition < 1:
        raise ValueError("sessions_per_condition must be at least 1")
    if len(set(categories)) != len(categories):
        raise ValueError("collection categories must be unique")

    planned: list[tuple[str, str, int]] = []
    for replicate in range(sessions_per_condition):
        block = [
            (category, condition, replicate)
            for category in categories
            for condition in CONDITIONS
        ]
        random.Random(schedule_seed + replicate).shuffle(block)
        planned.extend(block)
    return planned


@dataclass(slots=True)
class CollectResult:
    out_dir: Path
    sessions: list[Session] = field(default_factory=list)
    manifest_rows: list[dict] = field(default_factory=list)
    turn_rows: list[dict] = field(default_factory=list)
    total_tokens: int = 0
    total_cost: float = 0.0
    dry_run: bool = True

    @property
    def num_sessions(self) -> int:
        return len(self.sessions)


def _one_session(
    backend: OpenClawDockerBackend,
    scenario: Scenario,
    condition: str,
    index: int,
    out_dir: Path,
    run_date: str,
    delay_s: float,
) -> tuple[Session, dict, list[dict]]:
    """Run a single session end-to-end and build its schema + manifest + turns."""
    session_id = f"{scenario.key}-{condition}-{index:03d}"
    dest_dir = out_dir / scenario.key / condition

    scenario.setup(backend, condition, session_id)
    prompts = scenario.prompts(condition)

    turns: list[dict] = []
    last_turn = None
    total_latency = 0.0
    for ti, prompt in enumerate(prompts):
        turn = backend.send(prompt, session_id)
        last_turn = turn
        total_latency += turn.duration_s
        turns.append({
            "session_id": session_id,
            "category": scenario.key,
            "condition": condition,
            "attack_present": condition == "attack",
            "turn_index": ti,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "prompt": prompt,
            "response_preview": turn.response_text[:280],
            "response_time_s": turn.duration_s,
            "word_count": len(turn.response_text.split()),
            "input_tokens": int(turn.usage.get("input", 0) or 0),
            "output_tokens": int(turn.usage.get("output", 0) or 0),
            "total_tokens": turn.total_tokens,
            "cost": turn.cost,
            "provider": turn.provider,
            "model": turn.model,
        })
        if delay_s and not backend.dry_run:
            time.sleep(delay_s)

    # harvest native logs + parse the full session
    written = backend.harvest(last_turn, dest_dir, index) if last_turn else {}
    native_text = backend.read_native_session(last_turn) if last_turn else ""
    parsed = parse_session_jsonl(native_text)

    # apply declared task scope to the observed actions
    for a in parsed.actions:
        a.in_scope = not is_out_of_scope(a)

    result = scenario.evaluate(parsed, condition)
    result.risk_indicators.out_of_scope_ops = sum(
        1 for a in parsed.actions if not a.in_scope)

    attack_present = condition == "attack"
    marker = f"[{scenario.attack_marker}] " if scenario.attack_marker else ""
    label_notes = (
        f"{marker}live openclaw ({condition}); label derived from observed behavior "
        f"+ condition (heuristic): {result.notes}")

    session = Session(
        session_id=session_id,
        date=run_date,
        platform="OpenClaw",
        agent_name=f"{backend.container}:{parsed.model or backend.model or 'default'}",
        task_type=scenario.task_type,
        user_prompt=parsed.first_prompt or (prompts[0] if prompts else ""),
        input_document_type=scenario.input_document_type,
        agent_response=parsed.assistant_text,
        actions=list(parsed.actions),
        tool_calls=list(parsed.tool_calls),
        tool_trace_available=True,
        latency_seconds=round(total_latency, 3),
        risk_indicators=result.risk_indicators,
        human_label=result.label,
        label_notes=label_notes,
        attack_category=scenario.key if attack_present else "benign",
        attack_objective=scenario.attack_objective if attack_present else "",
        agent_config={
            "source": ("dry_run_openclaw_harness" if backend.dry_run
                       else "live_openclaw_docker"),
            "dry_run": backend.dry_run,
            "container": backend.container,
            "provider": parsed.model and parsed.provider or backend.model,
            "model": parsed.model or backend.model or "default",
            "prompt_family": scenario.family,
            "condition": condition,
            "attack_present": attack_present,
            "attack_succeeded": result.attack_succeeded,
            "num_turns": parsed.num_turns or len(prompts),
        },
    )
    session.validate()

    manifest = {
        "session_id": session_id,
        "category": scenario.key,
        "condition": condition,
        "attack_present": attack_present,
        "attack_succeeded": result.attack_succeeded,
        "human_label": result.label,
        "num_turns": parsed.num_turns or len(prompts),
        "num_actions": len(parsed.actions),
        "tool_calls": "|".join(parsed.tool_calls),
        "total_tokens": parsed.total_tokens,
        "cost_total": round(parsed.cost_total, 6),
        "latency_s": round(total_latency, 3),
        "provider": parsed.provider,
        "model": parsed.model,
        "native_session": written.get("session", ""),
        "native_gateway": written.get("gateway", ""),
        "notes": result.notes,
    }
    return session, manifest, turns


def collect_live(
    categories: list[str] | tuple[str, ...],
    *,
    sessions_per_condition: int = 2,
    out_dir: str | Path = "experiments",
    backend: OpenClawDockerBackend | None = None,
    delay_s: float = 0.0,
    run_date: str | None = None,
    dry_run: bool = False,
    schedule_seed: int = 13,
) -> CollectResult:
    """Run the full live collection and write all artifacts. Returns the result."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    backend = backend or OpenClawDockerBackend(dry_run=dry_run)
    run_date = run_date or date.today().isoformat()

    if not backend.is_available():
        raise RuntimeError(
            f"OpenClaw container {backend.container!r} is not running. Start it, or "
            f"pass dry_run=True. (docker ps did not list it.)")

    result = CollectResult(out_dir=out, dry_run=backend.dry_run)
    for collection_order, (key, condition, i) in enumerate(
            _planned_runs(categories, sessions_per_condition, schedule_seed)):
        scenario = get_scenario(key)
        # Always remove only this scenario's managed mock artifacts, even when a
        # Docker call, parser, or labeling step raises. A failed probe must never
        # leave state behind for the next probe.
        try:
            session, manifest, turns = _one_session(
                backend, scenario, condition, i, out, run_date, delay_s)
        finally:
            scenario.teardown(backend)
        session.agent_config["collection_order"] = collection_order
        session.agent_config["schedule_seed"] = schedule_seed
        manifest["collection_order"] = collection_order
        manifest["schedule_seed"] = schedule_seed
        result.sessions.append(session)
        result.manifest_rows.append(manifest)
        result.turn_rows.extend(turns)
        result.total_tokens += manifest["total_tokens"]
        result.total_cost += manifest["cost_total"]

    _write_outputs(result)
    return result


def _write_outputs(result: CollectResult) -> None:
    out = result.out_dir
    save_sessions_jsonl(result.sessions, out / "sessions.jsonl")

    manifest_path = out / "session_manifest.csv"
    if result.manifest_rows:
        cols = list(result.manifest_rows[0].keys())
        with manifest_path.open("w", encoding="utf-8", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=cols)
            w.writeheader()
            w.writerows(result.manifest_rows)

    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    turns_path = out / f"turns_{ts}.jsonl"
    with turns_path.open("w", encoding="utf-8") as fh:
        for row in result.turn_rows:
            fh.write(json.dumps(row) + "\n")

    n_attack = sum(1 for m in result.manifest_rows if m["condition"] == "attack")
    n_succeeded = sum(1 for m in result.manifest_rows if m["attack_succeeded"])
    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "dry_run": result.dry_run,
        "num_sessions": result.num_sessions,
        "num_attack_sessions": n_attack,
        "num_baseline_sessions": result.num_sessions - n_attack,
        "attacks_succeeded": n_succeeded,
        "categories": sorted({m["category"] for m in result.manifest_rows}),
        "schedule_seed": (
            result.manifest_rows[0].get("schedule_seed") if result.manifest_rows else None),
        "total_tokens": result.total_tokens,
        "total_cost_usd": round(result.total_cost, 6),
        "note": ("cost is provider-reported (0.0 on a flat Ollama-Cloud plan); "
                 "labels are condition + observed-behavior heuristics, not human adjudication"),
    }
    (out / "run_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
