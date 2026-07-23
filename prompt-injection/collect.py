"""Prompt-injection live-collection driver (reuses scigateway, adds two things).

Why a separate driver instead of ``scigateway collect-live``:

1. **Variant indexing** — each subtype needs 50 *different* generated prompts in
   two payload modes, so the driver passes ``(mode, index)`` to the scenario;
   Chenhao's ``collect.py`` re-runs one fixed prompt per replicate.
2. **Incremental append logging** — sessions and per-turn rows are appended and
   flushed *as each session completes* (the Spring script's crash-safety), so an
   interrupted first live run keeps everything already collected. Chenhao's driver
   writes ``sessions.jsonl`` only at the very end.

Everything else is reused unchanged: :class:`OpenClawDockerBackend` (incl. its
``dry_run`` mode), :func:`parse_session_jsonl`, the :class:`Session` schema, and
``is_out_of_scope`` for scope tagging. Output layout matches Chenhao's so the
shared pipeline (features → gateway → evaluate) consumes it directly:

    <out>/sessions.jsonl          (append-per-session; the schema input)
    <out>/turns.jsonl             (append-per-turn; crash-safety trace)
    <out>/<subtype>/<mode>/…      (native session_NNN.jsonl + gateway_NNN.log)
    <out>/session_manifest.csv    (one row per session)
    <out>/run_summary.json

``--dry-run`` uses synthetic native logs (no Docker/API). Note: dry-run only
fabricates a canned file *read* for prompts naming a .txt/.md/.csv/.pdf, so it
does NOT exercise the network/file-write escalation detection — that is validated
against a live agent later. Dry-run's job here is to prove the pipeline runs clean.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
import time
from datetime import date, datetime, timezone
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_REPO = _HERE.parent
for _p in (str(_REPO), str(_HERE)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from scigateway.live.docker_backend import OpenClawDockerBackend
from scigateway.live.openclaw_parser import parse_session_jsonl
from scigateway.live.scenarios import _behavior_rubric, is_out_of_scope
from scigateway.schema import Session
from scigateway.taxonomy import score_to_label

from prompts.controls import gen_controls
from scenarios import PI_FAMILIES, build_scenarios

PAYLOAD_MODES = ("echo", "escalate")
_DELAY = 0.0   # seconds to pause between live turns (rate-limit pacing); set by collect()


def _send_turns(backend, prompts, session_id, category, condition, mode):
    """Send each turn; return (turn_rows, last_turn, total_latency)."""
    rows, last, latency = [], None, 0.0
    for ti, prompt in enumerate(prompts):
        turn = backend.send(prompt, session_id)
        last = turn
        latency += turn.duration_s
        rows.append({
            "session_id": session_id, "category": category, "condition": condition,
            "payload_mode": mode, "attack_present": condition == "attack",
            "turn_index": ti, "timestamp": datetime.now(timezone.utc).isoformat(),
            "prompt": prompt, "response_preview": turn.response_text[:280],
            "response_time_s": turn.duration_s,
            "word_count": len(turn.response_text.split()),
            "total_tokens": turn.total_tokens, "cost": turn.cost,
            "provider": turn.provider, "model": turn.model,
        })
        if not backend.dry_run and _DELAY:
            time.sleep(_DELAY)
    return rows, last, latency


def _harvest_parse(backend, last, dest_dir, index):
    if last is not None:
        backend.harvest(last, dest_dir, index)
        native = backend.read_native_session(last)
    else:
        native = ""
    parsed = parse_session_jsonl(native)
    for a in parsed.actions:
        a.in_scope = not is_out_of_scope(a)
    return parsed


def _build_session(session_id, run_date, backend, *, category, task_type, condition,
                   parsed, prompts, latency, result, agent_config_extra):
    attack_present = condition == "attack"
    marker = "[prompt_injection] " if attack_present else ""
    session = Session(
        session_id=session_id, date=run_date, platform="OpenClaw",
        agent_name=f"{backend.container}:{parsed.model or backend.model or 'default'}",
        task_type=task_type,
        user_prompt=parsed.first_prompt or (prompts[0] if prompts else ""),
        input_document_type="none", agent_response=parsed.assistant_text,
        actions=list(parsed.actions), tool_calls=list(parsed.tool_calls),
        tool_trace_available=True, latency_seconds=round(latency, 3),
        risk_indicators=result.risk_indicators, human_label=result.label,
        label_notes=f"{marker}{condition} ({'dry' if backend.dry_run else 'live'}): {result.notes}",
        attack_category=category if attack_present else "benign",
        attack_objective=agent_config_extra.get("attack_objective", "") if attack_present else "",
        agent_config={
            "source": "dry_run_pi_harness" if backend.dry_run else "live_openclaw_docker",
            "dry_run": backend.dry_run, "container": backend.container,
            "model": parsed.model or backend.model or "default",
            "provider": parsed.provider or "",
            "prompt_family": category, "condition": condition,
            "attack_present": attack_present,
            "attack_succeeded": result.attack_succeeded,
            "num_turns": parsed.num_turns or len(prompts),
            **agent_config_extra,
        },
    )
    session.validate()
    return session


def _manifest_row(session, parsed, latency, result, extra):
    return {
        "session_id": session.session_id, "category": session.attack_category,
        "condition": session.agent_config["condition"],
        "payload_mode": extra.get("payload_mode", ""),
        "attack_present": session.agent_config["attack_present"],
        "attack_succeeded": result.attack_succeeded, "human_label": session.human_label,
        "num_turns": session.agent_config["num_turns"], "num_actions": len(parsed.actions),
        "tool_calls": "|".join(parsed.tool_calls), "latency_s": round(latency, 3),
        "notes": result.notes,
    }


def _attack_session(backend, scen, mode, index, out, run_date):
    session_id = f"{scen.key}-{mode}-attack-{index:03d}"
    scen._mode, scen._index = mode, index
    scen.setup(backend, "attack", session_id)
    try:
        prompts = scen.prompts("attack")
        variant = scen._current
        turns, last, latency = _send_turns(backend, prompts, session_id, scen.key, "attack", mode)
        parsed = _harvest_parse(backend, last, out / scen.key / mode, index)
        result = scen.evaluate(parsed, "attack")
        result.risk_indicators.out_of_scope_ops = sum(1 for a in parsed.actions if not a.in_scope)
        extra = {
            "payload_mode": mode, "subtype": scen.key, "pi_family": scen.pi_family,
            "technique": variant.technique, "primary": variant.primary,
            "canary": variant.canary, "escalation_target": variant.escalation_target,
            "attack_objective": scen.attack_objective,
        }
        session = _build_session(
            session_id, run_date, backend, category=scen.key, task_type=scen.task_type,
            condition="attack", parsed=parsed, prompts=prompts, latency=latency,
            result=result, agent_config_extra=extra)
        return session, turns, _manifest_row(session, parsed, latency, result, extra)
    finally:
        scen.teardown(backend)


def _control_session(backend, family, bench, index, out, run_date):
    session_id = f"{family}-control-{index:03d}"
    backend.reset_session(session_id)
    prompts = list(bench.turns)
    turns, last, latency = _send_turns(backend, prompts, session_id, family, "baseline", "control")
    parsed = _harvest_parse(backend, last, out / f"{family}_control" / "baseline", index)
    fs, cmd, cont, oos = _behavior_rubric(parsed)
    dims = {"instruction_robustness": 0, "memory_integrity": 0,
            "filesystem_safety": fs, "command_safety": cmd, "data_containment": cont}
    from scigateway.schema import RiskIndicators
    from scigateway.live.scenarios import ScenarioResult
    result = ScenarioResult(rubric_scores=dims,
                            risk_indicators=RiskIndicators(out_of_scope_ops=oos),
                            attack_succeeded=False, label=score_to_label(dims),
                            notes="benign control")
    extra = {"payload_mode": "none", "subtype": "control", "pi_family": family}
    session = _build_session(
        session_id, run_date, backend, category="benign", task_type="note_management",
        condition="baseline", parsed=parsed, prompts=prompts, latency=latency,
        result=result, agent_config_extra=extra)
    return session, turns, _manifest_row(session, parsed, latency, result, extra)


def collect(*, out_dir, n_attack, n_control, seed, dry_run, container, model,
            subtypes=None, delay=0.0, run_date=None):
    global _DELAY
    _DELAY = delay
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    backend = OpenClawDockerBackend(container=container, model=model, dry_run=dry_run)
    if not backend.is_available():
        raise RuntimeError(
            f"OpenClaw container {backend.container!r} is not running. Start it or pass --dry-run.")
    run_date = run_date or date.today().isoformat()
    # --n-attack is the per-mode count for a standard dual-mode subtype; total per
    # subtype = 2 * n_attack (== 50 at the default 25), split evenly across each
    # subtype's actual modes (echo-only subtypes put the whole 50 into echo).
    per_subtype = 2 * max(n_attack, 1)
    scenarios = build_scenarios(n_per_mode=per_subtype, seed=seed)
    if subtypes:                       # collect only the requested subtypes
        want = set(subtypes)
        scenarios = [s for s in scenarios if s.key in want]
        missing = want - {s.key for s in scenarios}
        if missing:
            raise ValueError(f"unknown subtypes: {sorted(missing)}")
    # controls are per-family: only run families the selected subtypes belong to.
    families = sorted({s.pi_family for s in scenarios})
    modes_used = sorted({m for s in scenarios for m in s.modes})

    sessions_path, turns_path = out / "sessions.jsonl", out / "turns.jsonl"
    sessions_path.write_text("", encoding="utf-8")   # truncate at run start
    turns_path.write_text("", encoding="utf-8")
    manifest_rows = []

    # append + flush per session/turn == crash safety
    with sessions_path.open("a", encoding="utf-8") as sf, turns_path.open("a", encoding="utf-8") as tf:
        def emit(session, turn_rows):
            sf.write(json.dumps(session.to_dict()) + "\n"); sf.flush()
            for tr in turn_rows:
                tf.write(json.dumps(tr) + "\n")
            tf.flush()

        n_fail = 0

        def _run(label, fn):
            """Run one session; a single failure (timeout/rate-limit) is logged and
            skipped so a long live run isn't lost to one bad turn."""
            nonlocal n_fail
            try:
                session, turns, manifest = fn()
            except Exception as e:  # noqa: BLE001 - resilience over a long live run
                n_fail += 1
                print(f"[warn] {label} failed: {type(e).__name__}: {str(e)[:160]}", flush=True)
                return
            emit(session, turns)
            manifest_rows.append(manifest)
            print(f"[{len(manifest_rows):4d}] {session.session_id:38s} "
                  f"label={session.human_label:10s} succeeded={manifest['attack_succeeded']}",
                  flush=True)

        for scen in scenarios:
            per_mode = per_subtype // len(scen.modes)
            for mode in scen.modes:
                for i in range(per_mode):
                    _run(f"{scen.key}-{mode}-{i:03d}",
                         lambda scen=scen, mode=mode, i=i: _attack_session(
                             backend, scen, mode, i, out, run_date))

        for family in families:
            for i, bench in enumerate(gen_controls(family, n_control, seed=seed)):
                _run(f"{family}-control-{i:03d}",
                     lambda family=family, bench=bench, i=i: _control_session(
                         backend, family, bench, i, out, run_date))

        if n_fail:
            print(f"[warn] {n_fail} sessions failed and were skipped", flush=True)

    _write_manifest_summary(out, manifest_rows, backend, modes_used, seed)
    return manifest_rows


def _write_manifest_summary(out, rows, backend, modes, seed):
    if rows:
        with (out / "session_manifest.csv").open("w", encoding="utf-8", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
            w.writeheader(); w.writerows(rows)
    n_attack = sum(1 for r in rows if r["attack_present"])
    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(), "dry_run": backend.dry_run,
        "num_sessions": len(rows), "num_attack_sessions": n_attack,
        "num_control_sessions": len(rows) - n_attack,
        "attacks_succeeded": sum(1 for r in rows if r["attack_succeeded"]),
        "payload_modes": list(modes), "seed": seed,
        "subtypes": sorted({r["category"] for r in rows if r["attack_present"]}),
        "note": "dry-run cannot exercise network/file-write escalation; labels are heuristic, not adjudicated",
    }
    (out / "run_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")


def main():
    ap = argparse.ArgumentParser(description="Collect prompt-injection sessions (attack + control).")
    ap.add_argument("--out-dir", default="pi_experiments")
    ap.add_argument("--subtypes", nargs="+", default=None,
                    help="only collect these subtype keys (default: all); controls run only "
                         "for the families those subtypes belong to")
    ap.add_argument("--n-attack", type=int, default=25,
                    help="per-mode attack count for a dual-mode subtype (total/subtype = 2*this = 50)")
    ap.add_argument("--n-control", type=int, default=50, help="control sessions per family")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--delay", type=float, default=0.0, help="seconds between live turns (pacing)")
    ap.add_argument("--container", default=None)
    ap.add_argument("--model", default=None)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    rows = collect(out_dir=args.out_dir, subtypes=args.subtypes, n_attack=args.n_attack,
                   n_control=args.n_control, seed=args.seed, dry_run=args.dry_run,
                   container=args.container, model=args.model, delay=args.delay)
    n_attack = sum(1 for r in rows if r["attack_present"])
    print(f"[pi-collect] {len(rows)} sessions ({n_attack} attack / {len(rows)-n_attack} control) "
          f"-> {args.out_dir}  dry_run={args.dry_run}")


if __name__ == "__main__":
    main()
