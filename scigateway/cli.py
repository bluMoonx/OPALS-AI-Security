"""Command-line interface for the real-agent SciGateway workflow.

Commands
--------
* ``collect-live``             drive the Dockerized OpenClaw agent and preserve native logs
* ``collect-live-multi-agent`` drive TWO real agent identities per probe (ethical
  drift / compromised-channel); requires a second agent profile already
  configured in the container
* ``analyze-live``              evaluate already-collected live sessions; never calls Docker
* ``adjudicate``                compare two completed blind worksheets; offline only
* ``info``                      print the live scenarios, threat model, and observable features
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from . import __version__

_PKG_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_EXPERIMENTS = _PKG_ROOT / "experiments"


def _setup_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.INFO if verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )


def _cmd_collect_live(args) -> int:
    """Collect real sessions from a running Dockerized OpenClaw container."""
    from .live.collect import collect_live
    from .live.docker_backend import OpenClawDockerBackend
    from .live.scenarios import DEFAULT_LIVE_CATEGORIES, SCENARIOS

    categories = args.categories or list(DEFAULT_LIVE_CATEGORIES)
    unknown = [category for category in categories if category not in SCENARIOS]
    if unknown:
        print(f"[collect-live] ERROR: unknown categories {unknown}; "
              f"choose from {sorted(SCENARIOS)}", file=sys.stderr)
        return 2

    backend = OpenClawDockerBackend(
        container=args.container, model=args.model, dry_run=args.dry_run)
    mode = "DRY-RUN (synthetic logs; no Docker/API)" if args.dry_run else "LIVE"
    print("=" * 70)
    print(f"  SciGateway - LIVE COLLECTION [{mode}]")
    print(f"  container={backend.container}  model={backend.model or 'container-default'}")
    print(f"  categories={categories}  sessions/condition={args.sessions}")
    print(f"  schedule_seed={args.schedule_seed} (randomized within each replicate)")
    if not args.dry_run:
        print("  Real turns spend provider tokens; every attack uses a harmless mock target.")
    print("=" * 70)

    try:
        result = collect_live(
            categories, sessions_per_condition=args.sessions,
            out_dir=args.out_dir, backend=backend, delay_s=args.delay,
            dry_run=args.dry_run, schedule_seed=args.schedule_seed)
    except (RuntimeError, ValueError) as exc:
        print(f"[collect-live] ERROR: {exc}", file=sys.stderr)
        return 1

    n_attack = sum(1 for row in result.manifest_rows if row["condition"] == "attack")
    n_succeeded = sum(1 for row in result.manifest_rows if row["attack_succeeded"])
    print(f"[collect-live] {result.num_sessions} sessions "
          f"({n_attack} attack / {result.num_sessions - n_attack} baseline) "
          f"across {len(set(row['category'] for row in result.manifest_rows))} categories")
    print(f"[collect-live] attacks succeeded (observed): {n_succeeded}/{n_attack}")
    print(f"[collect-live] tokens={result.total_tokens}  "
          f"provider-reported cost=${result.total_cost:.4f}")
    print(f"[collect-live] native logs + sessions.jsonl + manifest -> {args.out_dir}")
    if not args.dry_run:
        print("[collect-live] NEXT: run `python -m scigateway analyze-live` on the "
              "collected sessions. Analysis does not call Docker.")
    return 0


def _cmd_collect_live_multi_agent(args) -> int:
    """Collect real two-agent handoff sessions (ethical drift / compromised channel).

    Requires a second isolated OpenClaw agent profile already configured in the
    container (see ``1 - Start Here/REAL AGENT STUDY PROTOCOL.md``). Fails loud
    if that prerequisite is missing rather than silently degrading to a
    single-agent role-play.
    """
    from .live.docker_backend import OpenClawDockerBackend
    from .live.multi_agent import MULTI_AGENT_CATEGORIES, MULTI_AGENT_SCENARIOS, collect_live_multi_agent

    categories = args.categories or list(MULTI_AGENT_CATEGORIES)
    unknown = [category for category in categories if category not in MULTI_AGENT_SCENARIOS]
    if unknown:
        print(f"[collect-live-multi-agent] ERROR: unknown categories {unknown}; "
              f"choose from {sorted(MULTI_AGENT_SCENARIOS)}", file=sys.stderr)
        return 2

    backend = OpenClawDockerBackend(
        container=args.container, model=args.model, dry_run=args.dry_run)
    mode = "DRY-RUN (synthetic logs; no Docker/API)" if args.dry_run else "LIVE"
    print("=" * 70)
    print(f"  SciGateway - MULTI-AGENT LIVE COLLECTION [{mode}]")
    print(f"  container={backend.container}  model={backend.model or 'container-default'}")
    print(f"  categories={categories}  sessions/condition={args.sessions}")
    if not args.dry_run:
        print("  Each probe spends TWO real agent turns (role A + role B).")
    print("=" * 70)

    try:
        result = collect_live_multi_agent(
            categories, sessions_per_condition=args.sessions,
            out_dir=args.out_dir, backend=backend, delay_s=args.delay,
            dry_run=args.dry_run, schedule_seed=args.schedule_seed)
    except (RuntimeError, ValueError) as exc:
        print(f"[collect-live-multi-agent] ERROR: {exc}", file=sys.stderr)
        return 1

    n_attack = sum(1 for row in result.manifest_rows if row["condition"] == "attack")
    n_succeeded = sum(1 for row in result.manifest_rows if row["attack_succeeded"])
    print(f"[collect-live-multi-agent] {result.num_sessions} probes "
          f"({n_attack} attack / {result.num_sessions - n_attack} baseline)")
    print(f"[collect-live-multi-agent] attacks succeeded (observed): {n_succeeded}/{n_attack}")
    print(f"[collect-live-multi-agent] tokens={result.total_tokens}  "
          f"provider-reported cost=${result.total_cost:.4f}")
    print(f"[collect-live-multi-agent] sessions_multi_agent.jsonl + manifest -> {args.out_dir}")
    return 0


def _cmd_analyze_live(args) -> int:
    """Analyze a collected live dataset without launching an agent."""
    from .pipeline.live_analysis import analyze_live_sessions

    try:
        metrics = analyze_live_sessions(
            args.sessions_file, out_dir=args.out_dir, model_seed=args.model_seed,
            n_splits=args.n_splits)
    except (OSError, ValueError) as exc:
        print(f"[analyze-live] ERROR: {exc}", file=sys.stderr)
        return 2

    best = metrics["best_pooled_metrics"]
    print(f"[analyze-live] {metrics['config']['n_sessions']} live sessions; "
          f"{metrics['config']['n_splits']}-fold grouped CV")
    print(f"[analyze-live] best classifier: {metrics['best_config']['experiment']}/"
          f"{metrics['best_config']['model']}")
    print(f"[analyze-live] detection={best['attack_detection_rate']:.3f} "
          f"macroF1={best['macro_f1']:.3f} "
          f"FPR={best['false_positive_rate']:.3f} "
          f"FNR={best['false_negative_rate']:.3f}")
    print(f"[analyze-live] metrics, audit trail, error analysis, and figures -> {args.out_dir}")
    return 0


def _cmd_adjudicate(args) -> int:
    """Report inter-rater reliability without launching an agent."""
    import json

    from .labeling import (adjudication_report, load_heuristic_labels,
                           load_rater_labels, write_adjudication_markdown)

    try:
        rater_a = load_rater_labels(args.rater_a)
        rater_b = load_rater_labels(args.rater_b)
        if not rater_a or not rater_b:
            raise ValueError("both worksheets need at least one completed label")
        if not (set(rater_a) & set(rater_b)):
            raise ValueError("worksheets have no completed session in common")
        heuristic = load_heuristic_labels(args.answer_key) if args.answer_key else None
        report = adjudication_report(rater_a, rater_b, heuristic=heuristic)
        out = Path(args.out_dir)
        out.mkdir(parents=True, exist_ok=True)
        (out / "adjudication_report.json").write_text(
            json.dumps(report, indent=2), encoding="utf-8")
        write_adjudication_markdown(report, out / "adjudication_report.md")
    except (OSError, ValueError) as exc:
        print(f"[adjudicate] ERROR: {exc}", file=sys.stderr)
        return 2

    print(f"[adjudicate] n={report['n_common']} agreement={report['raw_agreement']:.3f} "
          f"kappa={report['cohens_kappa']:.3f} "
          f"({report['kappa_interpretation']})")
    print(f"[adjudicate] report -> {args.out_dir}")
    return 0


def _cmd_info(args) -> int:
    from .attacks import (ATTACK_CATEGORIES, CONCEPTUAL_CATEGORIES,
                          LIVE_HARNESS_CATEGORIES, LIVE_HARNESS_MULTI_AGENT_CATEGORIES)
    from .live.multi_agent import MULTI_AGENT_CATEGORIES
    from .live.scenarios import DEFAULT_LIVE_CATEGORIES
    from .pipeline import features as feat_mod
    from .taxonomy import RISK_TYPES

    print(f"SciGateway v{__version__}")
    print(f"\nSingle-agent live scenarios ({len(DEFAULT_LIVE_CATEGORIES)}):")
    for category in DEFAULT_LIVE_CATEGORIES:
        print(f"  - {category}")
    print(f"\nMulti-agent live scenarios ({len(MULTI_AGENT_CATEGORIES)}, "
          f"require a second agent profile - see collect-live-multi-agent):")
    for category in MULTI_AGENT_CATEGORIES:
        print(f"  - {category}")
    print(f"\nRisk taxonomy ({len(RISK_TYPES)} types):")
    for risk_type in RISK_TYPES:
        print(f"  [{risk_type.severity}] {risk_type.name}: {risk_type.meaning}")
    print(f"\nObservable features ({len(feat_mod.FEATURE_NAMES)}):")
    for spec in feat_mod.FEATURE_SPECS:
        print(f"  ({spec.family}) {spec.name} - {spec.rationale}")
    print(f"\nAttack taxonomy ({len(ATTACK_CATEGORIES)} categories: "
          f"{len(LIVE_HARNESS_CATEGORIES)} live-harness, "
          f"{len(LIVE_HARNESS_MULTI_AGENT_CATEGORIES)} live-harness-multi-agent, "
          f"{len(CONCEPTUAL_CATEGORIES)} conceptual):")
    tags = {"live_harness": "LIVE-HARNESS", "live_harness_multi_agent": "LIVE-HARNESS(multi-agent)",
           "conceptual": "conceptual"}
    for category in ATTACK_CATEGORIES:
        tag = tags.get(category.coverage, category.coverage)
        print(f"  [{category.severity}] {tag} {category.name}: {category.objective}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scigateway",
        description="Gateway-level security monitor for real AI-for-science agents.")
    parser.add_argument("--version", action="version", version=f"scigateway {__version__}")
    parser.add_argument("-v", "--verbose", action="store_true", help="log at INFO level")
    sub = parser.add_subparsers(dest="command", required=True)

    collect = sub.add_parser(
        "collect-live",
        help="collect REAL sessions from a running OpenClaw Docker container")
    collect.add_argument("--categories", nargs="+", default=None,
                         help="attack categories to run (default: all live scenarios)")
    collect.add_argument("--sessions", type=int, default=2,
                         help="sessions per condition per category (default: 2)")
    collect.add_argument("--container", default=None,
                         help="container name (default: $SCIGATEWAY_OPENCLAW_CONTAINER "
                              "or 'openclaw-gateway')")
    collect.add_argument("--model", default=None,
                         help="model override provider/id (default: container default)")
    collect.add_argument("--delay", type=float, default=0.0,
                         help="seconds to pause between real turns (default: 0)")
    collect.add_argument("--schedule-seed", type=int, default=13,
                         help="seed for randomized matched-replicate order (default: 13)")
    collect.add_argument("--out-dir", default=str(DEFAULT_EXPERIMENTS))
    collect.add_argument("--dry-run", action="store_true",
                         help="synthetic logs, no Docker/API spend (wiring tests only)")
    collect.set_defaults(func=_cmd_collect_live)

    multi = sub.add_parser(
        "collect-live-multi-agent",
        help="collect REAL two-agent handoff probes (ethical drift / compromised "
             "channel); requires a second agent profile already configured")
    multi.add_argument("--categories", nargs="+", default=None,
                       help="multi-agent categories to run (default: both)")
    multi.add_argument("--sessions", type=int, default=2,
                       help="probes per condition per category (default: 2)")
    multi.add_argument("--container", default=None,
                       help="container name (default: $SCIGATEWAY_OPENCLAW_CONTAINER "
                            "or 'openclaw-gateway')")
    multi.add_argument("--model", default=None,
                       help="model override provider/id (default: container default)")
    multi.add_argument("--delay", type=float, default=0.0,
                       help="seconds to pause between real turns (default: 0)")
    multi.add_argument("--schedule-seed", type=int, default=13)
    multi.add_argument("--out-dir", default=str(DEFAULT_EXPERIMENTS))
    multi.add_argument("--dry-run", action="store_true",
                       help="synthetic logs, no Docker/API spend (wiring tests only)")
    multi.set_defaults(func=_cmd_collect_live_multi_agent)

    analyze = sub.add_parser(
        "analyze-live",
        help="analyze collected live sessions; never starts Docker or an agent")
    analyze.add_argument("--sessions-file", default=str(DEFAULT_EXPERIMENTS / "sessions.jsonl"),
                         help="Session JSONL produced by collect-live")
    analyze.add_argument("--out-dir", default=str(DEFAULT_EXPERIMENTS / "analysis"),
                         help="directory for metrics, logs, error analysis, and figures")
    analyze.add_argument("--model-seed", type=int, default=13)
    analyze.add_argument("--n-splits", type=int, default=5, help="grouped CV folds")
    analyze.set_defaults(func=_cmd_analyze_live)

    adjudication_dir = DEFAULT_EXPERIMENTS / "adjudication"
    adjudicate = sub.add_parser(
        "adjudicate",
        help="compare two completed blind worksheets; no Docker or agent calls")
    adjudicate.add_argument("--rater-a", default=str(adjudication_dir / "worksheet_rater_A.csv"))
    adjudicate.add_argument("--rater-b", default=str(adjudication_dir / "worksheet_rater_B.csv"))
    adjudicate.add_argument("--answer-key", default=str(adjudication_dir / "answer_key.csv"),
                            help="researcher-only heuristic labels (omit with an empty value)")
    adjudicate.add_argument("--out-dir", default=str(adjudication_dir / "report"))
    adjudicate.set_defaults(func=_cmd_adjudicate)

    info = sub.add_parser("info", help="print live scenarios, features, and taxonomy")
    info.set_defaults(func=_cmd_info)
    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    _setup_logging(getattr(args, "verbose", False))
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
