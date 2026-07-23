"""Analyze collected real-agent sessions without invoking the agent again.

``analyze_live_sessions`` is deliberately separate from collection: it reads the
``sessions.jsonl`` emitted by :mod:`scigateway.live.collect`, performs grouped
cross-validation and gateway replay, then writes metrics, audit logs, error
analysis, and figures. It never imports the Docker backend and cannot spend
provider tokens.
"""

from __future__ import annotations

import json
import logging
import statistics
from pathlib import Path

from ..attacks import (CONCEPTUAL_CATEGORIES, LIVE_HARNESS_CATEGORIES,
                       categorize_session, severity_of)
from ..gateway import Gateway, IngressInterceptor, PolicyEngine, RuleRiskEvaluator
from ..schema import BLOCKING_ACTIONS, load_sessions_jsonl
from . import erroranalysis
from .evaluate import (CVResult, _OOFEvaluator, cross_validate_model,
                       gateway_outcomes, per_category_detection,
                       severity_weighted_detection, successful_attack_analysis)
from .evidence import (gateway_logs_for_sessions, input_provenance,
                       native_tool_policy_summary, wilson_interval)
from .features import build_feature_frame
from .train import EXPERIMENTS, _build_models

logger = logging.getLogger(__name__)


def _rule_predictions(sessions):
    interceptor, evaluator = IngressInterceptor(), RuleRiskEvaluator()
    prediction, score = {}, {}
    for session in sessions:
        evaluation = evaluator.evaluate(interceptor.intercept(session))
        prediction[session.session_id] = evaluation.label
        score[session.session_id] = evaluation.risk_score
    return prediction, score


def _compare_evaluators(sessions, ml_evaluator, rule_evaluator) -> dict:
    """Paired enforcement comparison, separating exact actions from block parity."""
    interceptor, policy = IngressInterceptor(), PolicyEngine()
    different_actions: list[str] = []
    different_blocks: list[str] = []
    for session in sessions:
        req = interceptor.intercept(session)
        ml_action = policy.decide(ml_evaluator.evaluate(req), req).enforcement_action
        rule_action = policy.decide(rule_evaluator.evaluate(req), req).enforcement_action
        if ml_action != rule_action:
            different_actions.append(session.session_id)
        if ((ml_action in BLOCKING_ACTIONS) != (rule_action in BLOCKING_ACTIONS)):
            different_blocks.append(session.session_id)
    n = len(sessions)
    return {
        "n_sessions": n,
        "exact_enforcement_action_agreement": (n - len(different_actions)) / n if n else 0.0,
        "block_decision_agreement": (n - len(different_blocks)) / n if n else 0.0,
        "n_different_enforcement_actions": len(different_actions),
        "different_enforcement_action_ids": different_actions,
        "n_different_block_decisions": len(different_blocks),
        "different_block_decision_ids": different_blocks,
    }


def _validate_live_dataset(sessions, df, requested_splits: int) -> int:
    if not sessions:
        raise ValueError("no sessions found; collect real sessions before analysis")

    non_live = [
        session.session_id for session in sessions
        if session.agent_config.get("source") != "live_openclaw_docker"
        or session.agent_config.get("dry_run", False)
    ]
    if non_live:
        preview = ", ".join(non_live[:5])
        raise ValueError(
            "analysis accepts only observed live OpenClaw sessions; found non-live "
            f"records ({preview})")

    families = sorted(df["prompt_family"].unique().tolist())
    if len(families) < 2:
        raise ValueError(
            "need sessions from at least two live scenario families for grouped "
            f"cross-validation; found {families}")

    n_splits = max(2, min(requested_splits, len(families)))
    from sklearn.model_selection import GroupKFold

    for train_index, _ in GroupKFold(n_splits=n_splits).split(
            df, groups=df["prompt_family"]):
        labels = set(df.iloc[train_index]["label"])
        if len(labels) < 2:
            raise ValueError(
                "at least one grouped-CV training fold has only one label; collect "
                "more varied real outcomes before fitting a classifier")

    missing_labels = {"safe", "suspicious", "unsafe"} - set(df["label"])
    if missing_labels:
        logger.warning(
            "live dataset has no %s label(s); corresponding class metrics are "
            "reported as zero rather than inferred", sorted(missing_labels))
    return n_splits


def analyze_live_sessions(
    sessions_file: str | Path,
    *,
    out_dir: str | Path = "analysis",
    model_seed: int = 13,
    n_splits: int = 5,
) -> dict:
    """Evaluate one collected, real-agent dataset and write its artifacts.

    The supplied JSONL is immutable input: analysis writes only under ``out_dir``.
    Every ML prediction is out-of-fold by live scenario family, so a model is not
    scored on a category it saw in that training fold.
    """
    sessions_path = Path(sessions_file)
    if not sessions_path.exists():
        raise ValueError(f"sessions file not found: {sessions_path}")
    sessions = load_sessions_jsonl(sessions_path)
    df = build_feature_frame(sessions)
    actual_splits = _validate_live_dataset(sessions, df, n_splits)

    out = Path(out_dir)
    (out / "logs").mkdir(parents=True, exist_ok=True)
    (out / "figures").mkdir(parents=True, exist_ok=True)
    df.to_csv(out / "features.csv", index=False)

    cv_results: list[CVResult] = []
    for experiment, features in EXPERIMENTS.items():
        for model_name in _build_models(model_seed):
            result = cross_validate_model(
                df, features, model_name, n_splits=actual_splits, seed=model_seed)
            result.experiment = experiment
            cv_results.append(result)

    best = max(cv_results, key=lambda result: (
        result.pooled["attack_detection_rate"], result.pooled["macro_f1"],
        -result.pooled["false_positive_rate"]))
    per_category = per_category_detection(sessions, best.oof_pred_by_id)
    severity_weighted = severity_weighted_detection(sessions, best.oof_pred_by_id)
    success_conditional = successful_attack_analysis(sessions, best.oof_pred_by_id)

    ml_gateway = gateway_outcomes(
        sessions, best.oof_pred_by_id, best.oof_score_by_id)
    rule_prediction, rule_score = _rule_predictions(sessions)
    rule_gateway = gateway_outcomes(sessions, rule_prediction, rule_score)
    evaluator_comparison = _compare_evaluators(
        sessions, _OOFEvaluator(best.oof_pred_by_id, best.oof_score_by_id),
        RuleRiskEvaluator())
    gateway_logs, missing_gateway_logs = gateway_logs_for_sessions(
        sessions_path.parent, sessions)
    platform_controls = native_tool_policy_summary(gateway_logs)
    platform_controls["n_analyzed_sessions"] = len(sessions)
    platform_controls["n_missing_session_gateway_logs"] = len(missing_gateway_logs)
    platform_controls["missing_session_gateway_log_ids"] = missing_gateway_logs[:20]
    platform_controls["matched_gateway_log_coverage"] = (
        len(gateway_logs) / len(sessions) if sessions else 0.0)
    platform_controls["n_unmatched_adjacent_gateway_logs"] = max(
        0, len(list(sessions_path.parent.rglob("gateway_*.log"))) - len(gateway_logs))
    provenance = input_provenance(sessions_path, gateway_logs)

    gateway = Gateway(
        evaluator=_OOFEvaluator(best.oof_pred_by_id, best.oof_score_by_id),
        audit_path=out / "audit_trail.jsonl")
    gateway.process_all(sessions, attach=True)
    _write_structured_logs(sessions, out / "logs" / "sessions.jsonl", out / "logs")

    errors = erroranalysis.analyze(sessions, best.oof_pred_by_id, ml_gateway)
    erroranalysis.write_markdown(errors, out / "error_analysis.md")

    latencies = [session.latency_seconds for session in sessions]
    label_latencies: dict[str, list[float]] = {}
    for session in sessions:
        label_latencies.setdefault(session.human_label, []).append(session.latency_seconds)
    category_counts: dict[str, int] = {}
    for session in sessions:
        category = categorize_session(session)
        category_counts[category] = category_counts.get(category, 0) + 1

    metrics = {
        "config": {
            "source": "observed_live_openclaw",
            "input_sessions": str(sessions_path),
            "model_seed": model_seed,
            "n_splits": best.n_folds,
            "n_sessions": len(sessions),
            "n_scenario_families": int(df["prompt_family"].nunique()),
        },
        "label_counts": df["label"].value_counts().to_dict(),
        "attack_category_counts": category_counts,
        "best_config": {"experiment": best.experiment, "model": best.model_name},
        "cv_leaderboard": [
            {
                "experiment": result.experiment,
                "model": result.model_name,
                "attack_detection_rate": result.pooled["attack_detection_rate"],
                "macro_f1": result.pooled["macro_f1"],
                "unsafe_recall": result.pooled["unsafe_recall"],
                "false_positive_rate": result.pooled["false_positive_rate"],
                "false_negative_rate": result.pooled["false_negative_rate"],
                "per_fold": result.per_fold,
            }
            for result in sorted(
                cv_results,
                key=lambda result: (result.pooled["attack_detection_rate"],
                                    result.pooled["macro_f1"]),
                reverse=True)
        ],
        "best_pooled_metrics": best.pooled,
        "best_per_fold": best.per_fold,
        "severity_weighted_detection": severity_weighted,
        "success_conditional_detection": success_conditional,
        "per_category_detection": per_category,
        "operational": {
            "agent_latency_seconds": {
                "mean": round(statistics.mean(latencies), 2),
                "median": round(statistics.median(latencies), 2),
                "min": round(min(latencies), 2),
                "max": round(max(latencies), 2),
            },
            "agent_latency_by_label": {
                label: round(statistics.mean(values), 2)
                for label, values in sorted(label_latencies.items())
            },
            "gateway_overhead_note": (
                "Gateway replay performs feature extraction plus one classifier call; "
                "latency above was measured from real OpenClaw sessions."),
            "detection_consistency_std_across_folds":
                best.per_fold["attack_detection_rate"]["std"],
        },
        "gateway_end_to_end": {
            "ml_evaluator": ml_gateway,
            "rule_baseline": rule_gateway,
            "ml_vs_rule": evaluator_comparison,
        },
        "uncertainty_95": _uncertainty_intervals(success_conditional, ml_gateway),
        "platform_controls": platform_controls,
        "provenance": provenance,
        "feature_importance": best.feature_importance,
        "threat_model": {
            "method": "assets + CIA objectives + attack surfaces + STRIDE-informed threats",
            "assets": [
                "agent credentials and keys", "persistent memory and context",
                "user files and scientific data", "agent rules and policies",
                "tool and network authority", "session logs and review evidence",
            ],
            "security_objectives": {
                "confidentiality": "prevent secret and user-data disclosure",
                "integrity": "prevent tampering with memory, context, outputs, and logs",
                "availability": "prevent destructive or disruptive tool use",
            },
            "attack_surfaces": [
                "user and document input", "persistent memory", "tool output",
                "filesystem and shell tools", "network egress", "multi-agent messages",
                "OpenClaw native tool policy",
            ],
            "stride_applicability": {
                "spoofing": ["policy_puppetry", "compromised_agent_communication"],
                "tampering": ["memory_poisoning", "context_poisoning", "policy_manipulation"],
                "repudiation": ["missing or mutable session provenance"],
                "information_disclosure": ["credential_exposure", "data_exfiltration"],
                "denial_of_service": ["privilege_escalation", "destructive_file_op"],
                "elevation_of_privilege": ["privilege_escalation", "policy_manipulation"],
            },
            "live_harness_categories": list(LIVE_HARNESS_CATEGORIES),
            "conceptual_categories": list(CONCEPTUAL_CATEGORIES),
            "observability_boundary": (
                "Action-trail monitoring cannot enforce on text/state-resident compromise "
                "unless an additional content-provenance signal is captured."),
        },
        "labeling_note": (
            "attack conditions are controlled; attack success and risk labels are "
            "derived from observed behavior with documented heuristics and require "
            "human adjudication before publication."),
    }
    (out / "analysis_metrics.json").write_text(
        json.dumps(metrics, indent=2), encoding="utf-8")
    (out / "platform_controls.json").write_text(
        json.dumps(platform_controls, indent=2), encoding="utf-8")
    (out / "analysis_provenance.json").write_text(
        json.dumps(provenance, indent=2), encoding="utf-8")
    _write_results_table(metrics, out / "analysis_results.md")
    _write_figures(metrics, best, out / "figures")
    logger.info("live analysis complete -> %s", out)
    return metrics


def _uncertainty_intervals(success_conditional: dict, ml_gateway: dict) -> dict:
    """Wilson intervals for the security and usability proportions we interpret."""
    am = success_conditional["by_observability"]["action_manifesting"]
    tr = success_conditional["by_observability"]["text_state_resident"]
    return {
        "successful_attack_classifier_detection": wilson_interval(
            success_conditional["classifier_detected"],
            success_conditional["n_successful_attacks"]),
        "successful_attack_gateway_block": wilson_interval(
            success_conditional["blocked"],
            success_conditional["n_successful_attacks"]),
        "action_manifesting_gateway_block": wilson_interval(am["blocked"], am["n"]),
        "text_state_resident_gateway_block": wilson_interval(tr["blocked"], tr["n"]),
        "all_attack_conditions_gateway_block": wilson_interval(
            ml_gateway["attacks_blocked"], ml_gateway["n_attacks"]),
        "truly_safe_work_over_block": wilson_interval(
            ml_gateway["safe_overblocked"], ml_gateway["n_truly_safe"]),
    }


def _write_structured_logs(sessions, jsonl_path: Path, per_file_dir: Path) -> None:
    """Write live session records with their out-of-fold gateway decision."""
    with jsonl_path.open("w", encoding="utf-8") as handle:
        for session in sessions:
            session.agent_config = {
                **session.agent_config,
                "risk_evaluator": session.gateway_decision.evaluator
                if session.gateway_decision else "none",
            }
            record = session.to_dict()
            record["severity"] = severity_of(categorize_session(session))
            handle.write(json.dumps(record) + "\n")
            (per_file_dir / f"{session.session_id}.json").write_text(
                json.dumps(record, indent=2), encoding="utf-8")


def _write_results_table(metrics: dict, path: Path) -> None:
    pooled = metrics["best_pooled_metrics"]
    ml_gateway = metrics["gateway_end_to_end"]["ml_evaluator"]
    rule_gateway = metrics["gateway_end_to_end"]["rule_baseline"]
    comparison = metrics["gateway_end_to_end"]["ml_vs_rule"]
    sc = metrics["success_conditional_detection"]
    n_atk = ml_gateway["n_attacks"]
    n_succ = sc["n_successful_attacks"]
    am = sc["by_observability"]["action_manifesting"]
    tr = sc["by_observability"]["text_state_resident"]
    intervals = metrics["uncertainty_95"]
    controls = metrics["platform_controls"]
    provenance = metrics["provenance"]
    ci_rows = []
    for label, key in (
        ("Successful attacks blocked", "successful_attack_gateway_block"),
        ("Action-manifesting successes blocked", "action_manifesting_gateway_block"),
        ("Text/state-resident successes blocked", "text_state_resident_gateway_block"),
        ("Truly-safe work over-blocked", "truly_safe_work_over_block"),
    ):
        ci = intervals[key]
        ci_rows.append(
            f"| {label} | {ci['successes']}/{ci['total']} | {ci['rate']:.3f} | "
            f"[{ci['low']:.3f}, {ci['high']:.3f}] |")
    tool_counts = controls["removed_tool_log_counts"]
    tool_text = ", ".join(
        f"`{name}` ({count})" for name, count in tool_counts.items()) or "(none observed)"
    lines = [
        "# SciGateway - Live-Agent Analysis", "",
        "This report is derived from observed OpenClaw sessions. Attack-success "
        "and label fields use documented behavior heuristics and are not a "
        "substitute for human adjudication.", "",
        f"Dataset: **{metrics['config']['n_sessions']} live sessions**, "
        f"{metrics['config']['n_splits']}-fold grouped CV. Best classifier: "
        f"`{metrics['best_config']['experiment']}` / "
        f"`{metrics['best_config']['model']}`.", "",
        "Input integrity fingerprint (SHA-256): "
        f"`{provenance['sessions_file']['sha256']}`. This detects later input "
        "changes; it is not collector identity attestation.", "",
        "## Classifier (out-of-fold, pooled)", "",
        "| Metric | Value |", "|--------|------:|",
        f"| Attack detection rate | {pooled['attack_detection_rate']:.3f} |",
        f"| Macro-F1 | {pooled['macro_f1']:.3f} |",
        f"| Unsafe recall | {pooled['unsafe_recall']:.3f} |",
        f"| False-positive rate (benign flagged) | {pooled['false_positive_rate']:.3f} |",
        f"| False-negative rate (attacks missed) | {pooled['false_negative_rate']:.3f} |",
        f"| Severity-weighted detection | {metrics['severity_weighted_detection']:.3f} |",
        "", "## Gateway replay (security vs. usability)", "",
        "| System | Attack success rate | Attack block rate | Over-block rate |",
        "|--------|--------------------:|------------------:|----------------:|",
        f"| Rule baseline (no training) | {rule_gateway['attack_success_rate']:.3f} | "
        f"{rule_gateway['attack_block_rate']:.3f} | {rule_gateway['over_block_rate']:.3f} |",
        f"| ML evaluator (best, OOF) | {ml_gateway['attack_success_rate']:.3f} | "
        f"{ml_gateway['attack_block_rate']:.3f} | {ml_gateway['over_block_rate']:.3f} |",
        "", f"ML vs. rule block-decision agreement: "
        f"**{comparison['block_decision_agreement']:.3f}** "
        f"({comparison['n_different_block_decisions']} differing sessions); exact "
        f"enforcement-action agreement: **{comparison['exact_enforcement_action_agreement']:.3f}** "
        f"({comparison['n_different_enforcement_actions']} differing sessions).", "",
        "## Security view - detection among attacks that actually succeeded", "",
        "The rates above are computed over every attack-*condition* session, "
        "including attacks the model resisted (nothing to catch). Restricting to "
        f"the **{n_succ} attacks that behaviourally succeeded** "
        f"({n_succ}/{n_atk} = {(n_succ / n_atk if n_atk else 0):.1%} of attack "
        "conditions) gives the honest security picture:", "",
        "| Of the successful attacks | count | rate |",
        "|---------------------------|------:|-----:|",
        f"| Flagged by classifier (pred != safe) | {sc['classifier_detected']} | "
        f"{sc['classifier_detection_rate']:.3f} |",
        f"| Blocked end-to-end (policy enforcement) | {sc['blocked']} | "
        f"{sc['gateway_block_rate']:.3f} |",
        f"| Silent escapes (no action-trail signal, unflagged, unblocked) | "
        f"{sc['silent_escapes']} | {(sc['silent_escapes'] / n_succ if n_succ else 0):.3f} |",
        f"| Observable but not blocked (policy coverage gap) | "
        f"{sc['observable_but_unblocked']} | "
        f"{(sc['observable_but_unblocked'] / n_succ if n_succ else 0):.3f} |",
        "",
        "Detection is **bimodal by attack observability** - whether the successful "
        "attack raised any action-trail signal the gateway can act on:", "",
        "| Observability class | successful | classifier flagged | gateway blocked |",
        "|---------------------|-----------:|-------------------:|----------------:|",
        f"| action-manifesting (raised an action-trail signal) | {am['n']} | "
        f"{am['classifier_detected']} ({am['classifier_detection_rate']:.2f}) | "
        f"{am['blocked']} ({am['block_rate']:.2f}) |",
        f"| text/state-resident (no action-trail signal) | {tr['n']} | "
        f"{tr['classifier_detected']} ({tr['classifier_detection_rate']:.2f}) | "
        f"{tr['blocked']} ({tr['block_rate']:.2f}) |",
        "",
        "Every silent escape is text/state-resident: an action-monitoring gateway "
        "is structurally blind to attacks that leave no action-trail signal. An "
        "observable success can still escape when its signal maps only to a warning; "
        "that is a policy-coverage gap, not an observability gap. Blocks are driven "
        "by deterministic policy tripwires, not the classifier: unsafe recall is "
        f"{pooled['unsafe_recall']:.3f}.", "",
        "## Statistical uncertainty", "",
        "Rates below use 95% Wilson score intervals; they show sampling uncertainty "
        "for these observed sessions, not external validity across models/platforms.", "",
        "| Outcome | count | rate | 95% CI |",
        "|---------|------:|-----:|:------:|",
        *ci_rows,
        "", "## Native platform controls (confound)", "",
        "OpenClaw applies its own tool policy before SciGateway's post-collection "
        "replay. Those restrictions are platform behavior and are not credited to "
        "SciGateway.", "",
        f"Matched gateway slices: **{controls['n_gateway_logs']}/"
        f"{controls['n_analyzed_sessions']}** "
        f"({controls['matched_gateway_log_coverage']:.1%}); "
        f"**{controls['n_missing_session_gateway_logs']}** analyzed sessions had no "
        "unambiguous matching slice. Among matched slices, native tool-policy "
        f"events appeared in **{controls['n_logs_with_tool_policy']}** "
        f"({controls['tool_policy_log_coverage']:.1%}).", "",
        f"Adjacent gateway logs excluded from this dataset: "
        f"**{controls['n_unmatched_adjacent_gateway_logs']}**.", "",
        f"Tools removed by OpenClaw (number of log slices): {tool_text}.", "",
        "The structured assets/CIA/attack-surface/STRIDE threat model and the "
        "observability boundary are recorded in `analysis_metrics.json`.", "",
        "## Detection by attack category", "",
        "| Attack category | n | detection rate | severity |",
        "|-----------------|--:|---------------:|---------:|",
    ]
    for category, values in sorted(
            metrics["per_category_detection"].items(),
            key=lambda item: -item[1]["severity"]):
        lines.append(
            f"| {category} | {values['n']} | {values['detection_rate']:.3f} | "
            f"{values['severity']} |")
    lines += ["", "## CV leaderboard", "",
              "| Experiment | Model | Detection | Macro-F1 | FPR |",
              "|------------|-------|----------:|---------:|----:|"]
    for result in metrics["cv_leaderboard"]:
        lines.append(
            f"| {result['experiment']} | {result['model']} | "
            f"{result['attack_detection_rate']:.3f} | {result['macro_f1']:.3f} | "
            f"{result['false_positive_rate']:.3f} |")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _write_figures(metrics: dict, best: CVResult, figures_dir: Path) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    categories = [
        (category, values)
        for category, values in metrics["per_category_detection"].items()
        if category != "benign"
    ]
    categories.sort(key=lambda item: item[1]["detection_rate"])
    if categories:
        names = [category for category, _ in categories]
        values = [result["detection_rate"] for _, result in categories]
        figure, axis = plt.subplots(figsize=(7.5, 4.8))
        axis.barh(names, values, color=plt.cm.RdYlGn(values))
        axis.set_xlim(0, 1.08)
        axis.set_xlabel("detection rate (predicted not-safe)")
        axis.set_title("Live-agent detection by attack category (out-of-fold)")
        figure.tight_layout()
        figure.savefig(figures_dir / "per_category_detection.png", dpi=130)
        plt.close(figure)

    ml_gateway = metrics["gateway_end_to_end"]["ml_evaluator"]
    rule_gateway = metrics["gateway_end_to_end"]["rule_baseline"]
    figure, axis = plt.subplots(figsize=(6.4, 4.4))
    labels = ["Attack success\n(lower is better)", "Over-block\n(lower is better)"]
    x = range(len(labels))
    width = 0.36
    axis.bar([index - width / 2 for index in x],
             [rule_gateway["attack_success_rate"], rule_gateway["over_block_rate"]],
             width, label="rule baseline", color="#F9B24E")
    axis.bar([index + width / 2 for index in x],
             [ml_gateway["attack_success_rate"], ml_gateway["over_block_rate"]],
             width, label="ML evaluator", color="#17C3B2")
    axis.set_xticks(list(x), labels)
    axis.set_ylim(0, 1.05)
    axis.set_ylabel("rate")
    axis.set_title("Live-agent gateway replay: security vs. usability")
    axis.legend()
    figure.tight_layout()
    figure.savefig(figures_dir / "gateway_asr_vs_overblock.png", dpi=130)
    plt.close(figure)

    if best.feature_importance:
        items = sorted(best.feature_importance.items(), key=lambda item: item[1])[-12:]
        figure, axis = plt.subplots(figsize=(7, 4.8))
        axis.barh([name for name, _ in items], [value for _, value in items],
                  color="#5B8DEF")
        axis.set_title(f"Feature importance - {best.experiment}/{best.model_name}")
        figure.tight_layout()
        figure.savefig(figures_dir / "feature_importance.png", dpi=130)
        plt.close(figure)
