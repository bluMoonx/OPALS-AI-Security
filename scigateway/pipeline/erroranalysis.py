"""Stage 4b — error analysis, not just aggregate scores.

Aggregate metrics hide *where* a monitor fails. The OPALS proposal asks for the
opposite: find the recurring false negatives, false positives, weak attack
categories, and the attacks that still slip through the end-to-end gateway, and
feed those back into the design. This module produces exactly that breakdown from
the out-of-fold predictions and the gateway outcomes.

Definitions (binary "flagged" view):
* **False negative** — a truly risky session the classifier predicted ``safe``.
  The costly error: an attack the monitor waved through.
* **False positive** — a benign session the classifier predicted not-``safe``.
  The usability cost: legitimate work needlessly flagged.
* **Gateway escape** — a truly-unsafe session the *end-to-end* gateway did not
  block (allowed or merely warned). The bottom line the whole system is judged on.
"""

from __future__ import annotations

from ..attacks import categorize_session, get_category
from ..gateway import IngressInterceptor


def _signals(session) -> list[str]:
    req = IngressInterceptor().intercept(session)
    return [k for k, v in req.signals.items() if v]


def analyze(sessions, pred_by_id, gateway_outcomes: dict | None = None) -> dict:
    """Return a structured error analysis over the out-of-fold predictions."""
    false_neg: list[dict] = []
    false_pos: list[dict] = []
    ambiguous: list[dict] = []
    over_blocked: list[dict] = []  # policy gated a genuinely-safe session

    for s in sessions:
        cat = categorize_session(s)
        is_attack = cat != "benign"
        pred = pred_by_id.get(s.session_id, "safe")
        flagged = pred != "safe"

        # Policy-driven over-block: a truly-safe session the end-to-end gateway
        # gated (via a hard tripwire, even when the classifier said safe). Only
        # available once decisions are attached to the sessions.
        gd = s.gateway_decision
        if (not is_attack) and s.human_label == "safe" and gd and gd.blocked:
            over_blocked.append({
                "session_id": s.session_id, "predicted_label": pred,
                "policy": gd.policy_name, "enforcement": gd.enforcement_action,
                "observable_signals": _signals(s)})

        # False negative: a ground-truth attack the classifier waved through.
        if is_attack and not flagged:
            false_neg.append({
                "session_id": s.session_id, "attack_category": cat,
                "true_label": s.human_label, "predicted_label": pred,
                "observable_signals": _signals(s),
                "num_actions": s.num_actions})
        # False positive: a *genuinely-safe* session (safe label, not an attack)
        # that the classifier flagged — the pure usability cost.
        elif (not is_attack) and s.human_label == "safe" and flagged:
            false_pos.append({
                "session_id": s.session_id, "attack_category": cat,
                "true_label": s.human_label, "predicted_label": pred,
                "observable_signals": _signals(s)})
        # A suspicious session predicted at either extreme is an "ambiguous" case.
        if s.human_label == "suspicious" and pred != "suspicious":
            ambiguous.append({
                "session_id": s.session_id, "true_label": "suspicious",
                "predicted_label": pred, "attack_category": cat})

    # Per-category miss rates (of attacks only), weakest first.
    cat_stats: dict[str, dict] = {}
    for s in sessions:
        cat = categorize_session(s)
        if cat == "benign":
            continue
        pred = pred_by_id.get(s.session_id, "safe")
        d = cat_stats.setdefault(cat, {"n": 0, "missed": 0})
        d["n"] += 1
        if pred == "safe":
            d["missed"] += 1
    for cat, d in cat_stats.items():
        d["miss_rate"] = d["missed"] / d["n"] if d["n"] else 0.0
        d["severity"] = get_category(cat).severity
    weakest = sorted(cat_stats.items(), key=lambda kv: (-kv[1]["miss_rate"], -kv[1]["severity"]))

    escapes: list[dict] = []
    if gateway_outcomes:
        # Re-derive which attacks escaped by replaying the block decision from the
        # per-category counts is lossy; instead flag attacks that were both a
        # classifier miss AND had no hard tripwire (why the gateway let them by).
        for fn in false_neg:
            if not fn["observable_signals"]:
                escapes.append(fn)

    return {
        "counts": {
            "false_negatives": len(false_neg),
            "false_positives": len(false_pos),
            "ambiguous_suspicious": len(ambiguous),
            "policy_over_blocks": len(over_blocked),
        },
        "false_negatives": false_neg,
        "false_positives": false_pos,
        "ambiguous_cases": ambiguous,
        "policy_over_blocks": over_blocked,
        "weakest_categories": [
            {"attack_category": c, **d} for c, d in weakest],
        "silent_escapes": escapes,
    }


def write_markdown(analysis: dict, path) -> None:
    """Write a human-readable error-analysis report."""
    from pathlib import Path
    c = analysis["counts"]
    lines = [
        "# SciGateway v2 - Error Analysis", "",
        f"- False negatives (attacks predicted safe): **{c['false_negatives']}**",
        f"- False positives (safe work predicted risky by the classifier): "
        f"**{c['false_positives']}**",
        f"- Policy over-blocks (safe work gated by a hard tripwire): "
        f"**{c.get('policy_over_blocks', 0)}**",
        f"- Ambiguous suspicious cases (not predicted suspicious): "
        f"**{c['ambiguous_suspicious']}**", "",
        "## Weakest attack categories (highest miss rate first)", "",
        "| Attack category | n | missed | miss rate | severity |",
        "|-----------------|--:|-------:|----------:|---------:|",
    ]
    for w in analysis["weakest_categories"]:
        lines.append(
            f"| {w['attack_category']} | {w['n']} | {w['missed']} | "
            f"{w['miss_rate']:.3f} | {w['severity']} |")
    if analysis["false_negatives"]:
        lines += ["", "## False negatives (attacks the classifier missed)", "",
                  "| session | category | true | predicted | observable signals |",
                  "|---------|----------|------|-----------|--------------------|"]
        for fn in analysis["false_negatives"][:40]:
            sig = ", ".join(fn["observable_signals"]) or "(none)"
            lines.append(
                f"| {fn['session_id']} | {fn['attack_category']} | {fn['true_label']} "
                f"| {fn['predicted_label']} | {sig} |")
    if analysis["silent_escapes"]:
        lines += ["", "## Silent escapes (missed AND no hard tripwire fired)", "",
                  "These are the sessions the *whole* gateway is most exposed on: the "
                  "classifier missed them and there was no deterministic signal to "
                  "catch them. Priority targets for the next feature/policy round.", ""]
        for e in analysis["silent_escapes"][:20]:
            lines.append(f"- `{e['session_id']}` — {e['attack_category']} "
                         f"(true={e['true_label']}, pred={e['predicted_label']})")
    if analysis["false_positives"]:
        lines += ["", "## False positives (safe work flagged by the classifier)", "",
                  "| session | true | predicted | observable signals |",
                  "|---------|------|-----------|--------------------|"]
        for fp in analysis["false_positives"][:40]:
            sig = ", ".join(fp["observable_signals"]) or "(none)"
            lines.append(
                f"| {fp['session_id']} | {fp['true_label']} | "
                f"{fp['predicted_label']} | {sig} |")
    over = analysis.get("policy_over_blocks", [])
    if over:
        by_policy: dict[str, int] = {}
        for o in over:
            by_policy[o["policy"]] = by_policy.get(o["policy"], 0) + 1
        lines += ["", "## Policy over-blocks (safe work gated by a hard tripwire)", "",
                  "These are the usability cost of the deterministic tripwires, NOT "
                  "classifier errors: the model scored them safe, but the policy gated "
                  "them because they touched a credential path or ran a flagged "
                  "command. Whether to gate these is a policy choice.", "",
                  "Breakdown by policy: " +
                  ", ".join(f"`{k}`={v}" for k, v in sorted(by_policy.items())), "",
                  "| session | policy | enforcement | observable signals |",
                  "|---------|--------|-------------|--------------------|"]
        for o in over[:40]:
            sig = ", ".join(o["observable_signals"]) or "(none)"
            lines.append(f"| {o['session_id']} | {o['policy']} | "
                         f"{o['enforcement']} | {sig} |")
    Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")
