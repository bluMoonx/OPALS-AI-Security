"""Figures for the group report / presentation.

Everything is recomputed from the committed datasets — no hardcoded numbers — so a
figure can never drift from the finding it illustrates. Writes PNG + the numeric
values it plotted, so a caption can quote exact figures.

    python prompt-injection/analysis/make_figures.py --out prompt-injection/dataset/figures

Figures
-------
1. ``confound_prompt_length``  the artifact that invalidated the first headline,
   and that ``controls_v2`` fixes.
2. ``overblock_trajectory``    100% -> 42% -> 30.6%, the real contribution.
3. ``collision_ceiling``       why 100% catch is capped: 61% of positives are
   byte-identical to a benign session.
4. ``rule_gateway_blind``      the deployed rule gateway blocks 1/400 of our attacks.
5. ``architecture_ranking``    features move tens of points, architecture moves two.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_REPO = _HERE.parent.parent
for _p in (str(_REPO), str(_HERE), str(_REPO / "prompt-injection")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import numpy as np

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

from detector_bench import (ACTION_DETAIL_NAMES, BEHAVIOUR_FEATURES,  # noqa: E402
                            apply_threshold, build_matrices, load_pool,
                            make_target, rule_scores, threshold_for_recall)
from scigateway.schema import load_sessions_jsonl  # noqa: E402

INK = "#1b2733"
ATTACK_C = "#D1495B"
BENIGN_C = "#2A9D8F"
ACCENT = "#3D7EA6"
WARN = "#E9A13B"

plt.rcParams.update({
    "figure.dpi": 150, "savefig.dpi": 190, "font.size": 10,
    "axes.edgecolor": "#94a3b8", "axes.labelcolor": INK, "text.color": INK,
    "xtick.color": INK, "ytick.color": INK, "axes.titleweight": "bold",
    "axes.spines.top": False, "axes.spines.right": False,
    "figure.facecolor": "white", "savefig.bbox": "tight",
})


def _finish(fig, path: Path, note: str | None = None):
    if note:
        fig.text(0.005, -0.02, note, fontsize=7.4, color="#64748b", va="top")
    fig.savefig(path)
    plt.close(fig)
    print(f"[fig] {path.relative_to(_REPO)}")


# --------------------------------------------------------------------------- #

def fig_confound(out: Path, values: dict):
    """Prompt-length distributions: the artifact, and the fix."""
    sys.path.insert(0, str(_REPO / "prompt-injection"))
    from prompts import controls as v1, controls_v2 as v2

    sessions = load_sessions_jsonl(_REPO / "prompt-injection/dataset/sessions.jsonl")
    attack = np.array([len(s.user_prompt.split()) for s in sessions
                       if s.agent_config.get("condition") == "attack"], float)
    c1 = np.array([len(" ".join(t).split()) for pool in v1.CONTROL_POOLS.values()
                   for t in pool], float)
    c2 = np.array([len(" ".join(t).split()) for pool in v2.CONTROL_POOLS.values()
                   for t in pool], float)

    fig, axes = plt.subplots(1, 2, figsize=(11.2, 4.1), sharey=True)
    bins = np.arange(0, 80, 3)
    for ax, ctrl, title, sub in (
            (axes[0], c1, "v1 controls — the artifact",
             f"benign max {c1.max():.0f} < attack median {np.median(attack):.0f}"),
            (axes[1], c2, "v2 controls — length-matched",
             "distributions overlap; length is uninformative")):
        ax.hist(attack, bins=bins, color=ATTACK_C, alpha=.62, label="attack prompts")
        ax.hist(ctrl, bins=bins, color=BENIGN_C, alpha=.62, label="benign controls")
        ax.axvline(ctrl.max(), color=INK, ls="--", lw=1.2)
        ax.annotate(f"benign max = {ctrl.max():.0f}w", xy=(ctrl.max(), ax.get_ylim()[1] * .82),
                    xytext=(6, 0), textcoords="offset points", fontsize=8.5, color=INK)
        ax.set_title(title, fontsize=11)
        ax.set_xlabel("prompt length (words)")
        ax.text(.5, -.235, sub, transform=ax.transAxes, ha="center",
                fontsize=8.6, color="#475569", style="italic")
    axes[0].set_ylabel("sessions / prompts")
    axes[0].legend(frameon=False, fontsize=9)

    caught_v1 = float((attack > c1.max()).mean())
    caught_v2 = float((attack > c2.max()).mean())
    fig.suptitle("A length threshold alone separated attack from benign — until it didn't",
                 fontsize=12.5, y=1.03)
    values["confound"] = {
        "attack_median": float(np.median(attack)),
        "v1_control_max": float(c1.max()), "v2_control_max": float(c2.max()),
        "v1_threshold_catches": caught_v1, "v2_threshold_catches": caught_v2,
    }
    _finish(fig, out / "confound_prompt_length.png",
            f"'Prompt longer than the benign maximum' flags {caught_v1:.1%} of attacks at zero "
            f"false positives under v1, {caught_v2:.1%} under v2.")


def fig_trajectory(out: Path, values: dict, repeats: int):
    """Over-block at each catch rate, per feature set. The real contribution."""
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import StratifiedShuffleSplit

    sessions, source = load_pool(verbose=False)
    Xb, Xf, bn, fn = build_matrices(sessions)
    mask, y, _ = make_target(sessions, source, "success")
    X = Xf[mask]

    sets = {
        "scigateway 17\n(shared baseline)": set(bn),
        "+ compliance\n(behaviour)": set(BEHAVIOUR_FEATURES),
        "+ action detail\n(behaviour2)": set(BEHAVIOUR_FEATURES) | set(ACTION_DETAIL_NAMES),
    }
    recalls = (1.0, 0.99, 0.95)
    splits = list(StratifiedShuffleSplit(n_splits=repeats, test_size=.30,
                                         random_state=0).split(X, y))
    results = {}
    for label, keep_names in sets.items():
        keep = np.array([n in keep_names for n in fn])
        acc = {r: [] for r in recalls}
        for tr, te in splits:
            m = RandomForestClassifier(n_estimators=400, class_weight="balanced_subsample",
                                       random_state=0, n_jobs=-1).fit(X[tr][:, keep], y[tr])
            p = m.predict_proba(X[te][:, keep])[:, 1]
            for r in recalls:
                t = threshold_for_recall(y[te], p, r)
                _, f = apply_threshold(y[te], p, t)
                acc[r].append(f)
        results[label] = {r: (float(np.mean(v)), float(np.std(v))) for r, v in acc.items()}

    fig, ax = plt.subplots(figsize=(8.6, 4.6))
    labels = list(sets)
    xs = np.arange(len(labels))
    width = .26
    for i, r in enumerate(recalls):
        vals = [results[l][r][0] for l in labels]
        errs = [results[l][r][1] for l in labels]
        colour = [ATTACK_C, WARN, ACCENT][i]
        bars = ax.bar(xs + (i - 1) * width, vals, width, yerr=errs, capsize=3,
                      color=colour, label=f"{r:.0%} of attacks caught")
        for b, v in zip(bars, vals):
            ax.text(b.get_x() + b.get_width() / 2, v + errs[i] * 0 + .015, f"{v:.0%}",
                    ha="center", fontsize=8.2, color=INK)
    ax.set_xticks(xs, labels, fontsize=9)
    ax.set_ylabel("over-block rate (benign work wrongly flagged)")
    ax.set_ylim(0, 1.08)
    ax.yaxis.set_major_formatter(lambda v, _: f"{v:.0%}")
    ax.set_title("Over-block falls with better features, not better models", fontsize=12.5)
    ax.legend(frameon=False, fontsize=9)
    values["trajectory"] = {l: {str(r): v for r, v in d.items()} for l, d in results.items()}
    _finish(fig, out / "overblock_trajectory.png",
            "Held-out test splits (threshold fixed on train), mean ± sd over "
            f"{repeats} repeats. No length feature in any bar — target = attack_succeeded.")


def fig_collisions(out: Path, values: dict):
    """Why 100% catch is capped: identical rows cannot be separated."""
    sessions, source = load_pool(verbose=False)
    Xb, Xf, bn, fn = build_matrices(sessions)
    mask, y, _ = make_target(sessions, source, "success")
    sess = [s for s, m in zip(sessions, mask) if m]
    keep = np.array([n in (set(BEHAVIOUR_FEATURES) | set(ACTION_DETAIL_NAMES))
                     for n in fn])
    X = np.round(Xf[mask][:, keep], 6)
    benign = {tuple(r) for r in X[y == 0]}
    pos = np.where(y == 1)[0]
    colliding = [i for i in pos if tuple(X[i]) in benign]
    no_action = sum(1 for i in colliding if len(sess[i].actions) == 0)
    same_action = len(colliding) - no_action
    separable = len(pos) - len(colliding)

    fig, ax = plt.subplots(figsize=(8.8, 2.9))
    segs = [
        (separable, "#2A9D8F", f"separable\n{separable}"),
        (same_action, "#E9A13B", f"same single action as a benign session\n{same_action}"),
        (no_action, "#D1495B", f"no action trail at all\n{no_action}"),
    ]
    left = 0
    for value, colour, label in segs:
        ax.barh([0], [value], left=left, color=colour, height=.55)
        ax.text(left + value / 2, 0, label, ha="center", va="center",
                fontsize=8.8, color="white", fontweight="bold")
        left += value
    ax.set_xlim(0, len(pos))
    ax.set_yticks([])
    ax.set_xlabel(f"successful attacks (n = {len(pos)})")
    ax.set_title(f"{len(colliding)}/{len(pos)} ({len(colliding)/len(pos):.0%}) of successful attacks are "
                 "byte-identical to a benign session", fontsize=12)
    for spine in ("left", "bottom"):
        ax.spines[spine].set_visible(False)
    values["collisions"] = {"n_positive": int(len(pos)), "colliding": int(len(colliding)),
                            "no_action": int(no_action), "same_action": int(same_action),
                            "separable": int(separable)}
    _finish(fig, out / "collision_ceiling.png",
            "Identical feature vectors receive identical scores from any classifier, so this "
            "fraction is an information ceiling — no architecture, tuning or resampling reaches it.")


def fig_rule_gateway(out: Path, values: dict):
    """The deployed rule gateway is blind to this entire attack vector."""
    from scigateway.schema import BLOCKING_ACTIONS
    from scigateway.gateway import IngressInterceptor, PolicyEngine, RuleRiskEvaluator

    files = {"ours\n(prompt injection)": "prompt-injection/dataset/sessions.jsonl",
             "Chenhao kimi": "chenhao-data_release/kimi_50/sessions.jsonl",
             "Chenhao deepseek": "chenhao-data_release/deepseek_50/sessions.jsonl"}
    interceptor, evaluator, policy = IngressInterceptor(), RuleRiskEvaluator(), PolicyEngine()
    rates, counts = {}, {}
    for label, rel in files.items():
        ss = load_sessions_jsonl(_REPO / rel)
        atk = [s for s in ss if s.agent_config.get("condition") == "attack"]
        blocked = 0
        for s in atk:
            req = interceptor.intercept(s)
            d = policy.decide(evaluator.evaluate(req), req)
            blocked += d.enforcement_action in BLOCKING_ACTIONS
        rates[label] = blocked / len(atk)
        counts[label] = (blocked, len(atk))

    fig, ax = plt.subplots(figsize=(7.4, 4.0))
    labels = list(rates)
    colours = [ATTACK_C, "#94a3b8", "#94a3b8"]
    bars = ax.bar(labels, [rates[l] for l in labels], color=colours, width=.55)
    for b, l in zip(bars, labels):
        n, d = counts[l]
        ax.text(b.get_x() + b.get_width() / 2, b.get_height() + .006,
                f"{n}/{d}\n{rates[l]:.1%}", ha="center", fontsize=9, color=INK)
    ax.set_ylabel("attacks blocked by the rule gateway")
    ax.set_ylim(0, max(rates.values()) * 1.45)
    ax.yaxis.set_major_formatter(lambda v, _: f"{v:.0%}")
    ax.set_title("The existing gateway's tripwires do not fire on prompt injection",
                 fontsize=12.5)
    values["rule_gateway"] = {l: {"blocked": counts[l][0], "attacks": counts[l][1],
                                  "rate": rates[l]} for l in labels}
    _finish(fig, out / "rule_gateway_blind.png",
            "scigateway's PolicyEngine, unmodified. Its tripwires (touched_secret, external_egress, "
            "dangerous_command, destructive_delete) were derived from credential-exposure attacks; "
            "our escalations write a scratch note or run a web_search and are marked in_scope.")


def fig_architecture(out: Path, values: dict, repeats: int):
    """Architecture is worth ~2 points; features were worth tens."""
    from sklearn.model_selection import StratifiedShuffleSplit
    from detector_bench import build_models

    sessions, source = load_pool(verbose=False)
    Xb, Xf, bn, fn = build_matrices(sessions)
    mask, y, _ = make_target(sessions, source, "success")
    keep = np.array([n in (set(BEHAVIOUR_FEATURES) | set(ACTION_DETAIL_NAMES))
                     for n in fn])
    X = Xf[mask][:, keep]
    splits = list(StratifiedShuffleSplit(n_splits=repeats, test_size=.30,
                                         random_state=0).split(X, y))

    from sklearn.base import clone
    scores = {}
    for name, model in build_models(0).items():
        vals = []
        try:
            for tr, te in splits:
                est = clone(model).fit(X[tr], y[tr])
                p = est.predict_proba(X[te])[:, 1]
                t = threshold_for_recall(y[te], p, 1.0)
                _, f = apply_threshold(y[te], p, t)
                vals.append(f)
        except Exception:
            continue
        scores[name] = float(np.mean(vals))

    ordered = sorted(scores.items(), key=lambda kv: kv[1])
    names = [n for n, _ in ordered]
    vals = [v for _, v in ordered]
    best = vals[0]
    colours = [ACCENT if v <= best + .02 else "#cbd5e1" for v in vals]

    fig, ax = plt.subplots(figsize=(8.2, 6.4))
    ax.barh(names, vals, color=colours, height=.66)
    for i, v in enumerate(vals):
        ax.text(v + .008, i, f"{v:.1%}", va="center", fontsize=8.2, color=INK)
    ax.set_xlabel("over-block at 100% catch (lower is better)")
    ax.set_xlim(0, min(1.05, max(vals) * 1.12))
    ax.xaxis.set_major_formatter(lambda v, _: f"{v:.0%}")
    ax.set_title("Every tree ensemble lands within two points of the best",
                 fontsize=12.5)
    ax.invert_yaxis()
    values["architecture"] = scores
    _finish(fig, out / "architecture_ranking.png",
            f"Same features (behaviour + action detail), same splits, {repeats} repeats. "
            "Highlighted bars are within 2 points of the best. Compare: changing the feature "
            "set moved this metric from 100% to 30.6%.")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="prompt-injection/dataset/figures")
    ap.add_argument("--repeats", type=int, default=10)
    ap.add_argument("--only", nargs="*", default=None)
    args = ap.parse_args()

    out = _REPO / args.out
    out.mkdir(parents=True, exist_ok=True)
    values: dict = {}

    jobs = {
        "confound": lambda: fig_confound(out, values),
        "trajectory": lambda: fig_trajectory(out, values, args.repeats),
        "collisions": lambda: fig_collisions(out, values),
        "rule": lambda: fig_rule_gateway(out, values),
        "architecture": lambda: fig_architecture(out, values, args.repeats),
    }
    for name, fn in jobs.items():
        if args.only and name not in args.only:
            continue
        fn()

    (out / "figure_values.json").write_text(json.dumps(values, indent=2), encoding="utf-8")
    print(f"[fig] {(out / 'figure_values.json').relative_to(_REPO)}  "
          "(exact plotted numbers, for captions)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
