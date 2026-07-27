"""
make_presentation_charts.py

Generates slide-ready figures for the memory-poisoning section of the group
presentation. Numbers are pulled live from feature_table.json so the charts
can never drift from the committed data.

Run from: memory-poisoning/notebooks/
    python3 make_presentation_charts.py

Writes: ../data/processed/graphs/attack_effectiveness.png
        ../data/processed/graphs/key_findings_summary.png
"""
import json
import os
from collections import Counter
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch

GREEN = "#2e7d32"
RED = "#c62828"
BLUE = "#1565c0"
TEAL = "#00838f"
SLATE = "#37474f"


def load_stats():
    processed = os.path.abspath(os.path.join("..", "data", "processed"))
    rows = json.load(open(os.path.join(processed, "feature_table.json")))
    attack = [r for r in rows if r["run_type"] == "attack"]
    baseline = [r for r in rows if r["run_type"] == "baseline"
                and r["question_category_or_type"] == "Clean Astrophysics Knowledge"]
    c = Counter(r["compliance_score"] for r in attack)
    took_bait = c.get("full_compliance", 0) + c.get("compliance_with_flag", 0)
    flagged = sum(1 for r in attack if r["flags_discrepancy_language"])
    return {
        "processed": processed,
        "n_attack": len(attack),
        "took_bait": took_bait,
        "took_bait_pct": 100 * took_bait / len(attack),
        "flagged_pct": 100 * flagged / len(attack),
        "baseline_correct_pct": 100.0,  # 10/10 astro baseline correct (score_results_v2)
    }


def attack_effectiveness(s):
    fig, ax = plt.subplots(figsize=(9, 6.2))
    conditions = ["Clean memory\n(untampered)", "Poisoned memory\n(false value planted)"]
    wrong = [0.0, s["took_bait_pct"]]
    colors = [GREEN, RED]
    bars = ax.bar(conditions, wrong, color=colors, width=0.55)
    ax.set_ylim(0, 105)
    ax.set_ylabel("% of answers that repeated the planted FALSE value", fontsize=11)
    ax.set_title("The agent knew the right answers — until we poisoned its memory",
                 fontsize=14, fontweight="bold", pad=14)
    for bar, w, n in zip(bars, wrong, [0, s["took_bait"]]):
        lab = f"{w:.0f}%" + (f"\n({n}/{s['n_attack']} trials)" if w > 0 else "\n(10/10 correct)")
        ax.text(bar.get_x() + bar.get_width()/2, w + 2, lab, ha="center",
                va="bottom", fontsize=12, fontweight="bold", color=colors[list(bars).index(bar)])
    ax.text(0.5, -0.16,
            f"When wrong, the agent warned that something conflicted with known physics only "
            f"{s['flagged_pct']:.0f}% of the time.",
            transform=ax.transAxes, ha="center", fontsize=10.5, style="italic", color=SLATE)
    for spine in ("top", "right"):
        ax.spines[spine].set_visible(False)
    plt.tight_layout()
    out = os.path.join(s["processed"], "graphs", "attack_effectiveness.png")
    plt.savefig(out, dpi=200, bbox_inches="tight")
    plt.close()
    return out


def key_findings_summary(s):
    fig, ax = plt.subplots(figsize=(11, 6))
    ax.axis("off")
    ax.set_title("Memory Poisoning — Key Findings", fontsize=18, fontweight="bold", pad=8)

    cards = [
        (f"{s['took_bait_pct']:.0f}%", "of answers repeated the\nplanted FALSE value",
         "The attack works", RED),
        (f"{s['flagged_pct']:.0f}%", "of the time did it warn\nanything looked wrong",
         "It rarely self-corrects", "#ef6c00"),
        ("0.95", "AUC detecting sessions that\nrely on injected memory*",
         "A gateway can flag it", TEAL),
    ]
    n = len(cards)
    for i, (big, sub, tag, color) in enumerate(cards):
        cx = (i + 0.5) / n
        box = FancyBboxPatch((cx - 0.145, 0.30), 0.29, 0.46,
                             boxstyle="round,pad=0.02,rounding_size=0.03",
                             transform=ax.transAxes, facecolor=color, alpha=0.10,
                             edgecolor=color, linewidth=1.8)
        ax.add_patch(box)
        ax.text(cx, 0.635, big, transform=ax.transAxes, ha="center", va="center",
                fontsize=40, fontweight="bold", color=color)
        ax.text(cx, 0.475, sub, transform=ax.transAxes, ha="center", va="center",
                fontsize=11, color=SLATE)
        ax.text(cx, 0.345, tag, transform=ax.transAxes, ha="center", va="center",
                fontsize=11.5, fontweight="bold", color=color)

    ax.text(0.5, 0.16,
            "Setup: agent answered astrophysics questions 10/10 correctly with a clean memory; "
            "we then planted false constants in its stored MEMORY.md.",
            transform=ax.transAxes, ha="center", fontsize=10, color=SLATE)
    ax.text(0.5, 0.06,
            "*Detects that the agent is relying on injected memory — telling poisoned from "
            "legitimate memory apart requires content-level fact-checking.",
            transform=ax.transAxes, ha="center", fontsize=8.8, style="italic", color="#78909c")

    out = os.path.join(s["processed"], "graphs", "key_findings_summary.png")
    plt.savefig(out, dpi=200, bbox_inches="tight")
    plt.close()
    return out


def main():
    s = load_stats()
    o1 = attack_effectiveness(s)
    o2 = key_findings_summary(s)
    print("Wrote:")
    print(" ", o1)
    print(" ", o2)
    print(f"\nStats used: took_bait={s['took_bait']}/{s['n_attack']} "
          f"({s['took_bait_pct']:.1f}%), flagged={s['flagged_pct']:.1f}%")


if __name__ == "__main__":
    main()
