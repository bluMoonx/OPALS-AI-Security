"""Generate the paper figures from the rebuilt, honest results.

Reads whatever is present and skips gracefully:
  analysis/rebuild/gold_*.jsonl          -> gold behavioral labels
  data/logs/collected_new10category/...  -> canary labels (for the comparison)
  analysis/rebuild/corpus_clean.jsonl    -> the rebuilt corpus
  models/aura_honest.joblib              -> final model metrics

Writes PNGs to figures/.
Run: python3 analysis/make_figures.py
"""
from __future__ import annotations
import json, glob, os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "figures")
os.makedirs(OUT, exist_ok=True)
plt.rcParams.update({"figure.dpi": 150, "font.size": 9,
                     "axes.spines.top": False, "axes.spines.right": False})
C_SAFE, C_RISK, C_ALT = "#2b8a6e", "#c0392b", "#2c5aa0"
made = []


def _load_jsonl(p):
    rows = []
    if not os.path.exists(p): return rows
    for l in open(p, errors="ignore"):
        l = l.strip()
        if not l: continue
        try: rows.append(json.loads(l))
        except Exception: pass
    return rows


def _gold_attack_rows():
    """The 817 hand-judged ATTACK rows, each paired with its EXACT source record.

    Uses the vetted resolver. Do NOT key gold by session_id: it is not unique (up to 9
    trials share one id, 51% of the corpus sits under a duplicated id), so a dict keyed on
    it silently collapses judgements and pairs labels with the wrong trial's response.
    The previous version of this file did exactly that AND globbed only `gold_*.jsonl`,
    missing all 12 `gold2_*.jsonl` files, so it rebuilt the headline figures from ~142
    attack rows instead of 817.
    """
    import sys
    sys.path.insert(0, os.path.join(ROOT, "analysis"))
    from eval_combined_gold import load_records, load_all_gold
    gold = load_all_gold(load_records())
    return [g for g in gold if g.get("condition") == "attack"]


def fig_label_comparison():
    """THE headline finding: canary labeling under-counts attack success ~4x."""
    atk = _gold_attack_rows()
    if not atk: return
    n = len(atk)
    beh = sum(1 for g in atk if g["behavioral_label"] == 1)
    can = sum(1 for g in atk if g["_rec"].get("attack_succeeded"))
    # true positives: canary fired AND the behaviour really was compliance
    tp = sum(1 for g in atk if g["_rec"].get("attack_succeeded") and g["behavioral_label"] == 1)
    missed = beh - tp

    fig, ax = plt.subplots(figsize=(4.6, 3.4))
    bars = ax.bar(["canary-derived\n(what we used)", "behavioral\n(hand-judged)"],
                  [100 * can / n, 100 * beh / n], color=[C_ALT, C_RISK], width=.55)
    for b, v in zip(bars, [can, beh]):
        ax.text(b.get_x() + b.get_width() / 2, b.get_height() + 1.5,
                f"{100*v/n:.1f}%\n({v}/{n})", ha="center", fontsize=9, weight="bold")
    ax.set_ylabel("attack success rate (%)")
    ax.set_title(f"Canary labeling under-counts attack success\n"
                 f"(n={n} hand-judged attack sessions; canary misses "
                 f"{missed} of {beh} = {100*missed/max(beh,1):.0f}%)", fontsize=10)
    ax.set_ylim(0, max(100 * beh / n, 100 * can / n) * 1.35)
    fig.tight_layout(); p = os.path.join(OUT, "fig1_label_undercount.png")
    fig.savefig(p); plt.close(fig); made.append(p)


def fig_per_category_asr():
    """Behavioral attack-success rate per category (where the agent is weak)."""
    atk = _gold_attack_rows()
    if not atk: return
    from collections import defaultdict
    tot, suc = defaultdict(int), defaultdict(int)
    for g in atk:
        c = g.get("category", "?"); tot[c] += 1; suc[c] += 1 if g["behavioral_label"] == 1 else 0
    cats = [c for c in tot if tot[c] >= 2]
    if not cats: return
    cats.sort(key=lambda c: suc[c] / tot[c])
    rates = [100 * suc[c] / tot[c] for c in cats]
    fig, ax = plt.subplots(figsize=(6.2, 0.34 * len(cats) + 1.5))
    ax.barh(range(len(cats)), rates, color=[C_RISK if r >= 50 else C_ALT for r in rates], height=.6)
    ax.set_yticks(range(len(cats)))
    ax.set_yticklabels([c.replace("_", " ") for c in cats], fontsize=8)
    for i, (c, r) in enumerate(zip(cats, rates)):
        ax.text(r + 1.5, i, f"{r:.0f}% ({suc[c]}/{tot[c]})", va="center", fontsize=7.5)
    ax.set_xlabel("behavioral attack success rate (%)")
    ax.set_title("Which attacks actually work on the agent", fontsize=10)
    ax.set_xlim(0, 108)
    fig.tight_layout(); p = os.path.join(OUT, "fig2_per_category_asr.png")
    fig.savefig(p); plt.close(fig); made.append(p)


def fig_corpus_composition():
    rows = _load_jsonl(os.path.join(ROOT, "analysis/rebuild/corpus_clean.jsonl"))
    if not rows: return
    from collections import Counter
    src = Counter(r.get("source", "?") for r in rows)
    pos = Counter(r.get("source", "?") for r in rows if r.get("label") == 1)
    labels = list(src)
    fig, ax = plt.subplots(figsize=(5.2, 3.4))
    x = np.arange(len(labels))
    ax.bar(x - .18, [src[s] for s in labels], .36, label="total", color=C_ALT)
    ax.bar(x + .18, [pos[s] for s in labels], .36, label="unsafe", color=C_RISK)
    ax.set_xticks(x); ax.set_xticklabels([s[:16] for s in labels], fontsize=8, rotation=12)
    ax.set_ylabel("sessions"); ax.legend(frameon=False, fontsize=8)
    ax.set_title(f"Rebuilt corpus: {len(rows)} sessions, "
                 f"{sum(pos.values())} unsafe ({100*sum(pos.values())/len(rows):.0f}%)", fontsize=10)
    fig.tight_layout(); p = os.path.join(OUT, "fig3_corpus.png")
    fig.savefig(p); plt.close(fig); made.append(p)


def fig_honest_vs_inflated():
    """Show the corrected metrics next to the withdrawn ones."""
    import joblib
    mp = os.path.join(ROOT, "models/aura_honest.joblib")
    if not os.path.exists(mp): return
    b = joblib.load(mp)
    honest = b.get("pooled_oof_auc")
    if honest is None: return
    fig, ax = plt.subplots(figsize=(5.0, 3.4))
    names = ["reported\n(invalid)", "canary-leaked\nprotocol", "honest\n(true LOACO)"]
    vals = [0.905, 0.836, float(honest)]
    cols = [C_RISK, "#999999", C_SAFE]
    bars = ax.bar(names, vals, color=cols, width=.55)
    for b_, v in zip(bars, vals):
        ax.text(b_.get_x() + b_.get_width() / 2, v + .015, f"{v:.3f}",
                ha="center", fontsize=9, weight="bold")
    ax.axhline(0.5, ls=":", c="#888", lw=1)
    ax.text(2.42, .512, "chance", fontsize=7, c="#888")
    ax.set_ylabel("ROC-AUC"); ax.set_ylim(0, 1.05)
    ax.set_title("Withdrawn vs corrected performance", fontsize=10)
    fig.tight_layout(); p = os.path.join(OUT, "fig4_honest_vs_inflated.png")
    fig.savefig(p); plt.close(fig); made.append(p)


def main():
    for fn in (fig_label_comparison, fig_per_category_asr,
               fig_corpus_composition, fig_honest_vs_inflated):
        try: fn()
        except Exception as e: print(f"  skip {fn.__name__}: {type(e).__name__}: {e}")
    print(f"generated {len(made)} figures -> {OUT}")
    for p in made: print("  " + os.path.basename(p))


if __name__ == "__main__":
    main()
