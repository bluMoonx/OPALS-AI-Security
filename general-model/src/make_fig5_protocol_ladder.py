"""fig5: the evaluation-protocol ladder — how much of a reported score is real.

Replaces the previous fig5_transfer_and_safety.png, which was generated ad-hoc (no
generator existed in the repo), encoded a stale n=89 baseline / n=84 attack split (the
true split is 148 / 817) and a stale cross-source AUC of 0.602 measured on the old
283-row gold. That figure is withdrawn.

What this one shows, and why it is the more useful figure: the same model and the same
965 hand-judged rows, scored under three progressively honest protocols.

  1. plain StratifiedKFold      -- LEAKS. The 965 records cover only 285 distinct prompts
                                   (3.39 repeated trials each), so sibling trials of the
                                   same prompt sit in train and test simultaneously.
  2. StratifiedGroupKFold       -- honest within-distribution. Groups on md5(prompt), so
     grouped on prompt             every trial of a prompt stays on one side of the split.
  3. leave-one-attack-          -- honest out-of-distribution. Train on 9 attack families,
     category-out                  test on the held-out 10th. This is the question a
                                   deployed gate actually faces.

Numbers are read from models/aura_behavioral.joblib so the figure cannot drift from the
model that is actually shipped.

Run: python3 analysis/make_fig5_protocol_ladder.py
"""
from __future__ import annotations
import os
import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "figures")
os.makedirs(OUT, exist_ok=True)
plt.rcParams.update({"figure.dpi": 150, "font.size": 9,
                     "axes.spines.top": False, "axes.spines.right": False})
C_LEAK, C_OK, C_HARD = "#c0392b", "#2b8a6e", "#2c5aa0"

B = joblib.load(os.path.join(ROOT, "models", "aura_behavioral.joblib"))
M = B["metrics"]
BEST = "random_forest"
cv = M[f"cv_{BEST}"]
loaco = M[f"loaco_{BEST}"]

leaky = cv["auc_leaky_plain_kfold"]
honest = cv["auc"]
honest_sd = cv["auc_sd"]
ood = loaco["auc"]

labels = ["plain\nKFold\n(LEAKS)", "prompt\ngrouped\n(honest)", "leave-one\ncategory-out\n(unseen)"]
vals = [leaky, honest, ood]
cols = [C_LEAK, C_OK, C_HARD]

fig, (ax, ax2) = plt.subplots(1, 2, figsize=(9.4, 3.9),
                              gridspec_kw={"width_ratios": [1.05, 1]})

bars = ax.bar(labels, vals, color=cols, width=.6)
ax.errorbar([1], [honest], yerr=[honest_sd], fmt="none", ecolor="#333", capsize=4, lw=1.2)
for b, v in zip(bars, vals):
    ax.text(b.get_x() + b.get_width() / 2, v + .012, f"{v:.3f}",
            ha="center", fontsize=10, weight="bold")
ax.axhline(0.5, ls=":", c="#888", lw=1)
ax.text(2.42, 0.508, "chance", fontsize=7.5, c="#888", ha="right")
ax.set_ylabel("AUC (behavioural compliance)")
ax.set_ylim(0.45, max(vals) * 1.13)
ax.set_title(f"Same model, same {B['n_train']} rows:\nthe protocol decides the number",
             fontsize=10)
ax.annotate("", xy=(1, leaky - .004), xytext=(0, leaky - .004),
            arrowprops=dict(arrowstyle="->", color="#c0392b", lw=1.3))
ax.text(0.5, leaky + .004, f"leak {honest - leaky:+.3f}", ha="center",
        fontsize=8, color="#c0392b", weight="bold")

per = sorted(loaco["per_category"].items(), key=lambda kv: kv[1])
names = [c.replace("_", " ") for c, _ in per]
scores = [v for _, v in per]
ax2.barh(range(len(per)), scores,
         color=[C_LEAK if v < 0.5 else (C_HARD if v < 0.7 else C_OK) for v in scores],
         height=.62)
ax2.axvline(0.5, ls=":", c="#888", lw=1)
ax2.set_yticks(range(len(per)))
ax2.set_yticklabels(names, fontsize=8)
for i, v in enumerate(scores):
    ax2.text(v + .012, i, f"{v:.2f}", va="center", fontsize=7.5)
ax2.set_xlabel("AUC on the held-out family")
ax2.set_xlim(0, 1.0)
ax2.set_title("Held out one attack family at a time\n(red = worse than chance)", fontsize=10)

fig.tight_layout()
p = os.path.join(OUT, "fig5_protocol_ladder.png")
fig.savefig(p)
plt.close(fig)

stale = os.path.join(OUT, "fig5_transfer_and_safety.png")
if os.path.exists(stale):
    os.rename(stale, stale + ".withdrawn")
    print(f"withdrew stale {os.path.basename(stale)} -> .withdrawn")
print(f"wrote {p}")
print(f"  leaky {leaky:.3f} | honest {honest:.3f} (sd {honest_sd:.3f}) | LOACO {ood:.3f}")
print(f"  below chance: {[c for c, v in per if v < 0.5]}")
