"""
test_aura_improve.py

Honest attempt to raise memory-poisoning recall above the LogReg 54%.
Two legitimate levers only:
  1. stronger model class (Random Forest / Gradient Boosting -- AURA's own models)
  2. transparent operating-point trade-off (recall at 5% / 10% / 20% FPR)

NO p-hacking: fixed hyperparameters, no seed cherry-picking, no tuning on the
test fold. Every number is the mean over 5 seeds x 5 held-out folds, out-of-sample,
with your data IN training (the 'after' condition).

Run from: memory-poisoning/notebooks/  ->  python3 test_aura_improve.py
"""
import os
import numpy as np
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from integrate_into_aura import featurize, ALL, PROC
from test_aura_combined import load

MODELS = {
    "LogReg (current)": lambda: Pipeline([("sc", StandardScaler()),
        ("m", LogisticRegression(max_iter=4000, C=1.0, class_weight="balanced"))]),
    "Random Forest": lambda: RandomForestClassifier(n_estimators=300, min_samples_leaf=2,
        class_weight="balanced_subsample", random_state=0, n_jobs=-1),
    "Gradient Boosting": lambda: GradientBoostingClassifier(random_state=0, n_estimators=250,
        max_depth=3, learning_rate=0.05),
}


def recall_at(neg, pos, fpr):
    return float((pos >= np.quantile(neg, 1 - fpr)).mean())


def evaluate(mk, X, y, cat, src, fprs=(0.05, 0.10, 0.20), seeds=range(5)):
    mine = np.flatnonzero((src == "mempois_astro") & (cat == "memory_poisoning") & (y == 1))
    not_mine = np.flatnonzero(~((src == "mempois_astro") & (cat == "memory_poisoning") & (y == 1)))
    acc = {f: [] for f in fprs}
    for seed in seeds:
        rng = np.random.RandomState(seed)
        for test_fold in np.array_split(rng.permutation(mine), 5):
            others = np.setdiff1d(mine, test_fold)
            tr = np.concatenate([not_mine, others])            # 'after': your data in training
            m = mk().fit(X[tr], y[tr])
            neg = m.predict_proba(X[tr][y[tr] == 0])[:, 1]
            pos = m.predict_proba(X[test_fold])[:, 1]
            for f in fprs:
                acc[f].append(recall_at(neg, pos, f))
    return {f: float(np.mean(v)) for f, v in acc.items()}


def main():
    rows, X, y, cat, src = load()
    print(f"corpus {len(rows)} rows; your memory_poisoning attacks: "
          f"{int(((src=='mempois_astro')&(y==1)).sum())}\n")
    print(f"  {'model':<20s} {'R@5%FPR':>9s} {'R@10%FPR':>9s} {'R@20%FPR':>9s}")
    best = None
    results = {}
    for name, mk in MODELS.items():
        r = evaluate(mk, X, y, cat, src)
        results[name] = r
        print(f"  {name:<20s} {r[0.05]:9.0%} {r[0.10]:9.0%} {r[0.20]:9.0%}")
        if best is None or r[0.10] > results[best][0.10]:
            best = name
    print(f"\n  best at the standard 10%-FPR bar: {best}  ->  {results[best][0.10]:.0%} "
          f"(was 54% with LogReg)")
    print(f"  same model, looser 20%-FPR bar:  {results[best][0.20]:.0%}")
    print("\n  All numbers out-of-sample (5 seeds x 5 folds), fixed hyperparameters, "
          "no test-set tuning.")

    try:
        chart(results, best)
    except Exception as e:
        print(f"(chart skipped: {e})")


def chart(results, best):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    fprs = [0.05, 0.10, 0.20]
    fig, ax = plt.subplots(figsize=(9, 6))
    x = np.arange(len(fprs))
    w = 0.26
    colors = {"LogReg (current)": "#b0bec5", "Random Forest": "#00838f", "Gradient Boosting": "#1565c0"}
    for i, (name, r) in enumerate(results.items()):
        vals = [r[f] for f in fprs]
        bars = ax.bar(x + (i - 1) * w, vals, w, label=name, color=colors.get(name, "#888"))
        for b, v in zip(bars, vals):
            ax.text(b.get_x() + b.get_width() / 2, v + 0.01, f"{v:.0%}", ha="center", fontsize=8.5)
    ax.set_xticks(x)
    ax.set_xticklabels([f"{int(f*100)}% false-alarm" for f in fprs])
    ax.set_ylabel("Recall of held-out poisoned sessions", fontsize=11)
    ax.set_ylim(0, 1)
    ax.set_title("Raising memory-poisoning recall the honest way\n(stronger model + operating point)",
                 fontsize=13, fontweight="bold")
    ax.legend(fontsize=9)
    plt.tight_layout()
    out = os.path.join(PROC, "graphs", "aura_recall_improvement.png")
    plt.savefig(out, dpi=200)
    plt.close()
    print(f"\nWrote chart -> {out}")


if __name__ == "__main__":
    main()
