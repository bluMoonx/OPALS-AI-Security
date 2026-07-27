"""Immediate baseline classifier on the Spring astrophysics memory-poisoning
turn logs (Track A: train on existing data now, before the 700 are collected).

Honesty notes:
* Features are ONLY observable linguistic/temporal signals. The ground-truth
  fields ``is_poisoned_session`` and ``used_poisoned_value`` are the label /
  harm outcome and are NEVER used as inputs (leakage discipline).
* Split is grouped by ``session_id`` so turns from one session never straddle
  train/test. Per-turn AND per-session metrics are reported.
* This detects memory poisoning in science QA, not the full attack zoo. It is a
  strong slice and a prototype for the science feature family, not the whole
  system.
"""
from __future__ import annotations
import json, glob
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import GroupKFold
from sklearn.metrics import f1_score, precision_score, recall_score, roc_auc_score

# Observable features a gateway could compute from prompt + reply text + timing.
FEATURES = ["hedge_count", "hedge_density", "certain_count", "qualifier_ratio",
            "attribution_count", "cites_memory_file", "numeric_value_count",
            "response_time_s", "word_count", "sentence_count",
            "avg_sentence_len", "output_tokens"]
# Deliberately excluded as leakage: is_poisoned_session (==label),
# used_poisoned_value (ground-truth harm outcome).

def load():
    rows = []
    for f in sorted(glob.glob("data/logs/spring_memory_poisoning/*.jsonl")):
        for line in open(f):
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    X = np.array([[float(r.get(k) or 0) for k in FEATURES] for r in rows], float)
    y = np.array([1 if r.get("label") == "attack" else 0 for r in rows], int)
    groups = np.array([r.get("session_id") for r in rows])
    return rows, X, y, groups

def main():
    rows, X, y, groups = load()
    print(f"loaded {len(y)} turns | {y.sum()} attack / {(y==0).sum()} baseline | "
          f"{len(set(groups))} sessions\n")

    models = {
        "logistic_regression": LogisticRegression(max_iter=2000, class_weight="balanced"),
        "random_forest": RandomForestClassifier(n_estimators=300,
                                                 class_weight="balanced_subsample",
                                                 random_state=0, n_jobs=-1),
    }
    gkf = GroupKFold(n_splits=5)
    for name, base in models.items():
        turn_f1, turn_p, turn_r, turn_auc, sess_acc = [], [], [], [], []
        for tr, te in gkf.split(X, y, groups):
            from sklearn.base import clone
            m = clone(base).fit(X[tr], y[tr])
            proba = m.predict_proba(X[te])[:, 1]
            pred = (proba >= 0.5).astype(int)
            turn_f1.append(f1_score(y[te], pred, zero_division=0))
            turn_p.append(precision_score(y[te], pred, zero_division=0))
            turn_r.append(recall_score(y[te], pred, zero_division=0))
            turn_auc.append(roc_auc_score(y[te], proba) if len(set(y[te])) > 1 else float("nan"))
            # session-level: a session is "attack" if any turn scores high
            g_te = groups[te]
            correct = tot = 0
            for s in set(g_te):
                mask = g_te == s
                sess_pred = int(proba[mask].max() >= 0.5)
                sess_true = int(y[te][mask].max())
                correct += sess_pred == sess_true
                tot += 1
            sess_acc.append(correct / tot)
        print(f"== {name} (5-fold grouped by session) ==")
        print(f"  per-turn    F1 {np.mean(turn_f1):.3f}  P {np.mean(turn_p):.3f}  "
              f"R {np.mean(turn_r):.3f}  ROC-AUC {np.nanmean(turn_auc):.3f}")
        print(f"  per-session accuracy {np.mean(sess_acc):.3f}")
        if name == "random_forest":
            m = base.fit(X, y)
            imp = sorted(zip(FEATURES, m.feature_importances_), key=lambda t: -t[1])
            print("  top features: " + ", ".join(f"{k}={v:.2f}" for k, v in imp[:6]))
        print()

if __name__ == "__main__":
    main()
