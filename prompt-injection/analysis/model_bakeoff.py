"""Model-architecture bake-off for the gateway detector.

Pools every schema-compatible dataset (scigateway Session schema) — Sathwik's
prompt-injection + Chenhao's kimi/deepseek releases — extracts the shared 17
observable features, and trains several classifier architectures under grouped
cross-validation (held out by prompt_family so a model is never tested on an
attack setup it trained on).

The metric that matters for a gateway is not raw accuracy but:
    "at the threshold that catches 100% of attacks, what is the over-block rate?"
(over-block = benign work wrongly blocked). We report that plus over-block at 99%
and 95% recall (100% is dominated by the single hardest-to-see attack), and AUC.

Usage:  python prompt-injection/analysis/model_bakeoff.py
"""

from __future__ import annotations

import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_REPO = _HERE.parent.parent
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

import numpy as np

from scigateway.pipeline.features import FEATURE_NAMES, extract_features
from scigateway.schema import load_sessions_jsonl

DATA_FILES = [
    "prompt-injection/dataset/sessions.jsonl",
    "chenhao-data_release/kimi_50/sessions.jsonl",
    "chenhao-data_release/deepseek_50/sessions.jsonl",
]


def load_pool():
    sessions, src = [], []
    for f in DATA_FILES:
        p = _REPO / f
        if not p.exists():
            print(f"[skip] {f} (not found)")
            continue
        ss = load_sessions_jsonl(p)
        sessions += ss
        src += [f.split("/")[1]] * len(ss)
        print(f"[load] {len(ss):4d} from {f}")
    X = np.array([[extract_features(s)[k] for k in FEATURE_NAMES] for s in sessions], float)
    # target: did the attack behaviourally succeed (the compromise a gateway must catch)
    y = np.array([1 if s.agent_config.get("attack_succeeded") else 0 for s in sessions], int)
    # group by pi_family (mine) / prompt_family (Chenhao) so each fold's held-out group
    # still contains BOTH classes — avoids the single-class-group pathology.
    groups = np.array([s.agent_config.get("pi_family")
                       or s.agent_config.get("prompt_family") or s.task_type
                       for s in sessions])
    return X, y, groups, np.array(src)


def overblock_at_recall(y, p, recall):
    """(over-block, achieved recall) at the threshold catching `recall` of attacks."""
    att = np.sort(p[y == 1])
    n = len(att)
    miss = int(np.floor((1 - recall) * n))            # attacks we allow to slip
    thr = att[miss] if miss < n else att[-1]
    achieved = float((att >= thr).mean())
    over = float((p[y == 0] >= thr).mean())
    return over, achieved


def build_models():
    from sklearn.ensemble import (GradientBoostingClassifier, RandomForestClassifier,
                                  VotingClassifier)
    from sklearn.linear_model import LogisticRegression
    from sklearn.neighbors import KNeighborsClassifier
    from sklearn.pipeline import make_pipeline
    from sklearn.preprocessing import StandardScaler
    from sklearn.svm import SVC

    knn = make_pipeline(StandardScaler(), KNeighborsClassifier(n_neighbors=5))
    logreg = make_pipeline(StandardScaler(),
                           LogisticRegression(max_iter=2000, class_weight="balanced"))
    rf = RandomForestClassifier(n_estimators=300, class_weight="balanced", random_state=0)
    gb = GradientBoostingClassifier(random_state=0)
    svm = make_pipeline(StandardScaler(),
                        SVC(kernel="rbf", probability=True, class_weight="balanced", random_state=0))
    ens = VotingClassifier(
        estimators=[("logreg", logreg), ("rf", rf), ("gb", gb)], voting="soft")
    return {"knn": knn, "logreg": logreg, "random_forest": rf,
            "grad_boost": gb, "svm_rbf": svm, "ensemble": ens}


def main():
    from sklearn.metrics import roc_auc_score
    from sklearn.model_selection import StratifiedGroupKFold, cross_val_predict

    X, y, groups, src = load_pool()
    print(f"\npool: {len(y)} sessions ({int(y.sum())} succeeded-attack / {int((y == 0).sum())} not), "
          f"{len(set(groups))} groups, {X.shape[1]} features")
    print("target = attack_succeeded (behavioural compromise); grouped+stratified 5-fold CV\n")

    cv = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=0)
    print(f"{'model':14s} {'AUC':>6} | {'overblock@100%':>14} {'@99%':>7} {'@95%':>7}")
    print("-" * 56)
    rows = []
    for name, model in build_models().items():
        p = cross_val_predict(model, X, y, cv=cv, groups=groups,
                              method="predict_proba", n_jobs=-1)[:, 1]
        auc = roc_auc_score(y, p)
        ob100, _ = overblock_at_recall(y, p, 1.0)
        ob99, _ = overblock_at_recall(y, p, 0.99)
        ob95, _ = overblock_at_recall(y, p, 0.95)
        rows.append((name, auc, ob100, ob99, ob95))
        print(f"{name:14s} {auc:6.3f} | {ob100:14.3f} {ob99:7.3f} {ob95:7.3f}")

    best = min(rows, key=lambda r: r[2])
    print(f"\nlowest over-block @ 100% catch: {best[0]} ({best[2]:.1%})  "
          f"[Chenhao's KNN baseline was 28%]")


if __name__ == "__main__":
    main()
