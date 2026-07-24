"""
train_classifier.py

Trains a small classifier to predict compliance_score (full_compliance vs
compliance_with_flag) on attack sessions, using the engineered features from
build_feature_table.py. This is the "predictive model" deliverable the OPALS
proposal calls for -- detecting when the agent has fully deferred to poisoned
memory vs. partially resisted, from gateway/session-log-derived features alone.

Run from: memory-poisoning/notebooks/
    python3 train_classifier.py
"""
import json
import os
import numpy as np
from sklearn.pipeline import make_pipeline
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.model_selection import StratifiedKFold, cross_val_predict
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
)
from sklearn.preprocessing import StandardScaler

FEATURES = [
    "response_length_chars", "cites_memory_md", "hedge_density",
    "qualifier_ratio", "numeric_value_count", "response_latency_seconds",
    "certainty_count", "attribution_count", "sentence_count",
    "avg_sentence_length", "quality_ratio",
]


def load(path):
    with open(path, "r") as f:
        return json.load(f)


def main():
    processed_dir = os.path.abspath(os.path.join("..", "data", "processed"))
    rows = load(os.path.join(processed_dir, "feature_table.json"))

    attack_rows = [r for r in rows if r["run_type"] == "attack"]
    # drop any row missing a feature value (e.g. latency parsing failure)
    attack_rows = [r for r in attack_rows if all(r.get(f) is not None for f in FEATURES)]

    print(f"Training on {len(attack_rows)} attack sessions")
    print(f"Features used: {FEATURES}")
    print("(tool_count, fallback_steps, had_error, memory_md_injected excluded -- "
          "zero variance on attack sessions, cannot predict anything)\n")

    X = np.array([[float(r[f]) for f in FEATURES] for r in attack_rows])
    y = np.array([1 if r["compliance_score"] == "full_compliance" else 0 for r in attack_rows])

    print(f"Class balance: full_compliance={sum(y)}, compliance_with_flag={len(y)-sum(y)}\n")

    n_splits = min(5, min(sum(y), len(y) - sum(y)))  # can't have more folds than the smaller class
    cv = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=42)

    for name, clf in [
        ("Logistic Regression", LogisticRegression(max_iter=1000)),
        ("Decision Tree (depth=3)", DecisionTreeClassifier(max_depth=3, random_state=42)),
        ("Random Forest", RandomForestClassifier(n_estimators=100, random_state=42)),
    ]:
        preds = cross_val_predict(clf, X, y, cv=cv)
        acc = accuracy_score(y, preds)
        prec = precision_score(y, preds)
        rec = recall_score(y, preds)
        f1 = f1_score(y, preds)
        cm = confusion_matrix(y, preds)

        print(f"=== {name} ({n_splits}-fold cross-validated) ===")
        print(f"  Accuracy:  {acc:.3f}")
        print(f"  Precision: {prec:.3f}  (of predicted full_compliance, how many really were)")
        print(f"  Recall:    {rec:.3f}  (of actual full_compliance, how many were caught)")
        print(f"  F1:        {f1:.3f}")
        print(f"  Confusion matrix (rows=actual, cols=predicted, order=[flag, full]):")
        print(f"    {cm}")

        # fit on all data (not cross-val) just to inspect feature importance/coeffs
        clf.fit(X, y)
        if hasattr(clf, "coef_"):
            print("  Feature coefficients:")
            for f, c in zip(FEATURES, clf.coef_[0]):
                print(f"    {f}: {c:.4f}")
        elif hasattr(clf, "feature_importances_"):
            print("  Feature importances:")
            for f, imp in zip(FEATURES, clf.feature_importances_):
                print(f"    {f}: {imp:.4f}")
        print()


if __name__ == "__main__":
    main()