"""Model roster and feature ablations for real-agent grouped CV.

Fitting and scoring happen in :mod:`scigateway.pipeline.evaluate`; this module
only declares the observable feature subsets and constructs fresh estimators for
each cross-validation fold.
"""

from __future__ import annotations

import logging

from .features import FEATURE_SPECS

logger = logging.getLogger(__name__)

_METADATA = tuple(spec.name for spec in FEATURE_SPECS if spec.family == "metadata")
_FILESYSTEM_COMMAND = tuple(
    spec.name for spec in FEATURE_SPECS if spec.family in ("filesystem", "command"))
_CONTAINMENT = tuple(
    spec.name for spec in FEATURE_SPECS if spec.family == "containment")

EXPERIMENTS: dict[str, tuple[str, ...]] = {
    "exp1_metadata_only": _METADATA,
    "exp2_fs_and_command": _METADATA + _FILESYSTEM_COMMAND,
    "exp3_full_gateway": _METADATA + _FILESYSTEM_COMMAND + _CONTAINMENT,
}


def _build_models(seed: int) -> dict[str, object]:
    """Return the classifier roster; XGBoost remains an optional dependency."""
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.linear_model import LogisticRegression
    from sklearn.tree import DecisionTreeClassifier

    models: dict[str, object] = {
        "logistic_regression": LogisticRegression(
            max_iter=2000, class_weight="balanced", random_state=seed),
        "decision_tree": DecisionTreeClassifier(
            max_depth=6, class_weight="balanced", random_state=seed),
        "random_forest": RandomForestClassifier(
            n_estimators=300, class_weight="balanced_subsample",
            random_state=seed, n_jobs=-1),
    }
    try:
        from xgboost import XGBClassifier  # type: ignore
    except Exception:  # pragma: no cover - depends on installation
        logger.info("xgboost not available; continuing with three models")
    else:
        models["xgboost"] = XGBClassifier(
            n_estimators=300, max_depth=4, learning_rate=0.1,
            subsample=0.9, colsample_bytree=0.9,
            objective="multi:softprob", num_class=3, random_state=seed,
            n_jobs=-1, eval_metric="mlogloss", tree_method="hist")
    return models
