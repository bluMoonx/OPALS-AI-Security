# !! QUARANTINED 2026-07-27 — DO NOT RUN. EMITS INVALID NUMBERS. !!
#
# This script joins gold labels to corpus records by `session_id`, which is NOT
# unique: 324 ids carry >1 trial (up to 9 deep) and 1,002 of 1,949 records (51.4%)
# sit under a duplicated id. The join silently pairs a human judgement with a
# DIFFERENT trial's response text.
#
# Damage measured here: trains on n=971 instead of the vetted n=965, keeping the 6 rows resolve_gold refuses
#   (line_idx 320, 326, 327, 1332, 1379, 1432). Superseded by analysis/train_behavioral.py.
#
# Correct loader:  from eval_combined_gold import load_records, load_all_gold
#                  gold = load_all_gold(load_records())   # 965 rows, exact _rec
# Re-enable only after porting the join: AURA_ALLOW_BROKEN_JOIN=1

"""Retrain the AURA general risk model on BEHAVIORAL (hand-judged) labels.

The shipped models/aura_general.joblib was trained on the canary label
(canary / attack_succeeded), which an adjudication of 971 sessions showed
recovers only a minority of true compliances. This script rebuilds the model on
hand-judged behavioral labels and reports, honestly, whether that helped.

Sources
-------
HAND (in-house, hand-judged, n=971)
    analysis/rebuild/gold_[A-E].jsonl   (300, original adjudication)
    analysis/rebuild/gold2_S*.jsonl     (671, the held-out attack sweep)
    resolved into data/logs/collected_new10category/newcats_sessions.jsonl by
    line_idx (0-based). session_id is NOT unique, so line_idx is the only safe
    key; every resolution is asserted against session_id.

CHENHAO (independent collection, n=1314)
    data/logs/chenhao_release/*.jsonl, rubric human_label
    safe -> 0, suspicious/unsafe -> 1.

Propagated (labeler-predicted) labels are NOT used: validate_labeler.py found
labeler_v2 collapses out-of-sample (F1 0.612, kappa 0.404) and is not safe to
propagate.

Leakage discipline
------------------
canary / attack_succeeded / human_label / condition are NEVER features. The
canary fields appear only as a reported baseline. `category` is not a feature
either (it would leak the attack taxonomy the gateway cannot see at runtime).
"""
from __future__ import annotations

import os as _os, sys as _sys  # QUARANTINE GUARD
if _os.environ.get("AURA_ALLOW_BROKEN_JOIN") != "1":
    _sys.exit("REFUSING TO RUN: broken session_id join -> invalid numbers. See header.")


import json
import os
import sys
from collections import Counter, defaultdict

import numpy as np
import joblib
from sklearn.ensemble import (GradientBoostingClassifier, HistGradientBoostingClassifier,
                              RandomForestClassifier)
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (f1_score, precision_recall_fscore_support, roc_auc_score,
                             roc_curve)
from sklearn.model_selection import StratifiedKFold
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

ROOT = "/Users/sid/Documents/Behavioral Risk Prediction for Autonomous AI Systems"
SRC = os.path.join(ROOT, "data/logs/collected_new10category/newcats_sessions.jsonl")
GD = os.path.join(ROOT, "analysis/rebuild")
CHENHAO_DIR = os.path.join(ROOT, "data/logs/chenhao_release")
OUT_MODEL = os.path.join(ROOT, "models/aura_behavioral.joblib")
OUT_JSON = os.path.join(GD, "retrain_behavioral_results.json")

sys.path.insert(0, os.path.join(ROOT, "analysis"))
from science_features import science_features  # noqa: E402

SEED = 0
# 1-indexed corpus line ranges the five original gold slices were drawn from
# (same convention as validate_labeler.py).
SLICE_RANGES = {
    "gold_A.jsonl": (1, 320), "gold_B.jsonl": (321, 640), "gold_C.jsonl": (641, 960),
    "gold_D.jsonl": (961, 1280), "gold_E.jsonl": (1281, 1601),
}


# ---------------------------------------------------------------- features
def featurize(reply: str, tools) -> dict:
    tools = [str(t) for t in (tools or [])]
    f = science_features(reply or "", tools)
    f["reply_word_count"] = float(len((reply or "").split()))
    f["num_tools"] = float(len(tools))
    return f


def tools_of(d: dict):
    return d.get("tools") or d.get("tool_calls") or []


FEATURES = sorted(featurize("x", []).keys())
BANNED = {"canary", "attack_succeeded", "human_label", "condition", "category",
          "attack_category", "gateway_decision", "risk_indicators"}
assert not (set(FEATURES) & BANNED), "leakage: banned field used as feature"


def matrix(rows):
    X = np.array([[r["feat"][k] for k in FEATURES] for r in rows], dtype=float)
    y = np.array([r["y"] for r in rows], dtype=int)
    return X, y


# ---------------------------------------------------------------- loaders
def load_newcats():
    with open(SRC) as f:
        return [json.loads(l) for l in f if l.strip()]


def load_hand(recs):
    """971 hand-judged sessions, resolved by line_idx, asserted on session_id."""
    by_sid = defaultdict(list)
    for i, r in enumerate(recs, 1):  # 1-indexed
        by_sid[r["session_id"]].append(i)

    out, seen = [], set()

    def add(idx0, g, slice_name):
        rec = recs[idx0]
        assert rec["session_id"] == g["session_id"], (slice_name, idx0)
        if idx0 in seen:
            raise ValueError("duplicate line_idx %d (%s)" % (idx0, slice_name))
        seen.add(idx0)
        out.append({
            "line_idx": idx0, "session_id": rec["session_id"],
            "category": rec.get("category"), "condition": rec.get("condition"),
            "slice": slice_name, "source": "hand",
            "y": int(g["behavioral_label"]),
            "confidence": g.get("confidence"),
            "canary_label": int(bool(rec.get("attack_succeeded")) or bool(rec.get("canary"))),
            "feat": featurize(rec.get("agent_response", ""), tools_of(rec)),
        })

    for fname, (lo, hi) in sorted(SLICE_RANGES.items()):
        path = os.path.join(GD, fname)
        if not os.path.exists(path):
            continue
        for ln_txt in open(path):
            if not ln_txt.strip():
                continue
            g = json.loads(ln_txt)
            if g.get("line_idx") is not None:
                ln = g["line_idx"] + 1
            elif g.get("source_line") is not None:
                ln = g["source_line"]
            else:
                cands = [x for x in by_sid.get(g["session_id"], []) if lo <= x <= hi]
                if len(cands) != 1:
                    raise ValueError("cannot resolve %s in %s: %r"
                                     % (g["session_id"], fname, cands))
                ln = cands[0]
            assert lo <= ln <= hi, (fname, ln)
            add(ln - 1, g, "orig_" + fname[5])

    for fname in sorted(f for f in os.listdir(GD)
                        if f.startswith("gold2_S") and f.endswith(".jsonl")):
        for ln_txt in open(os.path.join(GD, fname)):
            if not ln_txt.strip():
                continue
            g = json.loads(ln_txt)
            add(g["line_idx"], g, "new_" + fname[6:9])
    return out


def load_chenhao():
    rows = []
    for fname in sorted(os.listdir(CHENHAO_DIR)):
        if not fname.endswith(".jsonl"):
            continue
        for ln_txt in open(os.path.join(CHENHAO_DIR, fname)):
            if not ln_txt.strip():
                continue
            d = json.loads(ln_txt)
            lab = str(d.get("human_label", "")).strip().lower()
            if lab == "safe":
                y = 0
            elif lab in ("suspicious", "unsafe"):
                y = 1
            else:
                continue
            rows.append({
                "session_id": d.get("session_id"), "source": "chenhao",
                "file": fname, "y": y,
                "category": d.get("attack_category"),
                "feat": featurize(d.get("agent_response", ""), tools_of(d)),
            })
    return rows


# ---------------------------------------------------------------- metrics
def recall_at_fpr(y, s, target=0.10):
    """Recall (TPR) at the largest threshold whose FPR <= target."""
    fpr, tpr, thr = roc_curve(y, s)
    ok = np.where(fpr <= target)[0]
    i = ok[-1]
    return float(tpr[i]), float(fpr[i]), float(thr[i])


def score_block(y, s, thresh=0.5):
    p = (np.asarray(s) >= thresh).astype(int)
    pr, rc, f1, _ = precision_recall_fscore_support(y, p, average="binary",
                                                    zero_division=0)
    auc = roc_auc_score(y, s) if len(set(y)) > 1 else float("nan")
    r10, fpr10, thr10 = recall_at_fpr(y, s)
    # best-F1 operating point, for reference only
    ts = np.unique(np.round(np.asarray(s), 4))
    bf1 = max(f1_score(y, (np.asarray(s) >= t).astype(int), zero_division=0) for t in ts)
    return {"auc": round(float(auc), 4), "f1@0.5": round(float(f1), 4),
            "precision@0.5": round(float(pr), 4), "recall@0.5": round(float(rc), 4),
            "recall@10fpr": round(r10, 4), "fpr_at_that_point": round(fpr10, 4),
            "thresh@10fpr": round(thr10, 4), "best_f1_any_thresh": round(float(bf1), 4),
            "n": int(len(y)), "pos_rate": round(float(np.mean(y)), 4)}


def candidates():
    return {
        "logreg": make_pipeline(StandardScaler(),
                                LogisticRegression(max_iter=4000, class_weight="balanced",
                                                   random_state=SEED)),
        "random_forest": RandomForestClassifier(n_estimators=600, min_samples_leaf=3,
                                                class_weight="balanced_subsample",
                                                n_jobs=-1, random_state=SEED),
        "grad_boost": GradientBoostingClassifier(random_state=SEED),
        "hist_gb": HistGradientBoostingClassifier(random_state=SEED),
    }


def oof_scores(model_fn, X, y, k=5):
    """Out-of-fold probabilities only. Nothing in-fold is ever scored."""
    oof = np.zeros(len(y), dtype=float)
    skf = StratifiedKFold(n_splits=k, shuffle=True, random_state=SEED)
    for tr, te in skf.split(X, y):
        m = model_fn()
        m.fit(X[tr], y[tr])
        oof[te] = m.predict_proba(X[te])[:, 1]
    return oof


# ---------------------------------------------------------------- main
def main():
    recs = load_newcats()
    hand = load_hand(recs)
    chen = load_chenhao()

    print("=" * 78)
    print("CORPUS")
    print("=" * 78)
    print("hand-judged    n=%d   positives=%d (%.1f%%)"
          % (len(hand), sum(r["y"] for r in hand),
             100 * np.mean([r["y"] for r in hand])))
    print("  slices:", dict(sorted(Counter(r["slice"][:4] for r in hand).items())))
    print("  condition:", dict(Counter(r["condition"] for r in hand)))
    print("chenhao        n=%d   positives=%d (%.1f%%)"
          % (len(chen), sum(r["y"] for r in chen),
             100 * np.mean([r["y"] for r in chen])))
    print("propagated labels: NOT USED (labeler failed OOS validation, "
          "F1 0.612 / kappa 0.404 -> not safe to propagate)")
    print("features (%d):" % len(FEATURES), FEATURES)

    Xh, yh = matrix(hand)
    Xc, yc = matrix(chen)

    # canary baseline on the same hand-judged rows
    can = np.array([r["canary_label"] for r in hand], dtype=int)
    cpr, crc, cf1, _ = precision_recall_fscore_support(yh, can, average="binary",
                                                       zero_division=0)
    canary_baseline = {"f1": round(float(cf1), 4), "precision": round(float(cpr), 4),
                       "recall": round(float(crc), 4),
                       "agreement": round(float(np.mean(can == yh)), 4)}
    print("\ncanary label vs behavioral truth on the same rows:", canary_baseline)

    results = {}

    # ---- 1. CV on hand-judged, out-of-fold only
    print("\n" + "=" * 78)
    print("1. STRATIFIED 5-FOLD CV ON HAND-JUDGED (out-of-fold scores only)")
    print("=" * 78)
    cv = {}
    for name, _ in candidates().items():
        oof = oof_scores(lambda n=name: candidates()[n], Xh, yh)
        cv[name] = score_block(yh, oof)
        cv[name]["_oof"] = oof
        b = cv[name]
        print("  %-14s AUC %.4f  F1 %.4f  P %.4f  R %.4f | R@10%%FPR %.4f"
              % (name, b["auc"], b["f1@0.5"], b["precision@0.5"], b["recall@0.5"],
                 b["recall@10fpr"]))

    # ---- 2. cross-source transfer: train Chenhao -> test hand-judged
    print("\n" + "=" * 78)
    print("2. CROSS-SOURCE: train CHENHAO (n=%d) -> test HAND-JUDGED (n=%d)"
          % (len(chen), len(hand)))
    print("=" * 78)
    xsrc = {}
    for name in candidates():
        m = candidates()[name]
        m.fit(Xc, yc)
        s = m.predict_proba(Xh)[:, 1]
        xsrc[name] = score_block(yh, s)
        b = xsrc[name]
        print("  %-14s AUC %.4f  F1 %.4f  P %.4f  R %.4f | R@10%%FPR %.4f"
              % (name, b["auc"], b["f1@0.5"], b["precision@0.5"], b["recall@0.5"],
                 b["recall@10fpr"]))

    # ---- 2b. reverse transfer, for symmetry
    print("\n  reverse (train HAND -> test CHENHAO):")
    xrev = {}
    for name in candidates():
        m = candidates()[name]
        m.fit(Xh, yh)
        s = m.predict_proba(Xc)[:, 1]
        xrev[name] = score_block(yc, s)
        b = xrev[name]
        print("  %-14s AUC %.4f  F1 %.4f | R@10%%FPR %.4f"
              % (name, b["auc"], b["f1@0.5"], b["recall@10fpr"]))

    # ---- 3. pooled training (hand + chenhao), CV evaluated on hand rows only
    print("\n" + "=" * 78)
    print("3. POOLED TRAIN (hand + chenhao): folds over hand rows, chenhao always"
          " in train; scored on held-out hand rows only")
    print("=" * 78)
    pooled = {}
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=SEED)
    for name in candidates():
        oof = np.zeros(len(yh), dtype=float)
        for tr, te in skf.split(Xh, yh):
            m = candidates()[name]
            m.fit(np.vstack([Xh[tr], Xc]), np.concatenate([yh[tr], yc]))
            oof[te] = m.predict_proba(Xh[te])[:, 1]
        pooled[name] = score_block(yh, oof)
        pooled[name]["_oof"] = oof
        b = pooled[name]
        print("  %-14s AUC %.4f  F1 %.4f  P %.4f  R %.4f | R@10%%FPR %.4f"
              % (name, b["auc"], b["f1@0.5"], b["precision@0.5"], b["recall@0.5"],
                 b["recall@10fpr"]))

    # ---- 4. the incumbent canary-trained model, on behavioral truth
    print("\n" + "=" * 78)
    print("4. INCUMBENT models/aura_general.joblib (canary-trained) scored on the"
          " SAME hand-judged behavioral labels")
    print("=" * 78)
    incumbent = None
    try:
        blob = joblib.load(os.path.join(ROOT, "models/aura_general.joblib"))
        feats = list(blob["features"])
        Xi = np.array([[r["feat"][k] for k in feats] for r in hand], dtype=float)
        s = blob["model"].predict_proba(Xi)[:, 1]
        incumbent = score_block(yh, s)
        print("  aura_general   AUC %.4f  F1 %.4f  P %.4f  R %.4f | R@10%%FPR %.4f"
              % (incumbent["auc"], incumbent["f1@0.5"], incumbent["precision@0.5"],
                 incumbent["recall@0.5"], incumbent["recall@10fpr"]))
        print("  NOTE: these hand-judged rows were IN aura_general's own training set"
              " (with canary labels), so this number is optimistic for the incumbent.")
    except Exception as exc:
        print("  could not score incumbent: %r" % (exc,))

    # ---- 4b. HEAD-TO-HEAD ON LABEL CHOICE: same rows, same features, same folds,
    #          same estimator; only the TRAINING TARGET differs. Both are scored
    #          against behavioral truth on the held-out fold.
    print("\n" + "=" * 78)
    print("4b. LABEL-CHOICE HEAD-TO-HEAD (identical rows/features/folds/estimator;")
    print("    only the training target differs; both scored on BEHAVIORAL truth)")
    print("=" * 78)
    head2head = {}
    for name in ("random_forest", "grad_boost", "logreg"):
        oof_can = np.zeros(len(yh), dtype=float)
        for tr, te in skf.split(Xh, yh):
            m = candidates()[name]
            if len(set(can[tr])) < 2:
                continue
            m.fit(Xh[tr], can[tr])          # trained on the CANARY label
            oof_can[te] = m.predict_proba(Xh[te])[:, 1]
        b_can = score_block(yh, oof_can)     # evaluated on BEHAVIORAL truth
        b_beh = cv[name]
        head2och = {"trained_on_canary": b_can, "trained_on_behavioral": b_beh}
        head2h = {k: {kk: vv for kk, vv in v.items() if not kk.startswith("_")}
                  for k, v in head2och.items()}
        head2head[name] = head2h
        print("  %-14s canary-trained  AUC %.4f  F1 %.4f  R@10%%FPR %.4f"
              % (name, b_can["auc"], b_can["f1@0.5"], b_can["recall@10fpr"]))
        print("  %-14s behav-trained   AUC %.4f  F1 %.4f  R@10%%FPR %.4f   "
              "(dAUC %+.4f)"
              % ("", b_beh["auc"], b_beh["f1@0.5"], b_beh["recall@10fpr"],
                 b_beh["auc"] - b_can["auc"]))

    # ---- 4c. cross-source with per-source standardized features (does the
    #          transfer gap come from scale shift or from label semantics?)
    print("\n" + "=" * 78)
    print("4c. CROSS-SOURCE DIAGNOSTIC: features z-scored WITHIN each source")
    print("    (removes scale/verbosity shift; what remains is genuine disagreement)")
    print("=" * 78)
    def zs(X):
        mu, sd = X.mean(0), X.std(0)
        sd[sd == 0] = 1.0
        return (X - mu) / sd
    Xhz, Xcz = zs(Xh), zs(Xc)
    xsrc_z = {}
    for name in candidates():
        m = candidates()[name]
        m.fit(Xcz, yc)
        s = m.predict_proba(Xhz)[:, 1]
        xsrc_z[name] = score_block(yh, s)
        b = xsrc_z[name]
        print("  %-14s AUC %.4f  F1 %.4f | R@10%%FPR %.4f"
              % (name, b["auc"], b["f1@0.5"], b["recall@10fpr"]))

    # ---- 4d. operational slice: attack-condition hand rows only
    att = np.array([r["condition"] == "attack" for r in hand])
    best_oof = cv[max(cv, key=lambda n: cv[n]["auc"])]["_oof"]
    op = score_block(yh[att], best_oof[att])
    print("\n  operational slice (attack-condition hand rows only, n=%d): "
          "AUC %.4f  F1 %.4f  R@10%%FPR %.4f"
          % (att.sum(), op["auc"], op["f1@0.5"], op["recall@10fpr"]))

    # ---- pick the winner on CV AUC over the hand-judged data
    best_cv = max(cv, key=lambda n: cv[n]["auc"])
    best_pooled = max(pooled, key=lambda n: pooled[n]["auc"])
    use_pooled = pooled[best_pooled]["auc"] > cv[best_cv]["auc"] + 0.005
    win_name = best_pooled if use_pooled else best_cv
    win_block = pooled[best_pooled] if use_pooled else cv[best_cv]
    trained_on = "hand+chenhao" if use_pooled else "hand"

    final = candidates()[win_name]
    if use_pooled:
        final.fit(np.vstack([Xh, Xc]), np.concatenate([yh, yc]))
    else:
        final.fit(Xh, yh)

    metrics = {
        "cv_hand": {k: {kk: vv for kk, vv in v.items() if not kk.startswith("_")}
                    for k, v in cv.items()},
        "cross_source_chenhao_to_hand": xsrc,
        "cross_source_hand_to_chenhao": xrev,
        "pooled_cv_on_hand": {k: {kk: vv for kk, vv in v.items() if not kk.startswith("_")}
                              for k, v in pooled.items()},
        "incumbent_canary_model_on_behavioral_truth": incumbent,
        "label_choice_head_to_head": head2head,
        "cross_source_per_source_zscored": xsrc_z,
        "operational_attack_only_slice": op,
        "canary_label_baseline": canary_baseline,
        "winner": {"name": win_name, "trained_on": trained_on,
                   **{k: v for k, v in win_block.items() if not k.startswith("_")}},
        "n_hand": len(hand), "n_chenhao": len(chen),
        "propagated_labels_used": False,
    }

    joblib.dump({
        "model": final,
        "features": FEATURES,
        "metrics": metrics,
        "trained_on": ("%d hand-judged behavioral labels (gold_A-E + gold2_S01-S12)"
                       % len(hand)) + (" + %d Chenhao rubric labels" % len(chen)
                                       if use_pooled else ""),
        "label_type": "behavioral",
        "note": ("Retrained on hand-judged BEHAVIORAL compliance labels; replaces the "
                 "canary-trained aura_general.joblib. canary/attack_succeeded/"
                 "human_label/condition/category never used as features. No propagated "
                 "labeler labels (labeler failed OOS validation)."),
    }, OUT_MODEL)

    with open(OUT_JSON, "w") as f:
        json.dump(metrics, f, indent=2)

    print("\n" + "=" * 78)
    print("WINNER: %s trained on %s" % (win_name, trained_on))
    print({k: v for k, v in metrics["winner"].items()})
    print("saved ->", OUT_MODEL)
    print("saved ->", OUT_JSON)


if __name__ == "__main__":
    main()
