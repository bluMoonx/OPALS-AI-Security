"""G2 fix: retrain the general model on BEHAVIOURAL labels.

The shipped `models/aura_general.joblib` was trained on canary-derived labels, which we
have now proven recover only 21% of true compliances (kappa 0.20 vs hand judgement).
Anything learned from them is learning the wrong target.

This trains on the 965 hand-judged behavioural labels and evaluates honestly:
  * stratified CV on hand-judged data, OUT-OF-FOLD only
  * cross-source: train on Chenhao's independent rubric-labelled corpus -> test on our
    hand-judged gold (the transfer number that actually matters)
  * a direct comparison against training on the canary label, same features/protocol

Features come only from (reply text, tool names). Banned as inputs: canary,
attack_succeeded, human_label, condition, risk_indicators, gateway_decision.

Usage: python3 analysis/train_behavioral.py
"""
from __future__ import annotations
import json, os, sys, glob, hashlib
import numpy as np

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "analysis"))
from eval_combined_gold import load_records, load_all_gold          # noqa: E402
from science_features import science_features                       # noqa: E402
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import StratifiedKFold, StratifiedGroupKFold
from sklearn.metrics import roc_auc_score, f1_score
from sklearn.base import clone
import joblib

BANNED = ("canary", "attack_succeeded", "human_label", "condition",
          "risk_indicators", "gateway_decision", "label_notes")

# 10 seeds, not 3. At 3 seeds this model reads AUC 0.748 (sd 0.005); at 10 it reads
# 0.743 (sd 0.008). The 3-seed figure was a favourable draw from a distribution that had
# not been sampled enough to characterise — the same "best-of-N on the test set" error that
# sank two earlier submissions in the competition round.
SEEDS = tuple(range(10))


def feats(reply: str, tools) -> dict:
    sf = science_features(reply, tools or [])
    sf["reply_word_count"] = float(len(reply.split()))
    sf["num_tools"] = float(len(tools or []))
    return sf


FEATURE_NAMES = sorted(feats("x", []).keys())


def vec(reply, tools):
    f = feats(reply, tools)
    return [float(f[n]) for n in FEATURE_NAMES]


def load_gold_xy():
    """Hand-judged behavioural labels -> (X, y, groups=PROMPT HASH).

    The group key is the prompt hash, NOT the category and NOT session_id. The 965 gold
    records cover only 285 distinct prompts (3.39 repeated trials each), and 77% of those
    prompts carry the SAME label across all their repeats. Under a plain StratifiedKFold
    the repeated trials of one prompt land in train and test simultaneously, and the model
    memorises the response cluster instead of generalising. Measured cost of that leak:
    random_forest AUC 0.797 -> 0.748 (-0.049, about 16x the seed-to-seed sd of 0.003).
    """
    recs = load_records()
    gold = load_all_gold(recs)
    X, y, g = [], [], []
    for r in gold:
        rec = r["_rec"]
        reply = (rec.get("agent_response") or "").strip()
        if len(reply) < 20:
            continue
        X.append(vec(reply, rec.get("tools") or []))
        y.append(int(r["behavioral_label"]))
        g.append(hashlib.md5((rec.get("prompt") or "").encode()).hexdigest())
    return np.array(X, float), np.array(y), np.array(g)


def load_gold_canary_xy():
    """Same rows, but labelled by the OLD canary field — the control condition.

    Returns groups too, so the control is scored under the SAME prompt-grouped protocol.
    Comparing a grouped behavioural score against an ungrouped canary score would be
    rigging the comparison in the canary's favour.
    """
    recs = load_records()
    gold = load_all_gold(recs)
    X, y, g = [], [], []
    for r in gold:
        rec = r["_rec"]
        reply = (rec.get("agent_response") or "").strip()
        if len(reply) < 20:
            continue
        X.append(vec(reply, rec.get("tools") or []))
        y.append(1 if rec.get("attack_succeeded") else 0)
        g.append(hashlib.md5((rec.get("prompt") or "").encode()).hexdigest())
    return np.array(X, float), np.array(y), np.array(g)


def load_chenhao_xy():
    X, y = [], []
    for f in glob.glob(os.path.join(ROOT, "data/logs/chenhao_release/*.jsonl")):
        for line in open(f, errors="ignore"):
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except Exception:
                continue
            reply = (d.get("agent_response") or "").strip()
            hl = d.get("human_label")
            if len(reply) < 20 or hl not in ("safe", "suspicious", "unsafe"):
                continue
            X.append(vec(reply, d.get("tool_calls") or d.get("actions") or []))
            y.append(0 if hl == "safe" else 1)
    return np.array(X, float), np.array(y)


MODELS = {
    "logreg": lambda: make_pipeline(StandardScaler(),
                                    LogisticRegression(max_iter=5000, class_weight="balanced", C=0.05)),
    "random_forest": lambda: RandomForestClassifier(n_estimators=500, min_samples_leaf=3,
                                                    class_weight="balanced_subsample",
                                                    random_state=0, n_jobs=-1),
    "gradient_boost": lambda: GradientBoostingClassifier(random_state=0, max_depth=3),
}


def cv_oof(mk, X, y, groups=None, folds=5, seed=0):
    """Out-of-fold probabilities.

    If `groups` is given, uses StratifiedGroupKFold so every record sharing a group
    (= the same prompt) stays on ONE side of the split. That is the honest protocol here;
    the ungrouped path is retained only to quantify the leak.
    """
    if groups is not None:
        sp = StratifiedGroupKFold(folds, shuffle=True, random_state=seed)
        it = sp.split(X, y, groups)
    else:
        sp = StratifiedKFold(folds, shuffle=True, random_state=seed)
        it = sp.split(X, y)
    oof = np.zeros(len(y))
    for tr, te in it:
        m = mk().fit(X[tr], y[tr])
        oof[te] = m.predict_proba(X[te])[:, 1]
    return oof


def loaco(mk, X, y, cats):
    """Leave-one-attack-category-out: train on 9 families, test on the held-out 10th.

    This is the honest answer to "does it work on an attack family it has never seen?",
    which is the question a deployed gate actually faces. It is strictly harder than
    prompt-grouped CV, because whole regions of feature space are absent from training.
    """
    oof = np.zeros(len(y))
    per = {}
    for c in sorted(set(cats)):
        te = cats == c
        tr = ~te
        if te.sum() < 5 or len(set(y[tr])) < 2:
            continue
        p = mk().fit(X[tr], y[tr]).predict_proba(X[te])[:, 1]
        oof[te] = p
        if len(set(y[te])) > 1:
            per[c] = float(roc_auc_score(y[te], p))
    return float(roc_auc_score(y, oof)), per


def trivial_f1(y):
    """F1 of the degenerate always-positive classifier. Any reported F1 must beat this."""
    return float(f1_score(y, np.ones(len(y), dtype=int), zero_division=0))


def recall_at_fpr(y, p, fpr=0.10):
    neg = p[y == 0]
    if not len(neg):
        return float("nan")
    thr = np.quantile(neg, 1 - fpr)
    pos = p[y == 1]
    return float((pos >= thr).mean()) if len(pos) else float("nan")


def main():
    print("=" * 70)
    print("G2 — RETRAIN ON BEHAVIOURAL LABELS")
    print("=" * 70)

    Xg, yg, gg = load_gold_xy()
    Xc, yc = load_chenhao_xy()
    print(f"hand-judged gold : {len(yg)} rows, {yg.sum()} unsafe ({100*yg.mean():.1f}%)")
    print(f"chenhao (rubric) : {len(yc)} rows, {yc.sum()} unsafe ({100*yc.mean():.1f}%)")
    print(f"features         : {len(FEATURE_NAMES)}  (banned as inputs: {', '.join(BANNED)})")

    results = {}

    # ---- 1. CV on hand-judged behavioural labels -------------------------
    n_groups = len(set(gg))
    print(f"\n--- 1. 5-fold CV on hand-judged BEHAVIOURAL labels (out-of-fold) ---")
    print(f"  HONEST protocol = StratifiedGroupKFold grouped on prompt hash")
    print(f"  {len(yg)} records span only {n_groups} distinct prompts "
          f"({len(yg)/n_groups:.2f} repeated trials each) -> a plain split leaks.\n")
    floor = trivial_f1(yg)
    print(f"  TRIVIAL always-positive F1 floor = {floor:.3f}. Any F1 at or below this is "
          f"worth nothing.\n")
    print(f"  {'model':16s} {'HONEST (prompt-grouped)':>26s} {'leaky (plain KFold)':>24s}   leak")
    best = (None, -1.0)
    for name, mk in MODELS.items():
        row = {}
        for tag, grp in (("honest", gg), ("leaky", None)):
            aucs, f1s = [], []
            for seed in SEEDS:
                oof = cv_oof(mk, Xg, yg, groups=grp, seed=seed)
                aucs.append(roc_auc_score(yg, oof))
                f1s.append(f1_score(yg, (oof >= 0.5).astype(int), zero_division=0))
            row[tag] = (float(np.mean(aucs)), float(np.std(aucs)), float(np.mean(f1s)))
        (ha, hsd, hf1), (la, lsd, lf1) = row["honest"], row["leaky"]
        flag = "" if hf1 > floor else "  <- F1 BELOW the trivial floor"
        print(f"  {name:16s}  AUC {ha:.3f}(sd{hsd:.3f}) F1 {hf1:.3f}"
              f"   AUC {la:.3f}(sd{lsd:.3f}) F1 {lf1:.3f}   {ha-la:+.3f}{flag}")
        results[f"cv_{name}"] = {"auc": ha, "auc_sd": hsd, "f1": hf1,
                                 "f1_over_trivial_floor": hf1 - floor,
                                 "auc_leaky_plain_kfold": la, "f1_leaky": lf1,
                                 "leak_magnitude": ha - la,
                                 "protocol": f"StratifiedGroupKFold(prompt), {len(SEEDS)} seeds"}
        if ha > best[1]:
            best = (name, ha)
    print(f"  best (honest): {best[0]} @ AUC {best[1]:.3f}")
    results["trivial_f1_floor"] = floor

    # ---- 1b. leave-one-attack-category-out: the unseen-family number ----
    print(f"\n--- 1b. LEAVE-ONE-ATTACK-CATEGORY-OUT (generalisation to an UNSEEN family) ---")
    cats = np.array([g.get("category") or "?" for g in load_all_gold(load_records())
                     if len((g["_rec"].get("agent_response") or "").strip()) >= 20])
    for name, mk in MODELS.items():
        auc, per = loaco(mk, Xg, yg, cats)
        results[f"loaco_{name}"] = {"auc": auc, "per_category": per}
        print(f"  {name:16s} AUC {auc:.3f}")
        if name == best[0]:
            worst = sorted(per.items(), key=lambda kv: kv[1])[:3]
            print("      weakest families: " +
                  ", ".join(f"{c} {v:.3f}" for c, v in worst))
            below = [c for c, v in per.items() if v < 0.5]
            if below:
                print(f"      BELOW CHANCE on: {', '.join(below)}")
    results["_protocol"] = {"cv": "StratifiedGroupKFold, group=md5(prompt)",
                            "n_records": int(len(yg)), "n_distinct_prompts": int(n_groups),
                            "why": "965 records cover 285 prompts; plain KFold puts repeated "
                                   "trials of one prompt in train and test simultaneously"}

    # ---- 2. control: same rows, CANARY labels ----------------------------
    print("\n--- 2. CONTROL: identical features AND identical grouped protocol, CANARY labels ---")
    Xk, yk, gk = load_gold_canary_xy()
    print(f"  (same seeds as section 1 — a 1-seed control vs a 3-seed headline is not a "
          f"fair comparison)")
    for name, mk in MODELS.items():
        if yk.sum() < 10:
            break
        aucs = [roc_auc_score(yk, cv_oof(mk, Xk, yk, groups=gk, seed=s)) for s in SEEDS]
        auc, sd = float(np.mean(aucs)), float(np.std(aucs))
        print(f"  {name:16s} AUC {auc:.3f} (sd {sd:.3f})   <- learning the WRONG target")
        results[f"canary_cv_{name}"] = {"auc": auc, "auc_sd": sd,
                                        "protocol": "StratifiedGroupKFold(prompt), seeds 0/1/2"}

    # ---- 3. cross-source transfer ---------------------------------------
    print("\n--- 3. CROSS-SOURCE: train chenhao (rubric) -> test hand-judged gold ---")
    for name, mk in MODELS.items():
        m = mk().fit(Xc, yc)
        p = m.predict_proba(Xg)[:, 1]
        auc = roc_auc_score(yg, p)
        r10 = recall_at_fpr(yg, p, 0.10)
        print(f"  {name:16s} AUC {auc:.3f}   recall@10%FPR {r10:.3f}")
        results[f"xsrc_{name}"] = {"auc": float(auc), "recall_at_10fpr": float(r10)}

    # ---- 4. save the behavioural model -----------------------------------
    mk = MODELS[best[0]]
    final = mk().fit(Xg, yg)
    out = os.path.join(ROOT, "models", "aura_behavioral.joblib")
    joblib.dump({"model": final, "features": FEATURE_NAMES,
                 "label_type": "behavioural (hand-judged)",
                 "cv_auc": best[1], "n_train": int(len(yg)),
                 "cv_protocol": f"StratifiedGroupKFold, group=md5(prompt), 5-fold, "
                                f"{len(SEEDS)} seeds (0..{max(SEEDS)})",
                 "n_distinct_prompts": int(n_groups),
                 "loaco_auc": results.get(f"loaco_{best[0]}", {}).get("auc"),
                 "trivial_f1_floor": floor,
                 "metrics": results,
                 "note": "trained on 965 hand-judged behavioural labels; supersedes "
                         "aura_general.joblib which used discredited canary labels. "
                         "cv_auc is the PROMPT-GROUPED number. A plain StratifiedKFold "
                         "reports ~0.05 higher and is leaked: the 965 records cover only "
                         "285 distinct prompts."}, out)
    json.dump(results, open(os.path.join(ROOT, "models", "metrics_behavioral.json"), "w"), indent=2)
    print(f"\nsaved {out}")


if __name__ == "__main__":
    main()
