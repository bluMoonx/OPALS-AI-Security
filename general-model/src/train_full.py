"""Full AURA classifier — HONEST build, trained on the Spring science data.

Saves a real, pushable model artifact and metrics.

=== LEAKAGE FINDINGS (verified 2026-07-23, do not repeat these mistakes) ===
1. A session-aggregate "verification-collapse" feature (`traj_mem_rate`, the
   fraction of turns citing the memory file) gave AUC 0.98 — but it is DESIGN
   LEAKAGE. Baseline sessions cite memory 0.00 of the time, attack sessions 0.36,
   ONLY because the experiment defines the attack as a poisoned memory file the
   agent reads. It would not generalize to a deployment where legit tasks also
   read memory. REJECTED.
2. The behavioral trajectory (certainty slope / hedge slope across a session)
   did NOT help (0.744 < 0.785 base). The verification-collapse hypothesis, as
   operationalized, does not pan out on this data. REJECTED (honest negative).
3. Per-turn `cites_memory_file` is mildly design-linked (attack 0.36 / baseline
   0.00) but contributes ~nothing (0.785 -> 0.783 without it), so we DROP it to
   keep the model generalizable rather than let a design artifact ride along.
4. `response_time_s` may be an environment artifact; kept but flagged. Without it
   AUC is 0.769, so it is not load-bearing.

Honest headline: behavioral/linguistic features give ROC-AUC ~0.78 on held-out
sessions. That is the real number.
"""
from __future__ import annotations
import json, glob, os
import numpy as np
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import GroupKFold
from sklearn.metrics import f1_score, roc_auc_score
from sklearn.base import clone
import joblib

# Honest, generalizable feature set: linguistic + science + timing.
# Deliberately EXCLUDES cites_memory_file (design-linked) and all ground-truth
# fields (is_poisoned_session, used_poisoned_value).
FEATURES = ["hedge_count","hedge_density","certain_count","qualifier_ratio",
            "attribution_count","numeric_value_count","response_time_s",
            "word_count","sentence_count","avg_sentence_len","output_tokens"]

def load():
    rows=[]
    for f in sorted(glob.glob("data/logs/spring_memory_poisoning/*.jsonl")):
        for l in open(f):
            l=l.strip()
            if l: rows.append(json.loads(l))
    return rows

def matrix(rows):
    X=np.array([[float(r.get(c) or 0) for c in FEATURES] for r in rows],float)
    y=np.array([1 if r.get("label")=="attack" else 0 for r in rows],int)
    g=np.array([r["session_id"] for r in rows])
    return X,y,g

def cv(model,X,y,g):
    gkf=GroupKFold(5); f1s=[]; aucs=[]
    for tr,te in gkf.split(X,y,g):
        m=clone(model).fit(X[tr],y[tr]); p=m.predict_proba(X[te])[:,1]
        f1s.append(f1_score(y[te],(p>=.5).astype(int),zero_division=0))
        aucs.append(roc_auc_score(y[te],p) if len(set(y[te]))>1 else np.nan)
    return float(np.mean(f1s)), float(np.nanmean(aucs))

def main():
    os.makedirs("models",exist_ok=True)
    rows=load()
    X,y,g=matrix(rows)
    print(f"loaded {len(rows)} turns / {len(set(g))} sessions / {len(FEATURES)} honest features\n")
    models={
        "logreg": make_pipeline(StandardScaler(), LogisticRegression(max_iter=5000,class_weight="balanced")),
        "random_forest": RandomForestClassifier(n_estimators=400,class_weight="balanced_subsample",random_state=0,n_jobs=-1),
        "gradient_boost": GradientBoostingClassifier(random_state=0),
    }
    report={}; best=(None,-1)
    print(f"{'model':16s} {'F1':>6s} {'ROC-AUC':>8s}")
    for name,mdl in models.items():
        f1,auc=cv(mdl,X,y,g); report[name]={"f1":round(f1,3),"auc":round(auc,3)}
        print(f"{name:16s} {f1:6.3f} {auc:8.3f}")
        if auc>best[1]: best=(name,auc)
    bmodel=clone(models[best[0]]).fit(X,y)
    joblib.dump({"model":bmodel,"features":FEATURES,"cv_auc":round(best[1],3),
                 "trained_on":"spring_turns_1998","note":"honest behavioral features; see leakage findings in train_full.py"},
                "models/aura_v1.joblib")
    json.dump({"cv":report,"features":FEATURES,"best":best[0],"best_auc":round(best[1],3)},
              open("models/metrics.json","w"),indent=2)
    print(f"\nBEST: {best[0]} AUC {best[1]:.3f}  ->  saved models/aura_v1.joblib + metrics.json")

if __name__ == "__main__":
    main()
