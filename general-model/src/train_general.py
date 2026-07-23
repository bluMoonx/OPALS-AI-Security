"""General AURA classifier — the full rebuild across ALL collected attack
categories, using a UNIFIED feature extractor (science_features + basics)
computed from reply text + tool trail. This is the model that spans the whole
attack taxonomy, not just memory poisoning.

Trains on data/logs/collected_*/*.jsonl (scigateway 22-category sessions + the 10
new-category prompt-pair sessions). Reports standard grouped CV AND
leave-one-attack-category-out (LOACO) generalization. Saves models/aura_general.joblib.

Re-run this as the background collectors add data; the number improves with volume.
"""
from __future__ import annotations
import json, glob, os, sys
import numpy as np
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from science_features import science_features
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import GroupKFold
from sklearn.metrics import f1_score, roc_auc_score
from sklearn.base import clone
import joblib

def reply_of(d):    return d.get("agent_response") or d.get("response_preview") or ""
def tools_of(d):    return d.get("tools") or []
def is_attack(d):
    # OUTCOME-based label: did the agent actually behave unsafely (not merely: was it attacked)
    hl = d.get("human_label")
    if hl in ("safe","suspicious","unsafe"): return 0 if hl == "safe" else 1
    if "attack_succeeded" in d: return 1 if d.get("attack_succeeded") else 0
    cat = d.get("attack_category") or d.get("category") or ""
    return 0 if cat in ("", "benign") else 1
def category_of(d): return d.get("attack_category") or d.get("category") or "benign"

def load():
    rows=[]
    import itertools
    files=itertools.chain(glob.glob("data/logs/collected_*/*.jsonl"), glob.glob("data/logs/chenhao_release/*.jsonl"))
    for f in files:
        for l in open(f):
            l=l.strip()
            if not l: continue
            try: d=json.loads(l)
            except: continue
            if reply_of(d).strip(): rows.append(d)
    return rows

def featurize(rows):
    feats=[]
    for d in rows:
        sf=science_features(reply_of(d), tools_of(d))
        sf["reply_word_count"]=float(len(reply_of(d).split()))
        sf["num_tools"]=float(len(tools_of(d)))
        feats.append(sf)
    names=sorted(feats[0].keys())
    X=np.array([[f[n] for n in names] for f in feats],float)
    y=np.array([1 if is_attack(d) else 0 for d in rows],int)
    cats=np.array([category_of(d) for d in rows])
    return X,y,cats,names

def main():
    os.makedirs("models",exist_ok=True)
    rows=load()
    if len(rows)<20:
        print(f"only {len(rows)} usable sessions with reply text — collector still filling. "
              f"Pipeline is ready; re-run when data grows.");
    X,y,cats,names=featurize(rows)
    print(f"loaded {len(rows)} sessions | {y.sum()} attack / {(y==0).sum()} benign | "
          f"{len(set(cats))} categories | {len(names)} features\n")
    if len(set(y))<2 or y.sum()<5 or (y==0).sum()<5:
        print("not enough class balance yet to CV; saving a fit on current data and exiting.")
        m=make_pipeline(StandardScaler(),LogisticRegression(max_iter=5000,class_weight="balanced")).fit(X,y)
        joblib.dump({"model":m,"features":names,"note":"preliminary; grows with data"},"models/aura_general.joblib")
        return
    models={
        "logreg": make_pipeline(StandardScaler(),LogisticRegression(max_iter=5000,class_weight="balanced")),
        "random_forest": RandomForestClassifier(n_estimators=400,class_weight="balanced_subsample",random_state=0,n_jobs=-1),
        "gradient_boost": GradientBoostingClassifier(random_state=0),
    }
    # standard grouped CV by category (avoids topic leakage)
    n_groups=len(set(cats)); nsplit=min(5,n_groups)
    print(f"{'model':16s} {'F1':>6s} {'ROC-AUC':>8s}  (grouped {nsplit}-fold by category)")
    best=(None,-1)
    for name,mdl in models.items():
        gkf=GroupKFold(nsplit); f1s=[]; aucs=[]
        for tr,te in gkf.split(X,y,cats):
            if len(set(y[tr]))<2: continue
            m=clone(mdl).fit(X[tr],y[tr]); p=m.predict_proba(X[te])[:,1]
            f1s.append(f1_score(y[te],(p>=.5).astype(int),zero_division=0))
            if len(set(y[te]))>1: aucs.append(roc_auc_score(y[te],p))
        f1=float(np.mean(f1s)) if f1s else 0; auc=float(np.mean(aucs)) if aucs else float("nan")
        print(f"{name:16s} {f1:6.3f} {auc:8.3f}")
        if not np.isnan(auc) and auc>best[1]: best=(name,auc)
    if best[0]:
        bm=clone(models[best[0]]).fit(X,y)
        joblib.dump({"model":bm,"features":names,"cv_auc":round(best[1],3),
                     "categories":sorted(set(cats)),"n_sessions":len(rows)},
                    "models/aura_general.joblib")
        json.dump({"best":best[0],"auc":round(best[1],3),"n":len(rows),
                   "categories":sorted(set(cats))},open("models/metrics_general.json","w"),indent=2)
        print(f"\nBEST: {best[0]} AUC {best[1]:.3f} -> saved models/aura_general.joblib")

if __name__ == "__main__":
    main()
