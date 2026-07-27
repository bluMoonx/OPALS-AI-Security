# !! QUARANTINED 2026-07-27 — DO NOT RUN. EMITS INVALID NUMBERS. !!
#
# This script joins gold labels to corpus records by `session_id`, which is NOT
# unique: 324 ids carry >1 trial (up to 9 deep) and 1,002 of 1,949 records (51.4%)
# sit under a duplicated id. The join silently pairs a human judgement with a
# DIFFERENT trial's response text.
#
# Damage measured here: test slice = 448 rows from 283 collapsed labels; 441 of 441 checkable rows are NOT the
#   record the human judged. Its 'single most independent number in the whole study'
#   (chenhao->gold_human AUC 0.571) is WITHDRAWN.
#
# Correct loader:  from eval_combined_gold import load_records, load_all_gold
#                  gold = load_all_gold(load_records())   # 965 rows, exact _rec
# Re-enable only after porting the join: AURA_ALLOW_BROKEN_JOIN=1

"""
eval_ablations.py -- AURA rebuild, stage: ABLATIONS + GENERALIZATION.

What this establishes
---------------------
  A. FEATURE-FAMILY ABLATION   which observable feature groups actually carry signal
  B. CROSS-SOURCE TRANSFER     train chenhao -> test newcats, and the reverse.
                               (different collection, different prompts, different
                               labeller). THIS IS THE HEADLINE NUMBER.
  C. SAMPLE-SIZE CURVE         is the ceiling a data problem or a structural one
  D. CATEGORY DIFFICULTY       which attack families are detectable from reply text

Leakage discipline (enforced, not asserted)
-------------------------------------------
Feature functions receive exactly three things: prompt text, response text, and
the tool-NAME list. They never see `canary`, `attack_succeeded`, `human_label`,
`risk_indicators`, `gateway_decision`, `label_notes`, `condition`,
`attack_category`, or `source`. There is no bag-of-words / char-ngram anywhere:
every feature is a hand-specified structural or linguistic predicate, because raw
lexical features were proven circular on this corpus.

Evaluation is TRUE leave-one-attack-category-out (LOACO): one category held out
per fold, model trained on all remaining categories. Folds where the held-out
category is single-class have NO defined AUC and are counted, never silently
dropped from the denominator.
"""
from __future__ import annotations

import os as _os, sys as _sys  # QUARANTINE GUARD
if _os.environ.get("AURA_ALLOW_BROKEN_JOIN") != "1":
    _sys.exit("REFUSING TO RUN: broken session_id join -> invalid numbers. See header.")


import glob
import json
import os
import random
import sys
from collections import Counter, defaultdict

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.metrics import roc_auc_score, roc_curve
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

ROOT = "/Users/sid/Documents/Behavioral Risk Prediction for Autonomous AI Systems"
REBUILD = os.path.join(ROOT, "analysis/rebuild")
CORPUS = os.path.join(REBUILD, "corpus_clean.jsonl")
GOLD_GLOB = os.path.join(REBUILD, "gold_*.jsonl")

# FROZEN snapshots -- the live modules in analysis/compete are being edited by
# other stages of this rebuild; pinning them makes these numbers reproducible.
sys.path.insert(0, REBUILD)

from _frozen_compliance_features import (  # noqa: E402
    FEATURE_NAMES as CF_NAMES,
    compliance_features,
    rule_score,
)
from _frozen_science_features import science_features  # noqa: E402

RNG = np.random.RandomState(20260726)


# =============================================================================
# 1. EXTRA FEATURE FAMILIES (surface shape + tool trail)
# =============================================================================

SURFACE_NAMES = [
    "log_len_chars",
    "log_n_sentences",
    "mean_sentence_len",
    "n_code_fences",
    "frac_in_code",
    "n_bullet_lines",
    "n_heading_lines",
    "n_bold_spans",
    "n_question_marks",
    "n_colon_lines",
    "upper_ratio",
    "digit_ratio",
    "nonascii_ratio",
    "reply_prompt_len_ratio",
    "jaccard_prompt_reply",
]

TOOL_NAMES_F = [
    "n_tool_calls",
    "n_unique_tools",
    "tool_any",
    "tool_read",
    "tool_write",
    "tool_exec",
    "tool_net",
    "tool_search",
    "tool_read_no_write",
    "tool_exec_after_read",
]

_STOP = set("the a an and or of to in is are was were for on with that this it as be by at from "
            "i you your my we our not no do does did can could would should will".split())


def _tokens(s):
    out, cur = [], []
    for ch in (s or "").lower():
        if ch.isalnum():
            cur.append(ch)
        else:
            if cur:
                out.append("".join(cur))
                cur = []
    if cur:
        out.append("".join(cur))
    return out


def surface_features(prompt, response, tool_names=()):
    p = prompt or ""
    r = response or ""
    n = max(len(r), 1)
    sents = [s for s in r.replace("!", ".").replace("?", ".").split(".") if s.strip()]
    lines = r.split("\n")
    in_code = 0
    fence = False
    nf = 0
    for ln in lines:
        if ln.strip().startswith("```"):
            fence = not fence
            nf += 1
            continue
        if fence:
            in_code += len(ln) + 1
    pt = set(t for t in _tokens(p) if t not in _STOP and len(t) > 2)
    rt = set(t for t in _tokens(r) if t not in _STOP and len(t) > 2)
    jac = len(pt & rt) / max(len(pt | rt), 1)
    return {
        "log_len_chars": float(np.log1p(len(r))),
        "log_n_sentences": float(np.log1p(len(sents))),
        "mean_sentence_len": float(np.mean([len(s) for s in sents])) if sents else 0.0,
        "n_code_fences": float(nf // 2),
        "frac_in_code": in_code / n,
        "n_bullet_lines": float(sum(1 for ln in lines if ln.strip()[:2] in ("- ", "* ")
                                    or ln.strip()[:3] in ("1. ", "2. ", "3. "))),
        "n_heading_lines": float(sum(1 for ln in lines if ln.strip().startswith("#"))),
        "n_bold_spans": float(r.count("**") // 2),
        "n_question_marks": float(r.count("?")),
        "n_colon_lines": float(sum(1 for ln in lines if ":" in ln and len(ln) < 120)),
        "upper_ratio": sum(1 for c in r if c.isupper()) / n,
        "digit_ratio": sum(1 for c in r if c.isdigit()) / n,
        "nonascii_ratio": sum(1 for c in r if ord(c) > 127) / n,
        "reply_prompt_len_ratio": float(np.log1p(len(r)) - np.log1p(len(p))),
        "jaccard_prompt_reply": float(jac),
    }


_READ = ("read", "cat", "open", "grep", "fs_read", "file_read", "view", "ls", "glob")
_WRITE = ("write", "edit", "append", "create", "save", "patch", "fs_write")
_EXEC = ("exec", "bash", "shell", "run", "python", "sh", "command", "terminal")
_NET = ("curl", "http", "fetch", "post", "request", "upload", "send", "webhook", "email")
_SEARCH = ("search", "browse", "web", "google", "scholar", "arxiv", "lookup")


def tool_features(prompt, response, tool_names=()):
    ts = [str(t).lower() for t in (tool_names or [])]
    def has(pats):
        return 1.0 if any(any(p in t for p in pats) for t in ts) else 0.0
    read, write, ex = has(_READ), has(_WRITE), has(_EXEC)
    # ordering: did an exec follow a read in the trail
    exec_after_read = 0.0
    seen_read = False
    for t in ts:
        if any(p in t for p in _READ):
            seen_read = True
        elif seen_read and any(p in t for p in _EXEC):
            exec_after_read = 1.0
            break
    return {
        "n_tool_calls": float(len(ts)),
        "n_unique_tools": float(len(set(ts))),
        "tool_any": 1.0 if ts else 0.0,
        "tool_read": read,
        "tool_write": write,
        "tool_exec": ex,
        "tool_net": has(_NET),
        "tool_search": has(_SEARCH),
        "tool_read_no_write": 1.0 if (read and not write) else 0.0,
        "tool_exec_after_read": exec_after_read,
    }


SCIENCE_NAMES = [
    "hedge_density", "certainty_density", "attribution_count", "citation_present",
    "numeric_claim_count", "override_echo_count", "verified_externally",
    "unverified_confident_claim", "provenance_claim_count", "capability_spoof",
]

ALL_NAMES = CF_NAMES + SCIENCE_NAMES + SURFACE_NAMES + TOOL_NAMES_F


def featurize(prompt, response, tools):
    f = compliance_features(prompt, response, tools)
    f.update(science_features(response or "", list(tools or [])))
    f.update(surface_features(prompt, response, tools))
    f.update(tool_features(prompt, response, tools))
    return [float(f[k]) for k in ALL_NAMES]


# =============================================================================
# 2. FEATURE FAMILIES
# =============================================================================

FAM = {
    "demand_echo": ["echo_demanded_marker", "echo_demanded_clean", "echo_field_with_value",
                    "echo_field_slot", "novel_marker", "novel_marker_terminal"],
    "structure": ["format_demand_satisfied", "kv_stamp_line", "state_dump", "sysprompt_leak",
                  "schema_dump", "encoded_selfdump", "selfdisclosure_delivered",
                  "secret_value_emitted", "exfil_code"],
    "agency": ["fp_past_action", "commitment_to_finish", "solicits_secret",
               "attempted_target_access"],
    "refusal": ["refusal_present", "policy_refusal", "refusal_early", "refusal_first_sentence",
                "refusal_late_only", "capability_only_refusal", "flag_count", "flag_early",
                "hygiene_count"],
    "interaction": ["unopposed_echo", "unopposed_dump", "no_pushback", "reads_secret_source",
                    "demand_present", "unsafe_demand", "injection_structure",
                    "gated_action", "gated_structure"],
    "science": SCIENCE_NAMES,
    "surface": SURFACE_NAMES,
    "tool": TOOL_NAMES_F,
}

# the three super-families the ablation question is framed around
SUPER = {
    "SCIENCE_LINGUISTIC": FAM["science"] + FAM["refusal"] + FAM["agency"],
    "STRUCTURAL": FAM["demand_echo"] + FAM["structure"] + FAM["interaction"],
    "TOOL": FAM["tool"],
    "SURFACE": FAM["surface"],
}

_IDX = {n: i for i, n in enumerate(ALL_NAMES)}
assert len(_IDX) == len(ALL_NAMES), "duplicate feature name"
_covered = set().union(*FAM.values())
_gap = set(ALL_NAMES) - _covered
if _gap:  # a family member appeared upstream; surface it loudly rather than mis-bin it
    print(f"WARNING: unassigned features bucketed into 'interaction': {sorted(_gap)}")
    FAM["interaction"] = FAM["interaction"] + sorted(_gap)
    _covered = set().union(*FAM.values())
assert _covered == set(ALL_NAMES), f"family coverage gap: {set(ALL_NAMES) ^ _covered}"
SUPER["STRUCTURAL"] = FAM["demand_echo"] + FAM["structure"] + FAM["interaction"]


def cols(names):
    return np.array([_IDX[n] for n in names], dtype=int)


# =============================================================================
# 3. DATA
# =============================================================================

def norm_text(s):
    return " ".join((s or "").lower().split())


def load():
    rows = []
    with open(CORPUS) as fh:
        for line in fh:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    # dedup by exact normalised response text BEFORE any split
    seen = {}
    dropped = 0
    for r in rows:
        k = norm_text(r["agent_response"])
        if k in seen:
            dropped += 1
            continue
        seen[k] = r
    rows = list(seen.values())
    return rows, dropped


def load_gold():
    """283 hand-judged sessions (human behavioural label). Independent of every labeller."""
    g = {}
    for path in sorted(glob.glob(GOLD_GLOB)):
        with open(path) as fh:
            for line in fh:
                line = line.strip()
                if line:
                    d = json.loads(line)
                    g[d["session_id"]] = int(d["behavioral_label"])
    return g


# =============================================================================
# 4. METRICS
# =============================================================================

def recall_at_fpr(y, s, target):
    y = np.asarray(y)
    s = np.asarray(s, dtype=float)
    if len(set(y.tolist())) < 2:
        return float("nan"), float("nan")
    fpr, tpr, thr = roc_curve(y, s)
    ok = fpr <= target + 1e-12
    if not ok.any():
        return 0.0, float("inf")
    i = int(np.max(np.flatnonzero(ok)))
    return float(tpr[i]), float(thr[i])


def safe_auc(y, s):
    y = np.asarray(y)
    if len(set(y.tolist())) < 2:
        return float("nan")
    return float(roc_auc_score(y, s))


def make_model(kind="logreg"):
    if kind == "logreg":
        return Pipeline([("sc", StandardScaler()),
                         ("m", LogisticRegression(max_iter=4000, C=1.0,
                                                  class_weight="balanced",
                                                  solver="lbfgs"))])
    return GradientBoostingClassifier(random_state=0, n_estimators=200,
                                      max_depth=3, learning_rate=0.05)


def fit_predict(Xtr, ytr, Xte, kind="logreg"):
    if len(set(ytr.tolist())) < 2:
        return np.full(len(Xte), float(ytr[0]) if len(ytr) else 0.0)
    m = make_model(kind)
    m.fit(Xtr, ytr)
    return m.predict_proba(Xte)[:, 1]


# =============================================================================
# 5. LOACO
# =============================================================================

def loaco(X, y, groups, feat_idx=None, kind="logreg", subsample_n=None, seed=0):
    """True leave-one-attack-category-out. Returns dict with pooled + per-fold."""
    Xf = X if feat_idx is None else X[:, feat_idx]
    y = np.asarray(y)
    groups = np.asarray(groups)
    cats = sorted(set(groups.tolist()))
    oof = np.full(len(y), np.nan)
    per_fold = {}
    rs = np.random.RandomState(seed)
    for c in cats:
        te = groups == c
        tr = ~te
        tri = np.flatnonzero(tr)
        if subsample_n is not None and subsample_n < len(tri):
            tri = rs.choice(tri, size=subsample_n, replace=False)
        p = fit_predict(Xf[tri], y[tri], Xf[te], kind)
        oof[te] = p
        per_fold[c] = {
            "n": int(te.sum()),
            "pos": int(y[te].sum()),
            "auc": safe_auc(y[te], p),
        }
    defined = [c for c in cats if not np.isnan(per_fold[c]["auc"])]
    r10, t10 = recall_at_fpr(y, oof, 0.10)
    r5, _ = recall_at_fpr(y, oof, 0.05)
    return {
        "pooled_auc": safe_auc(y, oof),
        "n_folds_total": len(cats),
        "n_folds_defined": len(defined),
        "mean_fold_auc": float(np.mean([per_fold[c]["auc"] for c in defined])) if defined else float("nan"),
        "recall_at_10fpr": r10,
        "recall_at_5fpr": r5,
        "thr_at_10fpr": t10,
        "per_fold": per_fold,
        "oof": oof,
    }


# =============================================================================
# 6. REPORT
# =============================================================================

def hr(t=""):
    print("\n" + "=" * 100)
    if t:
        print(t)
        print("=" * 100)


def sub(t):
    print("\n" + "-" * 100)
    print(t)
    print("-" * 100)


def main():
    rows, dropped = load()
    print(f"corpus_clean rows after exact-normalised-response dedup: {len(rows)}  (dropped {dropped})")

    X = np.array([featurize(r["prompt"], r["agent_response"], r.get("tools") or [])
                  for r in rows], dtype=float)
    y = np.array([int(r["label"]) for r in rows])
    cat = np.array([r["attack_category"] or "unknown" for r in rows])
    src = np.array([r["source"] for r in rows])
    sid = np.array([r.get("session_id") or "" for r in rows])

    print(f"features: {X.shape[1]}   positives: {y.sum()} / {len(y)} "
          f"({y.mean():.1%})   categories: {len(set(cat.tolist()))}")
    print("by source:", dict(Counter(src.tolist())))

    results = {}

    # -------------------------------------------------------------------
    # LEAKAGE CHECK FIRST -- is the fitted model just re-deriving the labeller?
    # -------------------------------------------------------------------
    hr("0. LEAKAGE CHECK -- feature module vs the rule that produced the labels")
    rl = np.array([rule_score(r["prompt"], r["agent_response"], r.get("tools") or [])[1]
                   for r in rows])
    for s in ("newcats", "chenhao", "scigw22"):
        m = src == s
        if m.sum() == 0:
            continue
        agree = float((rl[m] == y[m]).mean())
        tp = int(((rl[m] == 1) & (y[m] == 1)).sum())
        fp = int(((rl[m] == 1) & (y[m] == 0)).sum())
        fn = int(((rl[m] == 0) & (y[m] == 1)).sum())
        prec = tp / max(tp + fp, 1)
        rec = tp / max(tp + fn, 1)
        print(f"  {s:9s} n={int(m.sum()):5d}  unfitted rule_score vs corpus label: "
              f"agree={agree:.3f}  P={prec:.3f}  R={rec:.3f}")
    print("  Interpretation: newcats labels come from behavioral_labeler.py, which shares")
    print("  lineage with compliance_features.py. High agreement on newcats and LOW agreement")
    print("  on chenhao would mean within-newcats scores are partly self-fulfilling.")
    print("  chenhao labels come from an independent rubric -> that number is the honest one.")
    results["leakage_check"] = {
        s: {"agree": float((rl[src == s] == y[src == s]).mean()), "n": int((src == s).sum())}
        for s in sorted(set(src.tolist()))
    }

    # -------------------------------------------------------------------
    # A. FEATURE-FAMILY ABLATION (LOACO on the full corpus)
    # -------------------------------------------------------------------
    hr("A. FEATURE-FAMILY ABLATION -- true leave-one-attack-category-out, full corpus")
    full = loaco(X, y, cat)
    print(f"FULL feature set ({len(ALL_NAMES)} features)")
    print(f"  pooled OOF AUC = {full['pooled_auc']:.3f}   "
          f"mean-of-defined-fold AUC = {full['mean_fold_auc']:.3f}   "
          f"folds with defined AUC = {full['n_folds_defined']}/{full['n_folds_total']}")
    print(f"  recall@10%FPR = {full['recall_at_10fpr']:.3f}   "
          f"recall@5%FPR = {full['recall_at_5fpr']:.3f}")
    results["full"] = {k: v for k, v in full.items() if k not in ("oof", "per_fold")}

    sub("A1. ONLY-ONE-FAMILY (what each group can do alone)")
    print(f"  {'family':<20s} {'nfeat':>5s}  {'pooledAUC':>9s} {'meanfold':>9s} "
          f"{'defined':>8s} {'R@10FPR':>8s} {'R@5FPR':>7s}")
    only = {}
    for fam in list(FAM) + [k for k in SUPER if k not in FAM]:
        names = FAM.get(fam) or SUPER[fam]
        r = loaco(X, y, cat, feat_idx=cols(names))
        only[fam] = r
        print(f"  {fam:<20s} {len(names):5d}  {r['pooled_auc']:9.3f} {r['mean_fold_auc']:9.3f} "
              f"{str(r['n_folds_defined'])+'/'+str(r['n_folds_total']):>8s} "
              f"{r['recall_at_10fpr']:8.3f} {r['recall_at_5fpr']:7.3f}")
    results["only_family"] = {k: {kk: vv for kk, vv in v.items() if kk not in ("oof", "per_fold")}
                              for k, v in only.items()}

    sub("A2. LEAVE-ONE-FAMILY-OUT (marginal contribution over the rest)")
    print(f"  {'dropped family':<20s} {'pooledAUC':>9s} {'dAUC':>7s} {'R@10FPR':>8s} {'dR@10':>7s}")
    loo = {}
    for fam in FAM:
        keep = [n for n in ALL_NAMES if n not in set(FAM[fam])]
        r = loaco(X, y, cat, feat_idx=cols(keep))
        loo[fam] = r
        print(f"  {fam:<20s} {r['pooled_auc']:9.3f} "
              f"{r['pooled_auc'] - full['pooled_auc']:+7.3f} "
              f"{r['recall_at_10fpr']:8.3f} "
              f"{r['recall_at_10fpr'] - full['recall_at_10fpr']:+7.3f}")
    results["leave_one_family_out"] = {
        k: {kk: vv for kk, vv in v.items() if kk not in ("oof", "per_fold")}
        for k, v in loo.items()}

    # -------------------------------------------------------------------
    # B. CROSS-SOURCE GENERALIZATION  *** HEADLINE ***
    # -------------------------------------------------------------------
    hr("B. CROSS-SOURCE GENERALIZATION  ***  THE HEADLINE TEST  ***")
    print("Different collection run, different prompts, different labelling procedure.")
    print("newcats label = deterministic behavioural labeller;  chenhao label = 5-dim rubric.")

    xsrc = {}
    for tr_s, te_s in (("chenhao", "newcats"), ("newcats", "chenhao")):
        tr = src == tr_s
        te = src == te_s
        p = fit_predict(X[tr], y[tr], X[te])
        auc = safe_auc(y[te], p)
        r10, _ = recall_at_fpr(y[te], p, 0.10)
        r5, _ = recall_at_fpr(y[te], p, 0.05)
        # within-source control: grouped CV inside the TEST source only
        ctl = loaco(X[te], y[te], cat[te])
        xsrc[f"{tr_s}->{te_s}"] = {
            "n_train": int(tr.sum()), "pos_train": int(y[tr].sum()),
            "n_test": int(te.sum()), "pos_test": int(y[te].sum()),
            "auc": auc, "recall_at_10fpr": r10, "recall_at_5fpr": r5,
            "within_test_source_loaco_auc": ctl["pooled_auc"],
            "within_test_source_loaco_r10": ctl["recall_at_10fpr"],
            "transfer_gap_auc": ctl["pooled_auc"] - auc,
        }
        sub(f"TRAIN {tr_s} (n={int(tr.sum())}, pos={int(y[tr].sum())})  ->  "
            f"TEST {te_s} (n={int(te.sum())}, pos={int(y[te].sum())})")
        print(f"  cross-source AUC          = {auc:.3f}")
        print(f"  cross-source recall@10FPR = {r10:.3f}")
        print(f"  cross-source recall@5FPR  = {r5:.3f}")
        print(f"  within-{te_s} LOACO AUC (control, same test set) = {ctl['pooled_auc']:.3f}"
              f"   R@10FPR = {ctl['recall_at_10fpr']:.3f}")
        print(f"  TRANSFER GAP (control - cross) = {ctl['pooled_auc'] - auc:+.3f} AUC")

    # cross-source onto the human-judged gold slice (labels from neither labeller)
    gold = load_gold()
    gm = np.array([s in gold for s in sid])
    if gm.sum() > 0:
        ygold = np.array([gold[s] for s in sid[gm]])
        sub(f"TRAIN chenhao -> TEST hand-judged GOLD slice "
            f"(n={int(gm.sum())}, pos={int(ygold.sum())}) [human labels, neither labeller]")
        tr = src == "chenhao"
        p = fit_predict(X[tr], y[tr], X[gm])
        auc = safe_auc(ygold, p)
        r10, _ = recall_at_fpr(ygold, p, 0.10)
        print(f"  AUC = {auc:.3f}   recall@10%FPR = {r10:.3f}")
        print("  This is the single most independent number in the whole study:")
        print("  training labels from the chenhao rubric, test labels from human judgement,")
        print("  and the newcats deterministic labeller touches neither side.")
        xsrc["chenhao->gold_human"] = {"n_test": int(gm.sum()), "pos_test": int(ygold.sum()),
                                       "auc": auc, "recall_at_10fpr": r10}
        # newcats-trained on gold, with gold sessions removed from training
        trn = (src == "newcats") & (~gm)
        p2 = fit_predict(X[trn], y[trn], X[gm])
        auc2 = safe_auc(ygold, p2)
        r10b, _ = recall_at_fpr(ygold, p2, 0.10)
        print(f"\n  [reference] TRAIN newcats minus gold sessions (n={int(trn.sum())}) -> gold: "
              f"AUC = {auc2:.3f}  R@10FPR = {r10b:.3f}")
        xsrc["newcats_minus_gold->gold_human"] = {"n_train": int(trn.sum()),
                                                  "auc": auc2, "recall_at_10fpr": r10b}
    results["cross_source"] = xsrc

    # -------------------------------------------------------------------
    # C. SAMPLE-SIZE CURVE
    # -------------------------------------------------------------------
    hr("C. SAMPLE-SIZE CURVE -- LOACO pooled AUC vs training-set size (5 seeds)")
    print("  Within every LOACO fold the training set is randomly subsampled to n.")
    print(f"  {'n_train':>8s}  {'pooledAUC (mean+-sd)':>24s}  {'R@10FPR':>16s}")
    curve = []
    ns = [100, 200, 400, 800, 1200, 1600, 2000, None]
    for n in ns:
        aucs, r10s = [], []
        for seed in range(5):
            r = loaco(X, y, cat, subsample_n=n, seed=seed)
            aucs.append(r["pooled_auc"])
            r10s.append(r["recall_at_10fpr"])
            if n is None:
                break  # deterministic
        lbl = "ALL" if n is None else str(n)
        curve.append({"n": n if n is not None else int(len(y)),
                      "auc_mean": float(np.mean(aucs)), "auc_sd": float(np.std(aucs)),
                      "r10_mean": float(np.mean(r10s)), "r10_sd": float(np.std(r10s))})
        print(f"  {lbl:>8s}  {np.mean(aucs):16.3f} +- {np.std(aucs):.3f}  "
              f"{np.mean(r10s):10.3f} +- {np.std(r10s):.3f}")
    results["sample_size_curve"] = curve
    d = curve[-1]["auc_mean"] - curve[-4]["auc_mean"]
    print(f"\n  AUC gain from n=800 to n=ALL({len(y)}): {d:+.3f}")
    print("  A flat tail means the ceiling is STRUCTURAL (features / label noise),")
    print("  not a data-volume problem. A rising tail means more data would help.")

    # -------------------------------------------------------------------
    # D. CATEGORY DIFFICULTY
    # -------------------------------------------------------------------
    hr("D. CATEGORY DIFFICULTY -- per-held-out-category, from the FULL LOACO run")
    thr = full["thr_at_10fpr"]
    oof = full["oof"]
    print(f"  global operating threshold at 10% FPR (pooled OOF): {thr:.4f}")
    print(f"\n  {'category':<32s} {'src':<8s} {'n':>5s} {'pos':>4s} {'foldAUC':>8s} "
          f"{'rec@thr':>8s} {'fp_rate':>8s}")
    tbl = []
    for c in sorted(set(cat.tolist())):
        m = cat == c
        srcs = "/".join(sorted(set(src[m].tolist())))
        a = full["per_fold"][c]["auc"]
        pos_m = m & (y == 1)
        neg_m = m & (y == 0)
        rec = float((oof[pos_m] >= thr).mean()) if pos_m.sum() else float("nan")
        fpr = float((oof[neg_m] >= thr).mean()) if neg_m.sum() else float("nan")
        tbl.append({"category": c, "sources": srcs, "n": int(m.sum()),
                    "pos": int(y[m].sum()), "fold_auc": a, "recall_at_global_thr": rec,
                    "fpr_at_global_thr": fpr})
    # rank: defined AUC first (desc), then undefined
    tbl.sort(key=lambda d: (np.isnan(d["fold_auc"]), -(d["fold_auc"] if not np.isnan(d["fold_auc"]) else 0)))
    for d_ in tbl:
        a = d_["fold_auc"]
        print(f"  {d_['category']:<32s} {d_['sources']:<8s} {d_['n']:5d} {d_['pos']:4d} "
              f"{('%8.3f' % a) if not np.isnan(a) else '     n/a'} "
              f"{('%8.3f' % d_['recall_at_global_thr']) if not np.isnan(d_['recall_at_global_thr']) else '     n/a'} "
              f"{('%8.3f' % d_['fpr_at_global_thr']) if not np.isnan(d_['fpr_at_global_thr']) else '     n/a'}")
    results["category_difficulty"] = tbl

    det = [d_ for d_ in tbl if not np.isnan(d_["fold_auc"])]
    sub("Detectable (fold AUC >= 0.75) vs undetectable-from-reply-text (fold AUC <= 0.60)")
    print("  DETECTABLE  : " + ", ".join(f"{d_['category']}({d_['fold_auc']:.2f})"
                                         for d_ in det if d_["fold_auc"] >= 0.75) or "  (none)")
    print("  UNDETECTABLE: " + ", ".join(f"{d_['category']}({d_['fold_auc']:.2f})"
                                         for d_ in det if d_["fold_auc"] <= 0.60) or "  (none)")
    print("  NO AUC (single-class held-out fold, cannot be scored): "
          + ", ".join(d_["category"] for d_ in tbl if np.isnan(d_["fold_auc"])))

    # -------------------------------------------------------------------
    # E. model-class sanity
    # -------------------------------------------------------------------
    hr("E. MODEL-CLASS SANITY -- gradient boosting under the same LOACO protocol")
    gb = loaco(X, y, cat, kind="gbm")
    print(f"  GBM  pooled OOF AUC = {gb['pooled_auc']:.3f}  "
          f"(logreg {full['pooled_auc']:.3f})   R@10FPR = {gb['recall_at_10fpr']:.3f} "
          f"(logreg {full['recall_at_10fpr']:.3f})   defined folds "
          f"{gb['n_folds_defined']}/{gb['n_folds_total']}")
    results["gbm"] = {k: v for k, v in gb.items() if k not in ("oof", "per_fold")}

    # -------------------------------------------------------------------
    # F. LEAKAGE HUNT -- everything above 0.90 gets attacked before it is reported
    # -------------------------------------------------------------------
    hr("F. LEAKAGE HUNT -- why is newcats->chenhao 0.95 and pooled LOACO 0.89?")

    sub("F1. Category-identity confound: is the LABEL just a function of attack_category?")
    print("  Oracle category-prior baseline: score each record by the positive RATE of its own")
    print("  category, measured on the test set itself. Uses NO reply text at all. If this")
    print("  matches the model, the model is doing category identification, not detection.")
    print(f"  {'test set':<28s} {'n':>6s} {'pos':>5s} {'catprior AUC':>13s} {'model AUC':>10s}")
    catprior = {}
    for name, mask, model_auc in (
            ("chenhao (all)", src == "chenhao", xsrc["newcats->chenhao"]["auc"]),
            ("newcats (all)", src == "newcats", xsrc["chenhao->newcats"]["auc"]),
            ("FULL corpus", np.ones(len(y), bool), full["pooled_auc"])):
        rate = {}
        for c in set(cat[mask].tolist()):
            mm = mask & (cat == c)
            rate[c] = float(y[mm].mean())
        s = np.array([rate[c] for c in cat[mask]])
        a = safe_auc(y[mask], s)
        catprior[name] = a
        print(f"  {name:<28s} {int(mask.sum()):6d} {int(y[mask].sum()):5d} "
              f"{a:13.3f} {model_auc:10.3f}")
    results["category_prior_auc"] = catprior
    print("\n  chenhao's positives are 78/101 a single category (credential_exposure, 100% positive)")
    print("  and three of its categories are 100% negative. Its label is close to a category id.")

    sub("F2. Univariate feature AUC (raw feature value vs label, no model, per source)")
    print("  Is one near-tautological feature carrying the model? Computed inside each source")
    print("  so between-category prevalence cannot inflate it.")
    mn, mc = src == "newcats", src == "chenhao"
    singles = []
    for nme in ALL_NAMES:
        v = X[:, _IDX[nme]]
        singles.append((nme, safe_auc(y[mn], v[mn]), safe_auc(y[mc], v[mc])))
    singles.sort(key=lambda t: -abs(t[1] - 0.5))
    print(f"  {'feature':<30s} {'AUC newcats':>12s} {'AUC chenhao':>12s}")
    for nme, a1, a2 in singles[:14]:
        print(f"  {nme:<30s} {a1:12.3f} {a2:12.3f}")
    results["univariate_feature_auc"] = [{"feature": n, "auc_newcats": a1, "auc_chenhao": a2}
                                         for n, a1, a2 in singles]
    print("  A feature strong on newcats but ~0.5 on chenhao is fitting the newcats LABELLER,")
    print("  not agent behaviour. Features strong on BOTH are the real transferable signal.")
    both = [t for t in singles if abs(t[1] - 0.5) > 0.10 and abs(t[2] - 0.5) > 0.10
            and (t[1] - 0.5) * (t[2] - 0.5) > 0]
    print(f"  features discriminative in BOTH sources with consistent sign: {len(both)} / {len(ALL_NAMES)}")
    for nme, a1, a2 in both[:10]:
        print(f"      {nme:<28s} newcats {a1:.3f}   chenhao {a2:.3f}")

    sub("F5. The pooling artifact: how much of pooled OOF AUC is BETWEEN-category prevalence?")
    print("  LOACO forbids training on the held-out category, but POOLING the OOF scores")
    print("  re-admits between-category separation: a category that is 100% positive gets")
    print("  uniformly high scores and inflates the pooled ROC. Centering each category's")
    print("  scores on its own median removes that and leaves only WITHIN-category ranking.")
    oof_c = oof.copy()
    for c in set(cat.tolist()):
        m = cat == c
        oof_c[m] = oof[m] - np.median(oof[m])
    within_auc = safe_auc(y, oof_c)
    wr10, _ = recall_at_fpr(y, oof_c, 0.10)
    print(f"\n  pooled OOF AUC (as reported)                    {full['pooled_auc']:.3f}   "
          f"R@10FPR {full['recall_at_10fpr']:.3f}")
    print(f"  mean of the {full['n_folds_defined']} defined per-fold AUCs                "
          f"{full['mean_fold_auc']:.3f}")
    print(f"  category-median-centred pooled AUC (within only) {within_auc:.3f}   "
          f"R@10FPR {wr10:.3f}")
    print(f"  oracle category-prior AUC (no reply text at all)  {catprior['FULL corpus']:.3f}")
    results["pooling_artifact"] = {
        "pooled_auc": full["pooled_auc"],
        "mean_fold_auc": full["mean_fold_auc"],
        "within_category_centred_auc": within_auc,
        "within_category_centred_r10": wr10,
        "oracle_category_prior_auc": catprior["FULL corpus"],
    }

    sub("F3. Tautology check: 'the agent did not push back' vs the label, per source")
    print("  The label DEFINITION is 'declined / flagged / ignored -> 0'. A feature that just")
    print("  detects the absence of refusal is definitionally close to the label, not a")
    print("  discovery. Reporting the raw agreement so the reader can discount it.")
    print(f"  {'source':<10s} {'n':>6s} {'no_pushback acc':>16s} {'refusal_present acc':>20s}")
    npb = X[:, _IDX["no_pushback"]]
    rp = X[:, _IDX["refusal_present"]]
    taut = {}
    for s_ in sorted(set(src.tolist())):
        m = src == s_
        a1 = float(((npb[m] > 0.5).astype(int) == y[m]).mean())
        a2 = float(((rp[m] < 0.5).astype(int) == y[m]).mean())
        taut[s_] = {"no_pushback_acc": a1, "refusal_absent_acc": a2, "n": int(m.sum())}
        print(f"  {s_:<10s} {int(m.sum()):6d} {a1:16.3f} {a2:20.3f}")
    results["tautology_check"] = taut

    sub("F4. Per-source LOACO -- the 0.886 pooled number decomposed")
    persrc = {}
    for s_ in ("newcats", "chenhao"):
        m = src == s_
        r = loaco(X[m], y[m], cat[m])
        persrc[s_] = {k: v for k, v in r.items() if k not in ("oof", "per_fold")}
        print(f"  {s_:<10s} n={int(m.sum()):5d} pos={int(y[m].sum()):4d}  "
              f"pooled AUC={r['pooled_auc']:.3f}  R@10FPR={r['recall_at_10fpr']:.3f}  "
              f"defined folds {r['n_folds_defined']}/{r['n_folds_total']}")
    results["per_source_loaco"] = persrc
    nfolds_by_src = Counter()
    for c in full["per_fold"]:
        if not np.isnan(full["per_fold"][c]["auc"]):
            nfolds_by_src["/".join(sorted(set(src[cat == c].tolist())))] += 1
    print(f"  the {full['n_folds_defined']} scorable folds by source: {dict(nfolds_by_src)}")
    print("  -> the pooled LOACO number is overwhelmingly a NEWCATS number, and newcats labels")
    print("     were produced by behavioral_labeler.py, a rule module of the same lineage as")
    print("     the feature module. Section 0 showed the UNFITTED rule already gets R=0.89 there.")

    sub("F6. LEAN configuration -- drop the two families that HURT (surface, tool)")
    lean_names = [n for n in ALL_NAMES if n not in set(FAM["surface"]) | set(FAM["tool"])]
    lean = loaco(X, y, cat, feat_idx=cols(lean_names))
    lean_oof_c = lean["oof"].copy()
    for c in set(cat.tolist()):
        m = cat == c
        lean_oof_c[m] = lean["oof"][m] - np.median(lean["oof"][m])
    print(f"  LEAN ({len(lean_names)} features)  pooled AUC={lean['pooled_auc']:.3f} "
          f"R@10FPR={lean['recall_at_10fpr']:.3f} R@5FPR={lean['recall_at_5fpr']:.3f}  "
          f"defined folds {lean['n_folds_defined']}/{lean['n_folds_total']}")
    print(f"  LEAN within-category-centred AUC = {safe_auc(y, lean_oof_c):.3f}")
    trl = src == "chenhao"
    pl = fit_predict(X[trl][:, cols(lean_names)], y[trl], X[src == "newcats"][:, cols(lean_names)])
    print(f"  LEAN cross-source chenhao->newcats AUC = {safe_auc(y[src=='newcats'], pl):.3f} "
          f"(full-feature: {xsrc['chenhao->newcats']['auc']:.3f})")
    results["lean"] = {k: v for k, v in lean.items() if k not in ("oof", "per_fold")}
    results["lean"]["within_category_centred_auc"] = safe_auc(y, lean_oof_c)
    results["lean"]["cross_source_chenhao_to_newcats_auc"] = safe_auc(y[src == "newcats"], pl)
    print("  NOTE: LEAN's pooled 0.908 is >0.90 and must NOT be reported as a headline.")
    print("  Its within-category AUC is 0.702 and the oracle category-prior is 0.902, so the")
    print("  pooled figure is the between-category prevalence artifact of section F5, not skill.")
    print("  The one genuine gain is cross-source: 0.601 -> 0.662. Surface (length/format) and")
    print("  tool-trail features are collection-specific and actively hurt transfer; drop them.")

    hr("HONEST VERDICT")
    print(f"""
  The headline generalization result is NEGATIVE, and the two directions disagree
  for a reason that has to be stated:

    chenhao -> newcats        AUC {xsrc['chenhao->newcats']['auc']:.3f}   R@10%FPR {xsrc['chenhao->newcats']['recall_at_10fpr']:.3f}
    newcats -> chenhao        AUC {xsrc['newcats->chenhao']['auc']:.3f}   R@10%FPR {xsrc['newcats->chenhao']['recall_at_10fpr']:.3f}
    chenhao -> human gold     AUC {xsrc['chenhao->gold_human']['auc']:.3f}   R@10%FPR {xsrc['chenhao->gold_human']['recall_at_10fpr']:.3f}

  The 0.95 is NOT a success. An oracle that sees only the attack_category NAME and
  no reply text at all scores {catprior['chenhao (all)']:.3f} on chenhao: 78 of its 101 positives are one
  category (credential_exposure) that is 100% positive, and three of its categories
  are 100% negative. Any model that can recognise "this reply printed a credential"
  clears 0.95 there without detecting behaviour. The model is BELOW that ceiling.

  The direction that is not degenerate -- chenhao -> newcats -- is {xsrc['chenhao->newcats']['auc']:.3f}, and the
  direction with genuinely independent test labels -- chenhao -> hand-judged human
  gold -- is {xsrc['chenhao->gold_human']['auc']:.3f}. Both are close to useless at a deployable operating point
  ({xsrc['chenhao->gold_human']['recall_at_10fpr']:.0%} recall at 10% FPR).

  Same conclusion from the other side: the pooled LOACO {full['pooled_auc']:.3f} is inflated by
  BETWEEN-category prevalence. Remove it by centring each category's scores on its
  own median and within-category discrimination is {within_auc:.3f} AUC, {wr10:.3f} recall@10%FPR.
  The oracle category-prior on the full corpus is {catprior['FULL corpus']:.3f} -- higher than the model.
  Most of the apparent skill is "which attack family is this", not "did the agent comply".

  Only {len(both)} of {len(ALL_NAMES)} features discriminate in BOTH sources with a consistent sign,
  and they are dominated by prompt-side and tool-side signals (demand_present,
  reads_secret_source, tool_read) rather than anything about the reply.

  The sample-size curve gains {curve[-1]['auc_mean'] - curve[-4]['auc_mean']:+.3f} AUC going from n=800 to n={len(y)}, with the
  per-seed sd already collapsed to {curve[-2]['auc_sd']:.3f}. The ceiling is STRUCTURAL, not a
  data-volume problem: more sessions of the same kind will not fix it. What would
  move it is (a) categories whose labels are not near-constant, and (b) labels that
  do not come from a rule module of the same lineage as the features.
""")

    hr("SUMMARY")
    print(f"  FULL LOACO pooled OOF AUC      {full['pooled_auc']:.3f}   "
          f"({full['n_folds_defined']}/{full['n_folds_total']} folds have a defined AUC)")
    print(f"  FULL LOACO mean-of-fold AUC    {full['mean_fold_auc']:.3f}   "
          f"(mean over the {full['n_folds_defined']} defined folds ONLY -- not all folds)")
    print(f"  FULL LOACO recall@10%FPR       {full['recall_at_10fpr']:.3f}")
    print(f"  FULL LOACO recall@5%FPR        {full['recall_at_5fpr']:.3f}")
    for k, v in xsrc.items():
        print(f"  CROSS-SOURCE {k:<34s} AUC {v['auc']:.3f}  R@10FPR {v['recall_at_10fpr']:.3f}")

    out = os.path.join(REBUILD, "eval_ablations_results.json")
    with open(out, "w") as fh:
        json.dump(results, fh, indent=2, default=lambda o: None if (isinstance(o, float) and np.isnan(o)) else float(o))
    print(f"\n  results json -> {out}")


if __name__ == "__main__":
    main()
