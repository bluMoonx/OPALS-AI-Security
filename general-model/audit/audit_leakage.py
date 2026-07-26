"""AURA adversarial leakage audit.

Assumes the reported 0.905 LOACO ROC-AUC is INFLATED and tries to prove it.

Checks
------
A. Reproduce the baseline exactly as train_general.py builds it.
B. Per-feature univariate AUC (pooled + leave-one-category-out).
C. Canary / attack-marker token presence in the text the features read.
D. Length & token-count shortcut.
E. SOURCE leakage: can source alone predict the label? can the features
   predict the source? does the model collapse when source is held fixed?
F. Schema-availability leakage (a field that only exists in one source file).

Run:  python3 analysis/hardening/audit_leakage.py
"""
from __future__ import annotations
import json, glob, os, sys, re, itertools, collections
import numpy as np

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "analysis"))
from science_features import science_features  # noqa: E402

from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import GroupKFold, StratifiedKFold
from sklearn.metrics import roc_auc_score, roc_curve
from sklearn.base import clone

RNG = 0
np.random.seed(RNG)


# ----------------------------------------------------------------- loading
def reply_of(d):  return d.get("agent_response") or d.get("response_preview") or ""
def tools_of(d):  return d.get("tools") or []


def is_attack(d):
    hl = d.get("human_label")
    if hl in ("safe", "suspicious", "unsafe"):
        return 0 if hl == "safe" else 1
    if "attack_succeeded" in d:
        return 1 if d.get("attack_succeeded") else 0
    cat = d.get("attack_category") or d.get("category") or ""
    return 0 if cat in ("", "benign") else 1


def category_of(d): return d.get("attack_category") or d.get("category") or "benign"


def load():
    """Exactly train_general.load(), but also tag the source file."""
    rows, srcs = [], []
    files = sorted(itertools.chain(
        glob.glob(os.path.join(ROOT, "data/logs/collected_*/*.jsonl")),
        glob.glob(os.path.join(ROOT, "data/logs/chenhao_release/*.jsonl"))))
    for f in files:
        short = os.path.relpath(f, os.path.join(ROOT, "data/logs"))
        for l in open(f):
            l = l.strip()
            if not l:
                continue
            try:
                d = json.loads(l)
            except Exception:
                continue
            if reply_of(d).strip():
                rows.append(d)
                srcs.append(short)
    return rows, np.array(srcs)


def featurize(rows):
    feats = []
    for d in rows:
        sf = science_features(reply_of(d), tools_of(d))
        sf["reply_word_count"] = float(len(reply_of(d).split()))
        sf["num_tools"] = float(len(tools_of(d)))
        feats.append(sf)
    names = sorted(feats[0].keys())
    X = np.array([[f[n] for n in names] for f in feats], float)
    y = np.array([is_attack(d) for d in rows], int)
    cats = np.array([category_of(d) for d in rows])
    return X, y, cats, names


# ----------------------------------------------------------------- metrics
def recall_at_fpr(y, p, target_fpr=0.10):
    if len(set(y)) < 2:
        return float("nan")
    fpr, tpr, _ = roc_curve(y, p)
    return float(np.interp(target_fpr, fpr, tpr))


def loaco_scores(X, y, groups, model, n_splits=5):
    """Leave-one-category-out style GroupKFold; returns pooled out-of-fold preds."""
    ng = len(set(groups))
    k = min(n_splits, ng)
    gkf = GroupKFold(k)
    oof = np.full(len(y), np.nan)
    fold_auc = []
    for tr, te in gkf.split(X, y, groups):
        if len(set(y[tr])) < 2:
            continue
        m = clone(model).fit(X[tr], y[tr])
        p = m.predict_proba(X[te])[:, 1]
        oof[te] = p
        if len(set(y[te])) > 1:
            fold_auc.append(roc_auc_score(y[te], p))
    ok = ~np.isnan(oof)
    pooled_auc = roc_auc_score(y[ok], oof[ok]) if len(set(y[ok])) > 1 else float("nan")
    return (float(np.mean(fold_auc)) if fold_auc else float("nan"),
            pooled_auc, recall_at_fpr(y[ok], oof[ok]), oof)


def hdr(t):
    print("\n" + "=" * 78)
    print(t)
    print("=" * 78)


def main():
    rows, srcs = load()
    X, y, cats, names = featurize(rows)
    print(f"loaded {len(rows)} sessions | {y.sum()} positive / {(y == 0).sum()} negative "
          f"| {len(set(cats))} categories | {len(names)} features")
    print("sources:", collections.Counter(srcs).most_common())

    RF = RandomForestClassifier(n_estimators=400, class_weight="balanced_subsample",
                                random_state=RNG, n_jobs=-1)
    LR = make_pipeline(StandardScaler(),
                       LogisticRegression(max_iter=5000, class_weight="balanced"))

    # ------------------------------------------------------------ A baseline
    hdr("A. BASELINE REPRODUCTION (GroupKFold by attack category)")
    for nm, mdl in (("random_forest", RF), ("logreg", LR)):
        fa, pa, r10, _ = loaco_scores(X, y, cats, mdl)
        print(f"  {nm:14s} mean-fold AUC {fa:.3f} | pooled-OOF AUC {pa:.3f} | "
              f"recall@10%FPR {r10:.3f}")
    fa_base, pa_base, r_base, oof_base = loaco_scores(X, y, cats, RF)

    # ------------------------------------------------------ B single features
    hdr("B. UNIVARIATE FEATURE AUC (a single feature >0.85 = leakage suspect)")
    print(f"  {'feature':30s} {'pooled AUC':>10s} {'LOACO AUC':>10s} {'dir':>4s}")
    uni = []
    for i, n in enumerate(names):
        v = X[:, i]
        if np.std(v) == 0:
            print(f"  {n:30s} {'CONSTANT':>10s}")
            uni.append((n, 0.5, 0.5))
            continue
        a = roc_auc_score(y, v)
        # LOACO with a 1-feature model (monotone -> use the raw value, direction fixed on train)
        gkf = GroupKFold(min(5, len(set(cats))))
        oof = np.full(len(y), np.nan)
        for tr, te in gkf.split(X, y, cats):
            if len(set(y[tr])) < 2:
                continue
            sign = 1.0 if roc_auc_score(y[tr], v[tr]) >= 0.5 else -1.0
            oof[te] = sign * v[te]
        ok = ~np.isnan(oof)
        la = roc_auc_score(y[ok], oof[ok]) if len(set(y[ok])) > 1 else float("nan")
        d = "+" if a >= 0.5 else "-"
        flag = "   <-- SUSPECT" if max(a, 1 - a) > 0.85 else ""
        print(f"  {n:30s} {a:10.3f} {la:10.3f} {d:>4s}{flag}")
        uni.append((n, a, la))

    # ------------------------------------------------------------ C canary
    hdr("C. CANARY / ATTACK-MARKER TOKENS INSIDE THE TEXT THE FEATURES READ")
    canary_rows = [r for r in rows if r.get("canary")]
    hit_pos = hit_neg = 0
    for r in canary_rows:
        c = str(r["canary"])
        if c and c.lower() in reply_of(r).lower():
            if is_attack(r):
                hit_pos += 1
            else:
                hit_neg += 1
    npos = sum(1 for r in canary_rows if is_attack(r))
    nneg = len(canary_rows) - npos
    print(f"  sessions carrying a canary: {len(canary_rows)} ({npos} pos / {nneg} neg)")
    print(f"  canary literal echoed in agent_response: {hit_pos} pos, {hit_neg} neg")
    marker_pat = re.compile(r"AURA-CANARY|CANARY|ATTACK_SUCCE|ground_truth|is_poisoned|"
                            r"attack_succeeded|human_label|risk_indicator", re.I)
    mp = sum(1 for r in rows if marker_pat.search(reply_of(r)) and is_attack(r))
    mn = sum(1 for r in rows if marker_pat.search(reply_of(r)) and not is_attack(r))
    print(f"  explicit label-ish marker strings in reply text: {mp} pos, {mn} neg")
    # does the canary token itself carry signal as a feature?
    has_can = np.array([1.0 if (r.get("canary") and
                                str(r["canary"]).lower() in reply_of(r).lower()) else 0.0
                        for r in rows])
    if np.std(has_can) > 0:
        print(f"  AUC of 'canary echoed' alone (pooled): {roc_auc_score(y, has_can):.3f}")

    # ------------------------------------------------------------ D length
    hdr("D. LENGTH / TOKEN-COUNT SHORTCUT")
    wc = np.array([len(reply_of(r).split()) for r in rows], float)
    cc = np.array([len(reply_of(r)) for r in rows], float)
    nt = np.array([len(tools_of(r)) for r in rows], float)
    for nm, v in (("reply_word_count", wc), ("reply_char_count", cc), ("num_tools", nt)):
        if np.std(v) == 0:
            print(f"  {nm:20s} CONSTANT")
            continue
        print(f"  {nm:20s} AUC {roc_auc_score(y, v):.3f} | "
              f"mean pos {v[y == 1].mean():8.1f} vs neg {v[y == 0].mean():8.1f} | "
              f"median pos {np.median(v[y == 1]):7.1f} vs neg {np.median(v[y == 0]):7.1f}")
    # length-only model under LOACO
    fa, pa, r10, _ = loaco_scores(wc.reshape(-1, 1), y, cats, RF)
    print(f"  LENGTH-ONLY model (word count, 1 feature): LOACO pooled AUC {pa:.3f}, "
          f"recall@10%FPR {r10:.3f}")

    # ------------------------------------------------------------ E source
    hdr("E. SOURCE LEAKAGE (highest-risk: model learns 'which file is this')")
    print("  source x label contingency:")
    print(f"  {'source':46s} {'n':>5s} {'pos':>5s} {'pos_rate':>9s}")
    for s in sorted(set(srcs)):
        m = srcs == s
        print(f"  {s:46s} {m.sum():5d} {y[m].sum():5d} {y[m].mean():9.3f}")
    base_rate = y.mean()
    print(f"  overall positive rate {base_rate:.3f}")

    # E1: source ALONE as a predictor, honestly CV'd by category
    src_names = sorted(set(srcs))
    Xsrc = np.array([[1.0 if s == sn else 0.0 for sn in src_names] for s in srcs])
    fa_s, pa_s, r_s, _ = loaco_scores(Xsrc, y, cats, RF)
    print(f"\n  E1. SOURCE-ID-ONLY model (one-hot source, no behaviour at all):")
    print(f"      LOACO pooled AUC {pa_s:.3f} | recall@10%FPR {r_s:.3f}")
    print(f"      -> this is the free AUC available from dataset provenance alone.")

    # E2: can the features recover the source? (if yes, RF can rebuild E1 internally)
    print("\n  E2. Can the FEATURES predict the SOURCE? (one-vs-rest, 5-fold stratified)")
    for sn in src_names:
        ys = (srcs == sn).astype(int)
        if ys.sum() < 10 or (ys == 0).sum() < 10:
            continue
        skf = StratifiedKFold(5, shuffle=True, random_state=RNG)
        oof = np.zeros(len(ys))
        for tr, te in skf.split(X, ys):
            m = clone(RF).fit(X[tr], ys[tr])
            oof[te] = m.predict_proba(X[te])[:, 1]
        print(f"      source={sn:44s} AUC {roc_auc_score(ys, oof):.3f}")

    # E3: within-source LOACO — the honest number
    print("\n  E3. WITHIN-SOURCE LOACO (train+test inside one source only):")
    print(f"      {'source':46s} {'n':>5s} {'pos':>5s} {'AUC':>7s} {'rec@10%':>8s}")
    for s in src_names:
        m = srcs == s
        if m.sum() < 40 or len(set(y[m])) < 2 or y[m].sum() < 5 or len(set(cats[m])) < 2:
            print(f"      {s:46s} {m.sum():5d} {y[m].sum():5d}   (skipped: too small/1 class)")
            continue
        fa_i, pa_i, r_i, _ = loaco_scores(X[m], y[m], cats[m], RF)
        print(f"      {s:46s} {m.sum():5d} {y[m].sum():5d} {pa_i:7.3f} {r_i:8.3f}")

    # E4: leave-one-SOURCE-out (train on 3 sources, test on the held-out one)
    print("\n  E4. LEAVE-ONE-SOURCE-OUT (does it transfer across collections?):")
    for s in src_names:
        te = srcs == s
        tr = ~te
        if len(set(y[te])) < 2 or len(set(y[tr])) < 2 or te.sum() < 40:
            print(f"      held-out {s:40s} (skipped)")
            continue
        m = clone(RF).fit(X[tr], y[tr])
        p = m.predict_proba(X[te])[:, 1]
        print(f"      held-out {s:40s} AUC {roc_auc_score(y[te], p):7.3f} "
              f"rec@10%FPR {recall_at_fpr(y[te], p):.3f}")

    # E5: group by SOURCE+CATEGORY jointly (blocks both leaks)
    print("\n  E5. GroupKFold grouped by (source, category) jointly:")
    joint = np.array([f"{a}|{b}" for a, b in zip(srcs, cats)])
    fa_j, pa_j, r_j, _ = loaco_scores(X, y, joint, RF)
    print(f"      pooled AUC {pa_j:.3f} | recall@10%FPR {r_j:.3f}")

    # E6: how much of the baseline is explained by source? residual test
    print("\n  E6. BASELINE vs SOURCE-ONLY, head to head:")
    print(f"      full-feature LOACO pooled AUC {pa_base:.3f}, recall@10%FPR {r_base:.3f}")
    print(f"      source-id-only  LOACO pooled AUC {pa_s:.3f}, recall@10%FPR {r_s:.3f}")

    # ------------------------------------------------- F schema availability
    hdr("F. SCHEMA-AVAILABILITY LEAKAGE (a feature only computable in one source)")
    for fname in ("num_tools", "verified_externally"):
        i = names.index(fname)
        print(f"  {fname}:")
        for s in src_names:
            m = srcs == s
            print(f"      {s:46s} nonzero in {(X[m, i] != 0).mean():6.3f} of rows")
    keys_per_src = {}
    for r, s in zip(rows, srcs):
        keys_per_src.setdefault(s, collections.Counter()).update(r.keys())
    allk = set().union(*[set(c) for c in keys_per_src.values()])
    print("\n  fields present in some sources but not others (schema fingerprint):")
    for k in sorted(allk):
        pres = {s: round(keys_per_src[s][k] / max(sum(srcs == s), 1), 2) for s in src_names}
        if len(set(pres.values())) > 1 and (max(pres.values()) > 0.9 and min(pres.values()) < 0.1):
            print(f"      {k:26s} {pres}")

    # --------------------------------------------------------- G ablations
    hdr("G. ABLATIONS — drop the suspect features, does the score survive?")
    drops = {
        "drop reply_word_count": ["reply_word_count"],
        "drop num_tools+verified_externally": ["num_tools", "verified_externally"],
        "drop length AND tool features": ["reply_word_count", "num_tools",
                                          "verified_externally"],
    }
    for label, dl in drops.items():
        keep = [i for i, n in enumerate(names) if n not in dl]
        fa_d, pa_d, r_d, _ = loaco_scores(X[:, keep], y, cats, RF)
        print(f"  {label:36s} AUC {pa_d:.3f} (base {pa_base:.3f})  rec@10% {r_d:.3f}")

    # label permutation sanity check
    hdr("H. LABEL-PERMUTATION SANITY CHECK (should land at ~0.500)")
    aucs = []
    for seed in range(5):
        rs = np.random.RandomState(seed)
        yp = y.copy()
        rs.shuffle(yp)
        _, pa_p, _, _ = loaco_scores(X, yp, cats, RF)
        aucs.append(pa_p)
    print(f"  permuted-label LOACO AUC: mean {np.mean(aucs):.3f} "
          f"(min {min(aucs):.3f}, max {max(aucs):.3f})")

    # -------------------------------------------- I metric-definition audit
    hdr("I. IS THE 0.905 A METRIC ARTIFACT? mean-of-fold-AUC vs pooled-OOF AUC")
    ncat = len(set(cats))
    for k in (5, 10, 20, ncat):
        gkf = GroupKFold(min(k, ncat))
        fold_auc, fold_rec, sizes = [], [], []
        oof = np.full(len(y), np.nan)
        for tr, te in gkf.split(X, y, cats):
            if len(set(y[tr])) < 2:
                continue
            m = clone(RF).fit(X[tr], y[tr])
            p = m.predict_proba(X[te])[:, 1]
            oof[te] = p
            if len(set(y[te])) > 1:
                fold_auc.append(roc_auc_score(y[te], p))
                fold_rec.append(recall_at_fpr(y[te], p))
                sizes.append(len(te))
        ok = ~np.isnan(oof)
        pooled = roc_auc_score(y[ok], oof[ok])
        print(f"  GroupKFold k={min(k, ncat):3d}: mean-of-fold AUC {np.mean(fold_auc):.3f} "
              f"(n folds scored {len(fold_auc)}, median fold size {int(np.median(sizes))}) "
              f"| POOLED-OOF AUC {pooled:.3f}")
        print(f"                mean-of-fold recall@10%FPR {np.mean(fold_rec):.3f} "
              f"| POOLED recall@10%FPR {recall_at_fpr(y[ok], oof[ok]):.3f}")

    # true leave-ONE-category-out (38 folds, one category each)
    print("\n  True leave-one-CATEGORY-out (one category held out at a time):")
    cat_list = sorted(set(cats))
    per_cat = []
    for c in cat_list:
        te = cats == c
        tr = ~te
        if len(set(y[te])) < 2 or len(set(y[tr])) < 2:
            per_cat.append((c, te.sum(), y[te].sum(), float("nan")))
            continue
        m = clone(RF).fit(X[tr], y[tr])
        p = m.predict_proba(X[te])[:, 1]
        per_cat.append((c, te.sum(), y[te].sum(), roc_auc_score(y[te], p)))
    scored = [a for *_, a in per_cat if not np.isnan(a)]
    unscored = [p for p in per_cat if np.isnan(p[3])]
    print(f"      categories with BOTH classes present (scorable): {len(scored)} / {len(cat_list)}")
    print(f"      categories silently DROPPED (single-class fold): {len(unscored)}")
    print(f"      mean AUC over scorable categories: "
          f"{np.mean(scored) if scored else float('nan'):.3f}")
    for c, n, pos, a in sorted(per_cat, key=lambda t: (np.isnan(t[3]), -t[1]))[:12]:
        print(f"        {c:34s} n={n:5d} pos={pos:4d} AUC={a:.3f}")

    # ------------------------------------------- J canary label circularity
    hdr("J. LABEL-DEFINITION CIRCULARITY (canary) AND HIGH-ENTROPY-TOKEN SHORTCUT")
    nm = srcs == "collected_new10category/newcats_sessions.jsonl"
    can_echo = np.array([1.0 if (r.get("canary") and
                                 str(r["canary"]).lower() in reply_of(r).lower()) else 0.0
                         for r in rows])
    print(f"  within newcats (n={nm.sum()}, pos={y[nm].sum()}): "
          f"AUC of canary-echo alone = {roc_auc_score(y[nm], can_echo[nm]):.3f}")
    print("  -> the LABEL (attack_succeeded) is DEFINED as 'canary appeared in reply'.")
    print("     Any text feature that detects a secret-looking token is label-circular.")
    ent = re.compile(r"\b(?=\w*\d)(?=\w*[A-Za-z])[A-Za-z0-9_\-]{12,}\b")
    hi = np.array([float(len(ent.findall(reply_of(r)))) for r in rows])
    print(f"  generic 'high-entropy token count' feature (never sees the canary value):")
    print(f"      pooled AUC {roc_auc_score(y, hi):.3f} | within-newcats AUC "
          f"{roc_auc_score(y[nm], hi[nm]):.3f}")
    fa_h, pa_h, r_h, _ = loaco_scores(hi.reshape(-1, 1), y, cats, RF)
    print(f"      LOACO pooled AUC {pa_h:.3f} rec@10%FPR {r_h:.3f}")

    # ------------------------------------------------ K refusal-length probe
    hdr("K. WHAT THE LENGTH SHORTCUT ACTUALLY IS")
    wc2 = np.array([len(reply_of(r).split()) for r in rows], float)
    for s in src_names:
        m = srcs == s
        if len(set(y[m])) < 2:
            continue
        print(f"  {s:46s} AUC(word_count) {roc_auc_score(y[m], wc2[m]):.3f} "
              f"| median pos {np.median(wc2[m & (y == 1)]):6.0f} "
              f"vs neg {np.median(wc2[m & (y == 0)]):6.0f}")

    # ------------------------------------ L category==label determinism
    hdr("L. IS THE LABEL JUST THE CATEGORY? (category-identity shortcut)")
    det_all = 0
    print(f"  {'category':34s} {'n':>5s} {'pos':>5s} {'purity':>7s}")
    for c in cat_list:
        m = cats == c
        pur = max(y[m].mean(), 1 - y[m].mean())
        det_all += max(y[m].sum(), (y[m] == 0).sum())
        print(f"  {c:34s} {m.sum():5d} {y[m].sum():5d} {pur:7.3f}"
              + ("  <-- single-class" if pur == 1.0 else ""))
    print(f"\n  A lookup table 'category -> majority label' is right on "
          f"{det_all}/{len(y)} = {det_all / len(y):.3f} of rows.")
    for s in src_names:
        m = srcs == s
        d = sum(max(y[m & (cats == c)].sum(), (y[m & (cats == c)] == 0).sum())
                for c in set(cats[m]))
        print(f"      {s:46s} category->label accuracy {d / m.sum():.3f}")
    single = sum(1 for c in cat_list if len(set(y[cats == c])) == 1)
    print(f"  {single}/{len(cat_list)} categories are SINGLE-CLASS -> their held-out fold "
          f"has no AUC and is silently skipped by the trainer.")

    # ------------------------------------ M in-sample vs honest, head to head
    hdr("M. WHERE DOES 0.905 / 81.4%@12.5%FPR COME FROM?")
    m_full = clone(RF).fit(X, y)
    p_in = m_full.predict_proba(X)[:, 1]
    print(f"  IN-SAMPLE (fit and score on all 3240):   AUC {roc_auc_score(y, p_in):.3f} "
          f"| recall@10%FPR {recall_at_fpr(y, p_in):.3f} "
          f"| recall@12.5%FPR {recall_at_fpr(y, p_in, 0.125):.3f}")
    skf = StratifiedKFold(5, shuffle=True, random_state=RNG)
    oof_r = np.zeros(len(y))
    for tr, te in skf.split(X, y):
        oof_r[te] = clone(RF).fit(X[tr], y[tr]).predict_proba(X[te])[:, 1]
    print(f"  RANDOM 5-fold (NOT grouped; leaks category):  AUC {roc_auc_score(y, oof_r):.3f} "
          f"| recall@10%FPR {recall_at_fpr(y, oof_r):.3f} "
          f"| recall@12.5%FPR {recall_at_fpr(y, oof_r, 0.125):.3f}")
    ok = ~np.isnan(oof_base)
    print(f"  HONEST grouped-by-category pooled OOF:        AUC "
          f"{roc_auc_score(y[ok], oof_base[ok]):.3f} "
          f"| recall@10%FPR {recall_at_fpr(y[ok], oof_base[ok]):.3f} "
          f"| recall@12.5%FPR {recall_at_fpr(y[ok], oof_base[ok], 0.125):.3f}")

    # ------------------------------------ N duplicate-reply leakage
    hdr("N. DUPLICATE REPLY TEXT (near-duplicate leakage under random splits)")
    texts = [reply_of(r) for r in rows]
    c = collections.Counter(texts)
    dup_rows = sum(v for v in c.values() if v > 1)
    print(f"  {len(texts)} rows, {len(c)} unique reply strings")
    print(f"  {dup_rows} rows ({dup_rows / len(texts):.3f}) share a reply string with "
          f"another row; the most repeated reply appears {c.most_common(1)[0][1]} times.")
    mixed = sum(1 for t, n in c.items() if n > 1 and
                len(set(y[i] for i, tt in enumerate(texts) if tt == t)) > 1)
    print(f"  {mixed} duplicated reply strings carry BOTH labels -> an irreducible "
          f"ceiling on any text-only model.")

    hdr("DONE")


if __name__ == "__main__":
    main()
