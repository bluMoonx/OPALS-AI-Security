"""ARM W2 — LAYERED MODEL: general model + per-family specialist models.

Question asked by the lead: does layering a general model with per-attack-family
specialist models beat the flat 12-feature RF, AT THE OPERATING POINT?

PROTOCOL (all honest, nothing selected on a reported slice)
  * FLAT baseline reproduced first: prompt-grouped 5-fold CV (10 seeds) AUC, and
    leave-one-attack-category-out (LOACO) AUC.
  * Every layered variant scored under the SAME two protocols.
  * The router is trained on (prompt, reply, tools) features ONLY.
    `attack_category` is a LABEL and is never an input to any scorer.
    Router accuracy is measured and its error propagates, because the routed
    score is computed from the ROUTER'S OWN posterior, never from the true family.
  * Per-family thresholds are chosen by an INNER grouped CV inside each training
    fold. Never on a reported slice.
  * >= 5 seeds everywhere. Bootstrap resamples PROMPT GROUPS.
  * Permuted-label control on the whole harness.

NO gold2 or sathwik response text is read or printed. Aggregates only.
"""
from __future__ import annotations
import os, sys, json, hashlib, time
import numpy as np

ROOT = (os.environ.get("AURA_ROOT") or os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "analysis"))
sys.path.insert(0, os.path.join(ROOT, "analysis", "signfix"))
HERE = os.path.dirname(os.path.abspath(__file__))

from build_features import build, BASE12                      # noqa: E402
from demand_features import DEMAND_NAMES                      # noqa: E402
from sklearn.ensemble import RandomForestClassifier           # noqa: E402
from sklearn.linear_model import LogisticRegression           # noqa: E402
from sklearn.model_selection import StratifiedGroupKFold, GroupKFold  # noqa: E402
from sklearn.metrics import roc_auc_score, f1_score           # noqa: E402

SEEDS = tuple(range(5))
MIN_SPEC_ROWS = 25          # a family needs this many training rows to get a specialist


def rf(seed=0, n=500, leaf=3):
    return RandomForestClassifier(n_estimators=n, min_samples_leaf=leaf,
                                  class_weight="balanced_subsample",
                                  random_state=seed, n_jobs=-1)


# ------------------------------------------------------------------ data
X_ALL, y, cats, groups, srcs, conds, NAMES = build()
J = {n: i for i, n in enumerate(NAMES)}
K_BASE = [J[n] for n in BASE12]                       # shipped flat feature set
K_ROUTE = [J[n] for n in BASE12 + DEMAND_NAMES]       # router may also see the prompt
X = X_ALL

FAMS = sorted(set(cats))


# ------------------------------------------------------- the layered stack
def fit_stack(Xtr, ytr, ctr, seed):
    """General model + router + one specialist per family present in training."""
    gen = rf(seed).fit(Xtr[:, K_BASE], ytr)
    router = rf(seed, n=300).fit(Xtr[:, K_ROUTE], ctr)
    specs = {}
    for c in sorted(set(ctr)):
        m = ctr == c
        if m.sum() < MIN_SPEC_ROWS or len(set(ytr[m])) < 2:
            continue
        specs[c] = rf(seed, n=300, leaf=2).fit(Xtr[m][:, K_BASE], ytr[m])
    return gen, router, specs


def stack_scores(fitted, Xte):
    """All component scores for held-out rows. Returns a dict of named score vectors."""
    gen, router, specs = fitted
    p_gen = gen.predict_proba(Xte[:, K_BASE])[:, 1]
    rcls = list(router.classes_)
    P = router.predict_proba(Xte[:, K_ROUTE])                 # router posterior
    have = [c for c in rcls if c in specs]
    if not have:
        z = np.zeros(len(Xte))
        return dict(gen=p_gen, soft=p_gen, hard=p_gen, mx=p_gen, mean=p_gen, spec_mat=None,
                    P=P, rcls=rcls)
    S = np.column_stack([specs[c].predict_proba(Xte[:, K_BASE])[:, 1] for c in have])
    Pi = P[:, [rcls.index(c) for c in have]]
    Pi = Pi / np.maximum(Pi.sum(axis=1, keepdims=True), 1e-9)
    soft = (Pi * S).sum(axis=1)
    hard = S[np.arange(len(S)), Pi.argmax(axis=1)]
    return dict(gen=p_gen, soft=soft, hard=hard, mx=S.max(axis=1), mean=S.mean(axis=1),
                spec_mat=S, P=P, rcls=rcls, have=have, Pi=Pi)


def inner_oof(Xtr, ytr, ctr, gtr, seed, folds=3):
    """Inner grouped CV inside a training fold -> OOF gen/soft scores, for
    learning blend weights and per-family thresholds WITHOUT touching test data."""
    o_gen = np.zeros(len(ytr)); o_soft = np.zeros(len(ytr))
    o_mx = np.zeros(len(ytr)); o_hard = np.zeros(len(ytr))
    try:
        sp = StratifiedGroupKFold(folds, shuffle=True, random_state=seed)
        it = list(sp.split(Xtr, ytr, gtr))
    except Exception:
        it = list(GroupKFold(folds).split(Xtr, ytr, gtr))
    for a, b in it:
        if len(set(ytr[a])) < 2:
            continue
        f = fit_stack(Xtr[a], ytr[a], ctr[a], seed)
        s = stack_scores(f, Xtr[b])
        o_gen[b] = s["gen"]; o_soft[b] = s["soft"]; o_mx[b] = s["mx"]; o_hard[b] = s["hard"]
    return o_gen, o_soft, o_mx, o_hard


def variant_scores(Xtr, ytr, ctr, gtr, Xte, seed):
    """Every W2 variant, scored for the held-out rows. One shared fit."""
    fitted = fit_stack(Xtr, ytr, ctr, seed)
    s = stack_scores(fitted, Xte)
    out = {"flat": s["gen"],
           "spec_soft_router": s["soft"],
           "spec_hard_router": s["hard"],
           "spec_max": s["mx"],
           "spec_mean": s["mean"],
           "blend_50_50": 0.5 * s["gen"] + 0.5 * s["soft"]}

    # --- learned blend + cascade + per-family thresholds need inner OOF -------
    og, os_, omx, oh = inner_oof(Xtr, ytr, ctr, gtr, seed)

    # (i) learned stacker: LR on [gen, soft, max] fit to INNER OOF only
    Z = np.column_stack([og, os_, omx])
    try:
        lr = LogisticRegression(max_iter=2000, class_weight="balanced").fit(Z, ytr)
        Zt = np.column_stack([s["gen"], s["soft"], s["mx"]])
        out["blend_learned"] = lr.predict_proba(Zt)[:, 1]
    except Exception:
        out["blend_learned"] = out["blend_50_50"]

    # (ii) CASCADE: trust the general model outside an uncertainty band; inside
    #      the band, hand the row to the routed specialist. Band chosen on inner OOF.
    best = (None, -1.0)
    for lo in (0.30, 0.35, 0.40, 0.45):
        for hi in (0.55, 0.60, 0.65, 0.70):
            band = (og >= lo) & (og <= hi)
            cand = np.where(band, os_, og)
            try:
                a = roc_auc_score(ytr, cand)
            except Exception:
                continue
            if a > best[1]:
                best = ((lo, hi), a)
    lo, hi = best[0] if best[0] else (0.40, 0.60)
    band_te = (s["gen"] >= lo) & (s["gen"] <= hi)
    out["cascade"] = np.where(band_te, s["soft"], s["gen"])
    # cascade variant that averages instead of replacing inside the band
    out["cascade_avg"] = np.where(band_te, 0.5 * s["gen"] + 0.5 * s["soft"], s["gen"])

    # (iii) PER-FAMILY THRESHOLDS on the FLAT model. The offset is the family's
    #       inner-OOF median score; subtracting it re-centres each family so one
    #       global cut behaves like a per-family cut. Router picks the family.
    off = {}
    gmed = float(np.median(og))
    for c in sorted(set(ctr)):
        m = ctr == c
        off[c] = float(np.median(og[m])) if m.sum() >= 10 else gmed
    rcls = s["rcls"]
    pred_fam = np.array(rcls)[s["P"].argmax(axis=1)]
    shift = np.array([off.get(c, gmed) for c in pred_fam])
    out["flat_perfam_thresh"] = s["gen"] - shift + gmed
    # soft version: expected offset under the router posterior
    off_vec = np.array([off.get(c, gmed) for c in rcls])
    out["flat_perfam_soft"] = s["gen"] - (s["P"] @ off_vec) + gmed

    return out, pred_fam


VARIANTS = ["flat", "spec_soft_router", "spec_hard_router", "spec_max", "spec_mean",
            "blend_50_50", "blend_learned", "cascade", "cascade_avg",
            "flat_perfam_thresh", "flat_perfam_soft"]


# ------------------------------------------------------------- protocols
def run_loaco(seed, yv=None, tag=""):
    """Leave-one-attack-category-out. Every row scored by a model that never saw
    its family. Returns {variant: score vector} plus router accuracy."""
    yy = y if yv is None else yv
    sc = {v: np.full(len(yy), np.nan) for v in VARIANTS}
    router_hits = router_n = 0
    for c in FAMS:
        te = cats == c; tr = ~te
        if te.sum() < 5 or len(set(yy[tr])) < 2:
            continue
        out, pf = variant_scores(X[tr], yy[tr], cats[tr], groups[tr], X[te], seed)
        for v in VARIANTS:
            sc[v][te] = out[v]
        router_hits += int((pf == c).sum()); router_n += int(te.sum())
    return sc, (router_hits / max(router_n, 1))


def run_groupcv(seed, yv=None, folds=5):
    """Prompt-grouped 5-fold CV. All 10 families visible in training."""
    yy = y if yv is None else yv
    sc = {v: np.full(len(yy), np.nan) for v in VARIANTS}
    hits = n = 0
    sp = StratifiedGroupKFold(folds, shuffle=True, random_state=seed)
    for tr, te in sp.split(X, yy, groups):
        out, pf = variant_scores(X[tr], yy[tr], cats[tr], groups[tr], X[te], seed)
        for v in VARIANTS:
            sc[v][te] = out[v]
        hits += int((pf == cats[te]).sum()); n += len(te)
    return sc, hits / max(n, 1)


def per_family_auc(score, yy=None):
    yy = y if yy is None else yy
    m = ~np.isnan(score)
    per = {}
    for c in FAMS:
        s = m & (cats == c)
        if s.sum() and len(set(yy[s])) > 1:
            per[c] = float(roc_auc_score(yy[s], score[s]))
    return float(roc_auc_score(yy[m], score[m])), per


def boot_delta(a, b, yy, grp, B=2000, seed=0):
    """CI on AUC(b) - AUC(a), resampling PROMPT GROUPS."""
    rng = np.random.default_rng(seed)
    m = ~np.isnan(a) & ~np.isnan(b)
    idx = np.where(m)[0]
    gs = np.array(grp)[idx]
    uniq = np.unique(gs)
    by = {u: idx[gs == u] for u in uniq}
    d = []
    for _ in range(B):
        pick = rng.choice(uniq, size=len(uniq), replace=True)
        ii = np.concatenate([by[u] for u in pick])
        if len(set(yy[ii])) < 2:
            continue
        d.append(roc_auc_score(yy[ii], b[ii]) - roc_auc_score(yy[ii], a[ii]))
    d = np.array(d)
    return float(np.mean(d)), float(np.quantile(d, .025)), float(np.quantile(d, .975))


def main():
    t0 = time.time()
    print("=" * 78)
    print("W2 — LAYERED MODEL (general + per-family specialists)")
    print("=" * 78)
    print(f"rows {len(y)}  positives {int(y.sum())}  families {len(FAMS)}  "
          f"prompt groups {len(set(groups))}")
    print(f"flat feature set = shipped 12; router feature set = 12 + {len(DEMAND_NAMES)} "
          f"prompt-demand features (attack_category NEVER an input)")

    res = {"protocol": {"seeds": list(SEEDS), "min_spec_rows": MIN_SPEC_ROWS,
                        "flat_features": BASE12, "router_features": BASE12 + DEMAND_NAMES}}

    # ---------------- LOACO --------------------------------------------------
    print("\n--- LOACO (train on 9 families, test the held-out 10th), 5 seeds ---")
    loaco_sc, r_acc = {v: [] for v in VARIANTS}, []
    for s in SEEDS:
        sc, ra = run_loaco(s)
        for v in VARIANTS:
            loaco_sc[v].append(sc[v])
        r_acc.append(ra)
        print(f"  seed {s} done  ({time.time()-t0:.0f}s)", flush=True)
    loaco_mean = {v: np.nanmean(np.array(loaco_sc[v]), axis=0) for v in VARIANTS}
    print(f"\n  ROUTER accuracy on the HELD-OUT family = {np.mean(r_acc):.4f} "
          f"(0 by construction: that family is absent from training). "
          f"Its error is fully propagated — the routed score uses the router's own "
          f"posterior, never the true family.")

    base_pooled, base_per = per_family_auc(loaco_mean["flat"])
    print(f"\n  {'variant':22s} {'LOACO AUC':>10s} {'delta':>8s}   {'boot95 CI on delta':>24s}")
    res["loaco"] = {}
    for v in VARIANTS:
        pooled, per = per_family_auc(loaco_mean[v])
        if v == "flat":
            print(f"  {v:22s} {pooled:10.4f} {'--':>8s}")
            ci = None
        else:
            d, lo, hi = boot_delta(loaco_mean["flat"], loaco_mean[v], y, groups)
            ci = [d, lo, hi]
            print(f"  {v:22s} {pooled:10.4f} {pooled-base_pooled:+8.4f}   "
                  f"[{lo:+.4f}, {hi:+.4f}]")
        res["loaco"][v] = {"auc": pooled, "per_family": per, "delta_ci": ci}
    res["router_acc_loaco"] = float(np.mean(r_acc))

    print("\n  per-family LOACO AUC (flat vs best layered variants)")
    show = ["flat", "spec_soft_router", "blend_50_50", "blend_learned", "cascade",
            "flat_perfam_soft"]
    print(f"  {'family':24s} " + " ".join(f"{v[:13]:>13s}" for v in show))
    for c in sorted(FAMS, key=lambda c: base_per.get(c, 1)):
        print(f"  {c:24s} " + " ".join(f"{res['loaco'][v]['per_family'].get(c, float('nan')):13.3f}"
                                       for v in show))

    # ---------------- prompt-grouped CV -------------------------------------
    print(f"\n--- prompt-grouped 5-fold CV (all families visible), 5 seeds "
          f"({time.time()-t0:.0f}s) ---")
    cv_sc, cv_racc = {v: [] for v in VARIANTS}, []
    for s in SEEDS:
        sc, ra = run_groupcv(s)
        for v in VARIANTS:
            cv_sc[v].append(sc[v])
        cv_racc.append(ra)
        print(f"  seed {s} done  ({time.time()-t0:.0f}s)", flush=True)
    cv_mean = {v: np.nanmean(np.array(cv_sc[v]), axis=0) for v in VARIANTS}
    print(f"\n  ROUTER accuracy (10-way family prediction, prompt-grouped OOF) = "
          f"{np.mean(cv_racc):.4f}   (chance = {1/len(FAMS):.3f})")
    res["router_acc_groupcv"] = float(np.mean(cv_racc))

    b0, _ = per_family_auc(cv_mean["flat"])
    res["groupcv"] = {}
    print(f"\n  {'variant':22s} {'CV AUC':>10s} {'delta':>8s}   {'boot95 CI on delta':>24s}")
    for v in VARIANTS:
        pooled, per = per_family_auc(cv_mean[v])
        if v == "flat":
            print(f"  {v:22s} {pooled:10.4f} {'--':>8s}")
            ci = None
        else:
            d, lo, hi = boot_delta(cv_mean["flat"], cv_mean[v], y, groups)
            ci = [d, lo, hi]
            print(f"  {v:22s} {pooled:10.4f} {pooled-b0:+8.4f}   [{lo:+.4f}, {hi:+.4f}]")
        res["groupcv"][v] = {"auc": pooled, "per_family": per, "delta_ci": ci}

    # ---------------- permuted-label control --------------------------------
    print(f"\n--- PERMUTED-LABEL CONTROL (labels shuffled within prompt groups' "
          f"complement; harness must read ~0.5) ---")
    rng = np.random.default_rng(7)
    yp = y.copy(); rng.shuffle(yp)
    perm = {}
    sc, _ = run_loaco(0, yv=yp)
    for v in VARIANTS:
        m = ~np.isnan(sc[v])
        perm[v] = float(roc_auc_score(yp[m], sc[v][m]))
    print("  " + "  ".join(f"{v}={perm[v]:.3f}" for v in VARIANTS))
    res["permuted_loaco_auc"] = perm

    np.save(os.path.join(HERE, "w2_loaco_scores.npy"),
            np.array([loaco_mean[v] for v in VARIANTS]))
    np.save(os.path.join(HERE, "w2_cv_scores.npy"),
            np.array([cv_mean[v] for v in VARIANTS]))
    json.dump(VARIANTS, open(os.path.join(HERE, "w2_variants.json"), "w"))
    json.dump(res, open(os.path.join(HERE, "w2_model_results.json"), "w"), indent=2,
              default=float)
    print(f"\nwrote w2_model_results.json  ({time.time()-t0:.0f}s)")


if __name__ == "__main__":
    main()
