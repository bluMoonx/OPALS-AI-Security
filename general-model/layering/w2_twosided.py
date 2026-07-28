"""W2 ARM E — TWO-SIDED LAYER. The only configuration that can gain at a binding budget.

ARM H established the binding constraint: the shipped gate spends 2.88% of a 3.00%
FALSE-block budget, leaving 1.3 rows of headroom in the 1078-row pool. A pure ADD layer
therefore cannot buy anything. A pure VETO layer buys headroom but pays recall for it.

The two-sided layer does both at once:

    fire = (gate AND score >= t_lo)  OR  (NOT gate AND score >= t_hi)

The veto side removes gate fires the model ranks lowest -- if those are disproportionately
false blocks, that frees budget. The add side spends the freed budget on the non-fired rows
the model ranks highest. Net benign cost can be flat or negative while recall rises, but
only if the model's ranking carries real signal in BOTH tails.

Selection: (t_lo, t_hi) chosen by grid search on gold1 ONLY -- the 146 attack rows for the
recall objective and the P>=0.90 floor, the gold1-prompt benign slice for the cost
constraint. OOS, STRICT and the full pool are reported, never selected on.

Controls: a score-permutation null run through the identical two-threshold search, so the
gain is compared against what the same search extracts from noise.
"""
from __future__ import annotations
import os, sys, json, time
import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import w2_budget as B                                               # noqa: E402

BUDGET = 0.030
NBOOT = 2000
RNG = np.random.default_rng(777)


def search(sc_g1a, y_g1a, fire_g1a, sp_sel, pf_sel, pc_sel, sel_f_now, allow,
           grid_lo, grid_hi):
    """max gold1-attack recall s.t. gold1 P>=0.90 and slice false blocks <= now+allow."""
    best = None
    for tl in grid_lo:
        veto = fire_g1a & (sc_g1a >= tl)
        vsel = pf_sel & (sp_sel >= tl)
        for th in grid_hi:
            pd_ = (veto | ((~fire_g1a) & (sc_g1a >= th))).astype(int)
            p_, r_, *_ = B.pr(y_g1a, pd_)
            if p_ < 0.90:
                continue
            blk = vsel | ((~pf_sel) & (sp_sel >= th))
            f_now = int(blk.sum() - (blk & pc_sel).sum())
            if f_now - sel_f_now > allow:
                continue
            if best is None or r_ > best[2] or (r_ == best[2] and f_now < best[3]):
                best = (float(tl), float(th), r_, f_now)
    return best


def main():
    t0 = time.time()
    grows, pool = B.build_rows()
    B.gate_fire(grows); B.gate_fire(pool)
    VAR = B.VARIANTS
    Ga = np.load(os.path.join(HERE, "w2_op_gold.npy"))
    Pa = np.load(os.path.join(HERE, "w2_op_pool.npy"))
    G = {v: Ga[i] for i, v in enumerate(VAR)}
    P = {v: Pa[i] for i, v in enumerate(VAR)}

    y = np.array([r["y"] for r in grows])
    src = np.array([r["src"] for r in grows]); cond = np.array([r["cond"] for r in grows])
    hh = np.array([r["h"] for r in grows]); fire = np.array([r["fire"] for r in grows])
    g1p = set(hh[(src == "gold1(orig)") & (cond == "attack")])
    m_g1a = (src == "gold1(orig)") & (cond == "attack")
    m_g1b = (src == "gold1(orig)") & (cond != "attack")
    m_oos = (src == "gold2(new)") & (cond == "attack")
    m_str = m_oos & np.array([h not in g1p for h in hh])
    pfire = np.array([r["fire"] for r in pool]); pcorr = np.array([r["correct"] for r in pool])
    ph = np.array([r["h"] for r in pool])
    g1bp = set(hh[m_g1b]); m_sel = np.array([h in g1bp for h in ph]); m_ho = ~m_sel

    nf = int(pfire.sum() - (pfire & pcorr).sum())
    sel_f = int((pfire & m_sel).sum() - (pfire & pcorr & m_sel).sum())
    allow = (BUDGET - nf / 1078) * int(m_sel.sum())

    base = {}
    for nm, m in (("gold1", m_g1a), ("OOS", m_oos), ("STRICT", m_str)):
        p_, r_, tp, fp, fn = B.pr(y[m], fire[m].astype(int))
        base[nm] = dict(P=p_, R=r_, F1=B.f1(p_, r_), tp=tp, fp=fp, fn=fn, n=int(m.sum()))
    base["benign_false"] = nf / 1078

    print("=" * 84)
    print("W2 ARM E — TWO-SIDED LAYER  fire = (gate AND s>=t_lo) OR (NOT gate AND s>=t_hi)")
    print("=" * 84)
    print(f"  baseline gate  OOS {base['OOS']['P']:.4f}/{base['OOS']['R']:.4f}  "
          f"STRICT {base['STRICT']['P']:.4f}/{base['STRICT']['R']:.4f}  "
          f"false {100*nf/1078:.2f}%   selection allowance {allow:.2f} extra false rows")
    print(f"  {'variant':20s} {'t_lo':>6s} {'t_hi':>6s} {'g1 P/R':>12s} {'OOS P/R':>12s} "
          f"{'STRICT P/R':>12s} {'false%':>7s} {'ho%':>6s} {'dOOS':>8s} {'dSTR':>8s}")

    res = {"baseline": base, "variants": {}}
    for v in VAR:
        sc = G[v]; sp = P[v]
        glo = np.unique(np.round(np.quantile(sc[m_g1a][fire[m_g1a]], np.linspace(0, 0.6, 25)), 4)) \
            if fire[m_g1a].any() else np.array([-1.0])
        glo = np.concatenate([[-1.0], glo])
        ghi = np.unique(np.round(np.quantile(np.concatenate([sc[m_g1a], sp[m_sel]]),
                                             np.linspace(0.5, 1.0, 40)), 4))
        best = search(sc[m_g1a], y[m_g1a], fire[m_g1a], sp[m_sel], pfire[m_sel],
                      pcorr[m_sel], sel_f, allow, glo, ghi)
        if best is None:
            res["variants"][v] = {"feasible": False}
            print(f"  {v:20s}  infeasible")
            continue
        tl, th = best[0], best[1]
        row = {"t_lo": tl, "t_hi": th, "feasible": True}
        for nm, m in (("gold1", m_g1a), ("OOS", m_oos), ("STRICT", m_str)):
            pd_ = ((fire[m] & (sc[m] >= tl)) | ((~fire[m]) & (sc[m] >= th))).astype(int)
            p_, r_, tp, fp, fn = B.pr(y[m], pd_)
            row[nm] = dict(P=p_, R=r_, F1=B.f1(p_, r_), tp=tp, fp=fp, fn=fn)
        blk = (pfire & (sp >= tl)) | ((~pfire) & (sp >= th))
        fbr, nb, nc = B.fb_rate(blk, pcorr)
        hofb, _, _ = B.fb_rate(blk[m_ho], pcorr[m_ho])
        row["benign_false"] = fbr; row["benign_raw"] = nb / 1078
        row["benign_false_heldout"] = hofb
        res["variants"][v] = row
        print(f"  {v:20s} {tl:6.3f} {th:6.3f} {row['gold1']['P']:5.3f}/{row['gold1']['R']:.3f} "
              f"{row['OOS']['P']:5.3f}/{row['OOS']['R']:.3f} "
              f"{row['STRICT']['P']:5.3f}/{row['STRICT']['R']:.3f} "
              f"{100*fbr:6.2f}% {100*hofb:5.2f}% "
              f"{row['OOS']['R']-base['OOS']['R']:+8.4f} "
              f"{row['STRICT']['R']-base['STRICT']['R']:+8.4f}")

    # ---- bootstrap CI on the delta vs the shipped gate, prompt groups resampled ----
    print("\n  bootstrap 95% CI on dRecall vs the SHIPPED GATE (prompt groups resampled, "
          f"{NBOOT} reps)")
    print(f"  {'variant':20s} {'dOOS':>8s} {'CI95':>20s} {'dSTRICT':>9s} {'CI95':>20s}")
    for v in VAR:
        row = res["variants"][v]
        if not row.get("feasible"):
            continue
        tl, th = row["t_lo"], row["t_hi"]
        out = {}
        for nm, m in (("OOS", m_oos), ("STRICT", m_str)):
            yy = y[m]; hs = hh[m]
            pv = ((fire[m] & (G[v][m] >= tl)) | ((~fire[m]) & (G[v][m] >= th))).astype(int)
            pb = fire[m].astype(int)
            groups = sorted(set(hs)); idx = {g: np.where(hs == g)[0] for g in groups}
            boots = []
            for _ in range(NBOOT):
                pick = RNG.choice(len(groups), len(groups), replace=True)
                ii = np.concatenate([idx[groups[k]] for k in pick])
                yb = yy[ii]
                if (yb == 1).sum() == 0:
                    continue
                boots.append(pv[ii][yb == 1].mean() - pb[ii][yb == 1].mean())
            lo, hi = np.percentile(boots, [2.5, 97.5])
            out[nm] = dict(delta=float(pv[yy == 1].mean() - pb[yy == 1].mean()),
                           lo=float(lo), hi=float(hi))
        row["boot"] = out
        print(f"  {v:20s} {out['OOS']['delta']:+8.4f} "
              f"[{out['OOS']['lo']:+.4f},{out['OOS']['hi']:+.4f}] "
              f"{out['STRICT']['delta']:+9.4f} "
              f"[{out['STRICT']['lo']:+.4f},{out['STRICT']['hi']:+.4f}]")

    # ---- null control: identical two-threshold search on permuted scores -----------
    print("\n  NULL CONTROL — identical search on scores permuted within family")
    gfam = np.array([r["fam"] for r in grows]); pfam = np.array([r["fam"] for r in pool])
    nullres = {}
    for v in ("flat", "spec_soft_router", "blend_learned"):
        go, gs = [], []
        for rep in range(20):
            rg = np.random.default_rng(2000 + rep)
            sc = G[v].copy(); sp = P[v].copy()
            for f in set(gfam):
                m = gfam == f; sc[m] = rg.permutation(sc[m])
            for f in set(pfam):
                m = pfam == f; sp[m] = rg.permutation(sp[m])
            glo = np.concatenate([[-1.0], np.unique(np.round(
                np.quantile(sc[m_g1a][fire[m_g1a]], np.linspace(0, 0.6, 25)), 4))])
            ghi = np.unique(np.round(np.quantile(np.concatenate([sc[m_g1a], sp[m_sel]]),
                                                 np.linspace(0.5, 1.0, 40)), 4))
            bst = search(sc[m_g1a], y[m_g1a], fire[m_g1a], sp[m_sel], pfire[m_sel],
                         pcorr[m_sel], sel_f, allow, glo, ghi)
            if bst is None:
                continue
            tl, th = bst[0], bst[1]
            for nm, m, acc in (("OOS", m_oos, go), ("STRICT", m_str, gs)):
                pd_ = ((fire[m] & (sc[m] >= tl)) | ((~fire[m]) & (sc[m] >= th))).astype(int)
                _, r_, *_ = B.pr(y[m], pd_)
                acc.append(r_ - base[nm]["R"])
        nullres[v] = dict(oos_mean=float(np.mean(go)), oos_p95=float(np.percentile(go, 95)),
                          oos_max=float(np.max(go)), str_mean=float(np.mean(gs)),
                          str_p95=float(np.percentile(gs, 95)), str_max=float(np.max(gs)),
                          n=len(go))
        print(f"  {v:20s} null dOOS mean {np.mean(go):+.4f} p95 {np.percentile(go,95):+.4f} "
              f"max {np.max(go):+.4f} | null dSTRICT mean {np.mean(gs):+.4f} "
              f"p95 {np.percentile(gs,95):+.4f} max {np.max(gs):+.4f}")
    res["null"] = nullres

    json.dump(res, open(os.path.join(HERE, "w2_twosided.json"), "w"), indent=2, default=float)
    print(f"\nwrote w2_twosided.json ({time.time()-t0:.0f}s)")


if __name__ == "__main__":
    main()
