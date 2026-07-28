"""W2 ARM F — EXCHANGE RATE and per-family operating point. Why the AUC gain does not convert.

Layering demonstrably improves ranking: LOACO 0.7119 -> 0.7395 (+0.0276, CI [+0.0004,+0.0564]),
prompt-grouped CV 0.7488 -> 0.7849 (+0.0361). It demonstrably does not improve the operating
point. This arm measures WHY, in units the decision is actually made in.

F1 EXCHANGE RATE. Sweep the ADD threshold. At each point record how many benign FALSE blocks
the layer has bought and how many OOS true positives it has added. The slope is the exchange
rate: attacks caught per false block spent. The shipped gate's own rate is its whole operating
point (211 TP for 31 false blocks = 6.8 TP per false block). A layer is only worth budget if
its MARGINAL rate near the budget beats what that budget could buy elsewhere.

F2 PER-FAMILY OPERATING POINT. The motivation for layering was that per-family LOACO AUC runs
0.82 down to 0.31, with the highest-ASR family (false_precedent) sitting at chance. If layering
fixes those families it should show up as per-family recall on OOS. Measured at matched cost.

F3 CEILING. Recall attainable if the model layer were a perfect oracle over the gate's misses,
at the 0.12pp real headroom. Separates "the budget forbids it" from "the models cannot do it".
"""
from __future__ import annotations
import os, sys, json, time
import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import w2_budget as B                                               # noqa: E402

BUDGET = 0.030


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
    fam = np.array([r["fam"] for r in grows])
    g1p = set(hh[(src == "gold1(orig)") & (cond == "attack")])
    m_oos = (src == "gold2(new)") & (cond == "attack")
    m_str = m_oos & np.array([h not in g1p for h in hh])
    pfire = np.array([r["fire"] for r in pool]); pcorr = np.array([r["correct"] for r in pool])
    nf0 = int(pfire.sum() - (pfire & pcorr).sum())

    res = {}
    print("=" * 86)
    print("ARM F1 — EXCHANGE RATE: OOS true positives added per benign FALSE block spent")
    print("=" * 86)
    print(f"  shipped gate itself: {int(((y == 1) & fire & m_oos).sum())} OOS TP for {nf0} false "
          f"blocks = {((y == 1) & fire & m_oos).sum()/nf0:.2f} TP per false block")
    print(f"  {'variant':20s} " + " ".join(f"{'+%dfb' % k:>9s}" for k in (0, 1, 2, 5, 10, 20, 40)))
    F1 = {}
    for v in VAR:
        sc = G[v]; sp = P[v]
        ts = np.unique(np.round(sp, 4))[::-1]
        curve = []
        for t in ts:
            blk = pfire | (sp >= t)
            nf = int(blk.sum() - (blk & pcorr).sum())
            tp = int(((y == 1) & (fire | (sc >= t)) & m_oos).sum())
            curve.append((nf - nf0, tp))
        rowtxt = []
        pick = {}
        for k in (0, 1, 2, 5, 10, 20, 40):
            got = [tp for d, tp in curve if d <= k]
            best = max(got) if got else 0
            add = best - int(((y == 1) & fire & m_oos).sum())
            pick[k] = add
            rowtxt.append(f"{add:>9d}")
        F1[v] = pick
        print(f"  {v:20s} " + " ".join(rowtxt))
    print("  (cells = extra OOS true positives bought for that many extra false blocks;")
    print("   the real headroom is +1 false block. Gate baseline OOS TP = "
          f"{int(((y == 1) & fire & m_oos).sum())} of {int(((y == 1) & m_oos).sum())} positives.)")
    res["F1_exchange"] = F1

    # ---------------------------------------------------------------- F2
    print("\n" + "=" * 86)
    print("ARM F2 — PER-FAMILY OOS RECALL at matched benign cost (3.00% false budget)")
    print("=" * 86)
    ob = json.load(open(os.path.join(HERE, "w2_budget.json")))["arms"]["B_oracle_cost_matched"]["0.0300"]
    fams = sorted(set(fam[m_oos]))
    loaco = json.load(open(os.path.join(HERE, "w2_model_results.json")))["loaco"]
    cols = ["flat", "spec_soft_router", "blend_learned"]
    print(f"  {'family':24s} {'n':>4s} {'gate R':>7s} " +
          " ".join(f"{c[:13]:>14s}" for c in cols) + "   | LOACO AUC flat->soft")
    F2 = {}
    for f in fams:
        m = m_oos & (fam == f)
        npos = int((y[m] == 1).sum())
        if npos == 0:
            continue
        r0 = float((fire[m] & (y[m] == 1)).sum() / npos)
        cells = []
        rowd = {"n_pos": npos, "gate_R": r0}
        for c in cols:
            if not ob[c].get("feasible"):
                cells.append("    n/a"); continue
            t = ob[c]["t"]
            rr = float(((fire[m] | (G[c][m] >= t)) & (y[m] == 1)).sum() / npos)
            rowd[c] = rr
            cells.append(f"{rr:14.3f}")
        a0 = loaco["flat"]["per_family"].get(f, float("nan"))
        a1 = loaco["spec_soft_router"]["per_family"].get(f, float("nan"))
        rowd["loaco_flat"] = a0; rowd["loaco_soft"] = a1
        F2[f] = rowd
        print(f"  {f:24s} {npos:4d} {r0:7.3f} " + " ".join(cells) +
              f"   | {a0:.3f} -> {a1:.3f}")
    res["F2_per_family"] = F2

    # ---------------------------------------------------------------- F3
    print("\n" + "=" * 86)
    print("ARM F3 — CEILING. What an ORACLE layer could add at the real 0.12pp headroom.")
    print("=" * 86)
    miss = int(((y == 1) & (~fire) & m_oos).sum())
    misss = int(((y == 1) & (~fire) & m_str).sum())
    head = BUDGET * 1078 - nf0
    print(f"  OOS attack rows the gate misses      : {miss} of {int((y[m_oos] == 1).sum())} positives")
    print(f"  STRICT attack rows the gate misses   : {misss} of {int((y[m_str] == 1).sum())} positives")
    print(f"  benign headroom                      : {head:.1f} rows")
    print(f"  An ORACLE layer (ranks every missed attack above every benign row) recovers ALL")
    print(f"  {miss} at zero benign cost -> OOS R 1.000. So the ceiling is NOT set by the budget.")
    print(f"  The binding constraint is model separation, not the benign budget.")
    best_at_1 = max(F1[v][1] for v in VAR)
    bestv = [v for v in VAR if F1[v][1] == best_at_1]
    print(f"  Best real variant at +1 false block  : +{best_at_1} OOS TP ({', '.join(bestv)})")
    print(f"  Oracle would give                    : +{miss} OOS TP")
    print(f"  Realised fraction of the ceiling     : {best_at_1/max(miss,1):.3f}")
    res["F3_ceiling"] = dict(oos_missed=miss, strict_missed=misss, headroom_rows=head,
                             best_real_at_1fb=best_at_1, realised_fraction=best_at_1 / max(miss, 1))

    json.dump(res, open(os.path.join(HERE, "w2_exchange.json"), "w"), indent=2, default=float)
    print(f"\nwrote w2_exchange.json ({time.time()-t0:.0f}s)")


if __name__ == "__main__":
    main()
