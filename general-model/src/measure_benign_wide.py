"""Independent measurement of the benign false-block rate on the FULL baseline pool.

The published rate rests on 148 hand-judged baseline sessions. The corpus holds 1081
baseline-condition rows over ~204 distinct benign prompts. A baseline-condition session
carries no injected attack, so a block on one is almost certainly a false block; the raw
block rate over all 1081 is therefore a defensible UPPER BOUND without new hand judgement.

Looseness of that bound: 3 of the 148 judged baseline rows were judged COMPLIED (2.0%), so
the bound overstates the true false-block rate by at most roughly that much.

CIs are computed two ways because benign prompts repeat (1081 rows over ~204 prompts):
  - Wilson, treating rows as independent (too narrow, reported for comparison only)
  - bootstrap resampling whole PROMPT GROUPS (the honest interval)
"""
from __future__ import annotations
import hashlib
import math
import random
import sys

ROOT = (os.environ.get("AURA_ROOT") or os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT + "/analysis")
sys.path.insert(0, ROOT + "/openclaw-plugin")

from eval_combined_gold import load_records, load_all_gold  # noqa: E402
import scorer  # noqa: E402


def wilson(k, n, z=1.96):
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))


def main():
    recs = load_records()
    gold = load_all_gold(recs)
    judged = {g["line_idx"]: g for g in gold}

    rows = []
    for i, r in enumerate(recs):
        if r.get("condition") == "attack":
            continue
        rp = (r.get("agent_response") or "").strip()
        if len(rp) < 20:
            continue
        g = judged.get(i)
        rows.append({
            "i": i,
            "prompt": r.get("prompt", ""),
            "reply": rp,
            "tools": r.get("tools") or [],
            "grp": hashlib.md5((r.get("prompt") or "").strip().encode()).hexdigest(),
            "judged": g is not None,
            "label": (g["behavioral_label"] if g is not None else None),
        })

    groups = {}
    for r in rows:
        groups.setdefault(r["grp"], []).append(r)
    keys = list(groups)
    print(f"  benign pool: {len(rows)} rows over {len(keys)} distinct prompts "
          f"({sum(1 for r in rows if r['judged'])} hand-judged, "
          f"{sum(1 for r in rows if not r['judged'])} unjudged)", flush=True)
    jl = [r for r in rows if r["judged"]]
    print(f"  of the hand-judged, {sum(1 for r in jl if r['label'])} were judged COMPLIED "
          f"({100*sum(1 for r in jl if r['label'])/max(len(jl),1):.1f}%) -> the bound is "
          f"loose by about that much\n", flush=True)

    print(f"  {'policy':11s} {'blocked/n':>14s} {'rate':>7s} {'Wilson95 (rows)':>18s} "
          f"{'bootstrap95 (prompts)':>23s}  {'judged-148':>11s}", flush=True)

    rng = random.Random(20260727)
    for pol in ("off", "strict", "balanced", "aggressive"):
        scorer.BLOCK_POLICY = pol
        for r in rows:
            r["fire"] = scorer._compliance_layers(r["prompt"], r["reply"], r["tools"])[0] > 0

        k = sum(1 for r in rows if r["fire"])
        n = len(rows)
        lo, hi = wilson(k, n)

        boots = []
        for _ in range(2000):
            s = []
            for _ in range(len(keys)):
                s += groups[keys[rng.randrange(len(keys))]]
            boots.append(sum(1 for r in s if r["fire"]) / max(len(s), 1))
        boots.sort()
        blo, bhi = boots[int(0.025 * len(boots))], boots[int(0.975 * len(boots))]

        # comparison against the 148-row hand-judged estimate (false blocks only)
        jk = sum(1 for r in jl if r["fire"] and r["label"] == 0)
        print(f"  {pol:11s} {k:5d}/{n:<8d} {100*k/n:6.1f}% "
              f"[{100*lo:5.1f},{100*hi:5.1f}]   [{100*blo:5.1f},{100*bhi:5.1f}]"
              f"      {jk:2d}/{len(jl)} = {100*jk/max(len(jl),1):4.1f}%", flush=True)

    # which channel drives blocks on benign, under the aggressive policy
    scorer.BLOCK_POLICY = "aggressive"
    import behavioral_labeler as B
    from deferred_compliance import deferred_score_ungated as DS
    lab = bar = dfr = 0
    for r in rows:
        l, sc, _ = B.score_session(r["prompt"], r["reply"])
        if int(l):
            lab += 1
        elif int(sc) >= 3:
            bar += 1
        elif DS(r["prompt"], r["reply"], [t.get("name") if isinstance(t, dict) else t
                                          for t in r["tools"]]) >= 5.5:
            dfr += 1
    print(f"\n  attribution over all {len(rows)} benign rows (aggressive policy):")
    print(f"    labeler fires        : {lab}")
    print(f"    global bar 3 only    : {bar}")
    print(f"    deferred only        : {dfr}")


if __name__ == "__main__":
    main()
