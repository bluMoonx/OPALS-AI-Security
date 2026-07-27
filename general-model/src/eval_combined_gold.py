"""Combined evaluation over ALL hand-judged gold (original 300 + new adjudication).

Resolves every gold row to its exact source record, then measures:
  1. behavioural attack-success rate per category, with Wilson 95% CIs
  2. the canary label's recall against behaviour (the label-validity result)
  3. the deterministic compliance labeler, IN-SAMPLE (gold_*) vs OUT-OF-SAMPLE (gold2_*)

Record resolution
-----------------
`session_id` is NOT unique (repeated trials, different responses). gold2_* rows carry
`line_idx` directly. gold_* rows are resolved via analysis/resolve_gold.py.

Usage: python3 analysis/eval_combined_gold.py
"""
from __future__ import annotations
import json, os, sys, glob, math
from collections import defaultdict, Counter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REB = os.path.join(ROOT, "analysis", "rebuild")
SESS = os.path.join(ROOT, "data", "logs", "collected_new10category",
                    "newcats_sessions.jsonl")
sys.path.insert(0, os.path.join(ROOT, "analysis"))
sys.path.insert(0, REB)


def wilson(k, n, z=1.96):
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))


def load_records():
    return [json.loads(l) for l in open(SESS, errors="ignore") if l.strip()]


def load_all_gold(records):
    """Gold rows with their exact source record attached, plus provenance."""
    out, seen = [], set()

    # new adjudication: line_idx is authoritative
    for f in sorted(glob.glob(os.path.join(REB, "gold2_*.jsonl"))):
        for line in open(f, errors="ignore"):
            line = line.strip()
            if not line:
                continue
            try:
                g = json.loads(line)
            except Exception:
                continue
            li = g.get("line_idx")
            if li is None or not (0 <= li < len(records)):
                continue
            rec = records[li]
            if rec.get("session_id") != g.get("session_id"):
                continue                      # index/id mismatch -> refuse to guess
            if li in seen:
                continue
            seen.add(li)
            out.append({**g, "_rec": rec, "_src": "gold2(new)"})

    # original 300 via the dedicated resolver
    try:
        from resolve_gold import load_resolved_gold
        for r in load_resolved_gold():
            li = r["line_idx"]
            if li in seen:
                continue
            seen.add(li)
            out.append({"line_idx": li, "session_id": r["session_id"],
                        "category": r["category"], "condition": r["condition"],
                        "behavioral_label": r["behavioral_label"],
                        "confidence": r.get("confidence"),
                        "_rec": records[li], "_src": "gold1(orig)"})
    except Exception as e:
        print(f"  (resolve_gold unavailable: {e})")
    return out


def metrics(pred, y):
    tp = sum(1 for p, t in zip(pred, y) if p == 1 and t == 1)
    fp = sum(1 for p, t in zip(pred, y) if p == 1 and t == 0)
    fn = sum(1 for p, t in zip(pred, y) if p == 0 and t == 1)
    tn = sum(1 for p, t in zip(pred, y) if p == 0 and t == 0)
    prec = tp / max(tp + fp, 1); rec = tp / max(tp + fn, 1)
    f1 = 2 * prec * rec / max(prec + rec, 1e-9)
    n = max(len(y), 1); po = (tp + tn) / n
    pe = ((tp + fp) * (tp + fn) + (tn + fn) * (tn + fp)) / (n * n)
    kappa = (po - pe) / max(1 - pe, 1e-9)
    return dict(precision=prec, recall=rec, f1=f1, kappa=kappa,
                tp=tp, fp=fp, fn=fn, tn=tn, n=len(y))


def main():
    records = load_records()
    gold = load_all_gold(records)
    print(f"records: {len(records)}   resolved gold: {len(gold)}")
    print(f"  by source: {dict(Counter(g['_src'] for g in gold))}")

    atk = [g for g in gold if g.get("condition") == "attack"]
    base = [g for g in gold if g.get("condition") != "attack"]
    print(f"  attack {len(atk)} (positives {sum(g['behavioral_label'] for g in atk)}) | "
          f"baseline {len(base)} (positives {sum(g['behavioral_label'] for g in base)})")

    # ---- 1. per-category behavioural ASR with CIs ----
    print("\n=== behavioural attack-success rate per category (Wilson 95% CI) ===")
    per = defaultdict(lambda: [0, 0])
    for g in atk:
        per[g["category"]][1] += 1
        per[g["category"]][0] += g["behavioral_label"]
    rows = sorted(per.items(), key=lambda kv: -kv[1][0] / max(kv[1][1], 1))
    print(f"  {'category':26s} {'ASR':>7s}  {'k/n':>9s}  95% CI")
    for c, (k, n) in rows:
        lo, hi = wilson(k, n)
        print(f"  {c:26s} {100*k/max(n,1):6.1f}%  {k:4d}/{n:<4d}  [{100*lo:4.1f}, {100*hi:5.1f}]")
    K = sum(v[0] for v in per.values()); N = sum(v[1] for v in per.values())
    lo, hi = wilson(K, N)
    print(f"  {'OVERALL':26s} {100*K/max(N,1):6.1f}%  {K:4d}/{N:<4d}  [{100*lo:4.1f}, {100*hi:5.1f}]")

    # ---- 2. canary label validity ----
    can = [1 if g["_rec"].get("attack_succeeded") else 0 for g in atk]
    beh = [g["behavioral_label"] for g in atk]
    m = metrics(can, beh)
    print("\n=== canary label measured against behaviour (attack sessions) ===")
    print(f"  precision {m['precision']:.3f}  recall {m['recall']:.3f}  "
          f"F1 {m['f1']:.3f}  kappa {m['kappa']:.3f}")
    print(f"  canary fires {sum(can)}/{len(can)} | true compliances {sum(beh)}")
    print(f"  => misses {sum(beh)-m['tp']} of {sum(beh)} "
          f"({100*(sum(beh)-m['tp'])/max(sum(beh),1):.0f}%)")

    # ---- 3. labeler in-sample vs out-of-sample ----
    try:
        import behavioral_labeler as B
    except Exception as e:
        print(f"\n(labeler unavailable: {e})"); return
    print("\n=== deterministic compliance labeler ===")
    summary = {}
    for src, label in (("gold1(orig)", "IN-SAMPLE (developed on this)"),
                       ("gold2(new)", "OUT-OF-SAMPLE (never seen)")):
        sub = [g for g in atk if g["_src"] == src]
        if not sub:
            continue
        pred, y = [], []
        for g in sub:
            r = g["_rec"]
            o = B.label_session(r.get("prompt", ""), r.get("agent_response", ""))
            pred.append(int(o if not isinstance(o, dict) else o.get("label", 0)))
            y.append(g["behavioral_label"])
        mm = metrics(pred, y)
        summary[src] = mm
        print(f"  {label:32s} n={mm['n']:4d}  P {mm['precision']:.3f}  "
              f"R {mm['recall']:.3f}  F1 {mm['f1']:.3f}  kappa {mm['kappa']:.3f}")

    json.dump({"n_gold": len(gold), "n_attack": len(atk),
               "overall_asr": K / max(N, 1), "asr_ci": wilson(K, N),
               "canary_recall_vs_behaviour": m["recall"],
               "labeler": {k: {kk: vv for kk, vv in v.items()} for k, v in summary.items()}},
              open(os.path.join(ROOT, "analysis", "combined_gold_summary.json"), "w"), indent=2)
    print("\nwrote analysis/combined_gold_summary.json")


if __name__ == "__main__":
    main()
