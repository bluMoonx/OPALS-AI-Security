# !! QUARANTINED 2026-07-27 - DO NOT RUN. EMITS INVALID NUMBERS. !!
#
# Lines 31 and 41 build dicts keyed by `session_id`, which is NOT unique: 326
# duplicated ids in the corpus, depth up to 9, 56% of records under a duplicated id.
# Both dicts are last-wins, so judgements are silently discarded and the survivors are
# paired with whichever trial happened to be read last. It also globs only the original
# gold_*.jsonl, missing all 671 gold2_* labels, and its own docstring still quotes the
# retired n=142 attack slice.
#
# This is the third instance of this bug class found in this repository. The others are
# analysis/rebuild/eval_ablations.py and analysis/rebuild/retrain_behavioral.py.
#
# Correct loader:  from eval_combined_gold import load_records, load_all_gold
#                  gold = load_all_gold(load_records())   # 965 rows, exact _rec
# Re-enable only after porting the join: AURA_ALLOW_BROKEN_JOIN=1


import os as _os, sys as _sys  # QUARANTINE GUARD
if _os.environ.get("AURA_ALLOW_BROKEN_JOIN") != "1":
    _sys.exit("REFUSING TO RUN: session_id join collapses gold. See header.")
"""Data loading for the AURA ensemble experiment.

Leakage discipline
------------------
Only `prompt` / `user_prompt`, `agent_response`, and tool-name lists ever reach a
feature function. `canary`, `attack_succeeded`, `human_label`, `condition`,
`risk_indicators`, `gateway_decision`, `label_notes`, `attack_objective` are read
ONLY to build labels / evaluation slices, and are never passed to featurisation.
"""
import glob
import json
import os

def _aura_find(*relparts):
    """Locate a data file across checkout layouts.

    The working tree keeps collections under data/logs/collected_<name>/ and the
    published repo under logs/<name>/. Trying both keeps every script runnable from a
    fresh clone instead of dying on a bare FileNotFoundError.
    """
    import os as _os
    _here = _os.path.dirname(_os.path.abspath(__file__))
    _roots = []
    _r = _here
    for _ in range(4):
        _roots.append(_r); _r = _os.path.dirname(_r)
    _name = relparts[-1]
    _dirs = ("data/logs/collected_new10category", "logs/new10category",
             "data/logs/collected_22category", "logs/collected_22category",
             "data/logs", "logs", "data", "")
    for _b in _roots:
        for _d in _dirs:
            _p = _os.path.join(_b, _d, _name) if _d else _os.path.join(_b, _name)
            if _os.path.exists(_p):
                return _p
    return _os.path.join(_here, _name)


ROOT = (os.environ.get("AURA_ROOT") or os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
GOLD_GLOB = os.path.join(ROOT, "analysis/rebuild/gold_*.jsonl")
SESSIONS = os.path.join(ROOT, _aura_find("newcats_sessions.jsonl"))
CHENHAO_GLOB = os.path.join(ROOT, "data/logs/chenhao_release/*.jsonl")


def load_gold():
    """283 unique hand-judged sessions joined to their (prompt, response, tools).

    17 session_ids were judged twice. Dedup rule: file order A,B,C,D,E, last one
    wins (15/17 duplicate pairs agree; 2 disagree). This reproduces the published
    slice size n=142 attack / 62 compliances.
    """
    sess = {}
    with open(SESSIONS) as fh:
        for line in fh:
            r = json.loads(line)
            sess[r["session_id"]] = r

    gold = {}
    for path in sorted(glob.glob(GOLD_GLOB)):
        with open(path) as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                g = json.loads(line)
                gold[g["session_id"]] = g

    out = []
    for sid, g in gold.items():
        s = sess[sid]
        out.append({
            "session_id": sid,
            "prompt": s.get("prompt") or "",
            "response": s.get("agent_response") or "",
            "tools": list(s.get("tools") or []),
            "category": g.get("category"),
            # --- eval-only fields, never featurised ---
            "y": int(g["behavioral_label"]),
            "condition": g["condition"],
            "confidence": g.get("confidence"),
            "canary_label": int(bool(s.get("attack_succeeded"))),
        })
    return out


def load_chenhao():
    """1314 independent sessions with rubric human_label (safe/suspicious/unsafe)."""
    out = []
    for path in sorted(glob.glob(CHENHAO_GLOB)):
        with open(path) as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                r = json.loads(line)
                tools = list(r.get("tool_calls") or [])
                lab = (r.get("human_label") or "").lower()
                out.append({
                    "session_id": r.get("session_id"),
                    "prompt": r.get("user_prompt") or "",
                    "response": r.get("agent_response") or "",
                    "tools": tools,
                    "category": r.get("attack_category"),
                    # --- eval/label-only ---
                    "human_label": lab,
                    "y_strict": 1 if lab == "unsafe" else 0,
                    "y_loose": 1 if lab in ("unsafe", "suspicious") else 0,
                })
    return out


if __name__ == "__main__":
    g = load_gold()
    c = load_chenhao()
    from collections import Counter
    print("gold", len(g), Counter((r["condition"], r["y"]) for r in g))
    print("gold attack n", sum(1 for r in g if r["condition"] == "attack"),
          "pos", sum(1 for r in g if r["condition"] == "attack" and r["y"] == 1))
    print("chenhao", len(c), Counter(r["human_label"] for r in c))
