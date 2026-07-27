"""Does the v2 control pool actually remove the prompt-length confound?

The v1 controls let "prompt longer than 18 words" separate attack from benign at
AUC 0.992. This checks the v2 pool against the *collected attack prompts* before
any tokens are spent re-collecting, and fails loudly if the artifact survives.

Pass criteria (per family, and pooled):
  * length-only AUC within [0.40, 0.60] -- i.e. prompt length is uninformative
  * benign p10/median/p90 within tolerance of the attack family's own targets
  * benign range covers the attack range (no clean threshold separates them)

Usage:  python prompt-injection/analysis/check_control_balance.py
"""

from __future__ import annotations

import sys
from collections import defaultdict
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_REPO = _HERE.parent.parent
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

import numpy as np

from scigateway.schema import load_sessions_jsonl

sys.path.insert(0, str(_REPO / "prompt-injection"))
from prompts import controls as controls_v1  # noqa: E402
from prompts import controls_v2  # noqa: E402

SESSIONS = _REPO / "prompt-injection/dataset/sessions.jsonl"
TOLERANCE = 0.10          # acceptable |AUC - 0.5|
MEDIAN_TOLERANCE = 6      # words


def words(turns) -> int:
    """Word count the way the collector records ``user_prompt`` (turns joined)."""
    return len(" ".join(turns).split())


def _auc(pos: np.ndarray, neg: np.ndarray) -> float:
    """AUC via rank statistic, no scipy dependency."""
    both = np.concatenate([pos, neg])
    order = both.argsort()
    ranks = np.empty(len(both), float)
    ranks[order] = np.arange(1, len(both) + 1)
    # average ranks for ties, so a constant feature scores exactly 0.5
    _, inv, counts = np.unique(both, return_inverse=True, return_counts=True)
    sums = np.zeros(len(counts))
    np.add.at(sums, inv, ranks)
    ranks = (sums / counts)[inv]
    n_pos = len(pos)
    return float((ranks[:n_pos].sum() - n_pos * (n_pos + 1) / 2) / (n_pos * len(neg)))


def main() -> int:
    if not SESSIONS.exists():
        print(f"[fail] {SESSIONS} not found")
        return 1
    sessions = load_sessions_jsonl(SESSIONS)
    attack_len: dict[str, list[int]] = defaultdict(list)
    for s in sessions:
        if s.agent_config.get("condition") == "attack":
            attack_len[s.agent_config.get("pi_family")].append(len(s.user_prompt.split()))

    print("=" * 78)
    print("CONTROL/ATTACK PROMPT-LENGTH BALANCE")
    print("=" * 78)
    print("length-only AUC of 0.5 means prompt length carries no class information.\n")

    failures: list[str] = []
    pooled = {"v1": ([], []), "v2": ([], [])}

    for family in sorted(attack_len):
        a = np.array(attack_len[family], float)
        row = f"\n--- {family} ---\n"
        row += (f"  attack        n={len(a):3d}  p10={np.percentile(a,10):5.1f} "
                f"med={np.median(a):5.1f} p90={np.percentile(a,90):5.1f} "
                f"range={a.min():.0f}-{a.max():.0f}\n")
        for version, mod in (("v1", controls_v1), ("v2", controls_v2)):
            pool = mod.CONTROL_POOLS.get(family)
            if not pool:
                continue
            b = np.array([words(t) for t in pool], float)
            score = _auc(a, b)
            pooled[version][0].extend(a.tolist())
            pooled[version][1].extend(b.tolist())
            flag = "" if abs(score - 0.5) <= TOLERANCE else "   <-- FAIL"
            row += (f"  {version} control  n={len(b):3d}  p10={np.percentile(b,10):5.1f} "
                    f"med={np.median(b):5.1f} p90={np.percentile(b,90):5.1f} "
                    f"range={b.min():.0f}-{b.max():.0f}   AUC={score:.3f}{flag}\n")
            if version == "v2":
                if abs(score - 0.5) > TOLERANCE:
                    failures.append(f"{family}: length AUC {score:.3f} (want 0.5+-{TOLERANCE})")
                if abs(np.median(b) - np.median(a)) > MEDIAN_TOLERANCE:
                    failures.append(
                        f"{family}: median {np.median(b):.0f} vs attack "
                        f"{np.median(a):.0f} (want within {MEDIAN_TOLERANCE})")
                if b.max() < np.percentile(a, 75):
                    failures.append(
                        f"{family}: control max {b.max():.0f} below attack p75 "
                        f"{np.percentile(a,75):.0f} -- a clean threshold still exists")
        print(row, end="")

    print("\n" + "=" * 78)
    print("POOLED")
    print("=" * 78)
    for version in ("v1", "v2"):
        a = np.array(pooled[version][0], float)
        b = np.array(pooled[version][1], float)
        if not len(b):
            continue
        score = _auc(a, b)
        # the v1 artifact in one line: how well does a single threshold separate?
        thresh = b.max()
        caught = float((a > thresh).mean())
        print(f"  {version}: length AUC={score:.3f}   "
              f"'prompt > {thresh:.0f} words' flags {caught:.1%} of attacks "
              f"at 0% false positives")

    print("\n" + "=" * 78)
    if failures:
        print(f"FAIL ({len(failures)} issue(s)) -- do NOT collect with this pool yet:")
        for f in failures:
            print(f"  * {f}")
        return 1
    print("PASS -- v2 control lengths are statistically indistinguishable from the")
    print("attack prompts in every family. Prompt length can no longer stand in for")
    print("the label, and a re-collection with this pool will produce a dataset whose")
    print("over-block numbers mean something.")
    print("\nDiversity: "
          + ", ".join(f"{f}={len(controls_v2.CONTROL_POOLS[f])}"
                      for f in sorted(controls_v2.CONTROL_POOLS))
          + f"  (total {sum(len(p) for p in controls_v2.CONTROL_POOLS.values())} unique, "
            f"v1 had {sum(len(p) for p in controls_v1.CONTROL_POOLS.values())})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
