"""Backfill ``attack_category`` so scigateway counts 400 attacks, not 315.

Group-doc Issue #1 ("315/285 -> 400/200"), diagnosed
--------------------------------------------------
``collect.py`` wrote the prompt-injection *subtype* into ``Session.attack_category``
(``delimiter_confusion``, ``hypothetical_framing``, …). But
``scigateway.attacks.categorize_session`` only honours that field when the value is
one of its **registered** categories; a subtype name is not, so it silently fell
through to the ``risk_indicators`` fallback:

    if risk.prompt_injection_followed: candidates.append("indirect_prompt_injection")

``prompt_injection_followed`` is only true when the attack **succeeded**. So the 85
attack sessions the agent successfully *resisted* had no risk indicator, fell to
``benign``, and were counted as benign controls.

Consequences in the shipped metrics:
  * 315 attacks / 285 "benign" instead of the real **400 / 200**
  * the 85 resisted attacks inflated the benign pool, so the over-block denominator
    was wrong
  * "successful attacks: 315 of 315 attack conditions" — a tautology, because the
    only sessions counted as attacks were the ones that succeeded
  * every attack was reported as ``indirect_prompt_injection``, which is also wrong:
    this track's injections all arrive in the user prompt (Evangeline owns the
    indirect/website vector), so they are **direct**

Fix
---
Write a registered category. All eight subtypes deliver the injection inside the
user's own prompt, so ``direct_prompt_injection`` is correct for all of them; the
subtype is already preserved in ``agent_config["subtype"]`` and ``prompt_family``,
so no granularity is lost.

``collect.py`` is fixed for future runs; this script backfills the collected file.
Idempotent, and reports exactly what it changed.

    python prompt-injection/analysis/fix_attack_category.py --check   # report only
    python prompt-injection/analysis/fix_attack_category.py           # rewrite
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from collections import Counter
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_REPO = _HERE.parent.parent

TARGETS = (
    _REPO / "prompt-injection/dataset/sessions.jsonl",
    _REPO / "prompt-injection/dataset/sessions_tierlabeled.jsonl",
)

ATTACK_CATEGORY = "direct_prompt_injection"
BENIGN_CATEGORY = "benign"


def correct_category(record: dict) -> str:
    """The registered category this session should carry, from its condition."""
    condition = record.get("agent_config", {}).get("condition")
    return ATTACK_CATEGORY if condition == "attack" else BENIGN_CATEGORY


def process(path: Path, apply: bool) -> dict:
    if not path.exists():
        return {"path": str(path), "missing": True}
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()]
    before = Counter(r.get("attack_category") for r in rows)
    changed = 0
    for r in rows:
        want = correct_category(r)
        if r.get("attack_category") != want:
            r["attack_category"] = want
            changed += 1
    after = Counter(r.get("attack_category") for r in rows)

    if apply and changed:
        backup = path.with_suffix(path.suffix + ".pre_category_fix")
        if not backup.exists():
            shutil.copy2(path, backup)
        with path.open("w", encoding="utf-8") as fh:
            for r in rows:
                fh.write(json.dumps(r) + "\n")
    return {"path": str(path.relative_to(_REPO)), "n": len(rows), "changed": changed,
            "before": dict(before), "after": dict(after)}


def verify() -> int:
    """Confirm scigateway now counts the true condition split."""
    if str(_REPO) not in sys.path:
        sys.path.insert(0, str(_REPO))
    from scigateway.attacks import is_attack
    from scigateway.schema import load_sessions_jsonl

    sessions = load_sessions_jsonl(TARGETS[0])
    n_attack = sum(1 for s in sessions if is_attack(s))
    n_benign = len(sessions) - n_attack
    declared = Counter(s.agent_config.get("condition") for s in sessions)
    print(f"\nscigateway is_attack() now sees: {n_attack} attack / {n_benign} benign")
    print(f"collector recorded            : {declared['attack']} attack / "
          f"{declared['baseline']} baseline")
    ok = n_attack == declared["attack"] and n_benign == declared["baseline"]
    print("MATCH — Issue #1 resolved" if ok else "STILL MISMATCHED")
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="report without rewriting")
    args = ap.parse_args()

    print("attack_category backfill (group-doc Issue #1)\n" + "=" * 60)
    for path in TARGETS:
        result = process(path, apply=not args.check)
        if result.get("missing"):
            print(f"[skip] {path} not found")
            continue
        verb = "would change" if args.check else "changed"
        print(f"\n{result['path']}  ({result['n']} rows)")
        print(f"  before: {result['before']}")
        print(f"  after : {result['after']}")
        print(f"  {verb}: {result['changed']}")
    if args.check:
        print("\n(--check: nothing written; a .pre_category_fix backup is made on write)")
        return 0
    return verify()


if __name__ == "__main__":
    raise SystemExit(main())
