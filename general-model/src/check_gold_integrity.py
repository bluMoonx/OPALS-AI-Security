"""Guard the invariant that makes the 965 gold labels valid.

Every gold label is keyed by `line_idx`, the 0-based line number in
data/logs/collected_new10category/newcats_sessions.jsonl. That key is only meaningful
while the corpus is edited APPEND-ONLY. A collector is still running and appending, so
this is a live risk, not a hypothetical one: if any line at or below the highest labelled
index is ever inserted, reordered, rewritten or deleted, all 965 labels silently point at
the wrong records and every downstream number becomes wrong without anything crashing.

`session_id` cannot be used as a fallback key. Measured on this corpus: 324 session_ids
carry more than one trial (up to 9 deep), 51.4% of records sit under a duplicated id, and
323 of 324 duplicate groups have DIFFERENT response text.

This script checks four things and exits non-zero on any failure:
  1. every gold row's line_idx is in range and its session_id matches records[line_idx]
  2. no duplicate line_idx across all gold files
  3. the labelled PREFIX of the corpus is unchanged since the fingerprint was taken
     (this is what catches a non-append edit)
  4. category and condition agree between the gold row and the record

Usage:
    python3 analysis/check_gold_integrity.py            # verify
    python3 analysis/check_gold_integrity.py --freeze   # (re)record the fingerprint

Run this before trusting any number, and after anything touches the corpus.
"""
from __future__ import annotations
import hashlib
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "analysis"))
FINGERPRINT = os.path.join(ROOT, "analysis", "gold_prefix_fingerprint.json")


def prefix_digest(records, upto):
    """SHA-256 over the labelled prefix, one record's canonical JSON per line.

    Hashing the parsed records rather than raw bytes means reformatting alone will not
    trip the alarm, but any change to content, order or count will.
    """
    h = hashlib.sha256()
    for r in records[:upto + 1]:
        h.update(json.dumps(r, sort_keys=True, separators=(",", ":")).encode())
        h.update(b"\n")
    return h.hexdigest()


def main() -> int:
    from eval_combined_gold import load_records, load_all_gold

    records = load_records()
    gold = load_all_gold(records)
    fails, warns = [], []

    print(f"corpus  : {len(records)} records")
    print(f"gold    : {len(gold)} labels")

    # ---- 1 + 4. every label points at the record it was judged from ----
    bad_sid = bad_cat = bad_cond = out_of_range = 0
    max_idx = -1
    for g in gold:
        li = g.get("line_idx")
        if li is None or not (0 <= li < len(records)):
            out_of_range += 1
            continue
        max_idx = max(max_idx, li)
        rec = records[li]
        if rec.get("session_id") != g.get("session_id"):
            bad_sid += 1
        if g.get("category") and rec.get("category") and g["category"] != rec["category"]:
            bad_cat += 1
        if g.get("condition") and rec.get("condition") and g["condition"] != rec["condition"]:
            bad_cond += 1
    for n, what in ((out_of_range, "line_idx out of range"),
                    (bad_sid, "session_id mismatch at line_idx"),
                    (bad_cat, "category mismatch"),
                    (bad_cond, "condition mismatch")):
        if n:
            fails.append(f"{n} rows: {what}")
    print(f"max labelled line_idx: {max_idx}   "
          f"(corpus has {len(records) - max_idx - 1} records appended past it)")

    # ---- 2. no duplicate keys ----
    idxs = [g["line_idx"] for g in gold if g.get("line_idx") is not None]
    if len(idxs) != len(set(idxs)):
        fails.append(f"{len(idxs) - len(set(idxs))} duplicate line_idx across gold files")

    # ---- 3. the labelled prefix must be byte-stable ----
    digest = prefix_digest(records, max_idx)
    if "--freeze" in sys.argv:
        json.dump({"max_labelled_line_idx": max_idx, "prefix_sha256": digest,
                   "n_records_at_freeze": len(records), "n_gold": len(gold)},
                  open(FINGERPRINT, "w"), indent=2)
        print(f"\nFROZE fingerprint: prefix[0..{max_idx}] sha256={digest[:16]}...")
        print(f"wrote {os.path.relpath(FINGERPRINT, ROOT)}")
        return 0

    if not os.path.exists(FINGERPRINT):
        warns.append("no fingerprint recorded yet — run with --freeze to establish one")
    else:
        fp = json.load(open(FINGERPRINT))
        if fp["max_labelled_line_idx"] != max_idx:
            warns.append(f"labelled range grew: {fp['max_labelled_line_idx']} -> {max_idx} "
                         f"(expected if you added labels; re-freeze)")
        old = prefix_digest(records, fp["max_labelled_line_idx"])
        if old != fp["prefix_sha256"]:
            fails.append(
                f"THE LABELLED PREFIX CHANGED. records[0..{fp['max_labelled_line_idx']}] "
                f"no longer hashes to the frozen value. The corpus was edited NON-APPEND-ONLY "
                f"and all {len(gold)} labels may now point at the wrong records.")
        else:
            print(f"prefix  : UNCHANGED since freeze "
                  f"(records[0..{fp['max_labelled_line_idx']}], sha256 {old[:16]}...)")
            print(f"          {len(records) - fp['n_records_at_freeze']} records appended since, "
                  f"which is safe")

    print()
    for w in warns:
        print(f"WARN  {w}")
    if fails:
        for f in fails:
            print(f"FAIL  {f}")
        print(f"\nGOLD INTEGRITY: FAILED ({len(fails)} problems)")
        return 1
    print("GOLD INTEGRITY: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
