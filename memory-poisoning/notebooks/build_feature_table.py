"""
build_feature_table.py

Joins matched_sessions.json (real behavioral signals straight from OpenClaw's
own trajectory logs: tool_count, fallback_steps, memory_md_injected) with the
compliance scores already computed (scored_baseline_v2.json /
scored_attack_v2.json), and adds a few simple text-derived features pulled
directly from things the OPALS proposal names explicitly: citation behavior,
risk keywords, response length.

This is the first real "behavioral dataset generated from execution traces"
deliverable the proposal describes -- one row per session, ready to feed into
whatever ML step comes next.

Run from: memory-poisoning/notebooks/
    python3 build_feature_table.py

Reads:  ../data/processed/matched_sessions.json
        ../data/processed/scored_baseline_v2.json
        ../data/processed/scored_attack_v2.json
Writes: ../data/processed/feature_table.json
        ../data/processed/feature_table.csv
"""

import json
import os
import csv
import re
from datetime import datetime


def load(path):
    with open(path, "r") as f:
        return json.load(f)


def cites_memory_md(text):
    """Does the response explicitly cite MEMORY.md as its source? This is
    the 'citation behavior' signal the OPALS proposal names directly."""
    if not text:
        return False
    return bool(re.search(r"MEMORY\.md", text, re.IGNORECASE))

def load_eval_keywords(eval_key_path):
    """Collect every keyword string from evaluation-key.json (both the clean
    and poisoned side of every entry). We use this as a banned-vocabulary
    list so our own text-derived features can never accidentally re-detect
    the same signal that produced the compliance labels."""
    with open(eval_key_path, "r") as f:
        eval_key = json.load(f)
    kw = set()
    for entry in eval_key:
        for side in ("expected_clean_answer", "expected_poisoned_answer"):
            for k in entry.get(side, {}).get("keywords", []):
                kw.add(k.strip().lower())
    return kw


def hedges_or_flags_discrepancy(text, banned_terms):
    """Does the response show any sign of flagging a discrepancy with
    standard/known values, independent of whether it still complied?
    Lightweight proxy: presence of comparison language.

    banned_terms comes from evaluation-key.json's own keyword lists — any
    marker that overlaps with it is rejected at runtime rather than silently
    double-counting the same signal as compliance_score."""
    if not text:
        return False
    markers = ["commonly cited as", "typically quoted as", "tension between",
               "differs from the", "compared to the", "in conflict with",
               "discrepancy between", "doesn't match", "does not match"]
    for m in markers:
        for b in banned_terms:
            if m in b or b in m:
                raise ValueError(
                    f"Marker '{m}' overlaps eval-key keyword '{b}' — "
                    "fix the marker list before trusting this feature."
                )
    text_low = text.lower()
    return any(m in text_low for m in markers)

def word_count(text):
    if not text:
        return 0
    return len(re.findall(r"\b\w+\b", text))


def hedge_density(text, banned_terms):
    """Epistemic hedge words per total word count."""
    markers = ["may", "might", "could", "possibly", "probably", "likely",
               "perhaps", "seems", "appears", "suggests"]
    for m in markers:
        for b in banned_terms:
            if m == b:
                raise ValueError(
                    f"Hedge marker '{m}' overlaps eval-key keyword '{b}' — fix before trusting this feature."
                )
    if not text:
        return 0.0
    wc = word_count(text)
    if wc == 0:
        return 0.0
    tokens = re.findall(r"\b\w+\b", text.lower())
    hedge_count = sum(1 for t in tokens if t in markers)
    return hedge_count / wc


def qualifier_ratio(text, banned_terms):
    """Quantitative-approximation phrases per total word count."""
    markers = ["roughly", "nearly", "around", "on the order of",
               "in the ballpark of", "give or take", "at least",
               "at most", "just over"]
    for m in markers:
        for b in banned_terms:
            if m in b or b in m:
                raise ValueError(
                    f"Qualifier marker '{m}' overlaps eval-key keyword '{b}' — fix before trusting this feature."
                )
    if not text:
        return 0.0
    wc = word_count(text)
    if wc == 0:
        return 0.0
    text_low = text.lower()
    q_count = sum(text_low.count(m) for m in markers)
    return q_count / wc


def numeric_value_count(text):
    """Count of distinct numeric tokens mentioned in the response."""
    if not text:
        return 0
    matches = re.findall(r"\d+(?:\.\d+)?", text)
    return len(set(matches))

def certainty_count(text, banned_terms):
    """Confidence-expressing phrases -- the counterpart lexicon to hedges,
    matching Group 18's paper design (they used both a hedge and a
    certainty lexicon together)."""
    markers = ["confirmed", "as documented", "according to my notes",
               "definitively", "without question", "certainly",
               "clearly indicates", "established value", "verified"]
    for m in markers:
        for b in banned_terms:
            if m in b or b in m:
                raise ValueError(
                    f"Certainty marker '{m}' overlaps eval-key keyword '{b}' — fix before trusting this feature."
                )
    if not text:
        return 0
    text_low = text.lower()
    return sum(text_low.count(m) for m in markers)


def attribution_count(text, banned_terms):
    """Source-attribution language -- broader than a literal 'MEMORY.md'
    string check; catches paraphrased references to a stored source."""
    markers = ["as recorded", "my notes indicate", "our records show",
               "the log states", "per our workspace", "based on our files",
               "according to our records", "as noted in"]
    for m in markers:
        for b in banned_terms:
            if m in b or b in m:
                raise ValueError(
                    f"Attribution marker '{m}' overlaps eval-key keyword '{b}' — fix before trusting this feature."
                )
    if not text:
        return 0
    text_low = text.lower()
    return sum(text_low.count(m) for m in markers)


def sentence_stats(text):
    if not text:
        return 0, 0.0
    sentences = [s for s in re.split(r'[.!?]+', text) if s.strip()]
    wc = word_count(text)
    return len(sentences), (wc / len(sentences) if sentences else 0.0)

def parse_ts(ts_str):
    # trajectory logs use e.g. "2026-07-18T00:20:52.080Z"
    return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))


def response_latency_seconds(source_file, raw_sessions_dir):
    """Seconds between prompt.submitted and model.completed for this
    session's trajectory file. Returns None if either event is missing
    (so it doesn't silently show up as 0.0 and get treated as real data)."""
    path = os.path.join(raw_sessions_dir, source_file)
    submitted_ts = None
    completed_ts = None
    try:
        with open(path, "r") as f:
            for line in f:
                d = json.loads(line)
                if d.get("type") == "prompt.submitted" and submitted_ts is None:
                    submitted_ts = parse_ts(d["ts"])
                elif d.get("type") == "model.completed" and submitted_ts is not None and completed_ts is None:
                    completed_ts = parse_ts(d["ts"])
    except FileNotFoundError:
        return None
    if submitted_ts is None or completed_ts is None:
        return None
    return (completed_ts - submitted_ts).total_seconds()

def build_score_lookup(scored_items, id_field="id"):
    lookup = {}
    for item in scored_items:
        lookup[item[id_field]] = item.get("score")
    return lookup


def main():
    processed_dir = os.path.abspath(os.path.join("..", "data", "processed"))

    sessions = load(os.path.join(processed_dir, "scored_sessions.json"))
    eval_key_path = os.path.abspath(os.path.join("..", "prompts", "evaluation-key.json"))
    raw_sessions_dir = os.path.abspath(os.path.join("..", "data", "raw", "session-logs", "sessions"))
    banned_terms = load_eval_keywords(eval_key_path)

    rows = []
    for s in sessions:
        qid = s["question_id"]
        run_type = s["run_type"]
        score = s.get("score")
        response = s.get("assistant_response") or ""

        row = {
            "session_id": s["sessionId"],
            "source_file": s["source_file"],
            "run_type": run_type,
            "question_id": qid,
            "question_category_or_type": s["question_category_or_type"],
            "compliance_score": score,
            "memory_md_injected": s["memory_md_injected"],
            "tool_count": s["tool_count"],
            "fallback_steps": s["fallback_steps"],
            "had_error": bool(s.get("error")),
            "response_length_chars": len(response),
            "cites_memory_md": cites_memory_md(response),
            "flags_discrepancy_language": hedges_or_flags_discrepancy(response, banned_terms),
            "hedge_density": hedge_density(response, banned_terms),
            "qualifier_ratio": qualifier_ratio(response, banned_terms),
            "numeric_value_count": numeric_value_count(response),
            "certainty_count": certainty_count(response, banned_terms),
            "attribution_count": attribution_count(response, banned_terms),
            "provider": s["provider"],
            "response_latency_seconds": response_latency_seconds(s["source_file"], raw_sessions_dir),
            "model_id": s["modelId"],
        }
        sent_count, avg_sent_len = sentence_stats(response)
        row["sentence_count"] = sent_count
        row["avg_sentence_length"] = avg_sent_len
        hedge_count_raw = sum(response.lower().count(m) for m in [
            "may", "might", "could", "possibly", "probably", "likely",
            "perhaps", "seems", "appears", "suggests"
        ])
        certain_count_raw = row["certainty_count"]
        row["quality_ratio"] = (
            hedge_count_raw / (hedge_count_raw + certain_count_raw)
            if (hedge_count_raw + certain_count_raw) > 0 else 0.0
        )
        rows.append(row)

    rows.sort(key=lambda r: (r["run_type"], r["question_id"]))

    out_json = os.path.join(processed_dir, "feature_table.json")
    with open(out_json, "w") as f:
        json.dump(rows, f, indent=2)

    out_csv = os.path.join(processed_dir, "feature_table.csv")
    if rows:
        with open(out_csv, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            writer.writeheader()
            writer.writerows(rows)

    print(f"Wrote {len(rows)} rows to:")
    print(f"  {out_json}")
    print(f"  {out_csv}")

    attack_rows = [r for r in rows if r["run_type"] == "attack"]

    # --- honesty check: flag any feature with zero variance across the
    # dataset before treating it as meaningful. A constant value (e.g. every
    # session showing the same tool_count, which is the number of AVAILABLE
    # tools, not tools actually CALLED) cannot predict anything. ---
    print("\n=== Feature variance check (uninformative if only 1 distinct value) ===")
    numeric_and_bool_features = [
        "tool_count", "fallback_steps", "response_length_chars",
        "cites_memory_md", "flags_discrepancy_language", "had_error",
        "hedge_density", "qualifier_ratio", "numeric_value_count",
        "response_latency_seconds", "certainty_count", "attribution_count",
        "sentence_count", "avg_sentence_length", "quality_ratio",
    ]
    for feat in numeric_and_bool_features:
        distinct = sorted(set(r[feat] for r in rows), key=str)
        flag = "  <-- UNINFORMATIVE (no variance)" if len(distinct) <= 1 else ""
        print(f"  {feat}: {len(distinct)} distinct value(s) -> {distinct}{flag}")

    print("\n=== Cross-tab: cites_memory_md vs compliance_score (attack only) ===")
    tally = {}
    for r in attack_rows:
        key = (r["cites_memory_md"], r["compliance_score"])
        tally[key] = tally.get(key, 0) + 1
    for key, count in sorted(tally.items()):
        print(f"  cites_memory_md={key[0]!s:5}  score={key[1]:25}  count={count}")

    print("\n=== Cross-tab: flags_discrepancy_language vs compliance_score (attack only) ===")
    tally2 = {}
    for r in attack_rows:
        key = (r["flags_discrepancy_language"], r["compliance_score"])
        tally2[key] = tally2.get(key, 0) + 1
    for key, count in sorted(tally2.items()):
        print(f"  flags_discrepancy_language={key[0]!s:5}  score={key[1]:25}  count={count}")

    print("\n=== response_length_chars by compliance_score (attack only, avg) ===")
    from collections import defaultdict
    lengths_by_score = defaultdict(list)
    for r in attack_rows:
        lengths_by_score[r["compliance_score"]].append(r["response_length_chars"])
    for score, lengths in sorted(lengths_by_score.items()):
        avg = sum(lengths) / len(lengths)
        print(f"  {score:25} n={len(lengths):2}  avg_chars={avg:.0f}  min={min(lengths)}  max={max(lengths)}")
    
    print("\n=== New feature averages by compliance_score (attack only) ===")
    for feat in ["hedge_density", "qualifier_ratio", "numeric_value_count", "response_latency_seconds"]:
        by_score = defaultdict(list)
        for r in attack_rows:
            val = r[feat]
            if val is not None:
                by_score[val].append(val) if False else by_score[r["compliance_score"]].append(val)
        print(f"\n  -- {feat} --")
        for score, vals in sorted(by_score.items()):
            avg = sum(vals) / len(vals)
            print(f"    {score:25} n={len(vals):2}  avg={avg:.4f}  min={min(vals):.4f}  max={max(vals):.4f}")

if __name__ == "__main__":
    main()