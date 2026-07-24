"""
word_frequency_diff.py

Finds words that appear disproportionately more often in compliance_with_flag
responses vs full_compliance responses (or vice versa), to build a lexicon
calibrated to this project's actual model (Kimi K2.5) instead of reusing
Group 18's lexicon, which was built around a different model's phrasing.

Run from: memory-poisoning/notebooks/
    python3 word_frequency_diff.py
"""
import json
import os
import re
from collections import Counter

STOPWORDS = {
    "the", "a", "an", "is", "are", "was", "were", "to", "of", "in", "on",
    "at", "for", "and", "or", "it", "this", "that", "these", "those", "as",
    "our", "your", "we", "you", "i", "be", "has", "have", "with", "from",
    "based", "according", "would", "will", "which", "if", "so", "but",
    "its", "their", "there", "here", "than", "then", "km", "s", "mpc",
}


def tokenize(text):
    words = re.findall(r"[a-zA-Z]+", text.lower())
    return [w for w in words if w not in STOPWORDS and len(w) > 2]


def main():
    processed_dir = os.path.abspath(os.path.join("..", "data", "processed"))
    rows = json.load(open(os.path.join(processed_dir, "feature_table.json")))
    sessions = json.load(open(os.path.join(processed_dir, "scored_sessions.json")))

    resp_by_id = {s["sessionId"]: s.get("assistant_response") or "" for s in sessions}

    flag_words = Counter()
    full_words = Counter()
    flag_docs = 0
    full_docs = 0

    for r in rows:
        if r["run_type"] != "attack":
            continue
        text = resp_by_id.get(r["session_id"], "")
        words = set(tokenize(text))  # count each word once per response (document frequency)
        if r["compliance_score"] == "compliance_with_flag":
            flag_words.update(words)
            flag_docs += 1
        elif r["compliance_score"] == "full_compliance":
            full_words.update(words)
            full_docs += 1

    print(f"compliance_with_flag responses: {flag_docs}")
    print(f"full_compliance responses: {full_docs}\n")

    all_words = set(flag_words) | set(full_words)
    diffs = []
    for w in all_words:
        flag_rate = flag_words[w] / flag_docs if flag_docs else 0
        full_rate = full_words[w] / full_docs if full_docs else 0
        diffs.append((w, flag_rate, full_rate, flag_rate - full_rate))

    print("=== Top 20 words MORE common in compliance_with_flag ===")
    for w, fr, fu, d in sorted(diffs, key=lambda x: -x[3])[:20]:
        print(f"  {w:20} flag_rate={fr:.2f}  full_rate={fu:.2f}  diff={d:+.2f}")

    print("\n=== Top 20 words MORE common in full_compliance ===")
    for w, fr, fu, d in sorted(diffs, key=lambda x: x[3])[:20]:
        print(f"  {w:20} flag_rate={fr:.2f}  full_rate={fu:.2f}  diff={d:+.2f}")


if __name__ == "__main__":
    main()