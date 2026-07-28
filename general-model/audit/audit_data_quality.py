"""AURA data-quality audit.

Measures, per dataset and pooled:
  1. exact record counts, parse failures
  2. schema field inventory + cross-dataset field-name collisions that corrupt pooling
  3. class balance (per the frozen outcome-based labeling rule) overall / per file / per category
  4. WHICH branch of the labeling rule fired for each record (silent label-semantics drift)
  5. exact-duplicate and near-duplicate agent_response text
  6. empty / truncated / error / non-answer responses that should be excluded
  7. categories with too few positives (or negatives) to learn from
  8. GroupKFold-by-category viability: how many held-out folds are single-class
  9. field-availability matrix for the features the current trainer actually reads

Read-only. Writes nothing except stdout.
Run:  python3 analysis/hardening/audit_data_quality.py
"""
from __future__ import annotations

import glob
import hashlib
import json
import os
import re
import sys
from collections import Counter, defaultdict

import numpy as np

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


ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.chdir(ROOT)
sys.path.insert(0, os.path.join(ROOT, "analysis"))

DATASETS = {
    "newcats10": [_aura_find("newcats_sessions.jsonl")],
    "scigateway22": ["data/logs/collected_22category/sessions.jsonl"],
    "sci22_turns": ["data/logs/collected_22category/turns.jsonl"],
    "chenhao": sorted(glob.glob("data/logs/chenhao_release/*.jsonl")),
    "spring_mempoison": sorted(glob.glob("data/logs/spring_memory_poisoning/*.jsonl")),
}
# sci22_turns is NOT in the task brief but IS matched by train_general.py's glob
# (data/logs/collected_*/*.jsonl), so it silently enters the pooled corpus.

ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
PLUGIN_LOG_RE = re.compile(r"\[plugins\]\s+loading ", re.I)
ERROR_RE = re.compile(
    r"^\s*(error|exception|traceback|timeout|rate.?limit|http \d{3}|"
    r"\{?\"?error\"?\s*:|request failed|connection (refused|reset|error))",
    re.I,
)
REFUSAL_RE = re.compile(
    r"(i (can'?t|cannot|won'?t|am unable to)|i'?m not able to|i do not have a tool)", re.I
)
WS_RE = re.compile(r"\s+")


# ---------------------------------------------------------------- loading ----
def load(paths):
    rows, bad = [], 0
    for p in paths:
        with open(p, "r", errors="replace") as fh:
            for ln, line in enumerate(fh, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                except Exception:
                    bad += 1
                    continue
                d["__file"] = os.path.basename(p)
                d["__line"] = ln
                rows.append(d)
    return rows, bad


# ------------------------------------------- frozen accessors / label rule ----
def reply_of(d):
    """Exactly what train_general.py reads."""
    return d.get("agent_response") or d.get("response_preview") or ""


def tools_of(d):
    """Exactly what train_general.py reads (note: only 'tools')."""
    return d.get("tools") or []


def tools_of_repaired(d):
    return d.get("tools") or d.get("tool_calls") or []


def label_and_branch(d):
    """Frozen outcome-based rule + which branch fired."""
    hl = d.get("human_label")
    if hl in ("safe", "suspicious", "unsafe"):
        return (0 if hl == "safe" else 1), "human_label"
    if "attack_succeeded" in d:
        return (1 if d.get("attack_succeeded") else 0), "attack_succeeded"
    cat = d.get("attack_category") or d.get("category") or ""
    return (0 if cat in ("", "benign") else 1), "category_fallback"


def category_of(d):
    return d.get("attack_category") or d.get("category") or "benign"


def condition_of(d):
    c = d.get("condition")
    if c:
        return c
    lb = d.get("label")
    if lb in ("attack", "baseline"):
        return lb
    sid = str(d.get("session_id", ""))
    if "-attack-" in sid:
        return "attack"
    if "-baseline-" in sid or "-benign-" in sid:
        return "baseline"
    return "unknown"


# --------------------------------------------------------- text hygiene ------
def norm(t):
    return WS_RE.sub(" ", ANSI_RE.sub("", t)).strip().lower()


def classify_text(raw):
    """Return a set of quality flags for one response string."""
    flags = set()
    t = ANSI_RE.sub("", raw)
    s = t.strip()
    if not s:
        flags.add("empty")
        return flags
    if len(s) < 20:
        flags.add("ultrashort_lt20char")
    if len(s.split()) < 5:
        flags.add("lt5words")
    if raw != t:
        flags.add("contains_ansi")
    if PLUGIN_LOG_RE.search(t):
        flags.add("cli_log_noise")
    if ERROR_RE.search(s):
        flags.add("error_text")
    if REFUSAL_RE.search(s):
        flags.add("refusal")
    # truncation heuristics: no terminal punctuation and ends mid-token
    if not s.endswith((".", "!", "?", '"', "`", ")", "]", "}", ":", "*")):
        flags.add("no_terminal_punct")
    if s.endswith(("...", "…")) or s.endswith("…"):
        flags.add("ellipsis_end")
    return flags


def sha(t):
    return hashlib.sha1(t.encode("utf-8", "replace")).hexdigest()


# ------------------------------------------------------------- reporting -----
def hdr(t):
    print("\n" + "=" * 78)
    print(t)
    print("=" * 78)


def sub(t):
    print("\n--- " + t + " " + "-" * max(0, 70 - len(t)))


def main():
    all_rows = {}
    hdr("1. FILE INVENTORY  (exact record counts)")
    print(f"{'dataset':18s} {'file':34s} {'records':>8s} {'parse_fail':>10s}")
    grand = 0
    for name, paths in DATASETS.items():
        rows, bad = load(paths)
        all_rows[name] = rows
        per_file = Counter(r["__file"] for r in rows)
        for f, n in sorted(per_file.items()):
            print(f"{name:18s} {f:34s} {n:8d} {'-':>10s}")
        if bad:
            print(f"{name:18s} {'(unparseable lines)':34s} {'':8s} {bad:10d}")
        print(f"{name:18s} {'TOTAL':34s} {len(rows):8d}")
        grand += len(rows)
    print(f"\nGRAND TOTAL records across all 4 datasets: {grand}")

    # --------------------------------------------------------------- schema --
    hdr("2. SCHEMA INVENTORY  (field presence per dataset, % of records)")
    fieldsets = {}
    for name, rows in all_rows.items():
        c = Counter()
        for r in rows:
            for k in r:
                if not k.startswith("__"):
                    c[k] += 1
        fieldsets[name] = {k: v / len(rows) for k, v in c.items()}
    allfields = sorted(set().union(*[set(f) for f in fieldsets.values()]))
    names = list(all_rows)
    print(f"{'field':26s} " + " ".join(f"{n:>17s}" for n in names))
    for f in allfields:
        cells = []
        for n in names:
            v = fieldsets[n].get(f)
            cells.append(f"{'.':>17s}" if v is None else f"{v*100:16.1f}%")
        print(f"{f:26s} " + " ".join(cells))

    sub("2b. SCHEMA COLLISIONS THAT CORRUPT POOLING")
    probes = [
        ("reply text", ["agent_response", "response_preview"]),
        ("tool trail", ["tools", "tool_calls", "actions"]),
        ("user prompt", ["prompt", "user_prompt", "query"]),
        ("category", ["category", "attack_category"]),
        ("condition", ["condition", "label"]),
        ("outcome label", ["human_label", "attack_succeeded", "used_poisoned_value"]),
    ]
    for concept, keys in probes:
        print(f"\n  {concept}:")
        for k in keys:
            present = [f"{n}={fieldsets[n].get(k,0)*100:.0f}%" for n in names]
            print(f"    {k:22s} " + "  ".join(present))

    # ------------------------------------------------------- label balance --
    hdr("3. CLASS BALANCE  (frozen outcome-based labeling rule)")
    print(f"{'dataset':18s} {'n':>6s} {'pos(unsafe)':>12s} {'neg(safe)':>10s} {'pos_rate':>9s}")
    for name, rows in all_rows.items():
        y = [label_and_branch(r)[0] for r in rows]
        print(f"{name:18s} {len(y):6d} {sum(y):12d} {len(y)-sum(y):10d} {np.mean(y):9.3f}")

    sub("3b. WHICH LABELING BRANCH FIRED  (label-semantics drift)")
    print(f"{'dataset':18s} {'human_label':>12s} {'attack_succ':>12s} {'cat_fallback':>13s}")
    for name, rows in all_rows.items():
        b = Counter(label_and_branch(r)[1] for r in rows)
        print(f"{name:18s} {b['human_label']:12d} {b['attack_succeeded']:12d} "
              f"{b['category_fallback']:13d}")

    sub("3c. CONDITION x LABEL  (does 'attack' condition imply positive label?)")
    for name, rows in all_rows.items():
        cc = Counter((condition_of(r), label_and_branch(r)[0]) for r in rows)
        conds = sorted({c for c, _ in cc})
        parts = [f"{c}: pos={cc[(c,1)]} neg={cc[(c,0)]}" for c in conds]
        print(f"  {name:18s} " + " | ".join(parts))

    sub("3d. SPRING: label vs used_poisoned_value (the real outcome variable)")
    rows = all_rows["spring_mempoison"]
    per_file = defaultdict(Counter)
    for r in rows:
        per_file[r["__file"]][(r.get("label"), r.get("is_poisoned_session"),
                               r.get("used_poisoned_value"))] += 1
    for f, c in sorted(per_file.items()):
        print(f"  {f}")
        for k, v in sorted(c.items(), key=lambda kv: str(kv[0])):
            print(f"     label={k[0]!s:9s} poisoned_session={k[1]!s:5s} "
                  f"used_poisoned_value={k[2]!s:5s}  n={v}")

    # ------------------------------------------------------ per category ----
    hdr("4. PER-CATEGORY BREAKDOWN  (pooled session datasets, spring shown separately)")
    session_rows = (all_rows["newcats10"] + all_rows["scigateway22"]
                    + all_rows["sci22_turns"] + all_rows["chenhao"])
    print(f"{'category':34s} {'n':>5s} {'pos':>5s} {'neg':>5s} {'pos_rate':>9s} {'source':>14s}")
    catstats = defaultdict(lambda: [0, 0, set()])
    for r in session_rows:
        c = category_of(r)
        y, _ = label_and_branch(r)
        catstats[c][0] += 1
        catstats[c][1] += y
        catstats[c][2].add(r["__file"].split("_")[0][:12])
    for c in sorted(catstats, key=lambda k: -catstats[k][0]):
        n, p, src = catstats[c]
        print(f"{c:34s} {n:5d} {p:5d} {n-p:5d} {p/n:9.3f} {','.join(sorted(src))[:14]:>14s}")
    print(f"\n  distinct categories (session datasets): {len(catstats)}")

    sub("4b. CATEGORIES TOO SMALL / DEGENERATE TO LEARN FROM")
    nopos = [c for c, (n, p, _) in catstats.items() if p == 0]
    noneg = [c for c, (n, p, _) in catstats.items() if p == n]
    fewpos = [(c, catstats[c][1], catstats[c][0]) for c in catstats
              if 0 < catstats[c][1] < 10]
    tiny = [(c, catstats[c][0]) for c in catstats if catstats[c][0] < 20]
    print(f"  categories with ZERO positives ({len(nopos)}): {sorted(nopos)}")
    print(f"  categories with ZERO negatives ({len(noneg)}): {sorted(noneg)}")
    print(f"  categories with 1-9 positives ({len(fewpos)}):")
    for c, p, n in sorted(fewpos, key=lambda x: x[1]):
        print(f"     {c:34s} pos={p:3d} / n={n}")
    print(f"  categories with <20 total records ({len(tiny)}):")
    for c, n in sorted(tiny, key=lambda x: x[1]):
        print(f"     {c:34s} n={n}")

    sub("4c. GroupKFold-by-category VIABILITY (leave-one-category-out)")
    single = [c for c, (n, p, _) in catstats.items() if p == 0 or p == n]
    print(f"  total groups: {len(catstats)}")
    print(f"  groups that are SINGLE-CLASS when held out: {len(single)} "
          f"({len(single)/len(catstats)*100:.1f}%)")
    n_single = sum(catstats[c][0] for c in single)
    print(f"  records inside single-class groups: {n_single} / {len(session_rows)} "
          f"({n_single/len(session_rows)*100:.1f}%)")
    print("  -> ROC-AUC is UNDEFINED on those folds. If the trainer skips them,")
    print("     the reported LOACO AUC is averaged over only the remaining folds.")
    evaluable = [c for c in catstats if c not in single]
    print(f"  folds that actually contribute an AUC: {len(evaluable)} "
          f"-> {sorted(evaluable)}")

    # -------------------------------------------------------- text quality --
    hdr("5. RESPONSE TEXT QUALITY  (what the feature extractor actually sees)")
    print(f"{'dataset':18s} {'n':>6s} {'empty':>6s} {'<5w':>5s} {'ansi':>6s} "
          f"{'cli_log':>8s} {'err':>5s} {'refusal':>8s} {'no_end_punct':>13s}")
    for name, rows in all_rows.items():
        f = Counter()
        for r in rows:
            for flag in classify_text(reply_of(r)):
                f[flag] += 1
        print(f"{name:18s} {len(rows):6d} {f['empty']:6d} {f['lt5words']:5d} "
              f"{f['contains_ansi']:6d} {f['cli_log_noise']:8d} {f['error_text']:5d} "
              f"{f['refusal']:8d} {f['no_terminal_punct']:13d}")

    sub("5b. LENGTH DISTRIBUTION of reply text (chars)")
    print(f"{'dataset':18s} {'min':>6s} {'p05':>7s} {'p25':>7s} {'median':>7s} "
          f"{'p75':>7s} {'p95':>8s} {'max':>8s}")
    for name, rows in all_rows.items():
        L = np.array([len(reply_of(r)) for r in rows])
        print(f"{name:18s} {L.min():6d} {np.percentile(L,5):7.0f} "
              f"{np.percentile(L,25):7.0f} {np.percentile(L,50):7.0f} "
              f"{np.percentile(L,75):7.0f} {np.percentile(L,95):8.0f} {L.max():8d}")

    sub("5c. SPRING response_preview: is it the agent's answer at all?")
    rows = all_rows["spring_mempoison"]
    lens = np.array([len(r.get("response_preview") or "") for r in rows])
    noise = sum(1 for r in rows
                if PLUGIN_LOG_RE.search(ANSI_RE.sub("", r.get("response_preview") or "")))
    distinct_norm = len({norm(r.get("response_preview") or "") for r in rows})
    print(f"  DISTINCT normalized previews across all {len(rows)} turns: {distinct_norm}")
    exact_len = Counter(lens.tolist())
    print(f"  n={len(rows)}  containing '[plugins] loading' CLI banner: {noise} "
          f"({noise/len(rows)*100:.1f}%)")
    print(f"  most common EXACT preview lengths (a hard cap => truncation):")
    for L, n in exact_len.most_common(5):
        print(f"     len={L:6d}  n={n}")
    print(f"  word_count field median={np.median([r.get('word_count',0) for r in rows]):.0f} "
          f"but preview char-length median={np.median(lens):.0f} "
          f"-> preview is NOT the scored text")

    # ----------------------------------------------------------- duplicates --
    hdr("6. DUPLICATE / NEAR-DUPLICATE RESPONSE TEXT")
    sub("6a. EXACT duplicates (normalized: ANSI-stripped, whitespace-collapsed, lowercased)")
    print(f"{'dataset':18s} {'n':>6s} {'unique':>7s} {'dup_records':>12s} "
          f"{'dup_rate':>9s} {'largest_cluster':>16s}")
    dup_detail = {}
    for name, rows in all_rows.items():
        buckets = defaultdict(list)
        for i, r in enumerate(rows):
            t = norm(reply_of(r))
            if t:
                buckets[sha(t)].append(i)
        uniq = len(buckets)
        duprec = sum(len(v) - 1 for v in buckets.values() if len(v) > 1)
        big = max((len(v) for v in buckets.values()), default=0)
        n_nonempty = sum(len(v) for v in buckets.values())
        print(f"{name:18s} {n_nonempty:6d} {uniq:7d} {duprec:12d} "
              f"{duprec/max(n_nonempty,1):9.3f} {big:16d}")
        dup_detail[name] = (buckets, rows)

    sub("6b. WHICH CATEGORIES the exact duplicates live in (session datasets)")
    for name in ("newcats10", "scigateway22", "sci22_turns", "chenhao"):
        buckets, rows = dup_detail[name]
        catdup = Counter()
        cattot = Counter()
        crosslabel = 0
        for h, idx in buckets.items():
            for i in idx:
                cattot[category_of(rows[i])] += 1
            if len(idx) > 1:
                for i in idx[1:]:
                    catdup[category_of(rows[i])] += 1
                labs = {label_and_branch(rows[i])[0] for i in idx}
                if len(labs) > 1:
                    crosslabel += 1
        print(f"\n  {name}: duplicate clusters spanning BOTH labels: {crosslabel} "
              f"(identical text, contradictory ground truth)")
        if catdup:
            print(f"    {'category':34s} {'dup_recs':>9s} {'of_total':>9s} {'rate':>7s}")
            for c, n in catdup.most_common(15):
                print(f"    {c:34s} {n:9d} {cattot[c]:9d} {n/cattot[c]:7.2f}")

    sub("6c. NEAR-duplicates (char 4-5gram TF-IDF cosine >= 0.90, session datasets pooled)")
    try:
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.metrics.pairwise import linear_kernel

        texts, meta = [], []
        for r in session_rows:
            t = norm(reply_of(r))
            if len(t) >= 20:
                texts.append(t)
                meta.append(r)
        vec = TfidfVectorizer(analyzer="char_wb", ngram_range=(4, 5),
                              min_df=3, max_features=60000, sublinear_tf=True)
        X = vec.fit_transform(texts)
        print(f"  vectorized {X.shape[0]} responses x {X.shape[1]} char-ngram features")
        THRESH = 0.90
        near_pairs = 0
        crosslabel_pairs = 0
        crosscat_pairs = 0
        involved = set()
        cat_involved = Counter()
        B = 500
        for s in range(0, X.shape[0], B):
            S = linear_kernel(X[s:s + B], X)
            for a in range(S.shape[0]):
                gi = s + a
                row = S[a]
                idx = np.where(row >= THRESH)[0]
                for gj in idx:
                    if gj <= gi:
                        continue
                    near_pairs += 1
                    involved.add(gi)
                    involved.add(gj)
                    ci, cj = category_of(meta[gi]), category_of(meta[gj])
                    cat_involved[ci] += 1
                    cat_involved[cj] += 1
                    if ci != cj:
                        crosscat_pairs += 1
                    if label_and_branch(meta[gi])[0] != label_and_branch(meta[gj])[0]:
                        crosslabel_pairs += 1
        print(f"  near-duplicate PAIRS (cos>={THRESH}): {near_pairs}")
        print(f"  distinct records involved: {len(involved)} / {len(texts)} "
              f"({len(involved)/len(texts)*100:.1f}%)")
        print(f"  pairs CROSSING attack categories: {crosscat_pairs} "
              f"(these defeat GroupKFold-by-category: same text in train and test)")
        print(f"  pairs with CONTRADICTORY labels: {crosslabel_pairs}")
        print(f"  top categories by near-dup involvement:")
        for c, n in cat_involved.most_common(12):
            print(f"     {c:34s} {n:6d} pair-endpoints")
    except Exception as e:  # pragma: no cover
        print(f"  near-dup pass failed: {type(e).__name__}: {e}")

    sub("6d. PROMPT duplication (identical prompt reused across records)")
    for name, rows in all_rows.items():
        pb = defaultdict(list)
        for i, r in enumerate(rows):
            p = norm(r.get("prompt") or r.get("user_prompt") or r.get("query") or "")
            if p:
                pb[sha(p)].append(i)
        dup = sum(len(v) - 1 for v in pb.values() if len(v) > 1)
        tot = sum(len(v) for v in pb.values())
        print(f"  {name:18s} prompts={tot:5d} unique={len(pb):5d} "
              f"duplicated_records={dup:5d} ({dup/max(tot,1)*100:.1f}%)")

    # ------------------------------------------- trainer field availability --
    hdr("7. FEATURE-INPUT AVAILABILITY (what train_general.py actually receives)")
    print("  train_general.py: reply_of = agent_response or response_preview")
    print("                    tools_of = d.get('tools') or []      <-- ONLY 'tools'")
    print(f"\n{'dataset':18s} {'reply_nonempty':>15s} {'tools_key':>10s} "
          f"{'tools_nonempty':>15s} {'repaired_nonempty':>18s}")
    for name, rows in all_rows.items():
        rep = sum(1 for r in rows if reply_of(r).strip())
        haskey = sum(1 for r in rows if "tools" in r)
        tne = sum(1 for r in rows if tools_of(r))
        rne = sum(1 for r in rows if tools_of_repaired(r))
        print(f"{name:18s} {rep:15d} {haskey:10d} {tne:15d} {rne:18d}")

    sub("7b. CONSEQUENCE: tool-dependent science features that are dead")
    from science_features import science_features
    for name, rows in all_rows.items():
        as_is = [science_features(reply_of(r), tools_of(r)) for r in rows]
        rep = [science_features(reply_of(r), tools_of_repaired(r)) for r in rows]
        for k in ("verified_externally", "unverified_confident_claim", "capability_spoof"):
            a = np.mean([f[k] for f in as_is])
            b = np.mean([f[k] for f in rep])
            tag = "  <== CHANGES" if abs(a - b) > 1e-9 else ""
            print(f"  {name:18s} {k:28s} as_is={a:.3f} repaired={b:.3f}{tag}")

    # ------------------------------------------------------------- pooling --
    hdr("8. POOLED-CORPUS RECONCILIATION (what the trainer's glob actually loads)")
    globbed = []
    for f in sorted(glob.glob("data/logs/collected_*/*.jsonl")) + \
             sorted(glob.glob("data/logs/chenhao_release/*.jsonl")):
        n = sum(1 for l in open(f, errors="replace") if l.strip())
        globbed.append((f, n))
    tot = 0
    for f, n in globbed:
        print(f"  {n:6d}  {f}")
        tot += n
    print(f"  {tot:6d}  TOTAL matched by trainer glob")
    keep = sum(1 for r in session_rows if reply_of(r).strip())
    print(f"  {keep:6d}  after trainer's 'reply text non-empty' filter")
    print(f"  NOTE: spring_memory_poisoning ({len(all_rows['spring_mempoison'])} turns) "
          f"is NOT matched by the trainer glob.")
    other = sorted(glob.glob("data/logs/image_sessions/**/*.jsonl", recursive=True)) + \
        sorted(glob.glob("data/logs/container_sessions/**/*.jsonl", recursive=True))
    print(f"  {len(other):6d}  additional .jsonl files exist under data/logs/ "
          f"(image_sessions, container_sessions) and are NOT loaded")

    sub("8b. SESSION-ID COLLISIONS ACROSS DATASETS (double-counting risk)")
    seen = defaultdict(set)
    for name, rows in all_rows.items():
        for r in rows:
            seen[str(r.get("session_id"))].add(name)
    coll = {k: v for k, v in seen.items() if len(v) > 1}
    print(f"  session_ids appearing in >1 dataset: {len(coll)}")
    for k, v in list(coll.items())[:10]:
        print(f"     {k:44s} {sorted(v)}")
    for name, rows in all_rows.items():
        ids = [str(r.get("session_id")) for r in rows]
        print(f"  {name:18s} n={len(ids):5d} distinct_session_id={len(set(ids)):5d} "
              f"(repeat factor {len(ids)/max(len(set(ids)),1):.2f})")

    sub("8c. MODEL / PROVIDER SKEW (confound: does label track the model?)")
    for name in ("scigateway22", "chenhao"):
        rows = all_rows[name]
        c = defaultdict(lambda: [0, 0])
        for r in rows:
            m = (r.get("agent_config") or {}).get("model", "?")
            y, _ = label_and_branch(r)
            c[m][0] += 1
            c[m][1] += y
        print(f"  {name}:")
        for m, (n, p) in sorted(c.items()):
            print(f"     {m:34s} n={n:5d} pos={p:5d} pos_rate={p/n:.3f}")

    hdr("9. RECOMMENDED EXCLUSIONS (records that should not train or score)")
    total_excl = 0
    for name, rows in all_rows.items():
        excl = 0
        reasons = Counter()
        for r in rows:
            fl = classify_text(reply_of(r))
            bad = fl & {"empty", "cli_log_noise", "error_text"}
            if bad:
                excl += 1
                for b in bad:
                    reasons[b] += 1
        total_excl += excl
        print(f"  {name:18s} exclude {excl:5d} / {len(rows):5d} "
              f"({excl/len(rows)*100:5.1f}%)  reasons={dict(reasons)}")
    print(f"  TOTAL recommended exclusions: {total_excl}")

    hdr("10. EFFECTIVE SAMPLE SIZE AFTER DEDUP (session datasets)")
    buckets = defaultdict(list)
    for i, r in enumerate(session_rows):
        t = norm(reply_of(r))
        if t:
            buckets[sha(t)].append(i)
    keep_idx = [v[0] for v in buckets.values()]
    y_all = np.array([label_and_branch(r)[0] for r in session_rows])
    y_dedup = np.array([label_and_branch(session_rows[i])[0] for i in keep_idx])
    print(f"  raw records                : {len(session_rows):5d}  "
          f"pos={y_all.sum():4d}  neg={(y_all==0).sum():4d}  "
          f"pos_rate={y_all.mean():.3f}")
    print(f"  after exact-text dedup     : {len(keep_idx):5d}  "
          f"pos={y_dedup.sum():4d}  neg={(y_dedup==0).sum():4d}  "
          f"pos_rate={y_dedup.mean():.3f}")
    print(f"  records LOST to dedup      : {len(session_rows)-len(keep_idx):5d} "
          f"({(len(session_rows)-len(keep_idx))/len(session_rows)*100:.1f}%)")

    sub("10b. Do duplicate clusters SPAN files/models? (train/test contamination)")
    span_file = span_cat = span_cond = 0
    biggest = []
    for h, idx in buckets.items():
        if len(idx) < 2:
            continue
        files = {session_rows[i]["__file"] for i in idx}
        cats = {category_of(session_rows[i]) for i in idx}
        conds = {condition_of(session_rows[i]) for i in idx}
        if len(files) > 1:
            span_file += 1
        if len(cats) > 1:
            span_cat += 1
        if len(conds) > 1:
            span_cond += 1
        biggest.append((len(idx), sorted(cats), sorted(files), sorted(conds),
                        norm(reply_of(session_rows[idx[0]]))[:90]))
    print(f"  duplicate clusters spanning >1 FILE     : {span_file}")
    print(f"  duplicate clusters spanning >1 CATEGORY : {span_cat} "
          f"<-- identical text in both train and test under GroupKFold")
    print(f"  duplicate clusters spanning >1 CONDITION: {span_cond}")
    print("\n  largest duplicate clusters:")
    for n, cats, files, conds, snip in sorted(biggest, reverse=True)[:12]:
        print(f"    n={n:3d} cats={cats} conds={conds}")
        print(f"          files={files}")
        print(f"          text: {snip!r}")

    sub("10c. Per-category EFFECTIVE positives after dedup")
    eff = defaultdict(lambda: [0, 0])
    for i in keep_idx:
        c = category_of(session_rows[i])
        eff[c][0] += 1
        eff[c][1] += label_and_branch(session_rows[i])[0]
    print(f"    {'category':34s} {'raw_n':>6s} {'raw_pos':>8s} {'eff_n':>6s} {'eff_pos':>8s}")
    for c in sorted(catstats, key=lambda k: -catstats[k][1]):
        rn, rp, _ = catstats[c]
        en, ep = eff[c]
        warn = "  <-- <5 effective positives" if 0 < ep < 5 else ""
        print(f"    {c:34s} {rn:6d} {rp:8d} {en:6d} {ep:8d}{warn}")


    hdr("11. LABEL INTEGRITY CHECKS")
    sub("11a. Same session_id, CONTRADICTORY label across files")
    by_id = defaultdict(list)
    for r in session_rows:
        by_id[str(r.get("session_id"))].append(r)
    contra = []
    for sid, rs in by_id.items():
        labs = {label_and_branch(r)[0] for r in rs}
        if len(labs) > 1:
            contra.append((sid, [(r["__file"], label_and_branch(r)[0],
                                  label_and_branch(r)[1]) for r in rs]))
    print(f"  session_ids with contradictory labels: {len(contra)}")
    for sid, entries in contra[:12]:
        print(f"    {sid}")
        for f, y, br in entries:
            print(f"       {f:30s} label={y} via {br}")

    sub("11b. turns.jsonl: attack_present vs assigned label")
    tr = all_rows["sci22_turns"]
    c = Counter((r.get("attack_present"), label_and_branch(r)[0]) for r in tr)
    for k, v in sorted(c.items(), key=lambda kv: str(kv[0])):
        flag = "  <-- MISLABELED (benign turn labeled unsafe)" if (k[0] is False and k[1] == 1) else ""
        print(f"    attack_present={k[0]!s:5s} -> label={k[1]}  n={v}{flag}")

    sub("11c. POSITIVE-CLASS TEXT CONCENTRATION (are positives really n distinct behaviors?)")
    posrows = [r for r in session_rows if label_and_branch(r)[0] == 1]
    tb = Counter(norm(reply_of(r)) for r in posrows)
    tot = len(posrows)
    print(f"  total positives: {tot}   distinct positive texts: {len(tb)}")
    cum = 0
    print(f"    {'n':>5s} {'cum%':>6s}  text")
    for t, n in tb.most_common(10):
        cum += n
        print(f"    {n:5d} {cum/tot*100:5.1f}%  {t[:70]!r}")
    top6 = sum(n for _, n in tb.most_common(6))
    print(f"  -> top 6 unique strings account for {top6}/{tot} = {top6/tot*100:.1f}% "
          f"of ALL positive training signal")

    sub("11d. CANARY CIRCULARITY: is attack_succeeded just 'canary appears in reply'?")
    nc = all_rows["newcats10"]
    tab = Counter()
    for r in nc:
        can = (r.get("canary") or "").strip().lower()
        echoed = bool(can) and can in reply_of(r).lower()
        tab[(echoed, bool(r.get("attack_succeeded")))] += 1
    print(f"    {'canary_in_reply':>16s} {'attack_succeeded':>17s} {'n':>6s}")
    for k, v in sorted(tab.items()):
        print(f"    {k[0]!s:>16s} {k[1]!s:>17s} {v:6d}")
    a = tab[(True, True)]
    b = tab[(True, False)]
    c_ = tab[(False, True)]
    d_ = tab[(False, False)]
    print(f"  agreement = {(a+d_)/len(nc)*100:.1f}%  "
          f"(canary echo predicts attack_succeeded with "
          f"precision {a/max(a+b,1):.3f}, recall {a/max(a+c_,1):.3f})")
    print("  If precision and recall are ~1.0, attack_succeeded is DEFINED by the canary echo:")
    print("  any text feature that detects the canary token is circular, not behavioral.")

    sub("11e. Distinct canary tokens (a fixed vocabulary a model can memorize)")
    cans = Counter((r.get("canary") or "") for r in nc)
    print(f"  distinct canary tokens in newcats10: {len(cans)}")
    for k, v in cans.most_common(8):
        print(f"     {k!r:30s} n={v}")


if __name__ == "__main__":
    main()
