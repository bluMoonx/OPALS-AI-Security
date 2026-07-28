"""Generate the paper figures from the rebuilt, honest results.

Reads whatever is present and skips gracefully:
  analysis/rebuild/gold2_*.jsonl + gold_*.jsonl  -> gold behavioural labels (via the
                                                    vetted loader, never by session_id)
  data/logs/collected_new10category/...          -> canary labels + the live corpus
  data/logs/chenhao_release/*.jsonl              -> external corpus (row counts only)
  data/logs/collected_22category/sessions.jsonl  -> external corpus (row counts only)

Writes PNGs to figures/.
Run: python3 analysis/make_figures.py

FIGURE AUDIT, 2026-07-27 (see PAPER_CORRECTIONS.md §5) — three defects fixed here:

  fig1_label_undercount.png   the two-line title was CLIPPED by figsize=(4.6, 3.4), so
                              the reader never saw the "79 %" that is the whole finding.
                              Figure widened; numbers were and are correct.

  fig3_corpus.png             WITHDRAWN (renamed .withdrawn). It plotted the frozen
                              corpus_clean.jsonl and put "363 unsafe (16 %)" in the
                              title. Three problems: (a) that 16 % is a MACHINE-LABEL
                              rate, and it pooled three different unvalidated heuristics
                              -- deterministic_behavioral_labeler (newcats),
                              chenhao_risk_indicator_or (chenhao), scigateway_heuristic
                              (scigw22) -- under one legend entry reading "unsafe";
                              (b) none of those 2303 rows is adjudicated, yet the number
                              sat in the same paper as an adjudicated headline ASR of
                              50.7 %, so a reader would read 16 % as an attack-success
                              rate; (c) it was 565 raw newcats rows stale.
                              Replaced by fig3_corpus_provenance.png, which plots ONLY
                              counts that are line counts or loader counts, carries no
                              machine-derived rate at all, and stamps its own snapshot
                              date because the collector is live.

  fig4_honest_vs_inflated.png RETIRED (renamed .withdrawn) and no longer generated.
                              Its "honest (true LOACO) 0.502" came from the canary-era
                              38-category aura_honest.joblib, defined on only 12 of 38
                              folds, one label generation out of date. The current honest
                              numbers are 0.7427 prompt-grouped / 0.7117 LOACO on
                              behavioural labels. fig5_protocol_ladder.png already tells
                              that story correctly and reads its values out of the
                              shipped artifact, so there is no replacement panel here.
"""
from __future__ import annotations
import datetime, json, glob, os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
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


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "figures")
os.makedirs(OUT, exist_ok=True)
plt.rcParams.update({"figure.dpi": 150, "font.size": 9,
                     "axes.spines.top": False, "axes.spines.right": False})
C_SAFE, C_RISK, C_ALT = "#2b8a6e", "#c0392b", "#2c5aa0"
made = []


def _load_jsonl(p):
    rows = []
    if not os.path.exists(p): return rows
    for l in open(p, errors="ignore"):
        l = l.strip()
        if not l: continue
        try: rows.append(json.loads(l))
        except Exception: pass
    return rows


def _gold_attack_rows():
    """The 817 hand-judged ATTACK rows, each paired with its EXACT source record.

    Uses the vetted resolver. Do NOT key gold by session_id: it is not unique (up to 9
    trials share one id, 51% of the corpus sits under a duplicated id), so a dict keyed on
    it silently collapses judgements and pairs labels with the wrong trial's response.
    The previous version of this file did exactly that AND globbed only `gold_*.jsonl`,
    missing all 12 `gold2_*.jsonl` files, so it rebuilt the headline figures from ~142
    attack rows instead of 817.
    """
    import sys
    sys.path.insert(0, os.path.join(ROOT, "analysis"))
    from eval_combined_gold import load_records, load_all_gold
    gold = load_all_gold(load_records())
    return [g for g in gold if g.get("condition") == "attack"]


def fig_label_comparison():
    """THE headline finding: canary labeling under-counts attack success ~4x."""
    atk = _gold_attack_rows()
    if not atk: return
    n = len(atk)
    beh = sum(1 for g in atk if g["behavioral_label"] == 1)
    can = sum(1 for g in atk if g["_rec"].get("attack_succeeded"))
    # true positives: canary fired AND the behaviour really was compliance
    tp = sum(1 for g in atk if g["_rec"].get("attack_succeeded") and g["behavioral_label"] == 1)
    missed = beh - tp

    # figsize was (4.6, 3.4): too narrow for the second title line, which got clipped
    # at "= " so the 79 % -- the finding itself -- never rendered. Widened, and the
    # subtitle is drawn as its own text object so tight_layout accounts for it.
    fig, ax = plt.subplots(figsize=(6.6, 3.8))
    bars = ax.bar(["canary-derived\n(what we used)", "behavioral\n(hand-judged)"],
                  [100 * can / n, 100 * beh / n], color=[C_ALT, C_RISK], width=.55)
    for b, v in zip(bars, [can, beh]):
        ax.text(b.get_x() + b.get_width() / 2, b.get_height() + 1.5,
                f"{100*v/n:.1f}%\n({v}/{n})", ha="center", fontsize=9, weight="bold")
    ax.set_ylabel("attack success rate (%)")
    ax.set_title("Canary labeling under-counts attack success", fontsize=11, pad=22)
    ax.text(0.5, 1.015,
            f"n={n} hand-judged attack sessions; canary misses "
            f"{missed} of {beh} = {100*missed/max(beh,1):.0f}%",
            transform=ax.transAxes, ha="center", va="bottom", fontsize=9.5, color="#333")
    ax.set_ylim(0, max(100 * beh / n, 100 * can / n) * 1.35)
    fig.tight_layout(); p = os.path.join(OUT, "fig1_label_undercount.png")
    fig.savefig(p); plt.close(fig); made.append(p)


def fig_per_category_asr():
    """Behavioral attack-success rate per category (where the agent is weak)."""
    atk = _gold_attack_rows()
    if not atk: return
    from collections import defaultdict
    tot, suc = defaultdict(int), defaultdict(int)
    for g in atk:
        c = g.get("category", "?"); tot[c] += 1; suc[c] += 1 if g["behavioral_label"] == 1 else 0
    cats = [c for c in tot if tot[c] >= 2]
    if not cats: return
    cats.sort(key=lambda c: suc[c] / tot[c])
    rates = [100 * suc[c] / tot[c] for c in cats]
    fig, ax = plt.subplots(figsize=(6.2, 0.34 * len(cats) + 1.5))
    ax.barh(range(len(cats)), rates, color=[C_RISK if r >= 50 else C_ALT for r in rates], height=.6)
    ax.set_yticks(range(len(cats)))
    ax.set_yticklabels([c.replace("_", " ") for c in cats], fontsize=8)
    for i, (c, r) in enumerate(zip(cats, rates)):
        ax.text(r + 1.5, i, f"{r:.0f}% ({suc[c]}/{tot[c]})", va="center", fontsize=7.5)
    ax.set_xlabel("behavioral attack success rate (%)")
    ax.set_title("Which attacks actually work on the agent", fontsize=10)
    ax.set_xlim(0, 108)
    fig.tight_layout(); p = os.path.join(OUT, "fig2_per_category_asr.png")
    fig.savefig(p); plt.close(fig); made.append(p)


def fig_corpus_provenance():
    """Where the evidence comes from, and how much of it is actually adjudicated.

    Replaces the withdrawn fig3_corpus.png. EVERY number on the face of this figure is
    either a raw line count of a source file or a count returned by the vetted gold
    loader. No machine label, and therefore no rate that could be misread as an
    attack-success rate, appears anywhere on it. The one rate a reader is entitled to
    take from this paper -- 50.7 % adjudicated behavioural ASR -- lives in fig1/fig2.

    newcats_sessions.jsonl is appended to by a live collector, so the panel stamps the
    snapshot date and the file's own mtime.
    """
    import sys
    sys.path.insert(0, os.path.join(ROOT, "analysis"))
    from eval_combined_gold import load_records, load_all_gold

    newcats_p = os.path.join(ROOT, _aura_find("newcats_sessions.jsonl"))
    scigw_p = os.path.join(ROOT, "data/logs/collected_22category/sessions.jsonl")
    chenhao_g = sorted(glob.glob(os.path.join(ROOT, "data/logs/chenhao_release/*.jsonl")))
    if not os.path.exists(newcats_p): return

    def _nlines(p):
        return sum(1 for l in open(p, errors="ignore") if l.strip())

    recs = load_records()
    gold = load_all_gold(recs)
    n_newcats = len(recs)                       # == line count of newcats_sessions.jsonl
    n_chenhao = sum(_nlines(p) for p in chenhao_g)
    n_scigw = _nlines(scigw_p) if os.path.exists(scigw_p) else 0
    # every gold row resolves into newcats_sessions.jsonl; assert rather than assume
    assert all(0 <= g["line_idx"] < n_newcats for g in gold), "gold row outside newcats"
    n_gold = len(gold)

    labels = ["newcats\n(this work, live)", "chenhao_release\n(external)",
              "collected_22category\n(external)"]
    totals = [n_newcats, n_chenhao, n_scigw]
    adjud = [n_gold, 0, 0]

    fig, ax = plt.subplots(figsize=(6.4, 3.9))
    x = np.arange(len(labels))
    b1 = ax.bar(x - .19, totals, .38, label="sessions collected", color=C_ALT)
    b2 = ax.bar(x + .19, adjud, .38, label="hand-adjudicated (gold)", color=C_SAFE)
    for bars, vals in ((b1, totals), (b2, adjud)):
        for b_, v in zip(bars, vals):
            ax.text(b_.get_x() + b_.get_width() / 2, v + max(totals) * .015,
                    f"{v}", ha="center", fontsize=8.5, weight="bold")
    ax.set_xticks(x); ax.set_xticklabels(labels, fontsize=8.5)
    ax.set_ylabel("sessions")
    ax.set_ylim(0, max(totals) * 1.18)
    ax.legend(frameon=False, fontsize=8.5, loc="upper right")
    ax.set_title("Evidence base: collected vs hand-adjudicated", fontsize=11, pad=20)
    stamp = datetime.datetime.now().strftime("%Y-%m-%d")
    mt = datetime.datetime.fromtimestamp(os.path.getmtime(newcats_p)).strftime("%Y-%m-%d %H:%M")
    ax.text(0.5, 1.015,
            f"snapshot {stamp} (newcats collector is live; file mtime {mt}). "
            f"No machine labels plotted.",
            transform=ax.transAxes, ha="center", va="bottom", fontsize=8, color="#333")
    fig.tight_layout(); p = os.path.join(OUT, "fig3_corpus_provenance.png")
    fig.savefig(p); plt.close(fig); made.append(p)


# fig4_honest_vs_inflated is intentionally NOT generated. See the module docstring.
# Its replacement is analysis/make_fig5_protocol_ladder.py -> fig5_protocol_ladder.png,
# which reads 0.7427 / 0.7117 straight out of models/metrics_behavioral.json.


def _retire(name, why):
    """Rename a published-but-misleading PNG to .withdrawn, once, and say so."""
    src = os.path.join(OUT, name)
    if os.path.exists(src):
        os.replace(src, src + ".withdrawn")
        print(f"  retired {name} -> {name}.withdrawn  ({why})")


def main():
    _retire("fig3_corpus.png", "machine-label rate readable as an ASR; stale")
    _retire("fig4_honest_vs_inflated.png", "canary-era 0.502 shown as 'the honest number'")
    for fn in (fig_label_comparison, fig_per_category_asr, fig_corpus_provenance):
        try: fn()
        except Exception as e: print(f"  skip {fn.__name__}: {type(e).__name__}: {e}")
    print(f"generated {len(made)} figures -> {OUT}")
    for p in made: print("  " + os.path.basename(p))


if __name__ == "__main__":
    main()
