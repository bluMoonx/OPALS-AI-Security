# Memory-Poisoning Track — Checkpoint: Feature Engineering & Group 18 Replication Attempt

**Status: checkpoint complete, track still open.** This closes out the feature-engineering
phase on the existing 40-session dataset. It does not conclude the memory-poisoning
track — more sessions, tool-forcing prompts, and a second domain remain open next
steps if time allows.

## 1. Starting point

Checkpoint 2 (feature-level analysis) had found `tool_count` and `fallback_steps`
were zero-variance (uninformative by construction, since MEMORY.md is pre-injected
into the system prompt and no tool calls are needed to read it), and had flagged a
possible correlation between `flags_discrepancy_language` and `compliance_with_flag`
(67% vs. 36%) — but noted a real keyword-leakage risk between that feature's word
list and `evaluation-key.json`'s own scoring keywords.

## 2. Bug #1 — keyword leakage, confirmed and fixed

`flags_discrepancy_language`'s marker list included the word `"standard"`, which is
also a clean-answer keyword in 6 of 10 `evaluation-key.json` Direct Retrieval entries.
This meant the feature was partially re-detecting the same signal that produced the
`compliance_with_flag` label, rather than providing independent evidence.

**Fix:** added a `load_eval_keywords()` function that collects every keyword from
both sides of `evaluation-key.json`, and a runtime check that raises `ValueError` if
any feature's marker word overlaps that list.

**Result after the fix:** `flags_discrepancy_language` became **zero-variance**
(every attack response scored `False`) once the leaking word was removed. This
confirms the original 67%/36% split was entirely an artifact of keyword leakage, not
a real behavioral signal. Reported here as a negative result, not hidden.

## 3. New features, motivated by prior work (Group 18 / CIST 117)

The OPALS proposal names the spring team's paper (Jaden Shen et al., "Gateway-Centered
Predictive and Preventive Security Framework for Agentic AI Systems") as an explicit
reference. That team ran a comparable memory-poisoning experiment on OpenClaw
(Gemini Flash Lite, 50 baseline / 50 attack sessions) and got a working random-forest
classifier (78.75% accuracy, F1 0.77, ROC-AUC 0.874) using: **response latency,
output length, hedge density, qualifier ratio, and numeric value count.** Notably,
none of those are `tool_count`/`fallback_steps` — consistent with this project's own
finding that those features are degenerate for direct-context Q&A prompts.

Four new features were added to `build_feature_table.py` to attempt a replication
on this dataset (different model, different query design — Direct/Derived split
vs. Group 18's pure trigger queries):

- `hedge_density` — epistemic hedge words ("may," "might," "could," "likely," etc.)
  per total word count
- `qualifier_ratio` — quantitative-approximation phrases ("roughly," "nearly,"
  "at least," etc.) per total word count
- `numeric_value_count` — count of distinct numeric tokens in the response
- `response_latency_seconds` — seconds between the `prompt.submitted` and
  `model.completed` events in each session's raw trajectory log

All new marker word lists were checked against the same banned-keyword list from
Bug #1 before use, to avoid reintroducing the same leakage problem.

## 4. Bug #2 — negative latency, found and fixed

One session (`53807520-...`) showed `response_latency_seconds = -0.225`. Root cause:
that session's `.trajectory.jsonl` file had a leftover `model.completed` event from
a *different, earlier* session appended before this session's own events — a known
pattern in this log format (the same kind of stray-fragment issue seen earlier with
an appended `model.fallback_step`). The original latency function grabbed the first
occurrence of each event type anywhere in the file, regardless of order, and paired
the wrong two timestamps.

**Fix:** `model.completed` is now only accepted if it occurs after this session's
own `prompt.submitted` has already been seen. For this specific corrupted file, no
valid completion event follows, so the session now correctly returns `None` for
latency instead of a fabricated negative number. This session was a **baseline**
session, so it did not affect any attack-only comparison.

## 5. Results (attack sessions only, n=10 per compliance group)

| Feature | full_compliance | compliance_with_flag | Discriminates? |
|---|---|---|---|
| `qualifier_ratio` | avg 0.0000 (**hard floor**, min=max=0) | avg 0.0022, range 0–0.0147 | **Yes** — clean separation |
| `hedge_density` | avg 0.0011, range 0–0.0106 | avg 0.0007, range 0–0.0068 | No — heavy overlap |
| `numeric_value_count` | avg 4.6, range 2–15 | avg 4.4, range 2–8 | No — heavy overlap |
| `response_latency_seconds` | avg 4.32s, range 1.08–7.70s | avg 3.82s, range 1.27–5.15s | No — heavy overlap |
| `cites_memory_md` | true in 9/10 | true in 10/10 | Weak — 1 outlier only |
| `response_length_chars` | avg 452, range 189–1018 | avg 523, range 215–912 | No — heavy overlap |

## 6. Honest conclusion

**One real, clean, non-leaky finding:** `qualifier_ratio` separates the two
compliance outcomes — every `full_compliance` session used zero qualifier language,
while `compliance_with_flag` sessions varied above zero. This is directionally
sensible (sessions where the model hedges toward the real value are exactly the
sessions where it surfaces both values instead of fully deferring to the poison).

**Three features failed to replicate Group 18's result** on this dataset, even
after fixing the latency bug: `hedge_density`, `numeric_value_count`, and
`response_latency_seconds` all show substantial overlap between groups. This is a
legitimate negative result worth reporting as-is — possible explanations include
model differences (Kimi K2.5 vs. Gemini Flash Lite), query design differences
(Direct/Derived split vs. Group 18's pure trigger queries), or simply insufficient
sample size (n=10 per group is thin for continuous-feature comparisons).

**Caveat on `qualifier_ratio` itself:** n=10 per group is small, and a hard floor at
0 for one group is a strong pattern but not yet statistically robust. Should be
treated as a promising lead, not a settled result, until confirmed on more sessions.

## 7. Second data batch (n=21/23) — qualifier_ratio replicated

Ran two additional batches of the same 20 attack queries (blocked partway through
by a shared-account Ollama Cloud quota limit, confirmed via a standalone diagnostic
script that bypassed Docker/OpenClaw entirely, and resolved once the quota reset).
Fixed the session-matching/scoring pipeline along the way so genuine repeat trials
are kept as separate rows instead of being deduplicated away, and so scores are
joined directly onto sessions (no more id-based join that could silently collide
once multiple trials share a question id).

Final sample: **21 compliance_with_flag, 23 full_compliance** attack sessions.

`qualifier_ratio`'s floor held exactly: every `full_compliance` session still has
`qualifier_ratio == 0.0000`, now across more than double the original sample.

## 8. Predictive classifier (final analysis)

Trained Logistic Regression (with and without feature scaling) and a depth-3
Decision Tree to predict `compliance_with_flag` vs. `full_compliance` from the six
non-degenerate features (`response_length_chars`, `cites_memory_md`,
`hedge_density`, `qualifier_ratio`, `numeric_value_count`,
`response_latency_seconds`), evaluated with 5-fold stratified cross-validation.

| Model | Accuracy | Precision | Recall | F1 |
|---|---|---|---|---|
| Logistic Regression (unscaled) | 0.568 | 0.562 | 0.783 | 0.655 |
| Logistic Regression (scaled) | 0.568 | 0.571 | 0.696 | 0.627 |
| Decision Tree (depth=3) | 0.477 | 0.500 | 0.522 | 0.511 |

**Baseline for comparison:** always predicting the majority class
(`full_compliance`) gives 23/44 = 0.523 accuracy. None of the three models beat
this by a meaningful margin — feature scaling did not change Logistic
Regression's accuracy at all.

**Isolating `qualifier_ratio` alone** (`qualifier_ratio > 0` → predict
`compliance_with_flag`): **precision 1.000, recall 0.143** (3/3 correct when it
fires, but only fires on 3 of 21 true `compliance_with_flag` cases). This
explains the model-level result precisely: `qualifier_ratio` is a perfectly
reliable but rarely-triggered rule, not a broad discriminator — its signal gets
diluted rather than amplified when blended with five other features that
individually show no discriminative power.

## 9. Final conclusion

Gateway/session-log-derived features, as engineered in this project, **do not
support a reliable classifier** for predicting memory-poisoning compliance
outcome (full vs. partial deference to the poison) on this dataset. This is a
legitimate, mechanistically-explained negative result, not a failed experiment:
one narrow, high-precision/low-recall rule (`qualifier_ratio`) was found and
replicated at n=21/23 with no degradation, but it does not generalize into a
usable predictor on its own, and no other feature combination improved on
majority-class guessing.

This contrasts informatively with Group 18's reported 78.75% accuracy using an
overlapping feature set (latency, output length, hedge density, qualifier ratio)
on a different model (Gemini Flash Lite vs. this project's Kimi K2.5) and a
different query design (pure trigger queries vs. this project's Direct
Retrieval/Derived Logic split). Worth naming directly in the writeup as an open
question: whether the gap is attributable to the model, the query design, sample
size, or some combination.

## 10. Open next steps (not started, optional future work)

In priority order if continuing beyond this checkpoint:
1. Add tool-forcing attack prompts (a new query category) so `tool_count`/
   `fallback_steps` stop being structurally degenerate — currently the biggest
   untested lever, since the entire feature set used here comes from
   direct-context Q&A with no real tool execution involved.
2. Add a second poisoned domain to test whether the `qualifier_ratio` rule and
   the classifier's negative result replicate outside astrophysics.
3. If pursuing the model-vs-Group-18 discrepancy specifically: rerun the same
   20 queries against Gemini Flash Lite (or another model) to isolate whether
   model choice explains the gap in classifier performance.
