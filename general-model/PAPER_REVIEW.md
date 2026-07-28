# PAPER_REVIEW.md — abstract and figures

Review of `OPALS Group 21 (3).pdf`, 2026-07-28. Every number below was recomputed from the
source data; nothing is asserted from reading the figure alone.

---

## 1. THE ABSTRACT

### Blocking problems

**1. The author list contradicts itself.** Page 2 lists four authors (Chenhao Zhang, Sid,
Sathwik Kintada, Kathleen Wang). Page 8 lists three — Sathwik is dropped. Nathan, Evangeline
and Audrey contributed collections that the paper uses. **Fix before anything else.**

**2. Broken sentence.** "...varied widely when the attack design changed, with a separately
collected browser-attack suite reproduced the enforcement result on a different attack
surface." Ungrammatical. Either "...changed. A separately collected browser-attack suite
reproduced the enforcement result..." or "...changed, with a separately collected
browser-attack suite reproducing...".

**3. The model name is wrong and inconsistent.** The abstract says "OpenClaw agentic AI
KimiK 2.5". Everywhere else it is `kimi-k2.5`. Pick one and it should be the real identifier.

**4. It cites Fig. 1 inside the abstract.** Abstracts must stand alone; most venues forbid
this. Delete "(Fig. 1)".

**5. It is ~370 words.** Typical limit is 250. It currently spends four sentences on
background before reaching the contribution.

**6. Overclaim.** "This allows almost the entirety of a research experiment to be carried
out by AI." Nothing in the paper supports "almost the entirety". Soften.

**7. The system is never named.** The gateway has no name in the abstract, so there is
nothing for a reader to cite or search for.

### Rewritten abstract (247 words)

> AI for science is moving beyond prediction. Agentic systems now read literature, propose
> hypotheses, design experiments, call analysis tools, and act on research data. The same
> ability creates a security problem: the papers, pages, and messages an agent reads can
> carry instructions it was never meant to follow. We ask whether a gateway placed in an
> agent's runtime path can recognise an agent moving toward unsafe, unreliable, or
> policy-violating scientific behaviour, and act before that behaviour occurs.
>
> We built such a gateway around a live OpenClaw agent running kimi-k2.5. It applies the
> runtime's native tool policy before a tool is made available, records every allow-or-deny
> decision as an execution log, and retains the session trace. In a matched-pair
> intervention the gateway denied the shell tool and stopped a shell-dependent
> privilege-escalation attack that succeeded in every control run.
>
> We then turned the retained traces into a structured behavioural data set to map the limit
> of that protection. Attacks that must request a tool to do damage were stopped, at an alarm
> rate on ordinary safe work low enough to leave the gate in place. Attacks whose effect is a
> false statement in an answer, or a false fact left in memory for later reuse, are not
> preventable this way: there is no tool request to refuse. We measured how much of a
> workload falls inside that boundary across six independently collected corpora. The covered
> share was stable across models and varied sharply with attack design.
>
> The contribution is a control point, not an attack taxonomy: a gateway that refuses a
> dangerous request before the agent can issue it, and that records what it cannot refuse.

Changes: fixed grammar and model name, removed the figure reference, cut background, dropped
the overclaim, and moved the honest negative (text-and-memory attacks are not preventable)
into its own sentence instead of a subordinate clause.

---

## 2. FIGURES

### The systemic problem: six figures show percentages with no interval

Five of the seven figures plot proportions on denominators between 4 and 16 and print them
as bare percentages. At those sizes the intervals are wider than the effects being shown.

| figure | cell | actual | 95% Wilson | width |
|---|---|---|---|---|
| Fig 2a | defended 0/4 | 0% | [0.0, 49.0] | **49 pt** |
| Fig 2a | control 4/4 | 100% | [51.0, 100] | **49 pt** |
| Fig 6 | provenance spoofing, +transcript 2/10 | 20% | [5.7, 51.0] | **45 pt** |
| Fig 7 | website payloads 2/8 | 25% | [7.1, 59.1] | **52 pt** |
| Fig 7 | broad taxonomy 14/16 | 88% | [64.0, 96.5] | **33 pt** |
| Fig 3 | action-manifesting 50/50 | 100% | [92.9, 100] | 7 pt |
| Fig 3 | text-or-state 0/160 | 0% | [0.0, 2.3] | 2 pt |

**Fig 3 is the only one whose bars are narrower than the gap they show.** It is the paper's
strongest figure and it should be presented as such.

### Figure by figure

**Fig 1 — architecture.** Correct but it undersells the system. It draws a single "native
tool policy" box. The deployed gateway has seven scoring layers with a block/flag split that
is the central design decision. Add the layer stack, or state in the caption that Fig 1 shows
only the native policy path.

**Fig 2 — matched A/B.** Two problems.
- n=4 per arm. The bars read as a clean 100%/0% result; the intervals overlap at 49 points
  wide. The text is honest ("a small demonstration of causal prevention, not a rate
  estimate") but **the figure is not**. Put n and the interval on the panel.
- Panel (b) puts "shell actions executed" (12) and "inline deny records" (21) on one shared
  "Recorded events" axis. **These are different units.** One counts attacker success, the
  other counts gateway bookkeeping. Sharing an axis implies 21 > 12 means something. Split
  the panels or relabel.

**Fig 3 — the tool boundary.** The best figure in the paper. Keep it. Add the two Wilson
intervals ([92.9, 100] and [0, 2.3]) — they are narrow and they *strengthen* the claim.
Caption correctly flags it as retrospective.

**Fig 4 — signal tiers.** The visual story is "both curves go up", which is the wrong
takeaway. The real finding is that the *ratio* collapses: attacks 24→72→96 while safe tasks
5→38→54, so precision falls 0.74→0.53→0.51. That is Fig 5's content, and it should be
visible here as a third panel or a precision line. Also state why the Deepseek series appears
in (a) but not (b).

**Fig 5 — confusion matrices.** Verified correct: 50/(50+18)=**0.735**, 151/(151+132)=**0.534**,
201/(201+190)=**0.514**, matching the printed 0.74 / 0.53 / 0.51. Row-normalised shading with
unequal denominators is explained in the caption. Only suggestion: annotate the precision
trend across the three panels, since that is the point.

**Fig 6 — per-category heatmap.** Strong; the block structure is a genuine finding. One fix:
**the provenance-spoofing row is n=10, so 0% / 10% / 20% is 0, 1 and 2 sessions.** Rendered
in the same colour scale as the n=50 rows it reads as a comparable measurement. Grey it,
hatch it, or move it to a footnote.

**Fig 7 — boundary across collections.** Good design. One fix: bar length encodes share but
nothing encodes n, and n runs from **8 to 315**. The 88% bar (n=16) and the 25% bar (n=8) are
visually equal in weight to the 41% bar (n=315). Encode n as bar thickness or opacity, or
order the rows by n. The pooled 30% line is dominated by the n=315 row and that is invisible.

### Verified correct

- Pooled action-manifesting share: **29.6%**, Wilson **[27, 33]**, over **816** successes.
  Matches the paper's "30% (27% to 33%)" and "816" exactly.
- Fig 5 precisions, all three.
- Indirect prompt injection 315/400 = 78.8%, and 22-category 16/41 = 39.0%.

---

## 3. STILL WRONG IN TABLE 2

**Memory poisoning row: 84 scored, 84 successes, 100%.** The control group is **20 sessions,
of which 10 are scored `not_applicable (control question, no ground truth)`** — so the
effective control is **10**. A 100% attack success rate quoted against a 10-session control
cannot support the false-positive claim the row implies. Either collect more controls or
state the effective n in the caption.

**Ten-category row: 798 scored, 226 successes.** Still not reproducible. No file in the
repository contains 798 attack rows; our collection is 1,085 attack / 1,081 baseline. The
paper's Data Availability section names
`standardized_analysis/standardize_tracks.py` as the script that regenerates it. **That file
does not exist in the repository.** Until it is committed, this row and the pooled 30% cannot
be checked by anyone outside the author.

**"no tool targets" caveat on the ten-category row is now stale.** The recovered action trail
carries `kind`, `target`, `in_scope` and `status` on every action: 6,387 action records over
950 enriched rows and 1,284 distinct trials, now in `general-model/logs/`. Quote
distinct-trial figures (660 trials with actions, 1,059 out-of-scope actions); never the
row-level sum, which the non-unique `session_id` join inflates.
