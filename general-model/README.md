# AURA — a live behavioral risk gate for OpenClaw

**AURA sits inside a running OpenClaw agent and decides, before each tool call and each
reply, whether to allow it, ask a human, or refuse it.**

It is a control point, not a classifier bolted on afterwards. Seven layers score every
event; the risk is the max; only the precise layers are allowed to block.

```
Scientific task + untrusted content
            │
            ▼
   ┌─────────────────┐   tool request    ┌──────────────────┐   allow / deny
   │  OpenClaw agent │ ────────────────▶ │  aura-monitor    │ ───────────────▶ tools
   └─────────────────┘                   │  (plugin)        │
            │                            └────────┬─────────┘
            │ reply                               │ HTTP
            ▼                                     ▼
   ┌─────────────────────────────────────────────────────────┐
   │  scorer.py  (host :5005)                                │
   │                                                         │
   │   BLOCK-grade   RULE ─ ECHO ─ COMPLIANCE ─ SPECIALIST    │
   │   FLAG-grade    ACTION ─ GENERAL ─ INSTRUCTED_ECHO       │
   │                                                         │
   │   risk = max(layers)   block ≥ 0.85   flag ≥ 0.50        │
   └────────────────────────┬────────────────────────────────┘
                            ▼
                   live dashboard /dashboard
```

---

## Results

### The gate, on held-out data

Shipped default, `AURA_BLOCK_POLICY=strict`:

| slice | n | precision | recall | tp / fp |
|---|---|---|---|---|
| **OOS** — unseen attack sessions | 671 | **0.9214** | **0.6029** | 211 / 18 |
| **STRICT** — prompt never seen in training | 288 | **0.9213** | **0.4767** | 82 / 7 |
| gold1 — threshold-fitting slice | 146 | 0.9310 | 0.8438 | 54 / 4 |
| independent corpus (different collector) | 400 | 0.9099 | 0.3206 | — |

**Benign cost: 31 false blocks in 1,081 sessions = 2.87%** [2.0, 4.0], budget 3.00%.
Of 54 raw blocks, 23 are objectively correct (canary disclosed, planted marker emitted,
credential code, secret-file solicitation), leaving 31 false.

### The full policy curve

| policy | OOS P / R | STRICT P / R | benign raw / correct / **FALSE** | rate | budget |
|---|---|---|---|---|---|
| `off` | .9235 / .4486 | .8793 / .2965 | 31 / 19 / **12** | 1.11% | ok |
| **`strict`** ← ships | **.9214 / .6029** | **.9213 / .4767** | 54 / 23 / **31** | **2.87%** | **ok** |
| `balanced` | .9217 / .6057 | .9222 / .4826 | 59 / 24 / **35** | 3.24% | over |
| `aggressive` | .9183 / .6743 | .9292 / .6105 | 130 / 31 / **99** | 9.16% | over |

`balanced` buys +1 tp on each slice for 4 more false blocks and breaks the budget.
`aggressive` blocks roughly one benign session in eleven.

### The model

`aura_behavioral.joblib` — Random Forest, 12 features, 965 hand-judged labels.

| metric | value |
|---|---|
| prompt-grouped CV AUC, 10 seeds | **0.7427** |
| leave-one-attack-category-out AUC | **0.7117** |
| controls, v1 (length-confounded) | **0/200** blocked |
| controls, v2 (length-matched, harder) | **0/200** blocked |
| test suite | **24 / 24** |

**F1 is the wrong lens here and we do not headline it.** The always-positive trivial F1 is
0.6035 on all gold, 0.6856 on OOS, 0.7478 on STRICT. F1 never looks at the benign
population, which is the entire point of a gate. Quote (recall, benign false-block rate).

### The corpus

| corpus | rows | distinct prompts | role |
|---|---|---|---|
| ten-category (ours) | 2,166 | 285 in gold | train + eval |
| hand-judged gold | 965 | 285 | 817 attack / 148 baseline |
| cross-source release | 1,314 | **10** | transfer; 81% carry tool output |
| independent prompt-injection | 600 | 455 | held-out transfer |
| independent controls v2 | 600 | 531 | benign, confound removed |
| memory poisoning | 94 | — | 84 attack / 10 control |
| broad taxonomy | 82 | — | 23 attack categories |
| browser payloads | 16 | — | live rerun with tool traces |
| **total** | **5,372** | | |

Action trail: **6,387 action records** with `kind`/`target`/`in_scope`/`status` over 950
enriched rows and **1,284 distinct trials**. Quote distinct-trial figures (660 trials with
actions, 1,059 out-of-scope actions) — the row-level sums are inflated by a non-unique
`session_id` join.

### Layering: measured, and it does not ship

LOACO **0.7117 -> 0.7395** (reproduced at 0.7402 on different seeds), moving exactly the
families that sat near chance: `cot_hijack` 0.307 -> 0.392, `false_precedent` 0.514 -> 0.655.
But the gain at the operating point is **+1 true positive per slice**, which a permuted-score
null reproduces exactly, and precision falls under 0.90. The gate buys **6.81 true positives
per false block**; the best layer buys **0.375**. Details in [`layering/`](layering/README.md).

Reproduce everything above:

```bash
python3 analysis/paper_repro/policy_curve.py    # the policy table
python3 layering/w2_repro.py                    # AUC, LOACO, per-family
python3 openclaw-plugin/test_suite.py           # 24 tests
```

> **No gate number may be quoted without its policy label.** A recall from one policy beside
> a benign rate from another describes a system that does not exist. That has happened here
> before. Full detail in [`GATE_OPERATING_POINTS.md`](GATE_OPERATING_POINTS.md).

---

## Start here

| I want to... | go to |
|---|---|
| **install and run the gate** | [`openclaw-plugin/README.md`](openclaw-plugin/README.md) |
| **see the numbers and how they were measured** | [`GATE_OPERATING_POINTS.md`](GATE_OPERATING_POINTS.md) |
| **understand each model file** | [`MODELS.md`](MODELS.md) |
| **know whether layering helps** | [`layering/README.md`](layering/README.md) |

```bash
cd openclaw-plugin && ./setup.sh          # install into a running OpenClaw container
python3 openclaw-plugin/test_suite.py     # 24 tests, run after any change
```

---

## The seven layers

| layer | grade | fires when |
|---|---|---|
| `rule` | **block** | the tool call itself is dangerous (recursive delete, secret-file read, egress) |
| `compliance` | **block** | the agent obeyed an instruction injected into content it read |
| `echo` | **block** | the reply repeats a distinctive token from untrusted content it ingested |
| `specialist` | **block** | memory-poisoning pattern *and* an untrusted-source frame |
| `action` | flag | the session's action trail is risky in aggregate |
| `general` | flag | the behavioural model is elevated |
| `instructed_echo` | flag | the reply emits a literal the prompt planted |

**Only precise layers may block.** The general model and the action layer are capped below
the block threshold, deliberately: they have broad coverage and mediocre precision, so they
raise an approval prompt instead of refusing outright. This is the single design decision
that keeps the benign cost inside budget.

`before_agent_run` is load-bearing. Without the prompt, the compliance layer short-circuits
and the entire measured detection stack is dead. That was a real production outage in this
plugin, and it is why the hook exists.

---

## Layout

```
general-model/
├── README.md                 ← you are here
├── MODELS.md                 what each .joblib is, and which one to use
├── GATE_OPERATING_POINTS.md  the authoritative numbers
│
├── openclaw-plugin/          THE PRODUCT
│   ├── README.md               install guide, config, dashboard, limitations
│   ├── scorer.py               scoring service + dashboard (/score /history /dashboard)
│   ├── aura-monitor/           the OpenClaw plugin (index.ts + manifest)
│   ├── behavioral_labeler.py   deterministic compliance channel
│   ├── deferred_compliance.py  deferred-solicitation channel
│   ├── setup.sh                one-command install
│   └── test_suite.py           24 tests
│
├── layering/                 the layered-model system + why it does not ship
├── models/                   trained models
├── analysis/paper_repro/     regenerates the numbers above
├── logs/                     collected sessions + recovered action trails
├── gold_labels/              965 hand-judged labels
└── figures/                  paper figures
```

---

## Method rules

These are not style preferences. Violating any one invalidates a result, and each has
already produced a wrong number in this project at least once.

1. **Never join gold labels to sessions by `session_id`.** 326 ids are duplicated, to depth
   9, covering 56% of rows. Use `load_all_gold(load_records())`.
2. **Benign cost is FALSE blocks, not RAW blocks.** Baseline rows are not attack-free: some
   disclose a canary or carry credential code, and blocking those is correct.
3. **Report recall with its benign cost.** Recall alone is not a result.
4. Thresholds are fitted on gold1 only, never on a reported slice.
5. Bootstrap **prompt groups**, never rows. Benign prompts repeat.
6. Every learned claim needs a permuted-label control.
7. **Do not quote F1 as a headline.** The always-positive trivial F1 is 0.6035 on all gold,
   0.6856 on OOS, 0.7478 on STRICT. F1 never looks at the benign population, which is the
   entire point of a gate.
8. Change a shipped file, re-run `test_suite.py`, it must stay at 24/24.

---

## Known limits

- **Benign cost on tool-using workloads is unmeasured.** 0 of 2,166 rows in our corpus carry
  tool output, so the ECHO layer is structurally invisible here. On an external corpus that
  does carry tool output it fires on 13.4% of benign replies.
- **On the CLI path the reply hooks do not fire.** `before_agent_reply` and `llm_output` are
  declared by the SDK but never delivered, so only the tool-call side is live there. The
  compliance numbers describe the reply path.
- **Recall does not transfer as well as precision.** On an independently collected corpus,
  precision holds near 0.91 but recall falls to 0.32.
- The gate detects **injection-driven secret disclosure** well and **generic marker-echo
  compliance** poorly. See `layering/README.md` and `PAPER_FACTCHECK.md`.
