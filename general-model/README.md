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

Shipped default (`AURA_BLOCK_POLICY=strict`), measured on held-out data:

| slice | precision | recall |
|---|---|---|
| **OOS** — 671 unseen attack sessions | **0.9214** | **0.6029** |
| **STRICT** — 288 whose prompt never appears in training | **0.9213** | **0.4767** |
| gold1 — 146 threshold-fitting sessions | 0.9310 | 0.8438 |

**Cost: 31 false blocks in 1,081 benign sessions = 2.87%** [2.0, 4.0], against a written
budget of 3.00%.

Full policy curve, and why `balanced` and `aggressive` are rejected, in
[`GATE_OPERATING_POINTS.md`](GATE_OPERATING_POINTS.md). Reproduce with
[`analysis/paper_repro/policy_curve.py`](analysis/paper_repro/policy_curve.py).

> **No gate number may be quoted without its policy label.** A recall from one policy beside
> a benign rate from another describes a system that does not exist. That has happened here
> before.

Model: `aura_behavioral.joblib`, Random Forest, 12 features, 965 hand-judged labels,
prompt-grouped 10-seed CV **AUC 0.7427**, leave-one-attack-category-out **0.7117**.

---

## Start here

| I want to... | go to |
|---|---|
| **install and run the gate** | [`openclaw-plugin/README.md`](openclaw-plugin/README.md) |
| **see the numbers and how they were measured** | [`GATE_OPERATING_POINTS.md`](GATE_OPERATING_POINTS.md) |
| **understand each model file** | [`MODELS.md`](MODELS.md) |
| **know whether layering helps** | [`layering/README.md`](layering/README.md) |
| **check the paper's claims** | [`PAPER_FACTCHECK.md`](PAPER_FACTCHECK.md) |

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
├── PAPER_FACTCHECK.md        every paper claim checked against source data
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
