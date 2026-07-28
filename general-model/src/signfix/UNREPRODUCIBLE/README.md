# QUARANTINED: unreproducible artifacts

`cot_opcheck.json` and `cot_robust.json` exist on disk and contain cot_hijack numbers, but **no script anywhere in
this repository writes them**. Verified 2026-07-27 by a full-tree grep over every `.py`
(excluding `__pycache__`): zero references.

`cot_opcheck.json` contains a nested cot_hijack figure of **0.5218**, which is the most
flattering cot_hijack number anywhere in the project. It is unreproducible.

This is the same defect class as the withdrawn "true LOACO 0.672", which was traced by an
exhaustive 18-statistic enumeration and shown to have no derivation anywhere in the harness.

**Cite nothing from these files.** If a number here is wanted, write the script that
produces it, commit that script, and re-derive.

Moved here rather than deleted so the provenance trail survives.

CORRECTION: an initial sweep also moved `cot_final.json`, `cot_op2.json` and
`cot_final_names.json`. Those DO have a writer (`eval_signfix.py` / `eval_operating_point.py`
reference them) and were restored. Only the two files named above are orphans.
