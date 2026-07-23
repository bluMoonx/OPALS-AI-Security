"""Two-rater human labeling + inter-rater reliability — the study's biggest
validity lever.

The live collector assigns each session a label from a documented *heuristic*
(``scenario.evaluate``). For a publishable result those labels need independent
human adjudication with a reported agreement statistic. This module supports the
workflow the study protocol calls for:

1. :func:`export_labeling_worksheet` — a **blind** CSV per rater (no category, no
   heuristic label, so raters aren't anchored);
2. two humans fill the five rubric columns independently;
3. :func:`load_rater_labels` — read each filled worksheet to ``{session_id: label}``;
4. :func:`adjudication_report` — raw agreement, **Cohen's kappa** (chance-corrected
   agreement), the disagreement list, and crucially **how well the existing
   heuristic labels match the humans** — the number that validates every result
   built on those labels.

Labels come from the project rubric in :mod:`scigateway.taxonomy` (five 0-2
dimensions summed to a label), so a rater's dimension scores map to a label by the
exact rule the rest of the system uses. Pure stdlib + scikit-learn (already a dep);
no Docker, no tokens.
"""

from __future__ import annotations

import csv
from pathlib import Path

from .taxonomy import RISK_LABELS, RUBRIC_DIMENSIONS, score_to_label

WORKSHEET_FIELDS = ("session_id", "user_prompt", "agent_response", "actions",
                    *RUBRIC_DIMENSIONS, "label", "notes")

# Landis & Koch (1977) interpretation bands for kappa.
_KAPPA_BANDS = ((0.0, "poor"), (0.20, "slight"), (0.40, "fair"),
                (0.60, "moderate"), (0.80, "substantial"), (1.01, "almost perfect"))


def interpret_kappa(kappa: float) -> str:
    for upper, name in _KAPPA_BANDS:
        if kappa < upper:
            return name
    return "almost perfect"


def _actions_summary(session, limit: int = 6) -> str:
    parts = [f"{a.kind}:{a.target[:40]}" for a in session.actions[:limit]]
    extra = len(session.actions) - limit
    if extra > 0:
        parts.append(f"(+{extra} more)")
    return " | ".join(parts)


def export_labeling_worksheet(sessions, path, *, preview_chars: int = 400) -> Path:
    """Write a blind per-rater CSV; rubric columns are empty for the human to fill.

    The attack category and heuristic label are intentionally omitted so raters
    are not anchored. Use :func:`export_answer_key` for the researcher's private
    mapping.
    """
    path = Path(path)
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=WORKSHEET_FIELDS)
        writer.writeheader()
        for session in sessions:
            writer.writerow({
                "session_id": session.session_id,
                "user_prompt": session.user_prompt[:preview_chars],
                "agent_response": session.agent_response[:preview_chars],
                "actions": _actions_summary(session),
            })
    return path


def export_answer_key(sessions, path) -> Path:
    """Researcher-only key: session_id -> heuristic label + attack category."""
    path = Path(path)
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["session_id", "heuristic_label", "attack_category", "attack_present"])
        for session in sessions:
            writer.writerow([session.session_id, session.human_label,
                             session.attack_category,
                             bool(session.agent_config.get("attack_present"))])
    return path


def load_rater_labels(path) -> dict[str, str]:
    """Read a filled worksheet -> ``{session_id: label}``.

    If all five rubric dimensions are filled, the label is computed from them by
    :func:`~scigateway.taxonomy.score_to_label` (the project's rule); otherwise the
    free-text ``label`` column is used. Rows with neither are skipped.
    """
    out: dict[str, str] = {}
    with Path(path).open(encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            sid = (row.get("session_id") or "").strip()
            if not sid:
                continue
            dims, have_all = {}, True
            for dim in RUBRIC_DIMENSIONS:
                val = (row.get(dim) or "").strip()
                if val == "":
                    have_all = False
                    break
                dims[dim] = int(val)
            if have_all:
                out[sid] = score_to_label(dims)
            elif (row.get("label") or "").strip() in RISK_LABELS:
                out[sid] = row["label"].strip()
    return out


def load_heuristic_labels(path) -> dict[str, str]:
    """Read the researcher answer key -> ``{session_id: heuristic_label}``."""
    out: dict[str, str] = {}
    with Path(path).open(encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            sid = (row.get("session_id") or "").strip()
            label = (row.get("heuristic_label") or "").strip()
            if sid and label in RISK_LABELS:
                out[sid] = label
    return out


def cohens_kappa(labels_a, labels_b) -> tuple[float, float]:
    """(unweighted, quadratic-weighted) Cohen's kappa over aligned label lists.

    Quadratic weighting credits near-misses (safe vs suspicious) more than far
    ones (safe vs unsafe), which suits ordinal risk labels.
    """
    from sklearn.metrics import cohen_kappa_score
    order = list(RISK_LABELS)
    unweighted = float(cohen_kappa_score(labels_a, labels_b, labels=order))
    quadratic = float(cohen_kappa_score(labels_a, labels_b, labels=order,
                                        weights="quadratic"))
    return unweighted, quadratic


def _agreement(pairs) -> float:
    return sum(1 for a, b in pairs if a == b) / len(pairs) if pairs else 0.0


def _pairwise_kappa(rater, other):
    ids = sorted(set(rater) & set(other))
    pairs = [(rater[i], other[i]) for i in ids]
    unweighted, _ = cohens_kappa([p[0] for p in pairs], [p[1] for p in pairs]) \
        if pairs else (0.0, 0.0)
    return {"n": len(ids), "raw_agreement": _agreement(pairs),
            "cohens_kappa": unweighted}


def adjudication_report(rater_a, rater_b, *, heuristic=None) -> dict:
    """Inter-rater reliability between two label dicts, plus (optional) how well the
    heuristic labels match each human rater — the validity check for the study."""
    ids = sorted(set(rater_a) & set(rater_b))
    a = [rater_a[i] for i in ids]
    b = [rater_b[i] for i in ids]
    unweighted, quadratic = cohens_kappa(a, b) if ids else (0.0, 0.0)

    report = {
        "n_rater_a": len(rater_a),
        "n_rater_b": len(rater_b),
        "n_common": len(ids),
        "raw_agreement": _agreement(list(zip(a, b))),
        "cohens_kappa": unweighted,
        "cohens_kappa_quadratic": quadratic,
        "kappa_interpretation": interpret_kappa(unweighted),
        "disagreements": [
            {"session_id": i, "rater_a": rater_a[i], "rater_b": rater_b[i]}
            for i in ids if rater_a[i] != rater_b[i]
        ],
        "rater_a_only": sorted(set(rater_a) - set(rater_b)),
        "rater_b_only": sorted(set(rater_b) - set(rater_a)),
    }
    report["n_disagreements"] = len(report["disagreements"])
    if heuristic is not None:
        report["heuristic_vs_rater_a"] = _pairwise_kappa(rater_a, heuristic)
        report["heuristic_vs_rater_b"] = _pairwise_kappa(rater_b, heuristic)
    return report


def write_adjudication_markdown(report: dict, path) -> Path:
    """Render an adjudication report as a short markdown summary."""
    lines = [
        "# Inter-rater reliability", "",
        f"- Completed labels from rater A: **{report['n_rater_a']}**",
        f"- Completed labels from rater B: **{report['n_rater_b']}**",
        f"- Sessions labeled by both raters: **{report['n_common']}**",
        f"- Raw agreement: **{report['raw_agreement']:.3f}**",
        f"- Cohen's kappa: **{report['cohens_kappa']:.3f}** "
        f"({report['kappa_interpretation']})",
        f"- Cohen's kappa (quadratic-weighted): **{report['cohens_kappa_quadratic']:.3f}**",
        f"- Disagreements: **{report['n_disagreements']}**",
    ]
    for name in ("a", "b"):
        key = f"heuristic_vs_rater_{name}"
        if key in report:
            h = report[key]
            lines.append(f"- Heuristic vs rater {name.upper()}: agreement "
                         f"{h['raw_agreement']:.3f}, kappa {h['cohens_kappa']:.3f} "
                         f"(n={h['n']})")
    if report["disagreements"]:
        lines += ["", "## Disagreements to adjudicate", "",
                  "| session | rater A | rater B |", "|---|---|---|"]
        lines += [f"| {d['session_id']} | {d['rater_a']} | {d['rater_b']} |"
                  for d in report["disagreements"]]
    path = Path(path)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path
