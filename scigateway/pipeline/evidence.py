"""Offline evidence helpers for reproducible, validity-aware analysis.

The analysis must distinguish SciGateway decisions from OpenClaw's native tool
policy and make later input changes detectable. These helpers only read already
collected files; they never import the agent backend or make provider calls.
"""

from __future__ import annotations

import hashlib
import re
from collections import Counter
from pathlib import Path

from ..live.gateway_log import gateway_log_summary

_Z_95 = 1.959963984540054
_SESSION_ID_RE = re.compile(r"^(?P<category>.+)-(?P<condition>attack|baseline)-(?P<index>\d+)$")


def wilson_interval(successes: int, total: int) -> dict:
    """A 95% Wilson score interval for a binomial rate.

    Wilson intervals remain informative at 0% and 100%, unlike the simple
    normal approximation. Counts are retained so every reported interval is
    auditable.
    """
    if total < 0 or successes < 0 or successes > total:
        raise ValueError("binomial counts must satisfy 0 <= successes <= total")
    if total == 0:
        return {"successes": 0, "total": 0, "rate": 0.0,
                "confidence": 0.95, "low": 0.0, "high": 1.0,
                "method": "Wilson score"}
    rate = successes / total
    z2 = _Z_95 ** 2
    denominator = 1 + z2 / total
    center = (rate + z2 / (2 * total)) / denominator
    margin = (_Z_95 / denominator) * (
        (rate * (1 - rate) / total + z2 / (4 * total ** 2)) ** 0.5)
    low = 0.0 if successes == 0 else max(0.0, center - margin)
    high = 1.0 if successes == total else min(1.0, center + margin)
    return {"successes": successes, "total": total, "rate": rate,
            "confidence": 0.95, "low": low, "high": high,
            "method": "Wilson score"}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def input_provenance(sessions_path: Path, gateway_logs: list[Path]) -> dict:
    """Content fingerprints for the immutable analysis inputs.

    This is integrity evidence, not identity attestation: it detects a later
    change to the inputs but does not prove who collected them.
    """
    root = sessions_path.parent
    manifest = hashlib.sha256()
    for path in gateway_logs:
        try:
            relative = path.relative_to(root).as_posix()
        except ValueError:
            relative = path.name
        manifest.update(relative.encode("utf-8"))
        manifest.update(b"\0")
        manifest.update(_sha256(path).encode("ascii"))
        manifest.update(b"\n")
    return {
        "integrity_scope": "content fingerprints; not collector identity attestation",
        "sessions_file": {
            "path": str(sessions_path),
            "bytes": sessions_path.stat().st_size,
            "sha256": _sha256(sessions_path),
        },
        "gateway_logs": {
            "root": str(root),
            "count": len(gateway_logs),
            "sha256_manifest": manifest.hexdigest(),
        },
    }


def gateway_logs_for_sessions(root: Path, sessions) -> tuple[list[Path], list[str]]:
    """Resolve only the gateway slice belonging to each analyzed session.

    The collection tree can also contain archives or separate multi-agent runs;
    an unrestricted recursive glob would contaminate the confound analysis.
    """
    paths: list[Path] = []
    missing: list[str] = []
    for session in sessions:
        match = _SESSION_ID_RE.fullmatch(session.session_id)
        if not match:
            missing.append(session.session_id)
            continue
        path = (root / match.group("category") / match.group("condition") /
                f"gateway_{int(match.group('index')):03d}.log")
        if path.is_file():
            paths.append(path)
        else:
            missing.append(session.session_id)
    return paths, missing


def native_tool_policy_summary(gateway_logs: list[Path]) -> dict:
    """Aggregate OpenClaw-native tool restrictions across session log slices."""
    removed_counts: Counter[str] = Counter()
    denied_counts: Counter[str] = Counter()
    model_counts: Counter[str] = Counter()
    logs_with_policy = 0
    parse_errors: list[str] = []

    for path in gateway_logs:
        try:
            summary = gateway_log_summary(path)
        except (OSError, UnicodeError, ValueError) as exc:
            parse_errors.append(f"{path.name}: {exc}")
            continue
        if summary["tool_policy_rules"]:
            logs_with_policy += 1
        removed_counts.update(summary["native_removed_tools"])
        denied_counts.update(summary["native_denied_tools"])
        if summary["model"]:
            model_counts.update([summary["model"]])

    n_logs = len(gateway_logs)
    return {
        "source": "OpenClaw gateway logs (native policy, before SciGateway replay)",
        "n_gateway_logs": n_logs,
        "n_logs_with_tool_policy": logs_with_policy,
        "tool_policy_log_coverage": logs_with_policy / n_logs if n_logs else 0.0,
        "removed_tool_log_counts": dict(sorted(removed_counts.items())),
        "denied_tool_log_counts": dict(sorted(denied_counts.items())),
        "model_log_counts": dict(sorted(model_counts.items())),
        "n_parse_errors": len(parse_errors),
        "parse_errors": parse_errors[:20],
        "validity_note": (
            "Native restrictions are a platform confound and must not be attributed "
            "to SciGateway. SciGateway outcomes remain post-collection replay."),
    }
