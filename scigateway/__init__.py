"""SciGateway — a gateway-level security monitor for AI-for-science agents.

This package implements the OPALS 2026 research plan "AI for Science Security":
detect unsafe, unreliable, or policy-violating behavior in AI-for-science agents
using only *non-invasive gateway logs* — never the model's internal weights.

The public surface is intentionally small; see :mod:`scigateway.pipeline` for the
end-to-end flow (collect -> extract features -> train -> evaluate -> report).
"""

__version__ = "1.0.0"

RISK_LABELS = ("safe", "suspicious", "unsafe")
"""The three session-level labels, ordered least -> most severe."""
