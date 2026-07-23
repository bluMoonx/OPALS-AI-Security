"""The real-agent analysis pipeline: features -> grouped CV -> gateway replay.

* :mod:`~scigateway.pipeline.features` turns observed sessions into a numeric
  feature table; model inputs never include labels or ground-truth risk fields.
* :mod:`~scigateway.pipeline.evaluate` performs grouped cross-validation and
  reports classifier and end-to-end gateway metrics.
* :mod:`~scigateway.pipeline.live_analysis` reads collected OpenClaw sessions and
  writes metrics, audit logs, error analysis, and figures without launching Docker.
"""
