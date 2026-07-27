"""Selector for the benign-control prompt pools.

Two versions exist and both must stay importable:

* **v1** (:mod:`prompts.controls`) — what the collected 600-session dataset used.
  Kept unchanged so that dataset stays reproducible. It carries a prompt-length
  artifact: its controls run 3–18 words against attacks at 10–74, so "prompt longer
  than 18 words" separates the classes at AUC 0.992 with zero false positives
  (``analysis/DETECTOR_FINDINGS.md`` §3). Do not collect new data with it.

* **v2** (:mod:`prompts.controls_v2`) — length-matched per family, 131 unique prompts
  instead of 55. Pooled length AUC 0.530. This is the default for new collections.

The chosen version is recorded on every control session as
``agent_config["control_pool_version"]`` so a mixed dataset stays self-describing:
analysis can always tell which pool a session came from, which matters because the
existing 200 controls and any new ones are not interchangeable.

Override the default with the ``PI_CONTROL_POOL_VERSION`` environment variable or
``collect.py --controls-version``.
"""

from __future__ import annotations

import os

from . import controls as _v1
from . import controls_v2 as _v2

_MODULES = {1: _v1, 2: _v2}

#: New collections use the length-matched pool unless told otherwise.
DEFAULT_VERSION = int(os.environ.get("PI_CONTROL_POOL_VERSION", "2"))


def resolve_version(version: int | None = None) -> int:
    v = DEFAULT_VERSION if version is None else int(version)
    if v not in _MODULES:
        raise ValueError(f"unknown control pool version {v!r}; have {sorted(_MODULES)}")
    return v


def control_module(version: int | None = None):
    return _MODULES[resolve_version(version)]


def gen_controls(family: str, n: int, *, seed: int = 0, version: int | None = None):
    """Version-aware :func:`prompts.controls.gen_controls`.

    Signature matches v1's so existing call sites work unchanged.
    """
    return control_module(version).gen_controls(family, n, seed=seed)


def pool_size(family: str, version: int | None = None) -> int:
    return len(control_module(version).CONTROL_POOLS[family])
