"""Regression tests for the length-matched control pool and its wiring.

The v1 pool let "prompt longer than 18 words" separate attack from benign at
AUC 0.992 with zero false positives -- an artifact that dominated every model we
fit. These tests fail if that artifact is ever reintroduced, and if the collector
stops recording which pool a session came from.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_HERE = Path(__file__).resolve().parent
_PI = _HERE.parent
_REPO = _PI.parent
for _p in (str(_REPO), str(_PI)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from prompts import control_pools, controls as controls_v1, controls_v2  # noqa: E402

FAMILIES = ("framing_social", "structural_parsing", "task_laundering",
            "temporal_reasoning")

# Measured from the 400 collected attack prompts, per pi_family.
ATTACK_MEDIAN = {"framing_social": 30, "structural_parsing": 27,
                 "task_laundering": 24.5, "temporal_reasoning": 29}


def _words(turns) -> int:
    return len(" ".join(turns).split())


def _lengths(family, module):
    return [_words(t) for t in module.CONTROL_POOLS[family]]


@pytest.mark.parametrize("family", FAMILIES)
def test_v2_median_is_close_to_the_attack_median(family):
    """The whole point: benign length must not stand in for the label."""
    import statistics
    median = statistics.median(_lengths(family, controls_v2))
    assert abs(median - ATTACK_MEDIAN[family]) <= 6, (
        f"{family}: v2 control median {median} vs attack {ATTACK_MEDIAN[family]}")


@pytest.mark.parametrize("family", FAMILIES)
def test_v2_covers_the_attack_range_at_both_ends(family):
    """A pool that is uniformly long is just the old artifact with the sign flipped.

    Caught a real overcorrection during development: the first v2 draft was
    entirely LONGER than the attacks (length AUC 0.29-0.44).
    """
    lengths = _lengths(family, controls_v2)
    assert min(lengths) <= 20, f"{family}: no short controls (min {min(lengths)})"
    assert max(lengths) >= 35, f"{family}: no long controls (max {max(lengths)})"


@pytest.mark.parametrize("family", FAMILIES)
def test_v2_is_more_diverse_than_v1(family):
    assert len(controls_v2.CONTROL_POOLS[family]) > len(controls_v1.CONTROL_POOLS[family])


def test_v2_pool_is_substantially_larger_overall():
    v1 = sum(len(p) for p in controls_v1.CONTROL_POOLS.values())
    v2 = sum(len(p) for p in controls_v2.CONTROL_POOLS.values())
    assert v2 >= 2 * v1, f"v2 has {v2} prompts, v1 had {v1}"


def test_controls_carry_no_injection_or_canary():
    """Controls are the negative class; an injection in one poisons the label."""
    banned = ("pi-", "<|im_", "[system]", "</system>", "ignore the",
              "ignore all", "ignore previous", "disregard", "do not tell",
              "without mentioning", "new instruction")
    for family, pool in controls_v2.CONTROL_POOLS.items():
        for turns in pool:
            text = " ".join(turns).lower()
            for phrase in banned:
                assert phrase not in text, f"{family}: control contains {phrase!r}"


def test_multi_turn_share_roughly_matches_the_attacks():
    """Attacks are ~7% multi-turn; controls should not differ structurally."""
    total = sum(len(p) for p in controls_v2.CONTROL_POOLS.values())
    multi = sum(1 for p in controls_v2.CONTROL_POOLS.values()
                for turns in p if len(turns) > 1)
    assert 0.02 <= multi / total <= 0.15, f"multi-turn share {multi / total:.3f}"


# -- selector / wiring ------------------------------------------------------- #

def test_selector_defaults_to_v2():
    assert control_pools.resolve_version(None) == 2


def test_selector_returns_each_version():
    assert control_pools.control_module(1) is controls_v1
    assert control_pools.control_module(2) is controls_v2


def test_selector_rejects_unknown_version():
    with pytest.raises(ValueError):
        control_pools.control_module(99)


def test_gen_controls_signature_matches_v1():
    """collect.py and scenarios.py call this positionally; keep it a drop-in."""
    got = control_pools.gen_controls("framing_social", 5, seed=3)
    assert len(got) == 5
    assert all(p.family == "framing_social" for p in got)
    assert got[0].meta.get("pool_version") == 2


def test_gen_controls_is_reproducible_for_a_seed():
    a = control_pools.gen_controls("task_laundering", 8, seed=11)
    b = control_pools.gen_controls("task_laundering", 8, seed=11)
    assert [p.turns for p in a] == [p.turns for p in b]


def test_collector_imports_the_selector_not_v1_directly():
    """Regression: controls_v2 was orphaned because collect.py imported v1."""
    for name in ("collect.py", "scenarios.py"):
        source = (_PI / name).read_text()
        assert "from prompts.control_pools import" in source, f"{name} bypasses the selector"
        assert "from prompts.controls import gen_controls" not in source, (
            f"{name} still imports the v1 pool directly")
