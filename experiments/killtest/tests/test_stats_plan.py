import random
from collections import Counter

import pytest

from killtest.config import load_catalog
from killtest.plan import DECOYS_PER_RUN, balanced_decoy_sets, build_plan
from killtest.stats import wilson


def test_wilson_zero_successes_has_nonzero_upper_bound():
    r = wilson(0, 600)
    assert r.low == 0.0
    assert 0.005 < r.high < 0.007  # ~0.64% — the "0 trips in 600 runs" bound quoted in docs


def test_wilson_known_value():
    r = wilson(10, 100)
    assert r.point == 0.1
    assert r.low == pytest.approx(0.0552, abs=1e-3)
    assert r.high == pytest.approx(0.1744, abs=1e-3)


def test_wilson_rejects_bad_input():
    with pytest.raises(ValueError):
        wilson(5, 3)


def test_balanced_sets_are_distinct_and_even():
    names = [f"d{i}" for i in range(20)]
    sets = balanced_decoy_sets(names, 200, 4, random.Random(1))
    assert all(len(set(s)) == 4 for s in sets)
    counts = Counter(d for s in sets for d in s)
    assert set(counts) == set(names)
    assert max(counts.values()) - min(counts.values()) <= 2  # 800 exposures / 20 = 40 each


def test_plan_shape_and_unique_tags():
    cat = load_catalog()
    specs = build_plan(cat, ["benign", "canary", "attack"], ["m1", "m2"], 40, seed=3)
    assert len(specs) == 3 * 2 * 40
    assert len({s.tag for s in specs}) == len(specs)
    assert all(len(s.decoys) == DECOYS_PER_RUN for s in specs)
    assert all(s.payload_id is None for s in specs if s.arm == "benign")
    assert all(s.payload_id for s in specs if s.arm != "benign")
    # every scenario used equally within a cell
    cell = [s for s in specs if s.arm == "benign" and s.model == "m1"]
    assert set(Counter(s.scenario for s in cell).values()) == {10}


def test_plan_is_deterministic():
    cat = load_catalog()
    a = build_plan(cat, ["benign"], ["m"], 20, seed=9)
    b = build_plan(cat, ["benign"], ["m"], 20, seed=9)
    assert a == b


def test_catalog_validates():
    cat = load_catalog()
    assert len(cat.decoys) == 17  # 3 retired 2026-11-25
    assert len(cat.scenarios) == 4
    assert all(len(s.tasks) == 10 for s in cat.scenarios.values())
    assert all(len(s.adjacent_tasks) == 5 for s in cat.scenarios.values())


def test_adjacent_arm_uses_adjacent_tasks():
    cat = load_catalog()
    specs = build_plan(cat, ["adjacent"], ["m"], 20, seed=5)
    assert all(s.payload_id is None for s in specs)
    assert all(s.task_index < 5 for s in specs)
