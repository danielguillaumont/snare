"""Build the list of runs: which scenario, task, decoys and payload each run gets."""

from __future__ import annotations

import random
from collections import deque
from dataclasses import asdict, dataclass

from .config import Catalog

DECOYS_PER_RUN = 4
ARMS = ("benign", "adjacent", "canary", "attack")


@dataclass(frozen=True)
class RunSpec:
    run_id: str
    arm: str
    model: str
    scenario: str
    task_index: int
    decoys: tuple[str, ...]
    payload_id: str | None
    tag: str
    tool_order_seed: int

    def to_dict(self) -> dict:
        d = asdict(self)
        d["decoys"] = list(self.decoys)
        return d


def balanced_decoy_sets(names: list[str], n_runs: int, k: int, rng: random.Random) -> list[tuple[str, ...]]:
    """Give each run k distinct decoys so every decoy is exposed about equally often.

    Draw from a stream of back-to-back shuffled permutations. A duplicate within a run
    (possible only at a permutation boundary) is pushed back to the front of the stream
    for the next run, so no decoy loses exposure.
    """
    if k > len(names):
        raise ValueError("k larger than decoy catalog")
    stream: deque[str] = deque()
    sets: list[tuple[str, ...]] = []
    for _ in range(n_runs):
        chosen: list[str] = []
        skipped: list[str] = []
        while len(chosen) < k:
            if not stream:
                perm = names[:]
                rng.shuffle(perm)
                stream.extend(perm)
            candidate = stream.popleft()
            (skipped if candidate in chosen else chosen).append(candidate)
        stream.extendleft(reversed(skipped))
        sets.append(tuple(chosen))
    return sets


def make_tag(rng: random.Random) -> str:
    return "SNR-" + "".join(rng.choice("0123456789ABCDEF") for _ in range(6))


def build_plan(catalog: Catalog, arms: list[str], models: list[str], runs_per_cell: int, seed: int) -> list[RunSpec]:
    """runs_per_cell runs for every (arm, model) pair. Scenarios and tasks are cycled evenly."""
    rng = random.Random(seed)
    scenario_names = sorted(catalog.scenarios)
    decoy_names = sorted(catalog.decoy_names)
    specs: list[RunSpec] = []
    used_tags: set[str] = set()

    for arm in arms:
        if arm not in ARMS:
            raise ValueError(f"unknown arm {arm!r}")
        payloads = {
            "benign": [None],
            "adjacent": [None],
            "canary": list(catalog.canaries),
            "attack": list(catalog.attacks),
        }[arm]
        for model in models:
            decoy_sets = balanced_decoy_sets(decoy_names, runs_per_cell, DECOYS_PER_RUN, rng)
            for i in range(runs_per_cell):
                scenario = catalog.scenarios[scenario_names[i % len(scenario_names)]]
                task_index = (i // len(scenario_names)) % len(scenario.tasks_for(arm))
                payload = payloads[i % len(payloads)]
                tag = make_tag(rng)
                while tag in used_tags:
                    tag = make_tag(rng)
                used_tags.add(tag)
                specs.append(
                    RunSpec(
                        run_id=f"{arm}-{model}-{i:04d}",
                        arm=arm,
                        model=model,
                        scenario=scenario.name,
                        task_index=task_index,
                        decoys=decoy_sets[i],
                        payload_id=payload.id if payload else None,
                        tag=tag,
                        tool_order_seed=rng.randrange(2**31),
                    )
                )
    return specs
