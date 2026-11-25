"""Execute a plan concurrently with a hard spending ceiling, streaming results to JSONL."""

from __future__ import annotations

import json
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Callable

import anthropic

from .config import Catalog
from .episode import run_episode
from .plan import RunSpec
from .pricing import estimate_run_cost


class Budget:
    """Thread-safe spend tracker. A run starts only if the ceiling hasn't been reached.

    In-flight runs can overshoot by at most (workers x one run's cost); keep workers small
    for expensive models.
    """

    def __init__(self, max_usd: float) -> None:
        self.max_usd = max_usd
        self.spent = 0.0
        self._lock = threading.Lock()

    def can_start(self) -> bool:
        with self._lock:
            return self.spent < self.max_usd

    def add(self, usd: float) -> None:
        with self._lock:
            self.spent += usd


def estimate_plan_cost(specs: list[RunSpec]) -> float:
    return sum(estimate_run_cost(s.model) for s in specs)


def _error_record(spec: RunSpec, err: str) -> dict:
    return {**spec.to_dict(), "error": err, "cost_usd": 0.0}


def execute(
    specs: list[RunSpec],
    client: Any,
    catalog: Catalog,
    out_dir: Path,
    *,
    max_usd: float,
    workers: int = 4,
    effort: str = "medium",
    on_result: Callable[[dict], None] | None = None,
) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    results_path = out_dir / "runs.jsonl"
    budget = Budget(max_usd)
    write_lock = threading.Lock()
    skipped = 0

    def one(spec: RunSpec) -> None:
        nonlocal skipped
        if not budget.can_start():
            with write_lock:
                skipped += 1
            return
        try:
            rec = run_episode(client, catalog, spec, effort=effort)
        except anthropic.RateLimitError as e:
            rec = _error_record(spec, f"rate_limited: {e.message}")
        except anthropic.APIStatusError as e:
            rec = _error_record(spec, f"api_{e.status_code}: {e.message}")
        except anthropic.APIConnectionError as e:
            rec = _error_record(spec, f"connection: {e}")
        budget.add(rec["cost_usd"])
        with write_lock:
            with results_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        if on_result:
            on_result(rec)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        list(pool.map(one, specs))

    return {"runs_planned": len(specs), "runs_skipped_budget": skipped, "spent_usd": round(budget.spent, 4)}
