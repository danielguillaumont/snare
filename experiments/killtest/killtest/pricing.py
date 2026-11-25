"""Cost accounting from API usage. Prices are USD per million tokens (Anthropic list prices)."""

from __future__ import annotations

from dataclasses import dataclass

CACHE_WRITE_MULTIPLIER = 1.25  # 5-minute cache writes


@dataclass(frozen=True)
class Price:
    input: float
    output: float
    cache_read: float


PRICES: dict[str, Price] = {
    "claude-opus-5-5": Price(4.00, 20.00, 0.20),
    "claude-sonnet-5-5": Price(2.00, 10.00, 0.10),
    "claude-haiku-5-5": Price(0.10, 0.50, 0.01),
    "fake": Price(0.0, 0.0, 0.0),
    # Scripted attacker policies (killtest/policies.py): no model, no cost.
    **{f"policy-{n}": Price(0.0, 0.0, 0.0) for n in ("greedy", "files_only", "targeted", "snare_aware")},
}

# Per-run token profile for the pre-flight estimate, measured on the 60-run Haiku pilot
# (results/20261125T191619Z): ~1.3k cache-write, ~1.3k cache-read, ~260 output tokens per run.
# Output is padded to 600 because larger models tend to write and think more.
EST_PROFILE = {
    "input_tokens": 50,
    "cache_creation_input_tokens": 1_300,
    "cache_read_input_tokens": 1_300,
    "output_tokens": 600,
}


def usage_cost(model: str, usage: dict[str, int]) -> float:
    p = PRICES.get(model)
    if p is None:
        raise KeyError(f"no price for model {model!r}; add it to pricing.PRICES")
    return (
        usage.get("input_tokens", 0) * p.input
        + usage.get("cache_creation_input_tokens", 0) * p.input * CACHE_WRITE_MULTIPLIER
        + usage.get("cache_read_input_tokens", 0) * p.cache_read
        + usage.get("output_tokens", 0) * p.output
    ) / 1_000_000


def estimate_run_cost(model: str) -> float:
    return usage_cost(model, EST_PROFILE)
