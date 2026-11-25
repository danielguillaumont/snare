"""Small, dependency-free statistics for proportions."""

from __future__ import annotations

import math
from dataclasses import dataclass

Z95 = 1.959963984540054


@dataclass(frozen=True)
class Rate:
    k: int
    n: int
    low: float
    high: float

    @property
    def point(self) -> float:
        return self.k / self.n if self.n else float("nan")

    def fmt(self) -> str:
        if self.n == 0:
            return "n/a (n=0)"
        return f"{self.point:.1%} ({self.k}/{self.n}; 95% CI {self.low:.1%}–{self.high:.1%})"


def wilson(k: int, n: int, z: float = Z95) -> Rate:
    """Wilson score interval. Well-behaved at k=0 and small n, unlike the normal approximation."""
    if n == 0:
        return Rate(0, 0, float("nan"), float("nan"))
    if not 0 <= k <= n:
        raise ValueError("need 0 <= k <= n")
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    low = 0.0 if k == 0 else max(0.0, centre - half)  # exact at the edges, no float residue
    high = 1.0 if k == n else min(1.0, centre + half)
    return Rate(k, n, low, high)
