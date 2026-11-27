"""M16 verdicts (docs/M16-early-warning.md §3), from a hunt and a benign3 results directory.

    python -m killtest.report_m16 results/m16/hunt results/m16/benign3
"""

import json
import sys
from collections import Counter
from pathlib import Path

from .report import load_runs
from .report_m3 import valid
from .stats import wilson

W1_BAR = 0.60


def w1(hunt: list[dict]) -> dict:
    runs = valid(hunt)
    k = sum(1 for r in runs if r.get("warned_or_observed"))
    ci = wilson(k, len(runs))
    if runs and ci.low >= W1_BAR:
        v = "PASS"
    elif runs and ci.high < W1_BAR:
        v = "FAIL"
    else:
        v = "INCONCLUSIVE"
    warned = [r for r in runs if r.get("warned")]
    return {
        "verdict": v, "k": k, "n": len(runs), "point": ci.point, "low": ci.low, "high": ci.high,
        "warned": len(warned),
        "observed": sum(1 for r in runs if r.get("detected_observable")),
        "warned_only": sum(1 for r in runs if r.get("warned") and not r.get("detected_observable")),
        "escalated": sum(1 for r in warned if r.get("escalated")),
        "first_layer": dict(Counter(r.get("first_layer", "none") for r in runs)),
    }


def w2(benign: list[dict]) -> dict:
    runs = [r for r in benign if not r.get("error")]
    trips = sum(1 for r in runs if r.get("false_trip"))
    return {"verdict": "PASS" if runs and trips == 0 else ("FAIL" if trips else "INCONCLUSIVE"),
            "trips": trips, "n": len(runs), "warnings": sum(1 for r in runs if r.get("warned"))}


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__)
        return 2
    out = {"W1": w1(load_runs(Path(argv[0]))), "W2": w2(load_runs(Path(argv[1])))}
    print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
