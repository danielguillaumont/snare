"""Command line: `python -m killtest run ...` and `python -m killtest report DIR`."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from .config import load_catalog
from .plan import ARMS, M0_ARMS, M3_ARMS, build_plan
from .pricing import PRICES

DEFAULT_MODELS = ["claude-haiku-5-5", "claude-sonnet-5-5", "claude-opus-5-5"]
RESULTS_ROOT = Path("results")


def load_dotenv(path: Path = Path(".env")) -> None:
    """Load KEY=VALUE lines from a git-ignored .env into os.environ. Never overrides, never prints values."""
    import os

    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key, value = key.strip(), value.strip().strip('"').strip("'")
        if value and key not in os.environ:
            os.environ[key] = value


def _resolve_dir(arg: str) -> Path:
    p = Path(arg)
    if p.name == "latest":
        pointer = p.parent / "LATEST"
        if not pointer.exists():
            sys.exit("no results yet: results/LATEST not found")
        return Path(pointer.read_text(encoding="utf-8").strip())
    return p


def cmd_run(a: argparse.Namespace) -> int:
    from .report import render_markdown, write_report
    from .runner import estimate_plan_cost, execute

    catalog = load_catalog()
    arms = list(M0_ARMS) if a.arm == "all" else list(M3_ARMS) if a.arm == "m3" else [a.arm]

    if a.policy:
        from .config import DATA_DIR
        from .policies import POLICIES, PolicyClient, policy_models, public_decoy_names

        models = policy_models(list(POLICIES) if a.policy == "all" else [a.policy])
        client = PolicyClient(public_decoy_names(DATA_DIR))
        a.dry_run = True  # no API calls; results go to a -dry directory unless --out is given
    elif a.dry_run:
        from .fake import FakeClient

        models = ["fake"]
        content_tools = frozenset(s.content_tool for s in catalog.scenarios.values())
        client = FakeClient(catalog.decoy_names, content_tools, catalog.attacker_marker)
    else:
        models = a.models or DEFAULT_MODELS
        unknown = [m for m in models if m not in PRICES or m == "fake"]
        if unknown:
            sys.exit(f"unknown model(s) {unknown}; known: {sorted(k for k in PRICES if k != 'fake')}")
        import os

        import anthropic

        load_dotenv()
        if not os.environ.get("ANTHROPIC_API_KEY"):
            sys.exit("ANTHROPIC_API_KEY not found: set it in the environment or in experiments/killtest/.env")
        # No server-side fallback on purpose: a fallback would mix models within one model's results.
        client = anthropic.Anthropic(max_retries=4)

    specs = build_plan(catalog, arms, models, a.runs, a.seed)
    est = estimate_plan_cost(specs)
    print(f"{len(specs)} runs planned ({', '.join(arms)} x {', '.join(models)} x {a.runs}); "
          f"rough estimate ${est:.2f}; hard ceiling ${a.max_usd:.2f}")
    if not a.dry_run and est > a.max_usd:
        print("Estimate exceeds the ceiling: some runs will be skipped once the ceiling is hit.")
    if a.plan_only:
        return 0

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_dir = Path(a.out) if a.out else RESULTS_ROOT / f"{stamp}{'-dry' if a.dry_run else ''}"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "plan.json").write_text(
        json.dumps({"seed": a.seed, "effort": a.effort, "max_usd": a.max_usd, "specs": [s.to_dict() for s in specs]}, indent=1),
        encoding="utf-8",
    )

    done = 0

    def progress(rec: dict) -> None:
        nonlocal done
        done += 1
        if done % 10 == 0 or done == len(specs):
            print(f"  {done}/{len(specs)} runs", flush=True)

    meta = execute(specs, client, catalog, out_dir, max_usd=a.max_usd, workers=a.workers, effort=a.effort, on_result=progress)
    (out_dir / "meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    RESULTS_ROOT.mkdir(exist_ok=True)
    (RESULTS_ROOT / "LATEST").write_text(str(out_dir), encoding="utf-8")

    s = write_report(out_dir)
    print(f"spent ${meta['spent_usd']:.2f}; skipped {meta['runs_skipped_budget']} for budget")
    print(f"verdict: {s['verdict']} — {s['verdict_reason']}")
    print(f"report: {out_dir / 'report.md'}")
    return 0


def cmd_report(a: argparse.Namespace) -> int:
    from .report import write_report

    d = _resolve_dir(a.dir)
    s = write_report(d)
    print(f"verdict: {s['verdict']} — {s['verdict_reason']}")
    print(f"report: {d / 'report.md'}")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="killtest", description="Snare kill test")
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="run the experiment")
    r.add_argument("--arm", choices=[*ARMS, "all", "m3"], default="benign", help="all = the four M0 arms; m3 = the four M3a arms")
    r.add_argument("--runs", type=int, default=20, help="runs per (arm, model)")
    r.add_argument("--models", nargs="+", help=f"default: {' '.join(DEFAULT_MODELS)}")
    r.add_argument("--max-usd", type=float, default=2.0, help="hard spending ceiling (default $2)")
    r.add_argument("--workers", type=int, default=4)
    r.add_argument("--effort", choices=["low", "medium", "high"], default="medium")
    r.add_argument("--seed", type=int, default=7)
    r.add_argument("--out", help="output directory (default results/<timestamp>)")
    r.add_argument("--dry-run", action="store_true", help="use the scripted fake model; no API calls")
    r.add_argument("--policy", choices=["greedy", "files_only", "targeted", "snare_aware", "all"],
                   help="M3: run a scripted attacker policy instead of a model (no API calls, $0)")
    r.add_argument("--plan-only", action="store_true", help="print the plan and estimate, then exit")
    r.set_defaults(fn=cmd_run)

    rep = sub.add_parser("report", help="rebuild report.md for a results directory")
    rep.add_argument("dir", help="results directory, or results/latest")
    rep.set_defaults(fn=cmd_report)

    a = p.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")  # Windows consoles default to a legacy code page
    return a.fn(a)
