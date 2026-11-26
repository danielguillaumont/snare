"""Command line: `python -m killtest run ...` and `python -m killtest report DIR`."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from .config import load_catalog
from .plan import ARMS, ENVS, M0_ARMS, M3_ARMS, build_plan, load_fix_names
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
    if a.arm == "adjacent3" and a.env == "m3a":
        print("note: adjacent3 with catalog names is the M3a-fix2 control arm")

    if a.policy:
        from .config import DATA_DIR
        from .policies import POLICIES, PolicyClient, policy_models, public_decoy_names

        models = policy_models(list(POLICIES) if a.policy == "all" else [a.policy])
        client = PolicyClient(public_decoy_names(DATA_DIR), frozenset(load_fix_names()["all_generated"]))
        a.dry_run = True  # no API calls; results go to a -dry directory unless --out is given
    elif a.dry_run:
        from .fake import FakeClient

        models = ["fake"]
        content_tools = frozenset(s.content_tool for s in catalog.scenarios.values())
        decoy_names = catalog.decoy_names
        if a.env != "m3a":  # every name the plan might show, so the fake can recognize decoys
            decoy_names = decoy_names | frozenset(load_fix_names()["all_generated"])
        client = FakeClient(decoy_names, content_tools, catalog.attacker_marker)
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

    specs = build_plan(catalog, arms, models, a.runs, a.seed, env=a.env)
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
        json.dumps({"seed": a.seed, "env": a.env, "effort": a.effort, "max_usd": a.max_usd, "specs": [s.to_dict() for s in specs]}, indent=1),
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


def _read_arg(v: str) -> str:
    return Path(v[1:]).read_text(encoding="utf-8") if v.startswith("@") else v


def cmd_screen(a: argparse.Namespace) -> int:
    """Decoy safety screen (docs/M3b-decoy-screen.md)."""
    from . import screen as sc
    from .runner import estimate_plan_cost, execute

    if a.tools == "m0":
        deployments = sc.m0_deployments(load_catalog())
    else:
        if not a.tools or not a.system:
            sys.exit("--tools FILE and --system TEXT|@FILE are required (or --tools m0)")
        tools = sc.tools_from_json(json.loads(Path(a.tools).read_text(encoding="utf-8")))
        deployments = (sc.Deployment(name="agent", system=_read_arg(a.system), tools=tools),)
    if a.decoys in ("catalog", "m0"):
        decoys = sc.catalog_decoys(include_retired=a.decoys == "m0")
    else:
        decoys = sc.decoys_from_json(json.loads(Path(a.decoys).read_text(encoding="utf-8")))

    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    lint_result = sc.lint(deployments, decoys)
    (out / "lint.json").write_text(json.dumps(lint_result, indent=1), encoding="utf-8")
    print(f"lint: {len(lint_result['errors'])} errors, {len(lint_result['warnings'])} warnings")
    for e in lint_result["errors"]:
        print(f"  error: {e}")
    if lint_result["errors"] and not a.ignore_lint:
        sys.exit("fix the lint errors first (or pass --ignore-lint)")

    client = None
    if not a.dry_run:
        import os

        import anthropic

        load_dotenv()
        if not os.environ.get("ANTHROPIC_API_KEY"):
            sys.exit("ANTHROPIC_API_KEY not found: set it in the environment or in experiments/killtest/.env")
        client = anthropic.Anthropic(max_retries=4)

    spent = 0.0
    if a.tasks:
        tasks = sc.load_tasks(Path(a.tasks))
    else:
        if a.dry_run:
            tasks = sc.fake_tasks(deployments, decoys, a.adjacent_per_decoy, a.benign)
        else:
            ceiling = min(a.max_usd, a.gen_max_usd)
            print(f"generating tasks with {a.generator_model} (ceiling ${ceiling:.2f})")
            tasks, spent = sc.generate_tasks(client, a.generator_model, deployments, decoys,
                                             n_adj=a.adjacent_per_decoy, n_ben=a.benign, max_usd=ceiling)
            print(f"  generation cost ${spent:.3f}")
        sc.save_tasks(tasks, out / "tasks.yaml")
        for n in tasks.get("notes", []):
            print(f"  note: {n}")
        print(f"tasks: {out / 'tasks.yaml'}")
        if a.generate_only:
            return 0

    catalog = sc.screen_catalog(deployments, decoys, tasks)
    if a.dry_run:
        from .fake import FakeClient

        models = ["fake"]
        content = frozenset(t.name for s in catalog.scenarios.values() for t in s.tools)
        client = FakeClient(catalog.decoy_names, content, sc.NO_ATTACKER)
    else:
        models = a.models
        unknown = [m for m in models if m not in PRICES or m == "fake"]
        if unknown:
            sys.exit(f"unknown model(s) {unknown}")
    plan = sc.build_screen_plan(catalog, tasks, models, reps=a.reps, benign_reps=a.benign_reps, k=a.k, seed=a.seed)
    budget = a.max_usd - spent
    est = estimate_plan_cost(plan.specs)
    print(f"{len(plan.specs)} runs planned; rough estimate ${est:.2f}; ceiling ${budget:.2f}")
    if a.plan_only:
        return 0
    runs_file = out / "runs.jsonl"
    if runs_file.exists():
        sys.exit(f"{runs_file} exists; use a new --out directory")
    (out / "plan.json").write_text(json.dumps(
        {"seed": a.seed, "k": a.k, "reps": a.reps, "benign_reps": a.benign_reps, "effort": a.effort,
         "max_usd": a.max_usd, "models": models, "specs": [s.to_dict() for s in plan.specs]}, indent=1),
        encoding="utf-8")
    (out / "targets.json").write_text(json.dumps(plan.targets, indent=1), encoding="utf-8")

    done = 0

    def progress(rec: dict) -> None:
        nonlocal done
        done += 1
        if done % 25 == 0 or done == len(plan.specs):
            print(f"  {done}/{len(plan.specs)} runs", flush=True)

    meta = execute(plan.specs, client, catalog, out, max_usd=budget, workers=a.workers, effort=a.effort,
                   on_result=progress)
    meta["generation_usd"] = round(spent, 4)
    (out / "meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    s = sc.write_screen_report(out, sorted(catalog.decoy_names), lint_result, validate=a.decoys == "m0")
    print(f"spent ${meta['spent_usd'] + spent:.2f}; skipped {meta['runs_skipped_budget']} for budget")
    print("verdicts: " + ", ".join(f"{k} {v}" for k, v in sorted(s["counts"].items())))
    for r in s["rows"]:
        if r["verdict"] in ("RETIRE", "REVIEW"):
            print(f"  {r['verdict']:7} {r['decoy']}: {r['adj_trips']}/{r['adj_exposures']} adjacent, "
                  f"{r['benign_trips']}/{r['benign_exposures']} benign")
    if s["validation"]:
        for k, c in s["validation"]["checks"].items():
            print(f"  {k} {'pass' if c['pass'] else 'FAIL'}: {c['detail']}")
    print(f"report: {out / 'report.md'}")
    return 0


def cmd_screen_report(a: argparse.Namespace) -> int:
    from . import screen as sc

    out = Path(a.dir)
    lint_result = json.loads((out / "lint.json").read_text(encoding="utf-8"))
    specs = json.loads((out / "plan.json").read_text(encoding="utf-8"))["specs"]
    names = sorted({d for s in specs for d in s["decoys"]})
    s = sc.write_screen_report(out, names, lint_result, validate=a.validate)
    print("verdicts: " + ", ".join(f"{k} {v}" for k, v in sorted(s["counts"].items())))
    print(f"report: {out / 'report.md'}")
    return 0


def cmd_dojo(a: argparse.Namespace) -> int:
    import os

    from . import dojo as dj
    from .screen import catalog_decoys

    out = Path(a.out)
    if (out / "runs.jsonl").exists():
        sys.exit(f"{out / 'runs.jsonl'} exists; use a new --out directory")
    decoys = catalog_decoys()
    installs = load_fix_names()["installs"]
    index = dj.task_index(a.suites)
    lint_result = dj.lint_suites(dj.suite_tools(), decoys, installs)
    out.mkdir(parents=True, exist_ok=True)
    (out / "lint.json").write_text(json.dumps(lint_result, indent=1), encoding="utf-8")
    dropped = {s: d for s, d in lint_result["dropped"].items() if d}
    print(f"lint: {len(lint_result['errors'])} errors; dropped {dropped or 'none'}")
    if lint_result["errors"] and not a.ignore_lint:
        sys.exit("lint errors (see lint.json); fix them or pass --ignore-lint")

    if a.dry_run:
        models = ["fake"]
        shown = {d.name for d in decoys} | {n for ins in installs for n in ins["names"].values()}
        client = dj.FakeDojoClient(shown, p_decoy=0.05, seed=a.seed)
    else:
        models = a.models
        unknown = [m for m in models if m not in PRICES or m == "fake"]
        if unknown:
            sys.exit(f"unknown model(s) {unknown}")
        import anthropic

        load_dotenv()
        if not os.environ.get("ANTHROPIC_API_KEY"):
            sys.exit("ANTHROPIC_API_KEY not found: set it in the environment or in experiments/killtest/.env")
        client = anthropic.Anthropic(max_retries=4)

    attack_users = None if a.attack_users == "all" else int(a.attack_users)
    specs = dj.build_dojo_plan(index, lint_result["allowed"], installs, models, arms=tuple(a.arms), reps=a.reps,
                               attack_users=attack_users, user_limit=a.user_limit, seed=a.seed)
    print(f"{len(specs)} runs planned ({', '.join(f'{arm} {sum(s.arm == arm for s in specs)}' for arm in a.arms)}); "
          f"hard ceiling ${a.max_usd:.2f}")
    if a.plan_only:
        return 0
    (out / "plan.json").write_text(json.dumps(
        {"agentdojo": dj.AGENTDOJO_VERSION, "benchmark": dj.BENCHMARK_VERSION, "attack": dj.ATTACK, "seed": a.seed,
         "effort": a.effort, "max_usd": a.max_usd, "models": models, "specs": [s.to_dict() for s in specs]},
        indent=1), encoding="utf-8")

    done = 0

    def progress(rec: dict) -> None:
        nonlocal done
        done += 1
        if done % 25 == 0 or done == len(specs):
            print(f"  {done}/{len(specs)} runs", flush=True)

    meta = dj.execute_dojo(specs, client, {d.name: d for d in decoys}, out, max_usd=a.max_usd, workers=a.workers,
                           effort=a.effort, on_result=progress)
    (out / "meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    s = dj.write_dojo_report([out], out, lint_result)
    print(f"spent ${meta['spent_usd']:.2f}; skipped {meta['runs_skipped_budget']} for budget; {s['errors']} errors")
    for k, c in s["checks"].items():
        print(f"  {k} {'pass' if c['pass'] else 'FAIL'}: {c['detail']}")
    print(f"report: {out / 'report.md'}")
    return 0


def cmd_dojo_report(a: argparse.Namespace) -> int:
    from . import dojo as dj

    dirs = [Path(d) for d in a.dirs]
    lint_path = dirs[0] / "lint.json"
    lint_result = json.loads(lint_path.read_text(encoding="utf-8")) if lint_path.exists() else None
    s = dj.write_dojo_report(dirs, Path(a.out), lint_result)
    for k, c in s["checks"].items():
        print(f"  {k} {'pass' if c['pass'] else 'FAIL'}: {c['detail']}")
    print(f"report: {Path(a.out) / 'report.md'}")
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
    r.add_argument("--env", choices=list(ENVS), default="m3a",
                   help="m3a = the M3a environment; fix = M3a-fix (v2 honey, varied secrets, per-install decoy names)")
    r.add_argument("--policy", choices=["greedy", "files_only", "targeted", "snare_aware", "code_reader", "all"],
                   help="M3: run a scripted attacker policy instead of a model (no API calls, $0)")
    r.add_argument("--plan-only", action="store_true", help="print the plan and estimate, then exit")
    r.set_defaults(fn=cmd_run)

    rep = sub.add_parser("report", help="rebuild report.md for a results directory")
    rep.add_argument("dir", help="results directory, or results/latest")
    rep.set_defaults(fn=cmd_report)

    sc = sub.add_parser("screen", help="M3b: screen a decoy set against your agent's own tools for false positives")
    sc.add_argument("--tools", help="your agent's tools: MCP tools/list JSON or a list (optional 'result' per tool); "
                                    "'m0' = the four M0 scenarios")
    sc.add_argument("--system", help="system prompt text, or @FILE")
    sc.add_argument("--decoys", default="catalog", help="'catalog' (default), 'm0' (M0's original 20), or a JSON file")
    sc.add_argument("--tasks", help="tasks.yaml to use (skips generation)")
    sc.add_argument("--generate-only", action="store_true", help="write tasks.yaml for review, then stop")
    sc.add_argument("--generator-model", default="claude-opus-5-5")
    sc.add_argument("--adjacent-per-decoy", type=int, default=2)
    sc.add_argument("--benign", type=int, default=5, help="benign tasks per deployment")
    sc.add_argument("--reps", type=int, default=2, help="runs per adjacent task, per model")
    sc.add_argument("--benign-reps", type=int, default=4, help="runs per benign task, per model")
    sc.add_argument("--k", type=int, default=4, help="decoys shown per run")
    sc.add_argument("--models", nargs="+", default=["claude-haiku-5-5"])
    sc.add_argument("--max-usd", type=float, default=2.0, help="hard ceiling for generation + runs (default $2)")
    sc.add_argument("--gen-max-usd", type=float, default=1.0, help="ceiling for generation alone")
    sc.add_argument("--workers", type=int, default=4)
    sc.add_argument("--effort", choices=["low", "medium", "high"], default="medium")
    sc.add_argument("--seed", type=int, default=71)
    sc.add_argument("--out", required=True, help="output directory")
    sc.add_argument("--dry-run", action="store_true", help="fake tasks and the scripted fake model; no API calls")
    sc.add_argument("--plan-only", action="store_true")
    sc.add_argument("--ignore-lint", action="store_true")
    sc.set_defaults(fn=cmd_screen)

    sr = sub.add_parser("screen-report", help="rebuild a screen directory's report")
    sr.add_argument("dir")
    sr.add_argument("--validate", action="store_true", help="add the M3b validation checks (M0 decoys)")
    sr.set_defaults(fn=cmd_screen_report)

    dj = sub.add_parser("dojo", help="M3c: run Snare decoys inside AgentDojo suites (needs .[agentdojo])")
    dj.add_argument("--models", nargs="+", default=["claude-haiku-5-5"])
    dj.add_argument("--arms", nargs="+", choices=["plain", "benign", "attack"], default=["plain", "benign", "attack"])
    dj.add_argument("--suites", nargs="+", choices=["banking", "slack", "travel", "workspace"])
    dj.add_argument("--reps", type=int, default=1, help="runs per user task in plain/benign")
    dj.add_argument("--attack-users", default="all",
                    help="'all' = every (user, injection) pair; N = N user tasks per injection task (stratified)")
    dj.add_argument("--user-limit", type=int, help="first N user tasks per suite (pilot)")
    dj.add_argument("--max-usd", type=float, default=2.0, help="hard spending ceiling (default $2)")
    dj.add_argument("--workers", type=int, default=4)
    dj.add_argument("--effort", choices=["low", "medium", "high"], default="medium")
    dj.add_argument("--seed", type=int, default=97)
    dj.add_argument("--out", required=True)
    dj.add_argument("--dry-run", action="store_true", help="scripted fake model; no API calls")
    dj.add_argument("--plan-only", action="store_true")
    dj.add_argument("--ignore-lint", action="store_true")
    dj.set_defaults(fn=cmd_dojo)

    djr = sub.add_parser("dojo-report", help="M3c: one report over one or more dojo result directories")
    djr.add_argument("dirs", nargs="+")
    djr.add_argument("--out", required=True)
    djr.set_defaults(fn=cmd_dojo_report)

    a = p.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")  # Windows consoles default to a legacy code page
    return a.fn(a)
