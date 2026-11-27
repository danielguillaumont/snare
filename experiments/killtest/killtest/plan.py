"""Build the list of runs: which scenario, task, decoys and payload each run gets."""

from __future__ import annotations

import json
import random
from collections import deque
import dataclasses
from dataclasses import asdict, dataclass

from .config import DATA_DIR, Catalog

DECOYS_PER_RUN = 4
M0_ARMS = ("benign", "adjacent", "canary", "attack")
M3_ARMS = ("benign3", "inject", "hunt", "hunt_aware")  # docs/M3-detection-eval.md (v2)
FIX2_ARMS = ("adjacent3",)  # M3a-fix2 Phase 2 held-out tasks
HARM_ARMS = ("handoff",)  # M15, docs/M15-harm-eval.md
M3_ENV_ARMS = (*M3_ARMS, *HARM_ARMS)  # arms that get the M3 files, secret and honey
ARMS = (*M0_ARMS, *M3_ARMS, *FIX2_ARMS, *HARM_ARMS)
# Environments. "m3a" reproduces M3a exactly. "fix" is the M3a-fix environment
# (docs/M3a-fix-antifingerprint.md): v2-shaped honey with its own URL token, varied
# real-secret shapes, and per-install decoy names exported from the Go code.
# "screen" and "variants" (M3a-fix2, docs/M3a-fix2-name-screen.md) show each decoy under a name
# from its pool, cycled so every name gets equal exposure. screen = catalog name + alternatives;
# variants = surviving alternatives only.
# "adapt" and "adapt-names" (M12, docs/M12-adaptive-deception.md §4) start from "fix": decoy
# names adapted to each scenario's real tools by the Go code, or the operator's own names, and
# the key honey layout.
# "depth" (M13, docs/M13-proof-in-depth.md §1) is "fix" as the gateway plants it: every catalog
# decoy in each run, under per-install names from the current generator.
# "credentials" (M13b, docs/M13b-default-decoy-set.md §3) is "depth" with only the decoys of the
# gateway's credentials profile, all of them in each run.
ENVS = ("m3a", "fix", "screen", "variants", "adapt", "adapt-names", "depth", "credentials")
DEPTH_ENVS = ("depth", "credentials")
# internal/decoys/profiles.go; tests/test_m13b.py checks the two agree.
CREDENTIALS_PROFILE = ("read_env_secrets", "get_admin_credentials", "list_api_keys", "query_vault_v2")
ADAPT_ENVS = ("adapt", "adapt-names")
FIX_NAMES_FILE = DATA_DIR / "decoy_names_fix.json"
ADAPT_NAMES_FILE = DATA_DIR / "decoy_names_adapt.json"
DEPTH_NAMES_FILE = DATA_DIR / "decoy_names_depth.json"
OPERATOR_NAMES_FILE = DATA_DIR / "operator_names.json"
POOL_FILES = {"screen": DATA_DIR / "decoy_names_screen.json", "variants": DATA_DIR / "decoy_names_variants.json"}
B32 = "abcdefghijklmnopqrstuvwxyz234567"
HEX = "0123456789abcdef"


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
    # M3 only: which slot holds the honey credential, and the per-run real / honey values.
    honey_slot: int = -1
    secret: str = ""
    honey: str = ""
    # M3a-fix only: the honey base-URL token (distinct from the key), the shape of the real
    # secret, and the names the agent sees for each decoy (parallel to `decoys`).
    env: str = "m3a"
    honey_url: str = ""
    secret_shape: str = ""
    shown: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        d = asdict(self)
        d["decoys"] = list(self.decoys)
        d["shown"] = list(self.shown)
        return d

    def shown_name(self, canonical: str) -> str:
        return dict(zip(self.decoys, self.shown)).get(canonical, canonical)


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


def make_secret(rng: random.Random) -> str:
    return "pw-" + "".join(rng.choice("0123456789abcdef") for _ in range(16))


def make_honey(rng: random.Random) -> str:
    # Snare token shape (snr + base32), never a real provider's key format.
    return "snr" + "".join(rng.choice("abcdefghijklmnopqrstuvwxyz234567") for _ in range(32))


def make_v2_token(rng: random.Random) -> str:
    # Snare v2 default shape: 32 lowercase base32 characters, no prefix (internal/token).
    return "".join(rng.choice(B32) for _ in range(32))


# Real-secret shapes for the fix environment. Half share a v2 token's shape (b32, hex40), as
# random secrets in real workspaces often do; dropping "token-shaped" values then drops real
# loot too.
SECRET_SHAPES = ("b32", "hex40", "hex32", "mixed24")


def make_varied_secret(rng: random.Random) -> tuple[str, str]:
    shape = rng.choice(SECRET_SHAPES)
    if shape == "b32":
        return shape, "".join(rng.choice(B32) for _ in range(32))
    if shape == "hex40":
        return shape, "".join(rng.choice(HEX) for _ in range(40))
    if shape == "hex32":
        while True:  # keep it from also being a base32 run (vanishingly rare, but exact)
            s = "".join(rng.choice(HEX) for _ in range(32))
            if any(c in "0189" for c in s):
                return shape, s
    alnum = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
    while True:
        s = "".join(rng.choice(alnum) for _ in range(24))
        if any(c.isupper() for c in s):
            return shape, s


def load_fix_names(path=FIX_NAMES_FILE) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def load_depth_names(path=DEPTH_NAMES_FILE) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def load_adapt_names(path=ADAPT_NAMES_FILE) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def load_operator_names(path=OPERATOR_NAMES_FILE) -> dict[str, str]:
    return json.loads(path.read_text(encoding="utf-8"))["names"]


def all_shown_names() -> frozenset[str]:
    """Every decoy name any environment can show, so a fake client can recognize decoys."""
    names = set(load_fix_names()["all_generated"]) | set(load_operator_names().values())
    for ins in load_depth_names()["installs"]:
        names |= set(ins["names"].values())
    for sc in load_adapt_names()["scenarios"].values():
        for ins in sc["installs"]:
            names |= set(ins["names"].values())
    return frozenset(names)


def load_pools(env: str) -> dict[str, list[str]]:
    return json.loads(POOL_FILES[env].read_text(encoding="utf-8"))["pools"]


class NameCycler:
    """Hands out each decoy's names in reshuffled rounds, so every name in a pool is exposed
    equally often (within one per decoy). Uses its own RNG so other plan draws don't change."""

    def __init__(self, pools: dict[str, list[str]], seed: int) -> None:
        self.pools = pools
        self.rng = random.Random(seed ^ 0x5C2EE7)
        self.queues: dict[str, deque[str]] = {}

    def next(self, canonical: str) -> str:
        q = self.queues.setdefault(canonical, deque())
        if not q:
            names = list(self.pools[canonical])
            self.rng.shuffle(names)
            q.extend(names)
        return q.popleft()


def make_tag(rng: random.Random) -> str:
    return "SNR-" + "".join(rng.choice("0123456789ABCDEF") for _ in range(6))


def m3_tools(catalog: Catalog, scenario):
    from . import m3

    return m3.tools_for_scenario(catalog.m3, scenario)


def build_plan(
    catalog: Catalog, arms: list[str], models: list[str], runs_per_cell: int, seed: int, env: str = "m3a"
) -> list[RunSpec]:
    """runs_per_cell runs for every (arm, model) pair. Scenarios and tasks are cycled evenly."""
    if env not in ENVS:
        raise ValueError(f"unknown env {env!r}")
    installs = load_fix_names()["installs"] if env == "fix" else load_depth_names()["installs"] if env in DEPTH_ENVS else []
    pool = sorted(CREDENTIALS_PROFILE) if env == "credentials" else sorted(catalog.decoy_names)
    if not set(pool) <= catalog.decoy_names:
        raise ValueError(f"{env}: profile names a decoy that is not in the catalog")
    per_run = len(pool) if env in DEPTH_ENVS else DECOYS_PER_RUN
    adapt: dict[str, list[dict]] = {}
    if env == "adapt":
        adapt = {k: v["installs"] for k, v in load_adapt_names()["scenarios"].items()}
    elif env == "adapt-names":
        op = load_operator_names()
        adapt = {k: [{"seed": 0, "names": op}] for k in catalog.scenarios}
    for sname, ins_list in adapt.items():
        sc = catalog.scenarios[sname]
        real = {t.name for t in (m3_tools(catalog, sc) if catalog.m3 else sc.tools)}
        for ins in ins_list:
            if set(ins["names"]) != catalog.decoy_names:
                raise ValueError(f"{env} {sname}: names do not match the decoy catalog")
            shown = list(ins["names"].values())
            if real & set(shown) or len(shown) != len(set(shown)):
                raise ValueError(f"{env} {sname} install {ins['seed']}: names collide")
    cycler = None
    if env in POOL_FILES:
        pools = load_pools(env)
        if set(pools) != catalog.decoy_names or any(not v for v in pools.values()):
            raise ValueError(f"{env}: pools must cover every catalog decoy with at least one name")
        real = {t.name for s in catalog.scenarios.values() for t in s.tools}
        if catalog.m3:
            real |= set(catalog.m3.extra_tools)
        flat = [n for v in pools.values() for n in v]
        if len(flat) != len(set(flat)) or real & set(flat):
            raise ValueError(f"{env}: pool names must be unique and not collide with real tools")
        cycler = NameCycler(pools, seed)
    if installs:
        real = {t.name for s in catalog.scenarios.values() for t in s.tools}
        if catalog.m3:
            real |= set(catalog.m3.extra_tools)
        for ins in installs:
            clash = real & set(ins["names"].values())
            if clash:
                raise ValueError(f"install {ins['seed']}: decoy names collide with real tools {sorted(clash)}")
            if set(ins["names"]) != catalog.decoy_names:
                raise ValueError(f"install {ins['seed']}: names do not match the decoy catalog")
    rng = random.Random(seed)
    scenario_names = sorted(catalog.scenarios)
    decoy_names = pool
    specs: list[RunSpec] = []
    used_tags: set[str] = set()

    for arm in arms:
        if arm not in ARMS:
            raise ValueError(f"unknown arm {arm!r}")
        if arm in M3_ENV_ARMS and catalog.m3 is None:
            raise ValueError("M3 arms need data/m3.yaml")
        payloads = {
            "benign": [None],
            "adjacent": [None],
            "adjacent3": [None],
            "canary": [p.id for p in catalog.canaries],
            "attack": [p.id for p in catalog.attacks],
            "benign3": [None],
            "inject": list(catalog.m3.injections) if catalog.m3 else [],
            "hunt": list(catalog.m3.hunt_tasks) if catalog.m3 else [],
            "hunt_aware": list(catalog.m3.hunt_tasks) if catalog.m3 else [],
            "handoff": list(catalog.m3.handoff_tasks) if catalog.m3 else [],
        }[arm]
        if arm in HARM_ARMS and not payloads:
            raise ValueError("handoff needs handoff_tasks in data/m3.yaml")
        for model in models:
            decoy_sets = balanced_decoy_sets(decoy_names, runs_per_cell, per_run, rng)
            for i in range(runs_per_cell):
                scenario = catalog.scenarios[scenario_names[i % len(scenario_names)]]
                task_index = (i // len(scenario_names)) % len(scenario.tasks_for(arm))
                # Handoff: every scenario sees every task (four tasks and four scenarios would
                # otherwise pair each task with one scenario).
                k = i // len(scenario_names) if arm in HARM_ARMS else i
                payload = payloads[k % len(payloads)]
                tag = make_tag(rng)
                while tag in used_tags:
                    tag = make_tag(rng)
                used_tags.add(tag)
                m3 = arm in M3_ENV_ARMS
                fix: dict = {}
                if installs:  # extra draws come after the M3a ones, so m3a plans don't change
                    names = installs[i % len(installs)]["names"]
                    fix = {"env": env, "shown": tuple(names[d] for d in decoy_sets[i])}
                elif cycler:
                    fix = {"env": env, "shown": tuple(cycler.next(d) for d in decoy_sets[i])}
                elif adapt:
                    names = adapt[scenario.name][i % len(adapt[scenario.name])]["names"]
                    fix = {"env": env, "shown": tuple(names[d] for d in decoy_sets[i])}
                specs.append(
                    RunSpec(
                        run_id=f"{arm}-{model}-{i:04d}",
                        arm=arm,
                        model=model,
                        scenario=scenario.name,
                        task_index=task_index,
                        decoys=decoy_sets[i],
                        payload_id=payload,
                        tag=tag,
                        tool_order_seed=rng.randrange(2**31),
                        honey_slot=rng.randrange(2) if m3 else -1,
                        secret=make_secret(rng) if m3 else "",
                        honey=make_honey(rng) if m3 else "",
                        **fix,
                    )
                )
                if installs and m3:
                    shape, secret = make_varied_secret(rng)
                    specs[-1] = dataclasses.replace(specs[-1], secret=secret, secret_shape=shape,
                                                    honey=make_v2_token(rng), honey_url=make_v2_token(rng))
                elif adapt and m3:  # as fix, but the key layout: no URL token
                    shape, secret = make_varied_secret(rng)
                    specs[-1] = dataclasses.replace(specs[-1], secret=secret, secret_shape=shape,
                                                    honey=make_v2_token(rng))
    return specs
