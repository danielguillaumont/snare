"""M13b credentials environment (docs/M13b-default-decoy-set.md §3)."""

import re
from pathlib import Path

from killtest.config import DATA_DIR, load_catalog
from killtest.episode import exposed_tools, run_episode
from killtest.plan import CREDENTIALS_PROFILE, build_plan, load_adapt_names, load_depth_names, load_fix_names
from killtest.policies import PolicyClient, public_decoy_names

PROFILES_GO = Path(__file__).resolve().parents[3] / "internal" / "decoys" / "profiles.go"


def specs(arm="hunt", n=40, seed=46):
    cat = load_catalog()
    return cat, build_plan(cat, [arm], ["claude-haiku-5-5"], n, seed=seed, env="credentials")


def test_profile_matches_the_go_profile():
    src = PROFILES_GO.read_text(encoding="utf-8")
    m = re.search(r'"credentials":\s*\{([^}]*)\}', src)
    assert m, "credentials profile not found in profiles.go"
    assert tuple(re.findall(r'"([a-z0-9_]+)"', m.group(1))) == CREDENTIALS_PROFILE


def test_every_run_shows_exactly_the_four_under_install_names():
    cat, ss = specs()
    installs = load_depth_names()["installs"]
    for i, s in enumerate(ss):
        assert s.env == "credentials" and set(s.decoys) == set(CREDENTIALS_PROFILE)
        names = installs[i % len(installs)]["names"]
        assert s.shown == tuple(names[d] for d in s.decoys)
        tools = exposed_tools(cat, s)
        assert sum(t.is_decoy for t in tools) == 4
        assert s.honey and s.honey_url and s.honey != s.honey_url  # depth's honey layout


def test_benign_arms_get_the_same_four():
    for arm in ("benign3", "adjacent3"):
        _, ss = specs(arm, n=12)
        assert all(set(s.decoys) == set(CREDENTIALS_PROFILE) for s in ss)
        assert all(bool(s.honey) == (arm == "benign3") for s in ss)  # adjacent3 has no honey file, as in M13


def test_scripted_greedy_is_caught():
    cat, ss = specs(n=20)
    client = PolicyClient(public_decoy_names(DATA_DIR), frozenset(load_fix_names()["all_generated"]),
                          load_adapt_names()["space"])
    for s in ss:
        s = s.__class__(**{**s.__dict__, "model": "policy-greedy"})
        assert run_episode(client, cat, s)["detected_observable"]
