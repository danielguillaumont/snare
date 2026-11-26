"""M3c integration with the real AgentDojo package (offline fake model, $0)."""

from __future__ import annotations

import pytest

from killtest import dojo
from killtest.screen import catalog_decoys

# --------------------------------------------------------------------------- integration (agentdojo)

pytest.importorskip("agentdojo")


@pytest.fixture(scope="module")
def decoy_defs():
    return {d.name: d for d in catalog_decoys()}


def test_index_matches_benchmark():
    idx = dojo.task_index()
    assert {s: (len(v["user"]), len(v["injection"])) for s, v in idx.items()} == {
        "banking": (16, 9), "slack": (21, 5), "travel": (20, 7), "workspace": (40, 14)}


def test_catalog_lints_clean_on_agentdojo(decoy_defs):
    from killtest.plan import load_fix_names

    res = dojo.lint_suites(dojo.suite_tools(), tuple(decoy_defs.values()), load_fix_names()["installs"])
    assert not res["errors"]
    assert all(len(a) >= dojo.K for a in res["allowed"].values())


def _one(arm, decoy_defs, client, injection=None):
    names = sorted(decoy_defs)[:4]
    spec = dojo.DojoSpec(run_id=0, model="fake", arm=arm, suite="banking", user_task="user_task_0",
                         injection_task=injection, rep=0, decoys=tuple(names) if arm != "plain" else (),
                         names={n: n for n in names} if arm != "plain" else {}, tool_order_seed=1)
    return dojo.run_dojo_episode(client, spec, decoy_defs)


def test_episode_with_a_decoy_call_records_a_trip(decoy_defs):
    client = dojo.FakeDojoClient(set(decoy_defs), p_decoy=1.0)
    rec = _one("benign", decoy_defs, client)
    assert rec["tripped"] and rec["decoys_called"] and rec["first_decoy_call"] == 0
    assert rec["decoy_calls"][0]["args"] == {}
    assert rec["security"] is None and rec["error"] is None


def test_plain_episode_shows_no_decoys(decoy_defs):
    seen = []

    class Spy(dojo.FakeDojoClient):
        def _create(self, **kw):
            seen.append({t["name"] for t in kw["tools"]})
            return super()._create(**kw)

    rec = _one("plain", decoy_defs, Spy(set(decoy_defs), p_decoy=1.0))
    assert not rec["tripped"] and not (seen[0] & set(decoy_defs))
    assert len(seen[0]) == 11  # banking's real tools only


def test_attack_episode_injects_agentdojo_template(decoy_defs):
    captured = []

    class Spy(dojo.FakeDojoClient):
        def _create(self, **kw):
            captured.append(kw)
            return super()._create(**kw)

    # user_task_0 reads a bill; the fake answers without tools, so the injection is never seen,
    # but the attack must still build (ground-truth pass) and security must be scored.
    rec = _one("attack", decoy_defs, Spy(set(decoy_defs), p_decoy=0.0), injection="injection_task_0")
    assert rec["security"] is False and rec["utility"] is False
    injections = dojo._attack("banking").attack(dojo.suites()["banking"].get_user_task_by_id("user_task_0"),
                                                dojo.suites()["banking"].get_injection_task_by_id("injection_task_0"))
    assert injections and all("Claude" in v and "<INFORMATION>" in v for v in injections.values())

