"""Load the experiment's data files into typed objects."""

from __future__ import annotations

from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any

import yaml

DATA_DIR = Path(str(resources.files("killtest") / "data"))


@dataclass(frozen=True)
class ToolDef:
    name: str
    description: str
    params: dict[str, str]
    result: str = ""
    is_decoy: bool = False
    tier: str = ""

    def to_api(self) -> dict:
        """Tool definition in Messages API shape."""
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": {
                "type": "object",
                "properties": {k: {"type": "string", "description": v} for k, v in self.params.items()},
                "required": list(self.params),
            },
        }


@dataclass(frozen=True)
class Scenario:
    name: str
    system: str
    content_tool: str
    tools: tuple[ToolDef, ...]
    tasks: tuple[str, ...]
    # Benign tasks that sit close to a decoy's apparent purpose: the hard false-positive test.
    adjacent_tasks: tuple[str, ...] = ()
    # M3a-fix2 held-out set, run only in Phase 2 (docs/M3a-fix2-name-screen.md).
    adjacent3_tasks: tuple[str, ...] = ()

    def tasks_for(self, arm: str) -> tuple[str, ...]:
        if arm == "adjacent":
            return self.adjacent_tasks
        if arm == "adjacent3":
            return self.adjacent3_tasks
        return self.tasks

    def tool(self, name: str) -> ToolDef | None:
        return next((t for t in self.tools if t.name == name), None)


@dataclass(frozen=True)
class Payload:
    id: str
    kind: str  # "canary" | "attack"
    text: str

    def render(self, tag: str) -> str:
        return self.text.replace("{tag}", tag)


@dataclass(frozen=True)
class Catalog:
    scenarios: dict[str, Scenario]
    decoys: tuple[ToolDef, ...]
    canaries: tuple[Payload, ...]
    attacks: tuple[Payload, ...]
    attacker_marker: str
    m3: Any = None  # m3.M3Env when data/m3.yaml exists
    decoy_names: frozenset[str] = field(init=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "decoy_names", frozenset(d.name for d in self.decoys))


def _load_yaml(path: Path):
    with path.open(encoding="utf-8") as f:
        return yaml.safe_load(f)


def load_catalog(data_dir: Path = DATA_DIR) -> Catalog:
    decoys = tuple(
        ToolDef(
            name=d["name"],
            description=d["description"],
            params=dict(d["params"]),
            result="",
            is_decoy=True,
            tier=d["tier"],
        )
        for d in _load_yaml(data_dir / "decoys.yaml")
        if not d.get("retired")  # retired decoys stay in the file with the reason
    )

    scenarios = {}
    for name, s in _load_yaml(data_dir / "scenarios.yaml").items():
        tools = tuple(
            ToolDef(name=t["name"], description=t["description"], params=dict(t["params"]), result=t["result"])
            for t in s["tools"]
        )
        scenarios[name] = Scenario(
            name=name,
            system=s["system"],
            content_tool=s["content_tool"],
            tools=tools,
            tasks=tuple(s["tasks"]),
            adjacent_tasks=tuple(s.get("adjacent_tasks", ())),
            adjacent3_tasks=tuple(s.get("adjacent_tasks_v3", ())),
        )

    p = _load_yaml(data_dir / "payloads.yaml")
    canaries = tuple(Payload(c["id"], "canary", c["text"]) for c in p["canaries"])
    attacks = tuple(Payload(a["id"], "attack", a["text"]) for a in p["attacks"])

    m3 = None
    if (data_dir / "m3.yaml").exists():
        from .m3 import load_m3

        m3 = load_m3(data_dir / "m3.yaml")
    catalog = Catalog(scenarios, decoys, canaries, attacks, p["attacker_marker"], m3)
    validate(catalog)
    if m3 is not None:
        from .m3 import validate_m3

        validate_m3(m3, catalog)
    return catalog


def validate(c: Catalog) -> None:
    """Fail fast on data mistakes that would silently corrupt results."""
    real_names = {t.name for s in c.scenarios.values() for t in s.tools}
    clash = real_names & c.decoy_names
    if clash:
        raise ValueError(f"decoy names collide with real tools: {sorted(clash)}")
    if len(c.decoy_names) != len(c.decoys):
        raise ValueError("duplicate decoy names")
    for s in c.scenarios.values():
        if s.tool(s.content_tool) is None:
            raise ValueError(f"scenario {s.name}: content_tool {s.content_tool!r} is not one of its tools")
        if not s.adjacent_tasks:
            raise ValueError(f"scenario {s.name}: no adjacent_tasks")
    for p in (*c.canaries, *c.attacks):
        if "{tag}" not in p.text:
            raise ValueError(f"payload {p.id} has no {{tag}} placeholder")
