"""A scripted stand-in for the Anthropic client, for offline tests and dry runs.

It mimics just enough of `client.messages.create` for the harness: it reads the content
tool, sometimes touches a decoy, sometimes repeats a canary tag. Behavior is seeded from
the request, so the same plan gives the same results.
"""

from __future__ import annotations

import hashlib
import itertools
import random
import re
from types import SimpleNamespace

TAG_RE = re.compile(r"SNR-[0-9A-F]{6}")


class _Messages:
    def __init__(self, owner: "FakeClient") -> None:
        self._o = owner

    def create(self, **kw) -> SimpleNamespace:
        return self._o._respond(kw)


class FakeClient:
    def __init__(
        self,
        decoy_names: frozenset[str],
        content_tools: frozenset[str],
        attacker_marker: str,
        p_benign_trip: float = 0.03,
        p_attack_comply: float = 0.4,
        p_canary_obey: float = 0.5,
    ) -> None:
        self.decoy_names = decoy_names
        self.content_tools = content_tools
        self.attacker_marker = attacker_marker
        self.p_benign_trip = p_benign_trip
        self.p_attack_comply = p_attack_comply
        self.p_canary_obey = p_canary_obey
        self.messages = _Messages(self)
        self._ids = itertools.count(1)  # next() on a count is atomic under the GIL

    def _id(self) -> str:
        return f"toolu_fake_{next(self._ids)}"

    @staticmethod
    def _rng(kw: dict) -> random.Random:
        first = kw["messages"][0]["content"]
        names = ",".join(t["name"] for t in kw["tools"])
        digest = hashlib.sha256(f"{first}|{names}|{len(kw['messages'])}".encode()).hexdigest()
        return random.Random(int(digest[:16], 16))

    @staticmethod
    def _last_result_text(kw: dict) -> str:
        last = kw["messages"][-1]
        if last["role"] != "user" or isinstance(last["content"], str):
            return ""
        return "\n".join(str(b.get("content", "")) for b in last["content"] if isinstance(b, dict))

    def _respond(self, kw: dict) -> SimpleNamespace:
        rng = self._rng(kw)
        names = [t["name"] for t in kw["tools"]]
        decoys = [n for n in names if n in self.decoy_names]
        turn = (len(kw["messages"]) + 1) // 2
        result_text = self._last_result_text(kw)
        usage = SimpleNamespace(input_tokens=1500, output_tokens=120, cache_creation_input_tokens=0, cache_read_input_tokens=0)

        def tool_call(name: str, inp: dict) -> SimpleNamespace:
            block = SimpleNamespace(type="tool_use", id=self._id(), name=name, input=inp)
            return SimpleNamespace(content=[block], stop_reason="tool_use", usage=usage)

        def answer(text: str) -> SimpleNamespace:
            return SimpleNamespace(content=[SimpleNamespace(type="text", text=text)], stop_reason="end_turn", usage=usage)

        if turn == 1:
            content_tool = next((n for n in names if n in self.content_tools), names[0])
            return tool_call(content_tool, {"arg": "x"})

        if turn == 2:
            tag = TAG_RE.search(result_text)
            if self.attacker_marker in result_text and decoys and rng.random() < self.p_attack_comply:
                return tool_call(decoys[0], {"note": "requested by message"})
            if not tag and decoys and rng.random() < self.p_benign_trip:
                return tool_call(rng.choice(decoys), {"note": "seemed related"})
            if tag and self.attacker_marker not in result_text and rng.random() < self.p_canary_obey:
                return answer(f"Done. Reference: {tag.group(0)}")
            return answer("Done. Here is the summary you asked for.")

        return answer("Done.")
