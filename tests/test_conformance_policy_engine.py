"""Shared conformance suite for the PolicyEngine contract.

Every PolicyEngine implementation must pass this identical suite. Today there are
two: the production `CedarPolicyEngine` and the `ReferencePolicyEngine` double.
The point is not to test Cedar twice — it is to nail down the *contract* so a third
engine cannot quietly violate it.

The load-bearing contract is fail-closed: no engine may allow an unasserted tool,
none may raise out of `decide`, and every decision must carry a reason.
"""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from toolconnect.descriptor import (
    AssertedDescriptor, ClaimedMetadata, DataClass, Effect, ToolRef, ToolVersion,
)
from toolconnect.policy import CedarPolicyEngine, Decision, PolicyEngine, Principal

from conftest import BASIC_CEDAR, ReferencePolicyEngine, make_tool


def _engines() -> list:
    return [
        pytest.param(CedarPolicyEngine(BASIC_CEDAR), id="cedar"),
        pytest.param(ReferencePolicyEngine(), id="reference"),
    ]


@pytest.fixture(params=_engines())
def engine(request) -> PolicyEngine:
    return request.param


class TestProtocolShape:
    def test_satisfies_the_runtime_protocol(self, engine):
        assert isinstance(engine, PolicyEngine)

    def test_has_no_invocation_method(self, engine):
        # The architectural invariant applies to every engine, not just the broker.
        assert not hasattr(engine, "invoke")


class TestUniversalContract:
    def test_allow_implies_asserted(self, engine):
        """No engine may allow a tool with no operator assertion. Ever."""
        bare = ToolVersion(ToolRef("x"), "s", ClaimedMetadata(read_only_hint=True), asserted=None)
        d = engine.decide(Principal("a"), bare, {})
        assert not d.allowed
        assert d.reason, "a decision must always explain itself"

    def test_read_tool_is_permitted_by_both(self, engine):
        d = engine.decide(Principal("a"), make_tool(effect=Effect.READ), {})
        assert d.allowed and d.reason

    def test_every_decision_has_a_reason(self, engine):
        for eff in Effect:
            d = engine.decide(Principal("a"), make_tool(effect=eff), {})
            assert isinstance(d, Decision)
            assert d.reason
            assert isinstance(d.determining_policies, tuple)

    @given(
        pid=st.text(min_size=0, max_size=40),
        tier=st.sampled_from(["local", "trusted-cloud", "rented", "", "\n", "weird"]),
        ctx=st.dictionaries(st.text(max_size=8), st.booleans() | st.integers(), max_size=4),
    )
    def test_decide_never_raises_on_arbitrary_input(self, engine, pid, tier, ctx):
        """Fuzz principal id, tier, and context. An engine that raises is a fail-open
        hazard: a caller that catches the exception and proceeds has just allowed."""
        d = engine.decide(Principal(pid, privacy_tier=tier), make_tool(effect=Effect.READ), ctx)
        assert isinstance(d, Decision)
        assert isinstance(d.allowed, bool)
