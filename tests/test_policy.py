"""Cedar suitability, and the fail-closed guarantee.

These tests run offline. `cedarpy` evaluates in-process; nothing opens a socket.
"""

from __future__ import annotations

import pytest

from toolconnect.catalog import Catalog
from toolconnect.descriptor import (
    AssertedDescriptor, ClaimedMetadata, DataClass, Effect, ToolRef, ToolVersion,
    TrustedSource, TrustTier,
)
from toolconnect.policy import Broker, CedarPolicyEngine, Decision, Principal

cedarpy = pytest.importorskip("cedarpy")

POLICIES = """
@id("allow-read")
permit(principal, action == Action::"invoke", resource)
when { resource.effect == "read" };

@id("allow-write-local")
permit(principal, action == Action::"invoke", resource)
when { resource.effect == "write" && principal.privacy_tier == "local" };

@id("forbid-destructive-nonlocal")
forbid(principal, action, resource)
when { resource.effect == "destructive" && principal.privacy_tier != "local" };

@id("forbid-sensitive-read-when-delegated")
forbid(principal, action, resource)
when { resource.reads_sensitive && principal.delegated };
"""


def _tool(name: str, effect: Effect, reads=frozenset()) -> ToolVersion:
    return ToolVersion(
        ToolRef(name), "s", ClaimedMetadata(),
        AssertedDescriptor(effect=effect, reads=frozenset(reads), asserted_by="op"),
    )


@pytest.fixture
def engine() -> CedarPolicyEngine:
    return CedarPolicyEngine(POLICIES)


class TestCedarDecisions:
    def test_permit_returns_determining_policy_id(self, engine):
        d = engine.decide(Principal("a"), _tool("r", Effect.READ), {})
        assert d.allowed
        assert d.determining_policies == ("allow-read",)
        assert "allow-read" in d.reason

    def test_explicit_forbid_names_the_forbidding_policy(self, engine):
        d = engine.decide(Principal("a", privacy_tier="rented"), _tool("rm", Effect.DESTRUCTIVE), {})
        assert not d.allowed
        assert d.determining_policies == ("forbid-destructive-nonlocal",)
        assert not d.is_default_deny

    def test_forbid_overrides_permit(self, engine):
        """Cedar is forbid-wins. A read tool that trips a forbid is denied."""
        p = Principal("sub", on_behalf_of=Principal("mgr"))
        d = engine.decide(p, _tool("secrets", Effect.READ, reads={DataClass.SECRET}), {})
        assert not d.allowed
        assert "forbid-sensitive-read-when-delegated" in d.determining_policies

    def test_default_deny_is_distinguishable_from_explicit_forbid(self, engine):
        """No policy matches an external-effect tool. Deny, with empty reasons."""
        d = engine.decide(Principal("a"), _tool("post", Effect.EXTERNAL), {})
        assert not d.allowed
        assert d.determining_policies == ()
        assert d.is_default_deny
        assert "no policy matched" in d.reason

    def test_privacy_tier_gates_writes(self, engine):
        assert engine.decide(Principal("a", privacy_tier="local"), _tool("w", Effect.WRITE), {}).allowed
        d = engine.decide(Principal("a", privacy_tier="rented"), _tool("w", Effect.WRITE), {})
        assert not d.allowed and d.is_default_deny


class TestDelegationAttenuates:
    def test_authority_is_the_intersection_of_the_chain(self):
        """A local subagent acting for a rented manager is treated as rented."""
        chain = Principal("sub", privacy_tier="local", on_behalf_of=Principal("mgr", privacy_tier="rented"))
        assert chain.effective_tier() == "rented"

    def test_undelegated_principal_keeps_its_tier(self):
        assert Principal("a", privacy_tier="local").effective_tier() == "local"

    def test_delegation_cannot_escalate(self, engine):
        """Wrapping a rented manager in a local subagent must not unlock destructive."""
        chain = Principal("sub", privacy_tier="local", on_behalf_of=Principal("m", privacy_tier="rented"))
        assert not engine.decide(chain, _tool("rm", Effect.DESTRUCTIVE), {}).allowed


class TestFailClosed:
    def test_unasserted_tool_is_denied(self, engine):
        bare = ToolVersion(ToolRef("x"), "s", ClaimedMetadata(read_only_hint=True), asserted=None)
        d = engine.decide(Principal("a"), bare, {})
        assert not d.allowed
        assert d.determining_policies == ("<unasserted>",)

    def test_engine_error_denies_rather_than_allows(self, engine, monkeypatch):
        def boom(*_a, **_k):
            raise RuntimeError("cedar exploded")

        monkeypatch.setattr(engine._cedar, "is_authorized", boom)
        d = engine.decide(Principal("a"), _tool("r", Effect.READ), {})
        assert not d.allowed
        assert d.errors == ("cedar exploded",)

    def test_invalid_policy_set_is_refused_at_construction(self):
        with pytest.raises(ValueError, match="invalid Cedar policy set"):
            CedarPolicyEngine("this is not cedar")


class TestBrokerHasNoInvoke:
    def test_broker_exposes_no_invocation_method(self):
        """The architectural invariant, asserted as a test."""
        assert not hasattr(Broker, "invoke")
        assert not hasattr(CedarPolicyEngine, "invoke")

    def test_denials_are_recorded_like_allows(self, engine):
        cat = Catalog()
        cat.register_source(TrustedSource("s", TrustTier.KNOWN))
        cat.ingest_claimed("s", "r", ClaimedMetadata())
        cat.assert_descriptor("r", AssertedDescriptor(effect=Effect.READ, asserted_by="op"))
        cat.ingest_claimed("s", "unreviewed", ClaimedMetadata())

        audit: list[dict] = []
        broker = Broker(cat, engine, audit)
        assert broker.authorize(Principal("a"), "r").allowed
        assert not broker.authorize(Principal("a"), "unreviewed").allowed
        assert not broker.authorize(Principal("a"), "ghost").allowed

        assert len(audit) == 3, "a denial is a decision, not an error"
        assert [e["allowed"] for e in audit] == [True, False, False]
        assert audit[2]["determining_policies"] == ["<unregistered>"]

    def test_untrusted_source_denied_before_policy_runs(self, engine):
        cat = Catalog()
        cat.register_source(TrustedSource("bad", TrustTier.UNTRUSTED))
        cat.ingest_claimed("bad", "t", ClaimedMetadata())
        cat.assert_descriptor("t", AssertedDescriptor(effect=Effect.READ, asserted_by="op"))
        d = Broker(cat, engine, []).authorize(Principal("a"), "t")
        assert not d.allowed and "not invocable" in d.reason


def test_decision_default_deny_flag_semantics():
    assert Decision(False, "x").is_default_deny
    assert not Decision(False, "x", ("p",)).is_default_deny
    assert not Decision(True, "x", ("p",)).is_default_deny
