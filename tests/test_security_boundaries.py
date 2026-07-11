"""Security boundary tests.

These encode the trust model as executable assertions: a server's self-description
never authorizes it, trust cannot be self-elevated, delegation attenuates, policy
fails closed, and no input crashes the registry into an undefined state.
"""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from toolconnect.catalog import Catalog
from toolconnect.descriptor import (
    AssertedDescriptor, ClaimedMetadata, DataClass, Effect, ToolRef, ToolVersion,
    TrustedSource, TrustTier,
)
from toolconnect.policy import Broker, CedarPolicyEngine, Principal

from conftest import BASIC_CEDAR, make_tool


def _cat(tier: TrustTier) -> Catalog:
    c = Catalog()
    c.register_source(TrustedSource("src", tier), declares={"t"})
    c.ingest_claimed("src", "t", ClaimedMetadata(read_only_hint=True))
    return c


class TestUntrustedProvidersRejected:
    @pytest.mark.parametrize("tier", [TrustTier.UNTRUSTED, TrustTier.QUARANTINED])
    def test_asserted_tool_from_untrusted_source_is_not_invocable(self, tier):
        c = _cat(tier)
        c.assert_descriptor("t", AssertedDescriptor(effect=Effect.READ, asserted_by="op"))
        assert not c.invocable("t"), "trust ceiling must override a valid assertion"

    def test_broker_denies_untrusted_before_consulting_policy(self):
        c = _cat(TrustTier.UNTRUSTED)
        c.assert_descriptor("t", AssertedDescriptor(effect=Effect.READ, asserted_by="op"))
        d = Broker(c, CedarPolicyEngine(BASIC_CEDAR), []).authorize(Principal("a"), "t")
        assert not d.allowed and "not invocable" in d.reason


class TestMetadataCannotEscapeValidation:
    @given(
        ro=st.booleans(), idem=st.booleans(), destr=st.booleans(), ow=st.booleans(),
    )
    def test_no_self_reported_claim_makes_a_tool_invocable(self, ro, idem, destr, ow):
        """However a tool describes itself, it stays uninvocable until asserted."""
        c = Catalog()
        c.register_source(TrustedSource("src", TrustTier.VERIFIED))
        c.ingest_claimed("src", "t", ClaimedMetadata(
            read_only_hint=ro, idempotent_hint=idem,
            destructive_hint=destr, open_world_hint=ow,
        ))
        assert not c.invocable("t")

    def test_a_lying_tool_is_caught_by_the_conflict_check(self):
        c = Catalog()
        c.register_source(TrustedSource("src", TrustTier.VERIFIED), declares={"t"})
        c.ingest_claimed("src", "t", ClaimedMetadata(read_only_hint=True))
        # operator's ground truth: it is actually destructive
        c.assert_descriptor("t", AssertedDescriptor(effect=Effect.DESTRUCTIVE, asserted_by="op"))
        assert c.tools["t"].claim_conflicts()


class TestPermissionBoundaries:
    def test_delegation_cannot_escalate_privilege(self):
        """A local subagent acting for a rented manager is clamped to rented."""
        chain = Principal("sub", privacy_tier="local",
                          on_behalf_of=Principal("mgr", privacy_tier="rented"))
        assert chain.effective_tier() == "rented"

    @given(
        tiers=st.lists(st.sampled_from(["local", "trusted-cloud", "rented"]),
                       min_size=1, max_size=5),
    )
    def test_effective_tier_is_the_least_privileged_in_the_chain(self, tiers):
        order = {"local": 0, "trusted-cloud": 1, "rented": 2}
        p = None
        for t in tiers:
            p = Principal("n", privacy_tier=t, on_behalf_of=p)
        assert order[p.effective_tier()] == max(order[t] for t in tiers)


class TestFailClosed:
    @pytest.mark.parametrize("scenario", ["unknown_tool", "unasserted", "untrusted", "unregistered_source"])
    def test_every_unhappy_path_denies(self, scenario):
        eng = CedarPolicyEngine(BASIC_CEDAR)
        if scenario == "unknown_tool":
            c = Catalog()
            d = Broker(c, eng, []).authorize(Principal("a"), "nope")
        elif scenario == "unasserted":
            c = _cat(TrustTier.KNOWN)
            d = Broker(c, eng, []).authorize(Principal("a"), "t")
        elif scenario == "untrusted":
            c = _cat(TrustTier.UNTRUSTED)
            c.assert_descriptor("t", AssertedDescriptor(effect=Effect.READ, asserted_by="op"))
            d = Broker(c, eng, []).authorize(Principal("a"), "t")
        else:  # unregistered_source -> ingest raises, nothing becomes invocable
            with pytest.raises(KeyError):
                Catalog().ingest_claimed("ghost", "t", ClaimedMetadata())
            return
        assert not d.allowed


class TestRegistryCannotBeCrashed:
    @given(
        name=st.text(max_size=30),
        discovered=st.sets(st.text(max_size=10), max_size=6),
    )
    def test_drift_over_arbitrary_names_never_raises(self, name, discovered):
        c = Catalog()
        c.register_source(TrustedSource("s", TrustTier.KNOWN), declares={name})
        r = c.drift("s", discovered)
        assert isinstance(r.summary(), str)

    def test_invalid_signature_rejection_is_unbuilt(self):
        # There is no signing/verification mechanism in the prototype (TrustTier is
        # operator-assigned, not cryptographically attested). This test documents the
        # gap so it is visible; it must become a real test when signatures land.
        # See docs/VERIFICATION.md, Security section.
        import toolconnect
        assert not any("sign" in n.lower() for n in dir(toolconnect))
