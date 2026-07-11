"""Property-based tests for metadata normalization and claim-conflict detection.

The MCP-hint -> Effect crosswalk must be total, deterministic, and never raise, for
any combination of the four boolean-or-None hints. Claim-conflict detection must be
total for any (claimed, asserted) pair.
"""

from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from toolconnect.descriptor import (
    AssertedDescriptor, ClaimedMetadata, Effect, ToolRef, ToolVersion,
)

tri = st.sampled_from([True, False, None])
claimed_strat = st.builds(
    ClaimedMetadata,
    description=st.text(max_size=20),
    read_only_hint=tri, destructive_hint=tri, idempotent_hint=tri, open_world_hint=tri,
)
asserted_strat = st.builds(
    lambda e, idem: AssertedDescriptor(effect=e, idempotent=idem, asserted_by="op"),
    st.sampled_from(list(Effect)), st.booleans(),
)


class TestImpliedEffect:
    @given(claimed_strat)
    def test_total_and_deterministic(self, c):
        a, b = c.implied_effect(), c.implied_effect()
        assert a == b
        assert a is None or isinstance(a, Effect)

    @given(claimed_strat)
    def test_read_only_hint_dominates(self, c):
        if c.read_only_hint:
            assert c.implied_effect() is Effect.READ

    @given(claimed_strat)
    def test_all_none_hints_imply_nothing(self, c):
        if c.read_only_hint is None and c.destructive_hint is None and c.open_world_hint is None:
            assert c.implied_effect() is None

    def test_destructive_is_the_conservative_default(self):
        # MCP: destructiveHint defaults TRUE when not read-only. Silence is not safety.
        assert ClaimedMetadata(read_only_hint=False).implied_effect() is Effect.DESTRUCTIVE


class TestClaimConflicts:
    @given(claimed_strat, asserted_strat)
    def test_conflict_detection_is_total(self, claimed, asserted):
        """Must return a list for any pair, never raise."""
        tv = ToolVersion(ToolRef("t"), "s", claimed, asserted)
        assert isinstance(tv.claim_conflicts(), list)

    @given(claimed_strat)
    def test_unasserted_tool_has_no_conflicts(self, claimed):
        tv = ToolVersion(ToolRef("t"), "s", claimed, asserted=None)
        assert tv.claim_conflicts() == []

    def test_read_only_claim_versus_destructive_assertion_conflicts(self):
        tv = ToolVersion(
            ToolRef("t"), "s",
            ClaimedMetadata(read_only_hint=True),
            AssertedDescriptor(effect=Effect.DESTRUCTIVE, asserted_by="op"),
        )
        assert any("readOnlyHint" in c for c in tv.claim_conflicts())

    @given(st.sampled_from(list(Effect)))
    def test_agreement_yields_no_conflict(self, effect):
        """When the claim matches the assertion, there is nothing to flag."""
        ro = effect is Effect.READ
        ow = effect is Effect.EXTERNAL
        tv = ToolVersion(
            ToolRef("t"), "s",
            ClaimedMetadata(
                read_only_hint=ro,
                destructive_hint=(effect is Effect.DESTRUCTIVE),
                open_world_hint=ow,
            ),
            AssertedDescriptor(effect=effect, asserted_by="op"),
        )
        # implied_effect must equal the asserted effect for these hint settings,
        # which is exactly the no-conflict case for the effect axis.
        assert tv.claimed.implied_effect() is effect
        assert not any("effect" in c for c in tv.claim_conflicts())
