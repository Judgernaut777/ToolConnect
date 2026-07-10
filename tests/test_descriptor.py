"""Claimed metadata is evidence. Asserted metadata is authority."""

from __future__ import annotations

from toolconnect.descriptor import (
    AssertedDescriptor, ClaimedMetadata, DataClass, Effect, ToolRef, ToolVersion, TrustTier,
)


def _tv(claimed: ClaimedMetadata, asserted: AssertedDescriptor | None = None) -> ToolVersion:
    return ToolVersion(ToolRef("t", "1.0.0"), "src", claimed, asserted)


class TestClaimedHints:
    def test_silence_implies_nothing(self):
        assert ClaimedMetadata().implied_effect() is None

    def test_read_only_hint_wins(self):
        assert ClaimedMetadata(read_only_hint=True).implied_effect() is Effect.READ

    def test_destructive_is_the_default_when_not_read_only(self):
        # MCP: destructiveHint defaults to TRUE. Silence is not safety.
        assert ClaimedMetadata(read_only_hint=False).implied_effect() is Effect.DESTRUCTIVE

    def test_explicit_non_destructive_open_world(self):
        c = ClaimedMetadata(read_only_hint=False, destructive_hint=False, open_world_hint=True)
        assert c.implied_effect() is Effect.EXTERNAL


class TestClaimConflicts:
    def test_no_conflict_when_unasserted(self):
        assert _tv(ClaimedMetadata(read_only_hint=True)).claim_conflicts() == []

    def test_lying_tool_is_caught(self):
        """A tool claiming readOnly that the operator asserts is destructive."""
        tv = _tv(
            ClaimedMetadata(read_only_hint=True),
            AssertedDescriptor(effect=Effect.DESTRUCTIVE, asserted_by="op"),
        )
        conflicts = tv.claim_conflicts()
        assert len(conflicts) == 2
        assert any("readOnlyHint" in c for c in conflicts)

    def test_closed_world_claim_contradicted_by_external_sink(self):
        tv = _tv(
            ClaimedMetadata(read_only_hint=False, destructive_hint=False, open_world_hint=False),
            AssertedDescriptor(
                effect=Effect.EXTERNAL, writes=frozenset({DataClass.EXTERNAL}), asserted_by="op"
            ),
        )
        assert any("openWorldHint" in c for c in tv.claim_conflicts())

    def test_agreement_produces_no_conflict(self):
        tv = _tv(
            ClaimedMetadata(read_only_hint=True),
            AssertedDescriptor(effect=Effect.READ, asserted_by="op"),
        )
        assert tv.claim_conflicts() == []


class TestSensitivity:
    def test_declassification_breaks_sensitivity(self):
        d = AssertedDescriptor(
            effect=Effect.READ, reads=frozenset({DataClass.SECRET}),
            declassifies=True, asserted_by="op",
        )
        assert not d.reads_sensitive

    def test_secret_read_is_sensitive(self):
        d = AssertedDescriptor(
            effect=Effect.READ, reads=frozenset({DataClass.SECRET}), asserted_by="op"
        )
        assert d.reads_sensitive

    def test_external_is_a_sink_class_not_a_sensitive_read(self):
        assert not DataClass.EXTERNAL.is_sensitive
        d = AssertedDescriptor(
            effect=Effect.EXTERNAL, writes=frozenset({DataClass.EXTERNAL}), asserted_by="op"
        )
        assert d.is_external_sink


class TestTrustTier:
    def test_only_verified_and_known_are_invocable(self):
        assert TrustTier.VERIFIED.invocable and TrustTier.KNOWN.invocable
        assert not TrustTier.UNTRUSTED.invocable
        assert not TrustTier.QUARANTINED.invocable


def test_tool_ref_binds_approval_to_a_version():
    assert str(ToolRef("acme/db", "1.2.0")) == "acme/db@1.2.0"
    assert ToolRef("acme/db", "1.2.0") != ToolRef("acme/db", "1.3.0")
