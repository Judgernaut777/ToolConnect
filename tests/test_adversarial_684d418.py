"""Independent adversarial validation of the Finding A/B fixes (commit 684d418).

Authored by the verification agent. These are additive regression tests; they do not
modify production code. Each mirrors an adversarial case from the verification handoff.
"""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from toolconnect.catalog import AmbiguousToolName, AssertionStatus, Catalog
from toolconnect.descriptor import (
    AssertedDescriptor, ClaimedMetadata, DataClass, Effect, TrustedSource, TrustTier,
)
from toolconnect.flow import analyze_toolset


def _read(by: str = "op") -> AssertedDescriptor:
    return AssertedDescriptor(effect=Effect.READ, asserted_by=by)


def _claim(desc: str, ro: bool = True) -> ClaimedMetadata:
    return ClaimedMetadata(description=desc, read_only_hint=ro)


# ============================================================ Finding A adversarial

class TestShadowingResistance:
    def _both(self, order=("verified", "evil")) -> Catalog:
        c = Catalog()
        tiers = {"verified": TrustTier.VERIFIED, "evil": TrustTier.UNTRUSTED}
        for sid in order:
            c.register_source(TrustedSource(sid, tiers[sid]), declares={"search"})
            c.ingest_claimed(sid, "search", _claim(f"{sid} search"))
        return c

    def test_same_name_two_sources_coexist(self):
        c = self._both()
        assert len(c.tools) == 2
        assert c.get("verified", "search") is not None
        assert c.get("evil", "search") is not None

    def test_registration_order_reversed_is_symmetric(self):
        c = self._both(order=("evil", "verified"))
        assert len(c.tools) == 2
        # Whichever registered last did NOT overwrite the other.
        assert c.get("verified", "search").claimed.description == "verified search"
        assert c.get("evil", "search").claimed.description == "evil search"

    def test_untrusted_cannot_overwrite_verified(self):
        c = self._both()
        c.assert_descriptor("verified", "search", _read())
        # Evil re-announces aggressively under the same bare name.
        for i in range(5):
            c.ingest_claimed("evil", "search", _claim(f"evil rev {i}"))
        assert c.invocable("verified", "search")
        assert c.get("verified", "search").claimed.description == "verified search"

    def test_untrusted_cannot_inherit_assertion_state(self):
        c = self._both()
        c.assert_descriptor("verified", "search", _read())
        assert c.assertion_status("evil", "search") is AssertionStatus.NEVER
        assert not c.get("evil", "search").is_asserted
        assert not c.invocable("evil", "search")

    def test_source_a_assertion_never_touches_source_b(self):
        c = self._both()
        c.assert_descriptor("verified", "search", _read())
        # B's record must not exist; A's must be keyed to A only.
        assert ("evil", "search") not in c._assertions
        assert ("verified", "search") in c._assertions


class TestBareNameResolution:
    def test_ambiguous_bare_name_fails_explicitly(self):
        c = Catalog()
        for sid in ("a", "b"):
            c.register_source(TrustedSource(sid, TrustTier.KNOWN))
            c.ingest_claimed(sid, "dup", ClaimedMetadata())
        with pytest.raises(AmbiguousToolName):
            c.resolve("dup")

    def test_missing_bare_name_fails_explicitly(self):
        c = Catalog()
        with pytest.raises(KeyError):
            c.resolve("ghost")

    def test_ambiguity_introduced_after_unambiguous_lookup(self):
        c = Catalog()
        c.register_source(TrustedSource("a", TrustTier.KNOWN))
        c.ingest_claimed("a", "tool", ClaimedMetadata())
        assert c.resolve("tool") == ("a", "tool")  # unambiguous now
        c.register_source(TrustedSource("b", TrustTier.KNOWN))
        c.ingest_claimed("b", "tool", ClaimedMetadata())
        with pytest.raises(AmbiguousToolName):  # became ambiguous
            c.resolve("tool")

    def test_select_rejects_a_shadowed_name(self):
        c = Catalog()
        for sid in ("a", "b"):
            c.register_source(TrustedSource(sid, TrustTier.KNOWN))
            c.ingest_claimed(sid, "dup", ClaimedMetadata())
        with pytest.raises(AmbiguousToolName):
            c.select(["dup"])


class TestReplacementSemantics:
    def test_same_source_same_name_is_intentional_replacement(self):
        # Last-write-wins WITHIN a source is correct (one source, one tool of a name);
        # what was fixed is cross-source collision. Confirm no cross-source last-write.
        c = Catalog()
        c.register_source(TrustedSource("s", TrustTier.KNOWN))
        c.ingest_claimed("s", "t", _claim("first"))
        c.ingest_claimed("s", "t", _claim("second"))
        assert len(c.tools) == 1
        assert c.get("s", "t").claimed.description == "second"

    def test_no_delete_api_exists(self):
        # Deletion is not a supported operation; document the surface so a future
        # delete does not silently reintroduce shadowing via id reuse.
        assert not hasattr(Catalog, "delete")
        assert not hasattr(Catalog, "remove")
        assert not hasattr(Catalog, "deregister")


class TestMalformedIdentifiers:
    """Current validation rules: sources must be registered; names are opaque strings.
    These characterize actual behavior (there is no name/source syntax validation yet)."""

    def test_unregistered_source_is_rejected(self):
        c = Catalog()
        with pytest.raises(KeyError):
            c.ingest_claimed("", "t", ClaimedMetadata())
        with pytest.raises(KeyError):
            c.ingest_claimed("nope", "t", ClaimedMetadata())

    def test_empty_name_is_accepted_as_opaque_and_stays_namespaced(self):
        c = Catalog()
        c.register_source(TrustedSource("s", TrustTier.KNOWN))
        c.ingest_claimed("s", "", ClaimedMetadata())
        assert ("s", "") in c.tools
        assert not c.invocable("s", "")  # unasserted -> fail closed

    def test_empty_source_id_is_a_valid_namespace_if_registered(self):
        c = Catalog()
        c.register_source(TrustedSource("", TrustTier.KNOWN))
        c.ingest_claimed("", "t", ClaimedMetadata())
        c.register_source(TrustedSource("s", TrustTier.KNOWN))
        c.ingest_claimed("s", "t", ClaimedMetadata())
        # Empty-string source is still a distinct namespace: no collision with "s".
        assert len(c.tools) == 2
        with pytest.raises(AmbiguousToolName):
            c.resolve("t")


# ============================================================ Finding B adversarial

class TestAssertionStateMachine:
    def _asserted(self, claim: ClaimedMetadata) -> Catalog:
        c = Catalog()
        c.register_source(TrustedSource("s", TrustTier.KNOWN), declares={"t"})
        c.ingest_claimed("s", "t", claim)
        c.assert_descriptor("s", "t", _read())
        return c

    def test_never_asserted(self):
        c = Catalog()
        c.register_source(TrustedSource("s", TrustTier.KNOWN))
        c.ingest_claimed("s", "t", ClaimedMetadata())
        assert c.assertion_status("s", "t") is AssertionStatus.NEVER
        assert not c.invocable("s", "t")

    def test_reingested_unchanged_stays_asserted(self):
        c = self._asserted(_claim("v1"))
        c.ingest_claimed("s", "t", _claim("v1"))
        assert c.assertion_status("s", "t") is AssertionStatus.ASSERTED
        assert c.invocable("s", "t")

    def test_reingested_changed_drops_and_preserves_evidence(self):
        c = self._asserted(_claim("v1"))
        c.ingest_claimed("s", "t", _claim("v2"))
        assert c.assertion_status("s", "t") is AssertionStatus.CHANGED
        assert not c.invocable("s", "t")
        assert ("s", "t") in c._assertions  # prior evidence retained
        r = c.drift("s", {"t"})
        assert r.redefined_after_assertion == ("t",)
        assert r.unasserted == ()  # NOT collapsed into never-asserted

    def test_reasserted_binds_to_new_fingerprint(self):
        c = self._asserted(_claim("v1"))
        c.ingest_claimed("s", "t", _claim("v2"))
        c.assert_descriptor("s", "t", _read())  # vouch for v2
        assert c.invocable("s", "t")

    def test_rollback_to_older_asserted_fingerprint_does_not_restore(self):
        """Re-assert v2, then the server rolls back to v1 (an OLDER claim that was
        once asserted). v1 is no longer the vouched fingerprint -> not invocable."""
        c = self._asserted(_claim("v1"))       # vouched v1
        c.ingest_claimed("s", "t", _claim("v2"))
        c.assert_descriptor("s", "t", _read())  # now vouched v2
        assert c.invocable("s", "t")
        c.ingest_claimed("s", "t", _claim("v1"))  # rollback to old v1
        assert not c.invocable("s", "t")
        assert c.assertion_status("s", "t") is AssertionStatus.CHANGED

    def test_alternating_reingestion_tracks_only_the_vouched_fingerprint(self):
        c = self._asserted(_claim("A"))  # vouched fingerprint = A
        for _ in range(4):
            c.ingest_claimed("s", "t", _claim("B"))
            assert not c.invocable("s", "t"), "B was never vouched"
            c.ingest_claimed("s", "t", _claim("A"))
            assert c.invocable("s", "t"), "A is the vouched claim; assertion carries over"

    def test_assertion_records_cannot_cross_sources(self):
        c = Catalog()
        for sid in ("a", "b"):
            c.register_source(TrustedSource(sid, TrustTier.KNOWN))
            c.ingest_claimed(sid, "t", _claim("same"))
        c.assert_descriptor("a", "t", _read())
        # Same bare name, same claim, but B was never asserted -> B is not invocable.
        assert c.invocable("a", "t")
        assert not c.invocable("b", "t")
        assert c.assertion_status("b", "t") is AssertionStatus.NEVER


# ============================================================ property: no cross-source leak

@given(
    fps=st.lists(st.sampled_from(["p", "q", "r"]), min_size=1, max_size=8),
)
@settings(max_examples=100)
def test_property_invocable_iff_current_claim_is_the_vouched_one(fps):
    """After vouching for the first fingerprint, invocability holds exactly when the
    current re-ingested claim equals the vouched claim — for any sequence."""
    c = Catalog()
    c.register_source(TrustedSource("s", TrustTier.KNOWN))
    vouched = fps[0]
    c.ingest_claimed("s", "t", _claim(vouched))
    c.assert_descriptor("s", "t", _read())
    for fp in fps:
        c.ingest_claimed("s", "t", _claim(fp))
        assert c.invocable("s", "t") == (fp == vouched)


# ============================================================ flow-layer identity probe

class TestFlowLayerNameIdentity:
    """The catalog is namespaced, but flow analysis labels readers/sinks by bare
    ref.name. This probe checks whether a cross-source name collision inside ONE
    analyzed toolset corrupts the security-relevant verdict, or is merely a cosmetic
    label ambiguity. Reported in the verification report either way."""

    def test_cross_source_duplicate_name_does_not_hide_exfiltration(self):
        c = Catalog()
        c.register_source(TrustedSource("reader_src", TrustTier.KNOWN))
        c.register_source(TrustedSource("sink_src", TrustTier.KNOWN))
        # Two DISTINCT tools that happen to share the bare name "x".
        c.ingest_claimed("reader_src", "x", ClaimedMetadata())
        c.ingest_claimed("sink_src", "x", ClaimedMetadata())
        c.assert_descriptor("reader_src", "x", AssertedDescriptor(
            effect=Effect.READ, reads=frozenset({DataClass.SECRET}), asserted_by="op"))
        c.assert_descriptor("sink_src", "x", AssertedDescriptor(
            effect=Effect.EXTERNAL, writes=frozenset({DataClass.EXTERNAL}), asserted_by="op"))
        report = analyze_toolset(c.toolset([("reader_src", "x"), ("sink_src", "x")]))
        # The security verdict must remain correct: a secret->external path EXISTS.
        assert report.has_exfiltration_path, "flow verdict must not be hidden by name collision"
