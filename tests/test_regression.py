"""Regression tests: one cluster per defect the verification suite found.

Findings A and B were fixed in the namespaced-identity + assertion-evidence change.
These tests now assert the *fixed* contract and guard against regression. The history
is kept in the docstrings so a future reader knows what these defend.

Full write-up: docs/VERIFICATION.md (Findings) and docs/ARCHITECTURE.md §2.4.
"""

from __future__ import annotations

import dataclasses

import pytest

from toolconnect.catalog import AmbiguousToolName, AssertionStatus, Catalog
from toolconnect.descriptor import (
    AssertedDescriptor, ClaimedMetadata, Effect, TrustedSource, TrustTier,
)


def _read(by: str = "op") -> AssertedDescriptor:
    return AssertedDescriptor(effect=Effect.READ, asserted_by=by)


# ------------------------------------------------------------------- Finding A
# WAS: Catalog.tools keyed by bare name, so two sources offering a same-named tool
# collided and the second silently overwrote the first — an untrusted source could
# shadow a verified one. FIXED: identity is (source_id, name); the two coexist.

class TestFindingA_NamespacedIdentity:
    def _two_sources(self) -> Catalog:
        c = Catalog()
        c.register_source(TrustedSource("trusted", TrustTier.VERIFIED), declares={"search"})
        c.register_source(TrustedSource("evil", TrustTier.UNTRUSTED), declares={"search"})
        c.ingest_claimed("trusted", "search", ClaimedMetadata(read_only_hint=True))
        c.ingest_claimed("evil", "search", ClaimedMetadata(read_only_hint=True))
        return c

    def test_two_sources_same_name_are_distinct_tools(self):
        # This is the assertion that was a strict xfail at checkpoint 7be628f.
        # It now passes: the fix is real, and the marker is gone.
        c = self._two_sources()
        assert len(c.tools) == 2
        assert {tid for tid in c.tools} == {("trusted", "search"), ("evil", "search")}

    def test_neither_source_overwrites_the_other(self):
        c = self._two_sources()
        assert c.get("trusted", "search").source_id == "trusted"
        assert c.get("evil", "search").source_id == "evil"

    def test_untrusted_cannot_inherit_verified_assertion(self):
        c = self._two_sources()
        c.assert_descriptor("trusted", "search", _read())
        assert c.invocable("trusted", "search")
        assert not c.get("evil", "search").is_asserted
        assert not c.invocable("evil", "search")

    def test_bare_name_lookup_will_not_silently_pick(self):
        c = self._two_sources()
        with pytest.raises(AmbiguousToolName):
            c.resolve("search")

    def test_bare_name_resolves_when_globally_unique(self):
        c = Catalog()
        c.register_source(TrustedSource("solo", TrustTier.KNOWN))
        c.ingest_claimed("solo", "only", ClaimedMetadata())
        assert c.resolve("only") == ("solo", "only")


# ------------------------------------------------------------------- Finding B
# WAS: re-ingesting an asserted tool dropped the assertion but retained the bare
# fingerprint, and drift reported it as plain "unasserted" — collapsing "never
# asserted" with "asserted then changed." FIXED: assertion evidence (descriptor +
# vouched fingerprint) is durable; the four states are distinct.

class TestFindingB_ReingestionAfterAssertion:
    def _asserted(self, claim: ClaimedMetadata) -> Catalog:
        c = Catalog()
        c.register_source(TrustedSource("s", TrustTier.KNOWN), declares={"t"})
        c.ingest_claimed("s", "t", claim)
        c.assert_descriptor("s", "t", _read())
        return c

    def test_never_asserted_is_status_never(self):
        c = Catalog()
        c.register_source(TrustedSource("s", TrustTier.KNOWN), declares={"t"})
        c.ingest_claimed("s", "t", ClaimedMetadata())
        assert c.assertion_status("s", "t") is AssertionStatus.NEVER
        assert c.drift("s", {"t"}).unasserted == ("t",)
        assert c.drift("s", {"t"}).redefined_after_assertion == ()

    def test_reingest_unchanged_preserves_the_assertion(self):
        claim = ClaimedMetadata(description="v1", read_only_hint=True)
        c = self._asserted(claim)
        assert c.invocable("s", "t")
        # Identical re-announcement: the assertion stands, the tool stays invocable.
        c.ingest_claimed("s", "t", ClaimedMetadata(description="v1", read_only_hint=True))
        assert c.assertion_status("s", "t") is AssertionStatus.ASSERTED
        assert c.invocable("s", "t")
        assert c.drift("s", {"t"}).clean

    def test_reingest_changed_drops_invocability(self):
        c = self._asserted(ClaimedMetadata(description="v1", read_only_hint=True))
        c.ingest_claimed("s", "t", ClaimedMetadata(description="MALICIOUS", read_only_hint=True))
        assert not c.invocable("s", "t"), "a changed vouched tool must not stay invocable"

    def test_changed_reingest_is_distinct_from_never_asserted(self):
        c = self._asserted(ClaimedMetadata(description="v1", read_only_hint=True))
        c.ingest_claimed("s", "t", ClaimedMetadata(description="changed", read_only_hint=True))
        status = c.assertion_status("s", "t")
        assert status is AssertionStatus.CHANGED
        r = c.drift("s", {"t"})
        # Provenance preserved: reported as a vouched-tool change, NOT as never-asserted.
        assert r.redefined_after_assertion == ("t",)
        assert r.unasserted == ()

    def test_prior_assertion_provenance_survives_reingest(self):
        c = self._asserted(ClaimedMetadata(description="v1", read_only_hint=True))
        c.ingest_claimed("s", "t", ClaimedMetadata(description="changed"))
        # The evidence that an operator once vouched for this tool is retained.
        assert ("s", "t") in c._assertions
        assert c._assertions[("s", "t")].asserted_by == "op"

    def test_reassertion_restores_invocability_for_the_new_fingerprint(self):
        c = self._asserted(ClaimedMetadata(description="v1", read_only_hint=True))
        c.ingest_claimed("s", "t", ClaimedMetadata(description="v2", read_only_hint=True))
        assert not c.invocable("s", "t")
        # Operator reviews the new claim and re-vouches.
        c.assert_descriptor("s", "t", _read())
        assert c.invocable("s", "t")
        assert c.assertion_status("s", "t") is AssertionStatus.ASSERTED
        assert c.drift("s", {"t"}).clean

    def test_reassertion_binds_only_to_the_asserted_fingerprint(self):
        c = self._asserted(ClaimedMetadata(description="v1", read_only_hint=True))
        c.ingest_claimed("s", "t", ClaimedMetadata(description="v2", read_only_hint=True))
        c.assert_descriptor("s", "t", _read())  # vouch for v2
        assert c.invocable("s", "t")
        # Server flips back to v1: no longer the vouched fingerprint -> not invocable.
        c.ingest_claimed("s", "t", ClaimedMetadata(description="v1", read_only_hint=True))
        assert not c.invocable("s", "t")
        assert c.assertion_status("s", "t") is AssertionStatus.CHANGED
