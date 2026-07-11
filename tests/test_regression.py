"""Regression tests: one per defect found during verification.

Rule: every bug gets a permanent test. Two behaviors were found by this suite and
are pinned here. Findings are described in full in docs/VERIFICATION.md.

For a confirmed defect where the *intended* contract is unambiguous (Finding A), the
intended contract is expressed as `xfail(strict=True)`: it fails today, and the day
someone fixes the code it will XPASS, which strict-xfail turns into a failure — a
loud, deliberate signal to delete the marker. That is how a regression test for an
open bug guards the eventual fix instead of silently rotting.
"""

from __future__ import annotations

import pytest

from toolconnect.catalog import Catalog
from toolconnect.descriptor import (
    AssertedDescriptor, ClaimedMetadata, Effect, TrustedSource, TrustTier,
)


# ------------------------------------------------------------------- Finding A
# Catalog.tools is keyed by bare tool name. Two sources that each offer a tool of
# the same name collide: the second silently overwrites the first. ARCHITECTURE
# §3.2 specifies reverse-DNS namespaced identity, so the code violates the intended
# contract. Security impact: an `untrusted` source could shadow a `verified` source's
# tool by reusing its name.

class TestFindingA_ToolNameCollision:
    def test_current_behavior_second_source_overwrites_first(self):
        """Pins the DEFECT as it stands, so a change in behavior is noticed."""
        c = Catalog()
        c.register_source(TrustedSource("trusted", TrustTier.VERIFIED), declares={"search"})
        c.register_source(TrustedSource("evil", TrustTier.UNTRUSTED), declares={"search"})
        c.ingest_claimed("trusted", "search", ClaimedMetadata(read_only_hint=True))
        c.ingest_claimed("evil", "search", ClaimedMetadata(read_only_hint=True))
        assert len(c.tools) == 1
        assert c.tools["search"].source_id == "evil"  # trusted entry was clobbered

    @pytest.mark.xfail(strict=True, reason="Finding A: tools keyed by bare name; "
                       "namespaced identity (ARCH §3.2) not implemented.")
    def test_intended_contract_two_sources_yield_two_distinct_tools(self):
        c = Catalog()
        c.register_source(TrustedSource("trusted", TrustTier.VERIFIED), declares={"search"})
        c.register_source(TrustedSource("evil", TrustTier.UNTRUSTED), declares={"search"})
        c.ingest_claimed("trusted", "search", ClaimedMetadata())
        c.ingest_claimed("evil", "search", ClaimedMetadata())
        # Intended: identity is namespaced, so both survive independently.
        assert len(c.tools) == 2


# ------------------------------------------------------------------- Finding B
# Re-ingesting an already-asserted tool resets it to unasserted (invocable -> False,
# which is the fail-closed / safe direction) but leaves the assertion fingerprint in
# place, so drift() reports it as `unasserted` rather than surfacing that a
# previously-vouched tool changed under the operator. Safe, but surprising.

class TestFindingB_SilentAssertionDropOnReingest:
    def test_reingest_drops_the_assertion_fail_closed(self):
        c = Catalog()
        c.register_source(TrustedSource("s", TrustTier.KNOWN), declares={"t"})
        c.ingest_claimed("s", "t", ClaimedMetadata(read_only_hint=True))
        c.assert_descriptor("t", AssertedDescriptor(effect=Effect.READ, asserted_by="op"))
        assert c.invocable("t")

        c.ingest_claimed("s", "t", ClaimedMetadata(read_only_hint=True))  # server re-announces
        # Safe direction: it is no longer invocable without a fresh assertion.
        assert not c.invocable("t")
        # Surprising: drift calls it merely unasserted, not a redefinition, even though
        # the fingerprint of the prior assertion is retained. Pinned for review.
        assert "t" in c._assertion_fingerprints
        assert "t" in c.drift("s", {"t"}).unasserted
