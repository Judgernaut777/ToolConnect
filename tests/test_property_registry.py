"""Property-based tests for registry and drift invariants.

Randomized sequences of registration, ingestion, and assertion must never violate
the core rules: a server's claim never authorizes itself, drift is exact set
arithmetic, and a tool cannot exceed its source's trust ceiling.
"""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from toolconnect.catalog import Catalog
from toolconnect.descriptor import (
    AssertedDescriptor, ClaimedMetadata, Effect, TrustedSource, TrustTier,
)

names = st.text(alphabet="abcdefghij_", min_size=1, max_size=6)
name_sets = st.sets(names, max_size=8)
tiers = st.sampled_from(list(TrustTier))


def _catalog(tier: TrustTier, declares: set[str]) -> Catalog:
    c = Catalog()
    c.register_source(TrustedSource("s", tier), declares=declares)
    return c


class TestIngestNeverAuthorizes:
    @given(tier=tiers, name=names, ro=st.booleans())
    def test_ingest_alone_never_makes_invocable(self, tier, name, ro):
        c = _catalog(tier, {name})
        c.ingest_claimed("s", name, ClaimedMetadata(read_only_hint=ro))
        assert not c.invocable("s", name), "a claim must never authorize itself"

    @given(tier=tiers, name=names)
    def test_invocable_iff_asserted_and_tier_permits(self, tier, name):
        c = _catalog(tier, {name})
        c.ingest_claimed("s", name, ClaimedMetadata())
        c.assert_descriptor("s", name, AssertedDescriptor(effect=Effect.READ, asserted_by="op"))
        assert c.invocable("s", name) == tier.invocable

    @given(name=names, by=st.text(max_size=4))
    def test_assertion_requires_a_named_operator(self, name, by):
        c = _catalog(TrustTier.KNOWN, {name})
        c.ingest_claimed("s", name, ClaimedMetadata())
        desc = AssertedDescriptor(effect=Effect.READ, asserted_by=by)
        if by:
            c.assert_descriptor("s", name, desc)
            assert c.invocable("s", name)
        else:
            with pytest.raises(ValueError):
                c.assert_descriptor("s", name, desc)


class TestDriftIsExactSetArithmetic:
    @given(declared=name_sets, discovered=name_sets)
    def test_missing_and_undeclared_are_exact_set_differences(self, declared, discovered):
        c = _catalog(TrustTier.KNOWN, declared)
        r = c.drift("s", discovered)
        assert set(r.advertised_missing) == declared - discovered
        assert set(r.undeclared_present) == discovered - declared

    @given(declared=name_sets, discovered=name_sets)
    def test_clean_iff_all_five_categories_empty(self, declared, discovered):
        c = _catalog(TrustTier.KNOWN, declared)
        r = c.drift("s", discovered)
        expect_clean = (
            not (declared - discovered)
            and not (discovered - declared)
            and not discovered  # nothing ingested, so everything discovered is unasserted
        )
        assert r.clean == expect_clean

    @given(names=name_sets)
    def test_fully_asserted_matching_catalog_has_no_drift(self, names):
        c = _catalog(TrustTier.KNOWN, names)
        for n in names:
            c.ingest_claimed("s", n, ClaimedMetadata(read_only_hint=True))
            c.assert_descriptor("s", n, AssertedDescriptor(effect=Effect.READ, asserted_by="op"))
        r = c.drift("s", names)
        assert r.clean, r.summary()

    @given(declared=name_sets, discovered=name_sets)
    def test_report_lists_are_sorted_and_unique(self, declared, discovered):
        r = _catalog(TrustTier.KNOWN, declared).drift("s", discovered)
        for lst in (r.advertised_missing, r.undeclared_present, r.unasserted):
            assert list(lst) == sorted(set(lst))


class TestToolset:
    @given(registered=name_sets, requested=name_sets)
    def test_toolset_returns_only_registered_ids_sorted(self, registered, requested):
        c = _catalog(TrustTier.KNOWN, set())
        for n in registered:
            c.ingest_claimed("s", n, ClaimedMetadata())
        requested_ids = {("s", n) for n in requested}
        got = c.toolset(requested_ids)
        got_ids = [tv.id for tv in got]
        assert got_ids == sorted(("s", n) for n in registered & requested)
        assert len(got_ids) == len(set(got_ids))

    @given(names=name_sets)
    def test_resolve_is_unambiguous_for_single_source(self, names):
        c = _catalog(TrustTier.KNOWN, set())
        for n in names:
            c.ingest_claimed("s", n, ClaimedMetadata())
        for n in names:
            assert c.resolve(n) == ("s", n)  # one source -> never ambiguous
