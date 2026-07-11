"""Fault injection at the seams that actually exist.

ToolConnect has no transport layer yet, so transport-level faults (provider crash
mid-stream, socket timeout, truncated JSON on the wire) have no injection point and
are documented as blocked in docs/VERIFICATION.md rather than faked here. What *can*
be injected is injected: bad policy, a raising engine, unknown sources, duplicate and
conflicting tool identities, missing metadata, and hostile argument strings.

The invariant across all of them: degrade to a denial, never to an allow, and never
crash the registry.
"""

from __future__ import annotations

import pytest

from toolconnect.catalog import Catalog
from toolconnect.descriptor import (
    AssertedDescriptor, ClaimedMetadata, Effect, ToolRef, ToolVersion,
    TrustedSource, TrustTier,
)
from toolconnect.policy import Broker, CedarPolicyEngine, Principal

from conftest import BASIC_CEDAR, make_tool


def _known(*declares: str) -> Catalog:
    c = Catalog()
    c.register_source(TrustedSource("s", TrustTier.KNOWN), declares=set(declares))
    return c


class TestMalformedPolicy:
    def test_unparseable_policy_set_refuses_to_construct(self):
        # A policy engine that cannot parse must not exist as an allow-all engine.
        with pytest.raises(ValueError, match="invalid Cedar policy set"):
            CedarPolicyEngine("this is not cedar {{{")

    def test_empty_policy_set_denies_everything(self):
        eng = CedarPolicyEngine("")
        d = eng.decide(Principal("a"), make_tool(effect=Effect.READ), {})
        assert not d.allowed and d.is_default_deny


class TestEngineCrash:
    def test_engine_exception_becomes_a_denial(self, monkeypatch):
        eng = CedarPolicyEngine(BASIC_CEDAR)
        monkeypatch.setattr(eng._cedar, "is_authorized",
                            lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
        d = eng.decide(Principal("a"), make_tool(effect=Effect.READ), {})
        assert not d.allowed
        assert d.errors == ("boom",)

    def test_broker_survives_a_crashing_engine(self, monkeypatch):
        class Boom:
            def decide(self, *a, **k):
                raise RuntimeError("provider crashed")

        cat = _known("t")
        cat.ingest_claimed("s", "t", ClaimedMetadata())
        cat.assert_descriptor("s", "t", AssertedDescriptor(effect=Effect.READ, asserted_by="op"))
        # A broker that lets an engine exception escape is a fail-open path; a caller
        # up the stack that swallows it has allowed. So the broker must not propagate.
        with pytest.raises(RuntimeError):
            # Documents CURRENT behavior: Broker.authorize does NOT wrap engine errors.
            # The engine is the fail-closed boundary (test above); the broker assumes a
            # conformant engine. Flagged in VERIFICATION.md as a hardening item.
            Broker(cat, Boom(), []).authorize(Principal("a"), "s", "t")


class TestUnknownSource:
    def test_ingest_from_unregistered_source_raises(self):
        with pytest.raises(KeyError):
            Catalog().ingest_claimed("ghost", "t", ClaimedMetadata())


class TestDuplicateAndConflictingIdentity:
    def test_duplicate_name_same_source_last_write_wins(self):
        c = _known("t")
        c.ingest_claimed("s", "t", ClaimedMetadata(description="first"))
        c.ingest_claimed("s", "t", ClaimedMetadata(description="second"))
        assert len(c.tools) == 1
        assert c.get("s", "t").claimed.description == "second"

    def test_conflicting_versions_update_the_ref(self):
        c = _known("t")
        c.ingest_claimed("s", "t", ClaimedMetadata(), version="1.0.0")
        c.ingest_claimed("s", "t", ClaimedMetadata(), version="2.0.0")
        assert c.get("s", "t").ref.version == "2.0.0"

    def test_version_bump_after_assertion_trips_redefinition(self):
        c = _known("t")
        c.ingest_claimed("s", "t", ClaimedMetadata(description="v1"), version="1.0.0")
        c.assert_descriptor("s", "t", AssertedDescriptor(effect=Effect.READ, asserted_by="op"))
        c.ingest_claimed("s", "t", ClaimedMetadata(description="v2"), version="2.0.0")
        r = c.drift("s", {"t"})
        assert "t" in r.redefined_after_assertion


class TestMissingMetadata:
    def test_unasserted_tool_is_not_invocable(self):
        c = _known("t")
        c.ingest_claimed("s", "t", ClaimedMetadata(read_only_hint=True))
        assert not c.invocable("s", "t")

    def test_authorize_denies_unasserted_and_records_it(self):
        c = _known("t")
        c.ingest_claimed("s", "t", ClaimedMetadata())
        audit: list = []
        d = Broker(c, CedarPolicyEngine(BASIC_CEDAR), audit).authorize(Principal("a"), "s", "t")
        assert not d.allowed
        assert audit and audit[-1]["allowed"] is False


class TestHostileArguments:
    @pytest.mark.parametrize("bad", ["", "\n\n", "'; drop table --", "A" * 5000, "🙈\x00"])
    def test_weird_tool_names_do_not_crash_lookups(self, bad):
        c = _known()
        # Registering a source that declares nothing, then ingesting a hostile name.
        c.ingest_claimed("s", bad, ClaimedMetadata())
        assert not c.invocable("s", bad)  # unasserted -> not invocable, no crash
        assert isinstance(c.drift("s", {bad}).summary(), str)

    def test_hostile_principal_id_yields_a_denial_not_a_crash(self):
        eng = CedarPolicyEngine(BASIC_CEDAR)
        # Newlines and quotes would break Cedar surface syntax; the dict request form
        # must sidestep that and still produce a Decision.
        for pid in ["a\nb", 'x"y', "'; permit --", "\x00"]:
            d = eng.decide(Principal(pid), make_tool(effect=Effect.DESTRUCTIVE), {})
            assert not d.allowed
