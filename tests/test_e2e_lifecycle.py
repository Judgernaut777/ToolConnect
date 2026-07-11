"""End-to-end lifecycle over the surface that actually exists.

The handoff's example flow is `discover -> register -> list -> invoke -> shutdown`.
Three of those five steps are not implementable, and one is architecturally forbidden:

* `discover` — no transport/provider layer exists to discover anything.
* `invoke`   — ToolConnect is a decision point, NOT a data path. There is no invoke,
               by design (ARCHITECTURE §1, §8). Encoding an invoke contract here would
               contradict the architecture the handoff also says not to change.
* `shutdown` — no daemon/service lifecycle exists; nothing to shut down.

So this file exercises the real lifecycle end to end —
`register(ingest) -> assert -> list -> authorize -> record` — and separately asserts
the *correct* contract for the forbidden step: that no invocation surface exists.
See docs/VERIFICATION.md for the full mapping.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path[:0] = [str(Path(__file__).resolve().parents[1] / "fixtures")]

from real_catalog import CODING_AGENT_TOOLSET, build_catalog  # noqa: E402

import toolconnect  # noqa: E402
from toolconnect.catalog import Catalog  # noqa: E402
from toolconnect.descriptor import (  # noqa: E402
    AssertedDescriptor, ClaimedMetadata, Effect, TrustedSource, TrustTier,
)
from toolconnect.policy import Broker, CedarPolicyEngine, Principal  # noqa: E402

from conftest import BASIC_CEDAR  # noqa: E402


class TestFullLifecycle:
    def test_register_assert_list_authorize_record(self):
        # 1. register a source and ingest what it claims (the "discovery result")
        cat = Catalog()
        cat.register_source(TrustedSource("fs", TrustTier.KNOWN), declares={"read", "rm"})
        cat.ingest_claimed("fs", "read", ClaimedMetadata(read_only_hint=True))
        cat.ingest_claimed("fs", "rm", ClaimedMetadata(read_only_hint=False))

        # 2. nothing is invocable until an operator asserts it
        assert not cat.invocable("read")

        cat.assert_descriptor("read", AssertedDescriptor(effect=Effect.READ, asserted_by="op"))
        cat.assert_descriptor("rm", AssertedDescriptor(effect=Effect.DESTRUCTIVE, asserted_by="op"))

        # 3. list: the filtered, invocable view
        assert cat.invocable("read") and cat.invocable("rm")

        # 4. authorize (decision point) — read allowed, destructive denied by policy
        audit: list = []
        broker = Broker(cat, CedarPolicyEngine(BASIC_CEDAR), audit)
        allow = broker.authorize(Principal("agent"), "read")
        deny = broker.authorize(Principal("agent"), "rm")

        assert allow.allowed and allow.determining_policies == ("allow-read",)
        assert not deny.allowed

        # 5. record: both outcomes are in the audit trail, denial included
        assert [e["allowed"] for e in audit] == [True, False]
        assert audit[0]["tool"] == "read" and audit[1]["tool"] == "rm"

    def test_realistic_toolset_authorizes_consistently(self):
        cat = build_catalog()
        broker = Broker(cat, CedarPolicyEngine(BASIC_CEDAR), [])
        # Every read tool the coding agent holds is allowed; nothing crashes.
        for name in CODING_AGENT_TOOLSET:
            tv = cat.tools.get(name)
            if tv and tv.asserted and tv.asserted.effect is Effect.READ:
                assert broker.authorize(Principal("coder"), name).allowed


class TestArchitecturalInvariants:
    """The correct contract for the handoff's forbidden lifecycle steps."""

    def test_no_invocation_surface_anywhere_in_the_package(self):
        for obj in (Broker, CedarPolicyEngine, Catalog, toolconnect):
            for forbidden in ("invoke", "call_tool", "execute", "route"):
                assert not hasattr(obj, forbidden), f"{obj!r} must not expose {forbidden}"

    def test_no_discovery_or_shutdown_lifecycle_exists_yet(self):
        # These are unbuilt, not hidden. If they appear, the verification map in
        # docs/VERIFICATION.md is stale and must be updated alongside them.
        assert not hasattr(Catalog, "discover")
        assert not hasattr(Catalog, "shutdown")

    def test_broker_is_a_decision_point(self):
        # It authorizes and records. That is the whole surface.
        public = {m for m in dir(Broker) if not m.startswith("_")}
        assert "authorize" in public
        assert not (public & {"invoke", "execute", "call", "proxy", "forward"})
