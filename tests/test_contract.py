"""The authorization request/response contract is pinned, and versioned.

Deliverable 6: stable request/response contracts, with the decision shape versioned so
a client can detect an incompatible server. These are golden fixtures — a change to the
Decision JSON keys, or to ``DECISION_CONTRACT_VERSION``, must break a test here and force
a deliberate contract decision, not slip through.

The shape is exercised through the service (the same code the HTTP route calls), so the
golden pins what a real caller receives.
"""

from __future__ import annotations

import pytest

from toolconnect.policy import CedarPolicyEngine
from toolconnect.service import DECISION_CONTRACT_VERSION, ToolConnectService
from toolconnect.store import SqliteStore

ALLOW_READS = """
@id("allow-reads")
permit(principal, action == Action::"invoke", resource)
when { resource.effect == "read" };
"""

#: The exact, complete key set of an authorization Decision on the wire. Adding a key is
#: an additive change (same major); removing/renaming one is breaking (bump the major).
DECISION_KEYS = frozenset({
    "decision_id", "allowed", "reason", "determining_policies",
    "default_deny", "errors", "contract_version",
})


@pytest.fixture()
def service(tmp_path):
    store = SqliteStore(tmp_path / "tc.db")
    svc = ToolConnectService(store, CedarPolicyEngine(ALLOW_READS))
    svc.register_source("s", tier="known")
    svc.ingest_payload("s", [
        {"name": "reader", "claimed": {"read_only_hint": True}},
        {"name": "writer", "claimed": {"read_only_hint": False,
                                       "destructive_hint": False}},
    ])
    svc.assert_tool("s", "reader", {"effect": "read", "asserted_by": "op"})
    svc.assert_tool("s", "writer", {"effect": "write", "asserted_by": "op"})
    yield svc
    store.close()


class TestDecisionContract:
    def test_version_is_pinned(self):
        assert DECISION_CONTRACT_VERSION == "1.0"

    def test_allow_shape_is_exact(self, service):
        d = service.authorize({"id": "a"}, "s", "reader")
        assert frozenset(d) == DECISION_KEYS, "decision key set drifted"
        assert d["allowed"] is True
        assert d["determining_policies"] == ["allow-reads"]
        assert d["default_deny"] is False
        assert d["errors"] == []
        assert d["contract_version"] == "1.0"
        assert isinstance(d["decision_id"], str) and d["decision_id"]

    def test_explicit_deny_shape(self, service):
        # `writer` is asserted (so invocable) but the allow-reads policy does not permit
        # it → a default deny (no policy matched), distinct from an explicit forbid.
        d = service.authorize({"id": "a"}, "s", "writer")
        assert frozenset(d) == DECISION_KEYS
        assert d["allowed"] is False
        assert d["default_deny"] is True
        assert d["determining_policies"] == []
        assert d["contract_version"] == "1.0"

    def test_unknown_tool_deny_shape(self, service):
        d = service.authorize({"id": "a"}, "s", "ghost")
        assert frozenset(d) == DECISION_KEYS
        assert d["allowed"] is False
        assert "unknown tool" in d["reason"]
        assert d["contract_version"] == "1.0"

    def test_explicit_forbid_is_distinct_from_default_deny(self, tmp_path):
        forbid_policy = """
@id("forbid-writes")
forbid(principal, action == Action::"invoke", resource)
when { resource.effect == "write" };
@id("allow-all")
permit(principal, action == Action::"invoke", resource);
"""
        store = SqliteStore(tmp_path / "f.db")
        svc = ToolConnectService(store, CedarPolicyEngine(forbid_policy))
        svc.register_source("s", tier="known")
        svc.ingest_payload("s", [{"name": "w",
                                  "claimed": {"read_only_hint": False,
                                              "destructive_hint": False}}])
        svc.assert_tool("s", "w", {"effect": "write", "asserted_by": "op"})
        d = svc.authorize({"id": "a"}, "s", "w")
        assert d["allowed"] is False
        assert d["default_deny"] is False  # a rule fired
        assert d["determining_policies"] == ["forbid-writes"]
        store.close()
