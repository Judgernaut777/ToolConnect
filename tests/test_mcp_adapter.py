"""The MCP source adapter against a real server subprocess.

Nothing here is an in-process fake: every test spawns `fixtures/mini_mcp_server.py`
as a separate process and speaks actual JSON-RPC 2.0 over its stdio, including the
initialize handshake and paginated tools/list. The fixture server is minimal but
real — the adapter cannot tell it from a third-party MCP server.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from toolconnect.descriptor import AssertedDescriptor, Effect, TrustTier
from toolconnect.mcp_source import discover
from toolconnect.policy import CedarPolicyEngine
from toolconnect.service import ToolConnectService
from toolconnect.store import SqliteStore

REPO = Path(__file__).resolve().parent.parent
FIXTURE = str(REPO / "fixtures" / "mini_mcp_server.py")


def server_cmd(mode: str = "normal") -> list[str]:
    return [sys.executable, FIXTURE, "--mode", mode]


ALLOW_READS = """
@id("allow-reads")
permit(principal, action == Action::"invoke", resource)
when { resource.effect == "read" };
"""


@pytest.fixture()
def service(tmp_path):
    store = SqliteStore(tmp_path / "tc.db")
    svc = ToolConnectService(store, CedarPolicyEngine(ALLOW_READS))
    yield svc
    store.close()


class TestDiscovery:
    def test_full_discovery_over_real_stdio(self):
        result = discover(server_cmd(), timeout=15.0)
        assert result.server_name == "mini-mcp-fixture"
        assert result.server_version == "1.2.3"
        assert result.protocol_version == "2025-06-18"
        # Pagination followed: page one (2 tools) + page two (1 tool).
        assert sorted(t.name for t in result.tools) == ["fetch_url", "read_file", "write_file"]

    def test_annotations_normalize_into_claimed_metadata(self):
        result = discover(server_cmd(), timeout=15.0)
        by_name = {t.name: t for t in result.tools}
        rf = by_name["read_file"]
        assert rf.claimed.read_only_hint is True
        assert rf.claimed.idempotent_hint is True
        assert rf.claimed.description == "Read a file from the workspace"
        assert rf.input_schema["required"] == ["path"]
        fu = by_name["fetch_url"]
        assert fu.claimed.open_world_hint is True
        assert fu.claimed.read_only_hint is False

    def test_empty_server_discovers_zero_tools(self):
        result = discover(server_cmd("empty"), timeout=15.0)
        assert result.tools == ()


class TestServiceIngest:
    """End to end: register -> discover over the wire -> catalog -> policy."""

    def _register(self, service, tier="known"):
        service.register_source("io.test/mini", tier=tier, transport="mcp",
                                declares=["read_file", "write_file", "fetch_url"],
                                command=server_cmd())

    def test_ingest_populates_catalog_and_audit(self, service):
        self._register(service)
        out = service.ingest("io.test/mini", timeout=15.0)
        assert out["ingested"] == ["fetch_url", "read_file", "write_file"]
        assert out["server"] == {"name": "mini-mcp-fixture", "version": "1.2.3"}
        # Discovery is recorded and auditable.
        records = service.read_audit(kind="ingest")
        assert records[0]["body"]["ok"] is True
        assert service.verify_audit()["ok"] is True

    def test_discovered_tools_are_not_invocable_until_asserted(self, service):
        """A server's claim is never an authorization — even a readOnlyHint=true one."""
        self._register(service)
        service.ingest("io.test/mini", timeout=15.0)
        d = service.authorize({"id": "agent-1"}, "io.test/mini", "read_file")
        assert d["allowed"] is False
        assert "not invocable" in d["reason"]

    def test_asserted_tool_authorizes_through_cedar(self, service):
        self._register(service)
        service.ingest("io.test/mini", timeout=15.0)
        service.assert_tool("io.test/mini", "read_file", {
            "effect": "read", "asserted_by": "operator@host"})
        d = service.authorize({"id": "agent-1"}, "io.test/mini", "read_file")
        assert d["allowed"] is True
        assert d["determining_policies"] == ["allow-reads"]
        # But the write tool, unasserted, stays closed.
        d2 = service.authorize({"id": "agent-1"}, "io.test/mini", "write_file")
        assert d2["allowed"] is False

    def test_reingestion_of_identical_claims_keeps_assertions(self, service):
        self._register(service)
        service.ingest("io.test/mini", timeout=15.0)
        service.assert_tool("io.test/mini", "read_file", {
            "effect": "read", "asserted_by": "operator@host"})
        service.ingest("io.test/mini", timeout=15.0)  # same server, same claims
        assert service.catalog.invocable("io.test/mini", "read_file")
        drift = service.drift("io.test/mini")
        assert "read_file" not in drift["unasserted"]
        assert drift["redefined_after_assertion"] == []

    def test_drift_reports_unasserted_discovered_tools(self, service):
        self._register(service)
        service.ingest("io.test/mini", timeout=15.0)
        drift = service.drift("io.test/mini")
        assert drift["clean"] is False
        assert sorted(drift["unasserted"]) == ["fetch_url", "read_file", "write_file"]

    def test_ingest_survives_service_restart(self, service, tmp_path):
        """Hydration: a second service on the same DB sees the same governance state."""
        self._register(service)
        service.ingest("io.test/mini", timeout=15.0)
        service.assert_tool("io.test/mini", "read_file", {
            "effect": "read", "asserted_by": "operator@host"})

        svc2 = ToolConnectService(service.store, CedarPolicyEngine(ALLOW_READS))
        d = svc2.authorize({"id": "agent-1"}, "io.test/mini", "read_file")
        assert d["allowed"] is True
        assert not svc2.catalog.invocable("io.test/mini", "write_file")
        assert svc2.drift("io.test/mini")["observed_at"]
