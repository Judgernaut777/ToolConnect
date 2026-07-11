"""Transport fault injection over the real wire.

Each fault is produced by a real misbehaving MCP server subprocess (or a missing
one), not by monkeypatching the adapter. The invariant, three parts, holds for
every fault:

1. the discovery **fails closed** — a typed McpDiscoveryError, never a partial result;
2. the catalog is **unchanged** — no tool from a failed discovery is ingested;
3. the failure is **recorded** — an auditable `ingest` record with the fault kind,
   on the same hash chain as every allow and deny.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from toolconnect.mcp_source import McpDiscoveryError, discover
from toolconnect.policy import CedarPolicyEngine
from toolconnect.service import ServiceError, ToolConnectService
from toolconnect.store import SqliteStore

REPO = Path(__file__).resolve().parent.parent
FIXTURE = str(REPO / "fixtures" / "mini_mcp_server.py")


def server_cmd(mode: str) -> list[str]:
    return [sys.executable, FIXTURE, "--mode", mode]


@pytest.fixture()
def service(tmp_path):
    store = SqliteStore(tmp_path / "tc.db")
    svc = ToolConnectService(store, CedarPolicyEngine(""))
    yield svc
    store.close()


def _register(service, command: list[str]) -> None:
    service.register_source("io.test/faulty", tier="known", transport="mcp",
                            declares=["read_file"], command=command)


def _assert_failed_closed(service, command: list[str], expected_kind: str,
                          timeout: float = 15.0) -> None:
    """The shared three-part invariant for every transport fault."""
    _register(service, command)
    before = dict(service.catalog.tools)

    with pytest.raises(ServiceError) as exc_info:
        service.ingest("io.test/faulty", timeout=timeout)
    assert exc_info.value.status == 502
    assert expected_kind in str(exc_info.value)

    # 2. Nothing was ingested — not even tools from a successful earlier page.
    assert dict(service.catalog.tools) == before
    assert service.store.last_discovery("io.test/faulty") is None

    # 3. The failure is a first-class, hash-chained audit record.
    records = service.read_audit(kind="ingest")
    assert records, "a failed discovery must leave an audit record"
    body = records[0]["body"]
    assert body["ok"] is False
    assert body["fault_kind"] == expected_kind
    assert body["source_id"] == "io.test/faulty"
    assert service.verify_audit()["ok"] is True


class TestTransportFaults:
    def test_timeout(self, service):
        # A server that accepts initialize and then never answers tools/list.
        _assert_failed_closed(service, server_cmd("hang"), "timeout", timeout=1.5)

    def test_timeout_during_initialize(self, service):
        _assert_failed_closed(service, server_cmd("slowinit"), "timeout", timeout=1.5)

    def test_malformed_json(self, service):
        _assert_failed_closed(service, server_cmd("malformed"), "malformed_json")

    def test_truncated_response(self, service):
        # The server writes half a JSON frame and exits mid-message.
        _assert_failed_closed(service, server_cmd("truncate"), "truncated_response")

    def test_unavailable_source(self, service):
        # The configured server binary does not exist at all.
        _assert_failed_closed(
            service, ["/nonexistent/definitely-not-an-mcp-server"], "spawn_failed")

    def test_duplicate_identity(self, service):
        # One server announcing the same tool name twice is a shadowing hazard.
        _assert_failed_closed(service, server_cmd("dup"), "duplicate_tool")

    def test_partial_discovery(self, service):
        """Page 1 succeeds, page 2 errors: the WHOLE discovery must be discarded.

        A catalog holding half of a server's tools is worse than one holding none,
        because the missing half is exactly where a shadowing tool hides.
        """
        _assert_failed_closed(service, server_cmd("partial"), "protocol_error")


class TestAdapterLevelFaults:
    """The same faults at the `discover()` level, proving the typed taxonomy."""

    @pytest.mark.parametrize("mode,kind", [
        ("malformed", "malformed_json"),
        ("truncate", "truncated_response"),
        ("dup", "duplicate_tool"),
        ("partial", "protocol_error"),
    ])
    def test_fault_kinds(self, mode, kind):
        with pytest.raises(McpDiscoveryError) as exc_info:
            discover(server_cmd(mode), timeout=15.0)
        assert exc_info.value.kind == kind

    def test_timeout_kind(self):
        with pytest.raises(McpDiscoveryError) as exc_info:
            discover(server_cmd("hang"), timeout=1.0)
        assert exc_info.value.kind == "timeout"

    def test_spawn_failure_kind(self):
        with pytest.raises(McpDiscoveryError) as exc_info:
            discover(["/nonexistent/nope"], timeout=5.0)
        assert exc_info.value.kind == "spawn_failed"

    def test_timeout_does_not_leave_a_zombie(self):
        import subprocess
        with pytest.raises(McpDiscoveryError):
            discover(server_cmd("hang"), timeout=1.0)
        # The hung child was terminated; give the reaper a moment and check
        # there is no fixture process left running under this test's session.
        out = subprocess.run(["pgrep", "-f", "mini_mcp_server.py --mode hang"],
                             capture_output=True, text=True)
        assert out.stdout.strip() == "", "hung MCP server must be terminated"


class TestIngestPreconditions:
    def test_unknown_source_is_a_404(self, service):
        with pytest.raises(ServiceError) as exc_info:
            service.ingest("io.test/unregistered")
        assert exc_info.value.status == 404

    def test_source_without_command_is_a_409(self, service):
        service.register_source("io.test/nocmd", tier="known")
        with pytest.raises(ServiceError) as exc_info:
            service.ingest("io.test/nocmd")
        assert exc_info.value.status == 409

    def test_duplicate_identity_in_push_payload_fails_closed(self, service):
        service.register_source("io.test/push", tier="known")
        with pytest.raises(ServiceError) as exc_info:
            service.ingest_payload("io.test/push", [
                {"name": "t", "claimed": {}}, {"name": "t", "claimed": {}}])
        assert exc_info.value.status == 409
        assert service.catalog.get("io.test/push", "t") is None
