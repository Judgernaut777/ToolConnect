"""The HTTP surface, exercised over a real loopback socket.

These start the actual `ThreadingHTTPServer` from `toolconnect.server` on an
ephemeral 127.0.0.1 port and drive it with urllib — no test client shim, no
in-process handler calls. Under `unshare -rn` (the offline gate variant) the
loopback interface is down, so the whole module skips there; every other suite,
including all transport-fault tests, still runs offline.
"""

from __future__ import annotations

import json
import socket
import sys
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from toolconnect.policy import CedarPolicyEngine
from toolconnect.server import make_server
from toolconnect.service import ToolConnectService
from toolconnect.store import SqliteStore

REPO = Path(__file__).resolve().parent.parent
FIXTURE = str(REPO / "fixtures" / "mini_mcp_server.py")


def _loopback_available() -> bool:
    try:
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        cli = socket.socket()
        cli.settimeout(1.0)
        cli.connect(srv.getsockname())
        cli.close()
        srv.close()
        return True
    except OSError:
        return False


pytestmark = pytest.mark.skipif(
    not _loopback_available(),
    reason="loopback networking unavailable (offline gate variant)")

ALLOW_READS = """
@id("allow-reads")
permit(principal, action == Action::"invoke", resource)
when { resource.effect == "read" };
"""


@pytest.fixture()
def base_url(tmp_path):
    store = SqliteStore(tmp_path / "tc.db")
    service = ToolConnectService(store, CedarPolicyEngine(ALLOW_READS))
    httpd = make_server(service, host="127.0.0.1", port=0)  # ephemeral port
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    host, port = httpd.server_address[:2]
    yield f"http://{host}:{port}"
    httpd.shutdown()
    httpd.server_close()
    store.close()


def _call(method: str, url: str, body: dict | None = None) -> tuple[int, dict]:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


class TestRoutes:
    def test_health(self, base_url):
        status, body = _call("GET", f"{base_url}/health")
        assert status == 200
        assert body["status"] == "ok"
        assert body["audit_chain_ok"] is True

    def test_full_lifecycle_over_http(self, base_url):
        """register -> ingest (real MCP subprocess) -> assert -> authorize ->
        record outcome -> audit. The complete decision-point loop, over the wire,
        using a reverse-DNS source id containing a slash (the MCP registry
        convention that routing must support)."""
        sid = "io.test/mini"
        status, body = _call("POST", f"{base_url}/sources", {
            "source_id": sid, "tier": "known",
            "declares": ["read_file", "write_file", "fetch_url"],
            "command": [sys.executable, FIXTURE, "--mode", "normal"],
        })
        assert status == 200 and body["source_id"] == sid

        status, body = _call("POST", f"{base_url}/sources/{sid}/ingest", {"timeout": 15})
        assert status == 200
        assert body["ingested"] == ["fetch_url", "read_file", "write_file"]

        status, body = _call("GET", f"{base_url}/catalog/{sid}/read_file")
        assert status == 200
        assert body["assertion_status"] == "never_asserted"
        assert body["invocable"] is False

        status, body = _call("POST", f"{base_url}/assertions", {
            "source_id": sid, "name": "read_file",
            "descriptor": {"effect": "read", "asserted_by": "operator@host"}})
        assert status == 200
        assert body["invocable"] is True

        status, body = _call("GET", f"{base_url}/assertions/{sid}/read_file")
        assert status == 200
        assert body["status"] == "asserted"

        status, body = _call("POST", f"{base_url}/authorize", {
            "principal": {"id": "agent-1"},
            "source_id": sid, "name": "read_file"})
        assert status == 200
        assert body["allowed"] is True
        assert body["determining_policies"] == ["allow-reads"]
        decision_id = body["decision_id"]

        status, body = _call("POST", f"{base_url}/decisions/{decision_id}/outcome",
                             {"outcome": "success"})
        assert status == 200

        status, body = _call("GET", f"{base_url}/drift/{sid}")
        assert status == 200
        assert "write_file" in body["unasserted"]

        status, body = _call("GET", f"{base_url}/audit?limit=50")
        assert status == 200
        kinds = {r["kind"] for r in body["records"]}
        assert {"source", "ingest", "assertion", "decision", "outcome"} <= kinds

        status, body = _call("GET", f"{base_url}/audit/verify")
        assert status == 200 and body["ok"] is True

    def test_denials_come_back_as_200_decisions_not_errors(self, base_url):
        """A denial is a decision, not an HTTP error (ARCHITECTURE rule 4)."""
        _call("POST", f"{base_url}/sources", {"source_id": "s", "tier": "known"})
        status, body = _call("POST", f"{base_url}/authorize", {
            "principal": {"id": "a"}, "source_id": "s", "name": "ghost"})
        assert status == 200
        assert body["allowed"] is False
        assert "unknown tool" in body["reason"]

    def test_error_shapes(self, base_url):
        status, body = _call("GET", f"{base_url}/catalog/nope/ghost")
        assert status == 404 and "error" in body

        status, body = _call("POST", f"{base_url}/sources", {
            "source_id": "s2", "tier": "not-a-tier"})
        assert status == 400 and "unknown trust tier" in body["error"]["message"]

        status, body = _call("GET", f"{base_url}/no/such/route")
        assert status == 404

        status, body = _call("GET", f"{base_url}/drift/unknown-source")
        assert status == 404

    def test_drift_without_observation_is_409_not_a_guess(self, base_url):
        _call("POST", f"{base_url}/sources", {"source_id": "s3", "tier": "known"})
        status, body = _call("GET", f"{base_url}/drift/s3")
        assert status == 409
        assert "no discovery" in body["error"]["message"]

    def test_failed_ingest_is_recorded_and_5xx(self, base_url):
        _call("POST", f"{base_url}/sources", {
            "source_id": "s4", "tier": "known",
            "command": [sys.executable, FIXTURE, "--mode", "malformed"]})
        status, body = _call("POST", f"{base_url}/sources/s4/ingest", {"timeout": 15})
        assert status == 502
        assert "malformed_json" in body["error"]["message"]
        status, body = _call("GET", f"{base_url}/audit?kind=ingest")
        assert body["records"][0]["body"]["ok"] is False

    def test_malformed_request_body_is_a_400(self, base_url):
        req = urllib.request.Request(
            f"{base_url}/authorize", data=b"{not json", method="POST",
            headers={"Content-Type": "application/json"})
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(req, timeout=10)
        assert exc_info.value.code == 400

    def test_no_invocation_route_exists(self, base_url):
        """The negative contract: there is no data path through the service."""
        for path in ("/invoke", "/execute", "/call", "/tools/call", "/proxy"):
            status, _ = _call("POST", f"{base_url}{path}", {})
            assert status == 404, f"{path} must not exist"
