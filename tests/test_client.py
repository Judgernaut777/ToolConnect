"""The importable client library, driven against a real ``toolconnect`` HTTP server.

Deliverable 7: a clean, configurable client AgentConnect can adopt. These tests start
the actual server on loopback and exercise the client end to end — including its
fail-closed contract (unreachable / non-200 / incompatible contract version never
becomes an allow) and its bearer-token config surface.
"""

from __future__ import annotations

import socket
import sys
import threading
from pathlib import Path

import pytest

from toolconnect.client import (
    ClientDecision,
    ToolConnectClient,
    ToolConnectDenied,
    ToolConnectUnavailable,
)
from toolconnect.policy import CedarPolicyEngine
from toolconnect.server import make_server
from toolconnect.service import ToolConnectService
from toolconnect.store import SqliteStore

REPO = Path(__file__).resolve().parent.parent
MINI = str(REPO / "fixtures" / "mini_mcp_server.py")


def _loopback_available() -> bool:
    # A bind alone is not enough: under `unshare -rn` bind succeeds but the loopback
    # interface is down, so an actual connect must be proven (matches test_http_api).
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
def live(tmp_path):
    store = SqliteStore(tmp_path / "tc.db")
    service = ToolConnectService(store, CedarPolicyEngine(ALLOW_READS))
    httpd = make_server(service, host="127.0.0.1", port=0)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    host, port = httpd.server_address[:2]
    yield f"http://{host}:{port}", service
    httpd.shutdown()
    httpd.server_close()
    store.close()


@pytest.fixture()
def live_authed(tmp_path):
    store = SqliteStore(tmp_path / "tc.db")
    service = ToolConnectService(store, CedarPolicyEngine(ALLOW_READS))
    httpd = make_server(service, host="127.0.0.1", port=0, token="tok-123")
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    host, port = httpd.server_address[:2]
    yield f"http://{host}:{port}", "tok-123"
    httpd.shutdown()
    httpd.server_close()
    store.close()


def _seed_read_tool(base: str, token: str | None = None):
    c = ToolConnectClient(base, token=token)
    # Use the client's own transport by round-tripping through the service via HTTP.
    import json
    import urllib.request
    def post(path, body):
        data = json.dumps(body).encode()
        h = {"Content-Type": "application/json"}
        if token:
            h["Authorization"] = f"Bearer {token}"
        req = urllib.request.Request(base + path, data=data, method="POST", headers=h)
        urllib.request.urlopen(req, timeout=10).read()
    post("/sources", {"source_id": "s", "tier": "known"})
    post("/sources/s/tools", {"tools": [
        {"name": "reader", "claimed": {"read_only_hint": True}},
        {"name": "writer", "claimed": {"read_only_hint": False,
                                       "destructive_hint": False}},
    ]})
    post("/assertions", {"source_id": "s", "name": "reader",
                         "descriptor": {"effect": "read", "asserted_by": "op"}})
    post("/assertions", {"source_id": "s", "name": "writer",
                         "descriptor": {"effect": "write", "asserted_by": "op"}})
    return c


class TestClientHappyPath:
    def test_health_and_catalog(self, live):
        base, _ = live
        c = ToolConnectClient(base)
        assert c.health()["status"] == "ok"
        _seed_read_tool(base)
        names = {t["name"] for t in c.list_catalog()}
        assert {"reader", "writer"} <= names

    def test_authorize_allow_and_record_outcome(self, live):
        base, _ = live
        c = _seed_read_tool(base)
        decision = c.authorize({"id": "agent-1"}, "s", "reader")
        assert isinstance(decision, ClientDecision)
        assert decision.allowed is True
        assert decision.contract_version.startswith("1")
        assert decision.decision_id
        out = c.record_outcome(decision.decision_id, "success", {"note": "done"})
        assert out["decision_id"] == decision.decision_id

    def test_authorize_deny_is_a_value_not_an_exception(self, live):
        base, _ = live
        c = _seed_read_tool(base)
        decision = c.authorize({"id": "agent-1"}, "s", "writer")
        assert decision.allowed is False  # write denied by allow-reads policy
        assert decision.reason

    def test_require_raises_on_deny(self, live):
        base, _ = live
        c = _seed_read_tool(base)
        c.require({"id": "a"}, "s", "reader")  # allowed → no raise
        with pytest.raises(ToolConnectDenied) as exc:
            c.require({"id": "a"}, "s", "writer")
        assert exc.value.decision.allowed is False

    def test_drift_and_audit_reads(self, live):
        base, _ = live
        c = _seed_read_tool(base)
        c.authorize({"id": "a"}, "s", "reader")
        assert c.verify_audit()["ok"] is True
        kinds = {r["kind"] for r in c.read_audit(limit=50)}
        assert {"source", "assertion", "decision"} <= kinds


class TestClientFailClosed:
    def test_unreachable_server_raises_never_allows(self):
        # Nothing is listening on this port.
        c = ToolConnectClient("http://127.0.0.1:1", timeout=1.0)
        with pytest.raises(ToolConnectUnavailable):
            c.authorize({"id": "a"}, "s", "reader")

    def test_incompatible_contract_major_fails_closed(self, live, monkeypatch):
        """A server announcing a future contract major must not be read as an allow."""
        base, _ = live
        c = _seed_read_tool(base)
        # Force the client to expect a different major than the server sends.
        monkeypatch.setattr(c, "EXPECTED_CONTRACT_MAJOR", "99")
        with pytest.raises(ToolConnectUnavailable) as exc:
            c.authorize({"id": "a"}, "s", "reader")
        assert "contract" in str(exc.value).lower()

    def test_from_json_defaults_to_deny(self):
        # An empty/garbled body is a deny, structurally.
        assert ClientDecision.from_json({}).allowed is False
        assert ClientDecision.from_json({"reason": "x"}).allowed is False


class TestClientConfigSurface:
    def test_from_config_reads_url_and_token(self):
        c = ToolConnectClient.from_config({"base_url": "http://h:9/", "token": "t",
                                           "timeout": 5})
        assert c.base_url == "http://h:9" and c.token == "t" and c.timeout == 5.0

    def test_from_config_env_fallback(self):
        env = {"TOOLCONNECT_URL": "http://e:8095", "TOOLCONNECT_TOKEN": "envtok"}
        c = ToolConnectClient.from_config(env=env)
        assert c.base_url == "http://e:8095" and c.token == "envtok"

    def test_from_config_requires_url(self):
        with pytest.raises(ValueError):
            ToolConnectClient.from_config({}, env={})

    def test_token_is_sent_and_enforced(self, live_authed):
        base, token = live_authed
        # Without the token, the client fails closed on any call.
        anon = ToolConnectClient(base)
        with pytest.raises(ToolConnectUnavailable):
            anon.health()
        # With the token, the full flow works.
        c = _seed_read_tool(base, token=token)
        assert c.health()["status"] == "ok"
        assert c.authorize({"id": "a"}, "s", "reader").allowed is True
