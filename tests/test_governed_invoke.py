"""The client SDK's governed-invoke helper: authorize(final args) -> redeem ->
executor(frozen_args) -> outcome, against a real ``toolconnect serve`` over loopback.

Deliverable 2: the fail-closed governed-invoke wrapper AgentConnect (and any other
caller) can adopt so it never executes a tool it has not just redeemed a one-use grant
for. Complements ``tests/test_client.py`` (the plain authorize/record_outcome surface)
and ``tests/test_grants_http.py`` (the server-side grant lifecycle).
"""

from __future__ import annotations

import json
import socket
import threading
import urllib.request
from pathlib import Path

import pytest

from toolconnect.client import (
    ClientDecision,
    GrantRedeemDenied,
    ToolConnectClient,
    ToolConnectDenied,
    ToolConnectUnavailable,
)
from toolconnect.policy import CedarPolicyEngine
from toolconnect.server import make_server
from toolconnect.service import ToolConnectService
from toolconnect.store import SqliteStore


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


def _seed(base: str):
    def post(path, body):
        data = json.dumps(body).encode()
        req = urllib.request.Request(base + path, data=data, method="POST",
                                     headers={"Content-Type": "application/json"})
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


class TestGovernedInvokeHappyPath:
    def test_calls_authorize_redeem_executor_outcome_in_order(self, live):
        base, service = live
        _seed(base)
        c = ToolConnectClient(base)
        calls: list[str] = []
        received_args = {}

        def executor(args):
            calls.append("executor")
            received_args.update(args)
            return "the-result"

        result = c.governed_invoke(
            {"id": "a"}, "s", "reader", {"path": "/etc/hosts"}, executor)

        assert result == "the-result"
        assert calls == ["executor"]
        assert received_args == {"path": "/etc/hosts"}
        kinds = [r["kind"] for r in service.read_audit(limit=20)]
        # decision -> grant_issue -> grant_redeem -> outcome(executed) -> grant_close
        assert "grant_redeem" in kinds
        assert "grant_close" in kinds
        outcome_records = [r for r in service.read_audit(kind="outcome", limit=5)]
        assert outcome_records[0]["body"]["outcome"] == "executed"

    def test_executor_receives_frozen_snapshot_not_live_mutation(self, live):
        base, _ = live
        _seed(base)
        c = ToolConnectClient(base)
        mutable_args = {"path": "/a"}
        seen = {}

        def executor(args):
            seen.update(args)
            return None

        c.governed_invoke({"id": "a"}, "s", "reader", mutable_args, executor)
        mutable_args["path"] = "/mutated-after-call-started"
        assert seen == {"path": "/a"}


class TestGovernedInvokeDenials:
    def test_authorize_deny_raises_and_never_calls_executor(self, live):
        base, _ = live
        _seed(base)
        c = ToolConnectClient(base)
        called = []
        with pytest.raises(ToolConnectDenied):
            c.governed_invoke({"id": "a"}, "s", "writer", {"x": 1},
                              lambda args: called.append(args))
        assert called == []

    def test_governed_invoke_redeem_denied_end_to_end(self, live, monkeypatch):
        """Force a redeem-deny inside governed_invoke itself (not a manual replay)."""
        base, _ = live
        _seed(base)
        c = ToolConnectClient(base)
        original_redeem = c.redeem

        def sabotaged_redeem(grant_id, principal, args):
            # Consume the grant behind governed_invoke's back, then let its own
            # redeem attempt see "already_redeemed".
            original_redeem(grant_id, principal, args)
            return original_redeem(grant_id, principal, args)

        monkeypatch.setattr(c, "redeem", sabotaged_redeem)
        called = []
        with pytest.raises(GrantRedeemDenied) as exc:
            c.governed_invoke({"id": "a"}, "s", "reader", {"x": 1},
                              lambda args: called.append(args))
        assert called == []
        assert exc.value.redemption.reason == "already_redeemed"


class TestGovernedInvokeMixedFleetAndFailures:
    def test_stale_pre_1_1_server_allow_no_grant_refuses(self, live, monkeypatch):
        base, _ = live
        _seed(base)
        c = ToolConnectClient(base)

        stale_decision = ClientDecision(
            allowed=True, reason="ok", decision_id="fake-id",
            contract_version="1.0", grant=None, raw={})
        monkeypatch.setattr(c, "authorize", lambda *a, **k: stale_decision)
        called = []
        with pytest.raises(ToolConnectUnavailable):
            c.governed_invoke({"id": "a"}, "s", "reader", {"x": 1},
                              lambda args: called.append(args))
        assert called == []

    def test_executor_exception_propagates_cleanup_is_best_effort(self, live):
        base, service = live
        _seed(base)
        c = ToolConnectClient(base)

        class Boom(Exception):
            pass

        def executor(args):
            raise Boom("kaboom")

        with pytest.raises(Boom):
            c.governed_invoke({"id": "a"}, "s", "reader", {"x": 1}, executor)
        # Cleanup (close + error outcome) was attempted; the grant should now be closed.
        kinds = [r["kind"] for r in service.read_audit(limit=20)]
        assert "grant_close" in kinds

    def test_identity_echo_mismatch_is_refused(self, live, monkeypatch):
        base, _ = live
        _seed(base)
        c = ToolConnectClient(base)
        original_redeem = c.redeem

        def wrong_identity_redeem(grant_id, principal, args):
            r = original_redeem(grant_id, principal, args)
            # Simulate a server double that redeemed a DIFFERENT tool's grant.
            from toolconnect.client import ClientRedemption
            return ClientRedemption(
                redeemed=True, reason="ok", grant_id=r.grant_id,
                decision_id=r.decision_id, source_id="s", name="writer",
                contract_version=r.contract_version, raw=r.raw)

        monkeypatch.setattr(c, "redeem", wrong_identity_redeem)
        called = []
        with pytest.raises(ToolConnectUnavailable) as exc:
            c.governed_invoke({"id": "a"}, "s", "reader", {"x": 1},
                              lambda args: called.append(args))
        assert called == []
        assert "expected s:reader" in str(exc.value)

    def test_success_path_outcome_reporting_outage_never_destroys_result(self, live, monkeypatch):
        base, _ = live
        _seed(base)
        c = ToolConnectClient(base)

        def broken_record_outcome(*a, **k):
            raise ToolConnectUnavailable("audit path is down")

        monkeypatch.setattr(c, "record_outcome", broken_record_outcome)
        result = c.governed_invoke(
            {"id": "a"}, "s", "reader", {"x": 1}, lambda args: "still-got-it")
        assert result == "still-got-it"
