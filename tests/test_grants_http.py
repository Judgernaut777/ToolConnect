"""Argument-bound grants at the service + real HTTP layer (contract 1.1).

Exercises the whole issue -> redeem -> close/outcome lifecycle both in-process
(``ToolConnectService`` directly, for cases that need multiple in-process threads with
no HTTP-level global lock) and over a real loopback socket (for the routes, status
codes, and bearer-auth behavior a real caller sees).
"""

from __future__ import annotations

import json
import socket
import threading
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

import pytest

from toolconnect.policy import CedarPolicyEngine
from toolconnect.server import make_server
from toolconnect.service import (
    DECISION_CONTRACT_VERSION,
    MAX_GRANT_TTL_SECONDS,
    ServiceError,
    ToolConnectService,
)
from toolconnect.store import SqliteStore

ALLOW_READS = """
@id("allow-reads")
permit(principal, action == Action::"invoke", resource)
when { resource.effect == "read" };
"""


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


HTTP_AVAILABLE = _loopback_available()


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


# --------------------------------------------------------------------- in-process


class TestAuthorizeIssuesGrant:
    def test_allow_without_args_is_byte_identical_to_1_0_shape(self, service):
        d = service.authorize({"id": "a"}, "s", "reader")
        assert "grant" not in d
        assert d["contract_version"] == "1.1"

    def test_allow_with_args_issues_grant_and_audits_grant_issue(self, service):
        d = service.authorize({"id": "a"}, "s", "reader", args={"path": "/x"})
        assert d["allowed"] is True
        assert d["grant"] is not None
        records = service.read_audit(limit=10)
        by_kind = {r["kind"]: r for r in reversed(records)}
        assert "grant_issue" in by_kind
        assert by_kind["grant_issue"]["body"]["decision_id"] == d["decision_id"]
        # decision then grant_issue: adjacent seqs, grant_issue immediately after
        # its decision (read_audit returns newest-first).
        newest_two = [r for r in records if r["kind"] in ("decision", "grant_issue")][:2]
        assert newest_two[0]["kind"] == "grant_issue"
        assert newest_two[1]["kind"] == "decision"
        assert newest_two[0]["seq"] == newest_two[1]["seq"] + 1

    def test_deny_with_args_grant_is_null_no_grant_row_issued(self, service):
        d = service.authorize({"id": "a"}, "s", "writer", args={"path": "/x"})
        assert d["allowed"] is False
        assert d["grant"] is None
        kinds = {r["kind"] for r in service.read_audit(limit=10)}
        assert "grant_issue" not in kinds

    def test_ttl_seconds_without_args_is_400(self, service):
        with pytest.raises(ServiceError) as exc:
            service.authorize({"id": "a"}, "s", "reader", ttl_seconds=30)
        assert exc.value.status == 400

    @pytest.mark.parametrize("bad_ttl", [0, MAX_GRANT_TTL_SECONDS + 1, True, 1.5])
    def test_out_of_range_or_wrong_type_ttl_is_400(self, service, bad_ttl):
        with pytest.raises(ServiceError) as exc:
            service.authorize({"id": "a"}, "s", "reader", args={"x": 1}, ttl_seconds=bad_ttl)
        assert exc.value.status == 400

    def test_ttl_absent_defaults_to_60(self, service):
        d = service.authorize({"id": "a"}, "s", "reader", args={"x": 1})
        assert d["grant"]["ttl_seconds"] == 60

    def test_args_string_ttl_is_400(self, service):
        with pytest.raises(ServiceError):
            service.authorize({"id": "a"}, "s", "reader", args={"x": 1}, ttl_seconds="60")

    def test_expires_at_is_approximately_now_plus_ttl(self, service):
        from datetime import datetime, timezone
        before = datetime.now(timezone.utc)
        d = service.authorize({"id": "a"}, "s", "reader", args={"x": 1}, ttl_seconds=5)
        expires = datetime.fromisoformat(d["grant"]["expires_at"])
        delta = (expires - before).total_seconds()
        assert 4.0 <= delta <= 7.0  # generous bound; no client clock is ever read


class TestRedeemService:
    def test_redeem_echoes_stored_source_and_name(self, service):
        d = service.authorize({"id": "a"}, "s", "reader", args={"x": 1})
        r = service.redeem_grant(d["grant"]["grant_id"], {"id": "a"}, {"x": 1})
        assert r["redeemed"] is True
        assert r["source_id"] == "s"
        assert r["name"] == "reader"
        assert r["contract_version"] == "1.1"

    def test_every_deny_reason_appends_grant_redeem_denied(self, service):
        d = service.authorize({"id": "a"}, "s", "reader", args={"x": 1})
        gid = d["grant"]["grant_id"]
        service.redeem_grant(gid, {"id": "a"}, {"x": 1})  # consume it
        service.redeem_grant(gid, {"id": "a"}, {"x": 1})  # replay -> denied
        kinds = [r["kind"] for r in service.read_audit(limit=10)]
        assert kinds.count("grant_redeem_denied") == 1
        assert kinds.count("grant_redeem") == 1

    def test_rug_pull_between_issue_and_redeem_denies_not_invocable(self, service):
        d = service.authorize({"id": "a"}, "s", "reader", args={"x": 1})
        # Re-ingest with a changed claim: the assertion drops (claim fingerprint no
        # longer matches), so the tool is no longer invocable before redeem runs.
        service.ingest_payload("s", [
            {"name": "reader", "claimed": {"read_only_hint": False}},
        ])
        r = service.redeem_grant(d["grant"]["grant_id"], {"id": "a"}, {"x": 1})
        assert r["redeemed"] is False
        assert r["reason"] == "not_invocable"
        kinds = [rec["kind"] for rec in service.read_audit(limit=10)]
        assert "grant_close" in kinds

    def test_bad_state_filter_is_400(self, service):
        with pytest.raises(ServiceError) as exc:
            service.list_grants(state="bogus")
        assert exc.value.status == 400

    def test_list_grants_finds_dangling_issued_grant(self, service):
        d = service.authorize({"id": "a"}, "s", "reader", args={"x": 1})
        gid = d["grant"]["grant_id"]
        issued = [g["grant_id"] for g in service.list_grants(state="issued")]
        assert gid in issued


class TestOutcomeGrantClose:
    def test_outcome_with_grant_id_closes_and_flags_grant_closed(self, service):
        d = service.authorize({"id": "a"}, "s", "reader", args={"x": 1})
        gid = d["grant"]["grant_id"]
        service.redeem_grant(gid, {"id": "a"}, {"x": 1})
        resp = service.record_outcome(d["decision_id"], "executed", grant_id=gid)
        assert resp["grant_closed"] is True
        assert service.get_grant(gid)["status"] == "closed"

    def test_outcome_mismatched_decision_and_grant_is_400(self, service):
        d1 = service.authorize({"id": "a"}, "s", "reader", args={"x": 1})
        d2 = service.authorize({"id": "a"}, "s", "reader", args={"y": 2})
        with pytest.raises(ServiceError) as exc:
            service.record_outcome(d1["decision_id"], "executed", grant_id=d2["grant"]["grant_id"])
        assert exc.value.status == 400

    def test_outcome_unknown_grant_is_404(self, service):
        d = service.authorize({"id": "a"}, "s", "reader", args={"x": 1})
        with pytest.raises(ServiceError) as exc:
            service.record_outcome(d["decision_id"], "executed", grant_id="ghost")
        assert exc.value.status == 404

    def test_close_route_unknown_grant_is_404(self, service):
        with pytest.raises(ServiceError) as exc:
            service.close_grant("ghost")
        assert exc.value.status == 404

    def test_full_lifecycle_chain_verifies(self, service):
        d = service.authorize({"id": "a"}, "s", "reader", args={"x": 1})
        gid = d["grant"]["grant_id"]
        service.redeem_grant(gid, {"id": "a"}, {"x": 1})
        service.close_grant(gid)
        assert service.verify_audit()["ok"] is True

    def test_health_carries_contract_version(self, service):
        assert service.health()["contract_version"] == DECISION_CONTRACT_VERSION


class TestServiceLevelAuthorizeConcurrency:
    def test_two_concurrent_authorizes_bind_grant_to_their_own_decision_M3(self, service):
        """Regression for M3: without the ``_authz_lock``, a concurrent in-process
        caller could bind a grant to a DIFFERENT thread's decision_id."""
        results = []
        lock = threading.Lock()

        def call(i: int):
            d = service.authorize({"id": f"a{i}"}, "s", "reader", args={"i": i})
            with lock:
                results.append(d)

        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(call, range(16)))

        for d in results:
            issue_records = [
                r for r in service.read_audit(kind="grant_issue", limit=100)
                if r["body"]["grant_id"] == d["grant"]["grant_id"]
            ]
            assert len(issue_records) == 1
            assert issue_records[0]["body"]["decision_id"] == d["decision_id"]


# ------------------------------------------------------------------------- HTTP


pytestmark = pytest.mark.skipif(
    not HTTP_AVAILABLE, reason="loopback networking unavailable (offline gate variant)")


@pytest.fixture()
def base_url(tmp_path):
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
    httpd = make_server(svc, host="127.0.0.1", port=0)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    host, port = httpd.server_address[:2]
    yield f"http://{host}:{port}"
    httpd.shutdown()
    httpd.server_close()
    store.close()


@pytest.fixture()
def base_url_authed(tmp_path):
    store = SqliteStore(tmp_path / "tc.db")
    svc = ToolConnectService(store, CedarPolicyEngine(ALLOW_READS))
    svc.register_source("s", tier="known")
    svc.ingest_payload("s", [{"name": "reader", "claimed": {"read_only_hint": True}}])
    svc.assert_tool("s", "reader", {"effect": "read", "asserted_by": "op"})
    httpd = make_server(svc, host="127.0.0.1", port=0, token="tok-123")
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    host, port = httpd.server_address[:2]
    yield f"http://{host}:{port}"
    httpd.shutdown()
    httpd.server_close()
    store.close()


def _call(method: str, url: str, body=None, headers: dict | None = None) -> tuple[int, dict]:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Content-Type": "application/json",
                                          **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


class TestGrantHttpLifecycle:
    def test_authorize_redeem_close_over_http(self, base_url):
        status, d = _call("POST", f"{base_url}/authorize", {
            "principal": {"id": "a"}, "source_id": "s", "name": "reader",
            "args": {"path": "/x"}})
        assert status == 200 and d["allowed"] is True
        gid = d["grant"]["grant_id"]

        status, r = _call("POST", f"{base_url}/grants/{gid}/redeem", {
            "principal": {"id": "a"}, "args": {"path": "/x"}})
        assert status == 200
        assert r["redeemed"] is True

        status, g = _call("GET", f"{base_url}/grants/{gid}")
        assert status == 200 and g["status"] == "redeemed"

        status, c = _call("POST", f"{base_url}/grants/{gid}/close", {"reason": "done"})
        assert status == 200 and c["closed"] is True

        status, g2 = _call("GET", f"{base_url}/grants/{gid}")
        assert g2["status"] == "closed"

    def test_all_redeem_deny_reasons_return_200_not_404(self, base_url):
        status, body = _call("POST", f"{base_url}/grants/does-not-exist/redeem", {
            "principal": {"id": "a"}, "args": {"x": 1}})
        assert status == 200
        assert body["redeemed"] is False
        assert body["reason"] == "not_found"

    def test_redeem_malformed_body_is_400(self, base_url):
        status, d = _call("POST", f"{base_url}/authorize", {
            "principal": {"id": "a"}, "source_id": "s", "name": "reader",
            "args": {"path": "/x"}})
        gid = d["grant"]["grant_id"]
        status, body = _call("POST", f"{base_url}/grants/{gid}/redeem", {
            "principal": {"id": "a"}})  # missing args entirely
        assert status == 400

    def test_authorize_args_null_is_400(self, base_url):
        status, body = _call("POST", f"{base_url}/authorize", {
            "principal": {"id": "a"}, "source_id": "s", "name": "reader", "args": None})
        assert status == 400

    def test_nan_in_args_is_400_and_no_phantom_decision_audit(self, base_url):
        status0, before = _call("GET", f"{base_url}/audit?limit=1000")
        before_count = len(before["records"])
        # json.dumps emits a literal (non-conforming) NaN by default; the server's
        # permissive json.loads parses it, and hashing.args_hash then rejects it.
        status, body = _call("POST", f"{base_url}/authorize", {
            "principal": {"id": "a"}, "source_id": "s", "name": "reader",
            "args": {"n": float("nan")}})
        assert status == 400
        status1, after = _call("GET", f"{base_url}/audit?limit=1000")
        assert len(after["records"]) == before_count

    def test_grants_state_filter_over_http(self, base_url):
        status, d = _call("POST", f"{base_url}/authorize", {
            "principal": {"id": "a"}, "source_id": "s", "name": "reader",
            "args": {"path": "/x"}})
        gid = d["grant"]["grant_id"]
        status, body = _call("GET", f"{base_url}/grants?state=issued")
        assert status == 200
        assert any(g["grant_id"] == gid for g in body["grants"])
        status, body = _call("GET", f"{base_url}/grants?state=bogus")
        assert status == 400

    def test_outcome_with_grant_id_over_http(self, base_url):
        status, d = _call("POST", f"{base_url}/authorize", {
            "principal": {"id": "a"}, "source_id": "s", "name": "reader",
            "args": {"path": "/x"}})
        gid = d["grant"]["grant_id"]
        _call("POST", f"{base_url}/grants/{gid}/redeem",
              {"principal": {"id": "a"}, "args": {"path": "/x"}})
        status, body = _call("POST", f"{base_url}/decisions/{d['decision_id']}/outcome",
                             {"outcome": "executed", "grant_id": gid})
        assert status == 200
        assert body["grant_closed"] is True

    def test_close_unknown_grant_is_404(self, base_url):
        status, body = _call("POST", f"{base_url}/grants/ghost/close", {})
        assert status == 404

    def test_bearer_auth_required_on_grant_routes(self, base_url_authed):
        status, d = _call("POST", f"{base_url_authed}/authorize", {
            "principal": {"id": "a"}, "source_id": "s", "name": "reader",
            "args": {"x": 1}}, headers={"Authorization": "Bearer tok-123"})
        assert status == 200
        gid = d["grant"]["grant_id"]

        # No token at all -> 401 on every new route.
        status, _ = _call("POST", f"{base_url_authed}/grants/{gid}/redeem",
                          {"principal": {"id": "a"}, "args": {"x": 1}})
        assert status == 401
        status, _ = _call("GET", f"{base_url_authed}/grants/{gid}")
        assert status == 401
        status, _ = _call("GET", f"{base_url_authed}/grants")
        assert status == 401
        status, _ = _call("POST", f"{base_url_authed}/grants/{gid}/close", {})
        assert status == 401

        # Correct token -> works.
        status, r = _call("POST", f"{base_url_authed}/grants/{gid}/redeem",
                          {"principal": {"id": "a"}, "args": {"x": 1}},
                          headers={"Authorization": "Bearer tok-123"})
        assert status == 200 and r["redeemed"] is True
