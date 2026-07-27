"""``toolconnect gateway`` — the MCP enforcement proxy, end to end.

Every test drives a real ``Gateway`` instance against ``fixtures/callable_mcp_server.py``
spawned as an actual subprocess speaking real JSON-RPC 2.0 over stdio — the same fixture
family ``test_mcp_adapter.py`` uses for discovery, extended here with a real
``tools/call`` handler so the forward path has something real to hit. The client side
of the gateway (whatever spawned it — an agent runtime, an IDE) is simulated with
in-memory text streams: the gateway's client-facing protocol is exactly newline-
delimited JSON-RPC, so a StringIO pair is a faithful stand-in for a client's stdio.
"""

from __future__ import annotations

import json
import sys
from io import StringIO
from pathlib import Path

import pytest

import toolconnect.gateway as gateway_module
from toolconnect.gateway import (
    DENIED,
    DOWNSTREAM_UNAVAILABLE,
    INVALID_PARAMS,
    INVALID_REQUEST,
    METHOD_NOT_FOUND,
    NOT_PERMITTED,
    REDEEM_DENIED,
    Gateway,
)
from toolconnect.policy import CedarPolicyEngine
from toolconnect.service import ToolConnectService
from toolconnect.store import SqliteStore

REPO = Path(__file__).resolve().parent.parent
FIXTURE = str(REPO / "fixtures" / "callable_mcp_server.py")

ALLOW_READS = """
@id("allow-reads")
permit(principal, action == Action::"invoke", resource)
when { resource.effect == "read" };
"""

SOURCE_ID = "downstream-1"
PRINCIPAL = {"id": "agent-1"}


def server_cmd(mode: str = "normal") -> list[str]:
    return [sys.executable, FIXTURE, "--mode", mode]


@pytest.fixture()
def service(tmp_path):
    store = SqliteStore(tmp_path / "tc.db")
    svc = ToolConnectService(store, CedarPolicyEngine(ALLOW_READS))
    # `reader` is asserted read (Cedar allows it); `writer` is ingested but never
    # asserted (not invocable — distinct from being denied); `ghost` (advertised by
    # the fixture server) is never even ingested. All three exist so tools/list
    # filtering has real cases to prove: asserted+invocable, ingested-not-asserted,
    # and never-registered all resolve to "hidden", by three different mechanisms.
    svc.register_source(SOURCE_ID, "known")
    svc.ingest_payload(SOURCE_ID, [
        {"name": "reader", "claimed": {"read_only_hint": True}},
        {"name": "writer", "claimed": {"read_only_hint": False, "destructive_hint": False}},
    ])
    svc.assert_tool(SOURCE_ID, "reader", {"effect": "read", "asserted_by": "op"})
    yield svc
    store.close()


def make_gateway(service, mode: str = "normal", timeout: float = 5.0) -> tuple[Gateway, StringIO]:
    out = StringIO()
    gw = Gateway(service, principal=PRINCIPAL, source_id=SOURCE_ID,
                command=server_cmd(mode), client_in=StringIO(""), client_out=out,
                timeout=timeout)
    return gw, out


def _lines(out: StringIO) -> list[dict]:
    return [json.loads(ln) for ln in out.getvalue().splitlines() if ln.strip()]


def _drive(gw: Gateway, out: StringIO, *messages: dict) -> list[dict]:
    """Feed `messages` to the gateway as one client session, then read all replies."""
    gw._in = StringIO("\n".join(json.dumps(m) for m in messages) + "\n")
    gw.run()
    return _lines(out)


class TestPassthrough:
    def test_initialize_is_forwarded_and_relayed(self, service):
        gw, out = make_gateway(service)
        replies = _drive(gw, out, {
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                      "clientInfo": {"name": "test", "version": "0"}},
        })
        assert len(replies) == 1
        assert replies[0]["id"] == 1
        assert replies[0]["result"]["serverInfo"]["name"] == "callable-mcp-fixture"

    def test_ping_is_forwarded(self, service):
        gw, out = make_gateway(service)
        replies = _drive(gw, out, {"jsonrpc": "2.0", "id": 2, "method": "ping"})
        assert replies == [{"jsonrpc": "2.0", "id": 2, "result": {}}]

    def test_notifications_initialized_is_forwarded_with_no_reply(self, service):
        gw, out = make_gateway(service)
        replies = _drive(gw, out,
                         {"jsonrpc": "2.0", "method": "notifications/initialized"})
        assert replies == []

    def test_unrecognized_notification_is_dropped_silently(self, service):
        gw, out = make_gateway(service)
        replies = _drive(gw, out,
                         {"jsonrpc": "2.0", "method": "notifications/cancelled",
                          "params": {"requestId": 1}})
        assert replies == []


class TestToolsListFiltering:
    def test_only_asserted_invocable_tools_are_listed(self, service):
        gw, out = make_gateway(service)
        replies = _drive(gw, out, {"jsonrpc": "2.0", "id": 3, "method": "tools/list"})
        assert len(replies) == 1
        names = {t["name"] for t in replies[0]["result"]["tools"]}
        # reader: asserted+invocable -> visible. writer: ingested but never asserted
        # -> hidden. ghost: never even ingested -> hidden. Same outcome, three
        # different reasons, none of them "the server didn't offer it".
        assert names == {"reader"}


class TestGovernedToolsCall:
    def test_allowed_call_end_to_end_grant_redeemed_and_outcome_recorded(self, service):
        gw, out = make_gateway(service)
        replies = _drive(gw, out, {
            "jsonrpc": "2.0", "id": 4, "method": "tools/call",
            "params": {"name": "reader", "arguments": {"path": "/etc/hosts"}},
        })
        assert len(replies) == 1
        result = replies[0]["result"]
        # The fixture echoes back exactly what it received: proof the forwarded
        # arguments are the same ones that were authorized and redeemed, not a
        # re-derived or re-parsed copy.
        assert result["structuredContent"]["echoed_arguments"] == {"path": "/etc/hosts"}

        kinds = [r["kind"] for r in service.read_audit(limit=20)]
        assert "grant_issue" in kinds
        assert "grant_redeem" in kinds
        outcome = [r for r in service.read_audit(kind="outcome", limit=5)][0]
        assert outcome["body"]["outcome"] == "executed"
        assert outcome["body"]["detail"] == {}

    def test_denied_call_never_reaches_downstream(self, service):
        gw, out = make_gateway(service)
        replies = _drive(gw, out, {
            "jsonrpc": "2.0", "id": 5, "method": "tools/call",
            "params": {"name": "writer", "arguments": {"path": "/etc/passwd"}},
        })
        assert len(replies) == 1
        assert replies[0]["error"]["code"] == DENIED
        # No grant_redeem, no outcome, and specifically no evidence the downstream
        # process ever saw a tools/call for `writer` — `authorize` denied before any
        # grant existed to redeem or forward.
        kinds = [r["kind"] for r in service.read_audit(limit=20)]
        assert "grant_redeem" not in kinds
        assert "outcome" not in kinds

    def test_missing_name_is_refused_without_reaching_the_service(self, service):
        before = len(service.read_audit(limit=100))
        gw, out = make_gateway(service)
        replies = _drive(gw, out, {
            "jsonrpc": "2.0", "id": 6, "method": "tools/call",
            "params": {"arguments": {"x": 1}},
        })
        assert replies[0]["error"]["code"] == INVALID_PARAMS
        # No new audit record at all: the gateway refused before ever calling
        # authorize(), so no phantom `decision` record was left behind either.
        assert len(service.read_audit(limit=100)) == before

    def test_non_object_arguments_is_refused(self, service):
        gw, out = make_gateway(service)
        replies = _drive(gw, out, {
            "jsonrpc": "2.0", "id": 7, "method": "tools/call",
            "params": {"name": "reader", "arguments": "not-an-object"},
        })
        assert replies[0]["error"]["code"] == INVALID_PARAMS

    def test_replay_of_a_redeemed_grant_is_denied(self, service, monkeypatch):
        """A second redeem attempt on the same grant_id must fail — simulated by
        replaying the store's redeem_grant call after the gateway's own one-use grant
        was already consumed, proving the one-use property end to end."""
        gw, out = make_gateway(service)
        replies = _drive(gw, out, {
            "jsonrpc": "2.0", "id": 8, "method": "tools/call",
            "params": {"name": "reader", "arguments": {"path": "/a"}},
        })
        assert "result" in replies[0]
        grant_issue = [r for r in service.read_audit(kind="grant_issue", limit=5)][0]
        grant_id = grant_issue["body"]["grant_id"]
        redemption = service.redeem_grant(grant_id, PRINCIPAL, {"path": "/a"})
        assert redemption["redeemed"] is False
        assert redemption["reason"] == "already_redeemed"

    def test_redeem_denial_is_relayed_and_never_forwarded(self, service, monkeypatch):
        """Force a redeem-time deny (e.g. a concurrent redeemer won the race) and prove
        the gateway refuses with REDEEM_DENIED and still never calls the downstream."""
        gw, out = make_gateway(service, mode="crash")  # crash mode: forwarding would be fatal

        def fake_redeem(grant_id, principal, args):
            return {"redeemed": False, "reason": "already_redeemed",
                    "source_id": SOURCE_ID, "name": "reader"}

        monkeypatch.setattr(service, "redeem_grant", fake_redeem)
        replies = _drive(gw, out, {
            "jsonrpc": "2.0", "id": 16, "method": "tools/call",
            "params": {"name": "reader", "arguments": {"path": "/a"}},
        })
        assert replies[0]["error"]["code"] == REDEEM_DENIED
        # mode="crash" would have killed the fixture process had the call reached it;
        # the process exiting cleanly (no DOWNSTREAM_UNAVAILABLE) proves it never did.


class TestArgumentIntegrity:
    def test_forwarded_arguments_match_the_hash_that_was_authorized(self, service):
        """Args tampering between authorize and forward is impossible by construction:
        the gateway builds ONE frozen mapping and never re-reads `params` after it —
        proven here by cross-checking the grant's recorded args_hash, what the
        downstream fixture actually received, and the client's original arguments all
        agree, using ToolConnect's own canonical hasher as the independent check."""
        from toolconnect import hashing

        gw, out = make_gateway(service)
        args = {"path": "/etc/hosts", "flag": True, "n": 3}
        replies = _drive(gw, out, {
            "jsonrpc": "2.0", "id": 9, "method": "tools/call",
            "params": {"name": "reader", "arguments": args},
        })
        received = replies[0]["result"]["structuredContent"]["echoed_arguments"]
        assert received == args
        grant_issue = [r for r in service.read_audit(kind="grant_issue", limit=5)][0]
        assert grant_issue["body"]["args_hash"] == hashing.args_hash(args)
        assert grant_issue["body"]["args_hash"] == hashing.args_hash(received)


class TestDownstreamFaults:
    def test_downstream_crash_mid_call_reports_outcome_failure(self, service):
        gw, out = make_gateway(service, mode="crash", timeout=5.0)
        replies = _drive(gw, out, {
            "jsonrpc": "2.0", "id": 10, "method": "tools/call",
            "params": {"name": "reader", "arguments": {"path": "/a"}},
        })
        assert len(replies) == 1
        assert replies[0]["error"]["code"] == DOWNSTREAM_UNAVAILABLE
        outcome = [r for r in service.read_audit(kind="outcome", limit=5)][0]
        assert outcome["body"]["outcome"] == "error"
        # The grant was consumed (redeemed) even though the call then crashed —
        # authorization is not undone by a downstream failure after redemption.
        kinds = [r["kind"] for r in service.read_audit(limit=20)]
        assert "grant_redeem" in kinds

    def test_downstream_hang_times_out_and_reports_outcome_failure(self, service):
        gw, out = make_gateway(service, mode="hang", timeout=0.3)
        replies = _drive(gw, out, {
            "jsonrpc": "2.0", "id": 11, "method": "tools/call",
            "params": {"name": "reader", "arguments": {"path": "/a"}},
        })
        assert replies[0]["error"]["code"] == DOWNSTREAM_UNAVAILABLE
        outcome = [r for r in service.read_audit(kind="outcome", limit=5)][0]
        assert outcome["body"]["outcome"] == "error"

    def test_downstream_malformed_bytes_reports_outcome_failure(self, service):
        gw, out = make_gateway(service, mode="malformed", timeout=5.0)
        replies = _drive(gw, out, {
            "jsonrpc": "2.0", "id": 12, "method": "tools/call",
            "params": {"name": "reader", "arguments": {"path": "/a"}},
        })
        assert replies[0]["error"]["code"] == DOWNSTREAM_UNAVAILABLE
        outcome = [r for r in service.read_audit(kind="outcome", limit=5)][0]
        assert outcome["body"]["outcome"] == "error"

    def test_downstream_wellformed_rpc_error_is_relayed_and_marked_executed(self, service):
        """A well-formed JSON-RPC error from the tool server is a call-level outcome,
        not a transport failure: the grant IS consumed and the outcome IS "executed"
        — the call reached the server and the server made its own decision about it."""
        gw, out = make_gateway(service, mode="error", timeout=5.0)
        replies = _drive(gw, out, {
            "jsonrpc": "2.0", "id": 13, "method": "tools/call",
            "params": {"name": "reader", "arguments": {"path": "/a"}},
        })
        assert replies[0]["error"]["code"] == -32050
        assert "fixture error mode" in replies[0]["error"]["message"]
        outcome = [r for r in service.read_audit(kind="outcome", limit=5)][0]
        assert outcome["body"]["outcome"] == "executed"


class TestProtocolRefusals:
    def test_unpermitted_method_is_refused_without_forwarding(self, service):
        gw, out = make_gateway(service)
        replies = _drive(gw, out, {
            "jsonrpc": "2.0", "id": 14, "method": "resources/list", "params": {},
        })
        assert replies[0]["error"]["code"] == NOT_PERMITTED

    def test_batch_requests_are_refused_whole(self, service):
        before = len(service.read_audit(limit=100))
        gw, out = make_gateway(service)
        gw._in = StringIO(json.dumps([
            {"jsonrpc": "2.0", "id": 1, "method": "ping"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
             "params": {"name": "reader", "arguments": {}}},
        ]) + "\n")
        gw.run()
        replies = _lines(out)
        assert len(replies) == 1
        assert replies[0]["id"] is None
        assert "batch" in replies[0]["error"]["message"]
        # Nothing in the batch was forwarded or governed — no new audit trail at all.
        assert len(service.read_audit(limit=100)) == before

    def test_malformed_json_gets_a_parse_error_with_null_id(self, service):
        gw, out = make_gateway(service)
        gw._in = StringIO("not json at all\n")
        gw.run()
        replies = _lines(out)
        assert replies[0]["id"] is None
        assert replies[0]["error"]["code"] == -32700

    def test_unknown_tool_name_is_denied_not_forwarded(self, service):
        gw, out = make_gateway(service)
        replies = _drive(gw, out, {
            "jsonrpc": "2.0", "id": 15, "method": "tools/call",
            "params": {"name": "does-not-exist", "arguments": {}},
        })
        assert replies[0]["error"]["code"] == DENIED


class TestToolsListBounds:
    def test_cursor_cycle_is_refused_and_the_session_stays_alive(self, service):
        """A downstream that pages tools/list with a repeating nextCursor forever
        must be refused, not looped on: the gateway is single-threaded, so an
        unbounded pagination loop would wedge the whole session. The follow-up ping
        in the same session proves the gateway is still serving after the refusal."""
        gw, out = make_gateway(service, mode="list_cycle")
        replies = _drive(gw, out,
                         {"jsonrpc": "2.0", "id": 20, "method": "tools/list"},
                         {"jsonrpc": "2.0", "id": 21, "method": "ping"})
        assert len(replies) == 2
        assert replies[0]["error"]["code"] == DOWNSTREAM_UNAVAILABLE
        assert "cycle" in replies[0]["error"]["message"]
        assert replies[1] == {"jsonrpc": "2.0", "id": 21, "result": {}}

    def test_endless_fresh_cursors_hit_the_page_cap(self, service, monkeypatch):
        """Fresh (non-repeating) cursors forever must hit the page cap instead of
        paginating without end. Cap patched small so the test is fast; the code
        reads the module-level constant at call time."""
        monkeypatch.setattr(gateway_module, "_MAX_LIST_PAGES", 5)
        gw, out = make_gateway(service, mode="list_forever")
        replies = _drive(gw, out, {"jsonrpc": "2.0", "id": 22, "method": "tools/list"})
        assert replies[0]["error"]["code"] == DOWNSTREAM_UNAVAILABLE
        assert "pages" in replies[0]["error"]["message"]

    def test_accumulated_tool_count_is_bounded(self, service, monkeypatch):
        """Even below the page cap, the accumulated listing itself is bounded."""
        monkeypatch.setattr(gateway_module, "_MAX_LIST_TOOLS", 7)
        gw, out = make_gateway(service, mode="list_forever")
        replies = _drive(gw, out, {"jsonrpc": "2.0", "id": 23, "method": "tools/list"})
        assert replies[0]["error"]["code"] == DOWNSTREAM_UNAVAILABLE
        assert "tools" in replies[0]["error"]["message"]


class TestFrameBounds:
    def test_oversized_client_frame_is_refused_and_session_continues(self, service, monkeypatch):
        """A client line larger than the frame cap is refused with a null id (the id
        is unknowable without parsing it) and never buffered whole; the next line in
        the same session is served normally — no wedge, no memory blow-up."""
        monkeypatch.setattr(gateway_module, "_MAX_FRAME_BYTES", 4096)
        gw, out = make_gateway(service)
        big = '{"jsonrpc":"2.0","id":1,"method":"ping","pad":"' + "a" * 10000 + '"}'
        gw._in = StringIO(
            big + "\n" + json.dumps({"jsonrpc": "2.0", "id": 2, "method": "ping"}) + "\n")
        gw.run()
        replies = _lines(out)
        assert len(replies) == 2
        assert replies[0]["id"] is None
        assert replies[0]["error"]["code"] == INVALID_REQUEST
        assert "frame exceeds" in replies[0]["error"]["message"]
        assert replies[1] == {"jsonrpc": "2.0", "id": 2, "result": {}}

    def test_oversized_downstream_frame_is_refused_not_buffered(self, service, monkeypatch):
        """A downstream that floods one giant newline-less frame must produce a clean
        DOWNSTREAM_UNAVAILABLE (outcome recorded as error), not unbounded buffering
        until the per-call timeout — the buffer is capped and released."""
        monkeypatch.setattr(gateway_module, "_MAX_FRAME_BYTES", 4096)
        gw, out = make_gateway(service, mode="flood", timeout=10.0)
        replies = _drive(gw, out, {
            "jsonrpc": "2.0", "id": 32, "method": "tools/call",
            "params": {"name": "reader", "arguments": {"path": "/a"}},
        })
        assert replies[0]["error"]["code"] == DOWNSTREAM_UNAVAILABLE
        assert "exceeded" in replies[0]["error"]["message"]
        outcome = [r for r in service.read_audit(kind="outcome", limit=5)][0]
        assert outcome["body"]["outcome"] == "error"
        assert outcome["body"]["detail"]["fault_kind"] == "oversized_frame"


class TestOutcomeRecordingIsBestEffort:
    def test_non_serviceerror_outcome_fault_never_discards_a_successful_result(
            self, service, monkeypatch, capsys):
        """The downstream call already executed and its one-use grant is spent by the
        time the outcome is recorded; a raw sqlite3 fault there (NOT a ServiceError)
        must not turn the success into a reported failure — that would invite a
        client retry that double-executes a non-idempotent action."""
        import sqlite3

        def boom(*args, **kwargs):
            raise sqlite3.OperationalError("database is locked")

        monkeypatch.setattr(service, "record_outcome", boom)
        gw, out = make_gateway(service)
        replies = _drive(gw, out, {
            "jsonrpc": "2.0", "id": 30, "method": "tools/call",
            "params": {"name": "reader", "arguments": {"path": "/a"}},
        })
        assert len(replies) == 1
        assert replies[0]["result"]["structuredContent"]["echoed_arguments"] == {"path": "/a"}
        # Swallowed, but never silently: the fault is on stderr, not stdout.
        captured = capsys.readouterr()
        assert "outcome recording failed" in captured.err
        assert "outcome recording failed" not in out.getvalue()


class TestDownstreamReverseRequests:
    def test_reverse_request_is_refused_not_dropped(self, service):
        """A server-initiated request (sampling/createMessage) arriving mid-call gets
        an explicit METHOD_NOT_FOUND refusal so a downstream blocked on the reply is
        never deadlocked; the governed call then completes normally. If the gateway
        silently dropped the reverse request, this test would time out."""
        gw, out = make_gateway(service, mode="reverse", timeout=10.0)
        replies = _drive(gw, out, {
            "jsonrpc": "2.0", "id": 31, "method": "tools/call",
            "params": {"name": "reader", "arguments": {"path": "/a"}},
        })
        sc = replies[0]["result"]["structuredContent"]
        assert sc["echoed_arguments"] == {"path": "/a"}
        assert sc["reverse_reply_error_code"] == METHOD_NOT_FOUND
