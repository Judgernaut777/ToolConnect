"""Best-effort projection onto the shared Connect-ecosystem event bus
(``toolconnect.buspublish``, wired into ``ToolConnectService`` per
docs/EVENT_BUS.md §9's SHARED BUS WIRE CONTRACT).

Proves the three load-bearing properties the contract demands of every
publisher:

* when configured, each emit point (``authorize`` -> ``tool.authorized`` [+
  ``grant.issued`` on a granted permit], ``redeem_grant`` -> ``grant.redeemed``
  on success only, ``record_outcome`` -> ``tool.executed``) posts the right
  wire ``type``/``source_product``/payload shape to the bus;
* a disabled (unconfigured), dead, or erroring bus leaves ToolConnect's own
  return values byte-identical and never raises into the caller;
* no raw tool-call argument, and no other content the bus contract forbids,
  ever appears in an emitted body — checked at the raw-bytes level, the same
  posture AgentConnect's own ingress tests use for its side of this contract.

A real loopback socket is used for the fake bus server (mirrors
``test_grants_http.py``'s ``_loopback_available`` skip for the offline
``unshare -rn`` gate variant).
"""

from __future__ import annotations

import json
import socket
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from toolconnect.buspublish import (
    NO_PRINCIPAL_BUS_TIER,
    BusPublisher,
    bus_outcome_for_execution,
    bus_tier_for_principal,
)
from toolconnect.policy import CedarPolicyEngine
from toolconnect.service import ToolConnectService
from toolconnect.store import SqliteStore

ALLOW_READS = """
@id("allow-reads")
permit(principal, action == Action::"invoke", resource)
when { resource.effect == "read" };
"""

FORBID_ALL = "// no policies: everything default-denies"

CANARY_ARG = "CANARY_raw_argument_must_never_reach_the_bus"


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


class _FakeBus:
    """A tiny real HTTP server standing in for AgentConnect's `POST /events`.

    Records every request's raw body bytes AND the parsed JSON, so tests can
    assert both on structured fields and on raw-bytes absence of forbidden
    content (defense in depth — the same two-layer check the contract asks
    for: "no raw args/prompt/output/secret appears in any emitted body").
    """

    def __init__(self, *, status: int = 201, delay: float = 0.0) -> None:
        self.requests: list[dict] = []
        self.raw_bodies: list[bytes] = []
        self._status = status
        self._delay = delay
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):  # silence test output
                pass

            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                raw = self.rfile.read(length)
                if outer._delay:
                    time.sleep(outer._delay)
                outer.raw_bodies.append(raw)
                try:
                    outer.requests.append({
                        "path": self.path,
                        "auth": self.headers.get("Authorization", ""),
                        "body": json.loads(raw),
                    })
                except json.JSONDecodeError:
                    outer.requests.append({
                        "path": self.path,
                        "auth": self.headers.get("Authorization", ""),
                        "body": None,
                    })
                self.send_response(outer._status)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"seq": 1, "event_id": "ev-fake"}')

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    @property
    def url(self) -> str:
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}"

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()


@pytest.fixture()
def fake_bus():
    bus = _FakeBus()
    try:
        yield bus
    finally:
        bus.close()


def _svc(tmp_path, bus, policy: str = ALLOW_READS) -> ToolConnectService:
    store = SqliteStore(tmp_path / "tc.db")
    service = ToolConnectService(store, CedarPolicyEngine(policy), bus=bus)
    service.register_source("src1", "known")
    service.ingest_payload("src1", [{"name": "reader", "claimed": {"read_only_hint": True}}])
    service.assert_tool("src1", "reader", {"effect": "read", "asserted_by": "test-operator"})
    return service


PRINCIPAL = {"id": "agent-1", "privacy_tier": "local"}


# --------------------------------------------------------------------- configured


def test_authorize_allow_emits_tool_authorized_allowed(tmp_path, fake_bus):
    bus = BusPublisher(fake_bus.url, "tok-1")
    svc = _svc(tmp_path, bus)
    svc.authorize(PRINCIPAL, "src1", "reader")

    events = [r["body"] for r in fake_bus.requests]
    tool_events = [e for e in events if e["type"] == "tool.authorized"]
    assert len(tool_events) == 1
    e = tool_events[0]
    assert e["source_product"] == "toolconnect"
    # Contract §4.2: an allow carries NO outcome (null/absent = allow); "allowed"
    # is not a member of the closed outcome vocabulary. publish() omits the key.
    assert "outcome" not in e
    assert e["payload"]["principal_id"] == "agent-1"
    assert e["payload"]["source_id"] == "src1"
    assert e["payload"]["qualified_name"] == "src1:reader"
    assert e["payload"]["decision_id"]
    assert e["payload"]["grant_id"] is None  # legacy no-args call: no grant issued
    assert e["payload"]["args_hash"] is None


def test_authorize_deny_emits_tool_authorized_denied(tmp_path, fake_bus):
    bus = BusPublisher(fake_bus.url, "tok-1")
    svc = _svc(tmp_path, bus, policy=FORBID_ALL)
    svc.authorize(PRINCIPAL, "src1", "reader")

    events = [r["body"] for r in fake_bus.requests]
    tool_events = [e for e in events if e["type"] == "tool.authorized"]
    assert len(tool_events) == 1
    assert tool_events[0]["outcome"] == "denied"


def test_authorize_with_granted_args_also_emits_grant_issued(tmp_path, fake_bus):
    bus = BusPublisher(fake_bus.url, "tok-1")
    svc = _svc(tmp_path, bus)
    decision = svc.authorize(PRINCIPAL, "src1", "reader", args={"q": "hello"})
    grant_id = decision["grant"]["grant_id"]

    events = [r["body"] for r in fake_bus.requests]
    types = [e["type"] for e in events]
    assert types == ["tool.authorized", "grant.issued"]
    tool_evt, grant_evt = events
    assert tool_evt["payload"]["grant_id"] == grant_id
    assert tool_evt["payload"]["args_hash"] == decision["grant"]["args_hash"]
    assert grant_evt["source_product"] == "toolconnect"
    assert grant_evt["payload"]["grant_id"] == grant_id
    assert grant_evt["payload"]["args_hash"] == decision["grant"]["args_hash"]
    assert grant_evt["payload"]["qualified_name"] == "src1:reader"


def test_denied_authorize_with_args_does_not_emit_grant_issued(tmp_path, fake_bus):
    bus = BusPublisher(fake_bus.url, "tok-1")
    svc = _svc(tmp_path, bus, policy=FORBID_ALL)
    svc.authorize(PRINCIPAL, "src1", "reader", args={"q": "hello"})

    types = [r["body"]["type"] for r in fake_bus.requests]
    assert types == ["tool.authorized"]  # no grant.issued alongside a deny


def test_successful_redeem_emits_grant_redeemed(tmp_path, fake_bus):
    bus = BusPublisher(fake_bus.url, "tok-1")
    svc = _svc(tmp_path, bus)
    decision = svc.authorize(PRINCIPAL, "src1", "reader", args={"q": "hello"})
    grant_id = decision["grant"]["grant_id"]
    fake_bus.requests.clear()  # isolate the redeem call's own emission

    result = svc.redeem_grant(grant_id, PRINCIPAL, {"q": "hello"})
    assert result["redeemed"] is True

    events = [r["body"] for r in fake_bus.requests]
    assert [e["type"] for e in events] == ["grant.redeemed"]
    e = events[0]
    assert e["source_product"] == "toolconnect"
    assert e["payload"]["grant_id"] == grant_id
    assert e["payload"]["principal_id"] == "agent-1"
    assert e["payload"]["qualified_name"] == "src1:reader"


def test_denied_redeem_does_not_emit_grant_redeemed(tmp_path, fake_bus):
    bus = BusPublisher(fake_bus.url, "tok-1")
    svc = _svc(tmp_path, bus)
    decision = svc.authorize(PRINCIPAL, "src1", "reader", args={"q": "hello"})
    grant_id = decision["grant"]["grant_id"]
    fake_bus.requests.clear()

    # Wrong args -> the one-use grant's arg-binding check refuses the redemption.
    result = svc.redeem_grant(grant_id, PRINCIPAL, {"q": "WRONG"})
    assert result["redeemed"] is False

    types = [r["body"]["type"] for r in fake_bus.requests]
    assert "grant.redeemed" not in types


def test_record_outcome_emits_tool_executed(tmp_path, fake_bus):
    bus = BusPublisher(fake_bus.url, "tok-1")
    svc = _svc(tmp_path, bus)
    decision = svc.authorize(PRINCIPAL, "src1", "reader", args={"q": "hello"})
    grant_id = decision["grant"]["grant_id"]
    svc.redeem_grant(grant_id, PRINCIPAL, {"q": "hello"})
    fake_bus.requests.clear()

    svc.record_outcome(decision["decision_id"], "executed", grant_id=grant_id)

    events = [r["body"] for r in fake_bus.requests]
    assert [e["type"] for e in events] == ["tool.executed"]
    e = events[0]
    assert e["source_product"] == "toolconnect"
    # Contract §1: `outcome` is a closed vocabulary. ToolConnect's free-form
    # "executed" is mapped onto "succeeded", never forwarded verbatim.
    assert e["outcome"] == "succeeded"
    assert e["payload"]["decision_id"] == decision["decision_id"]
    assert e["payload"]["grant_id"] == grant_id
    assert e["payload"]["principal_id"] == "agent-1"
    assert e["payload"]["qualified_name"] == "src1:reader"


def test_publish_carries_bearer_token_and_source_product(tmp_path, fake_bus):
    bus = BusPublisher(fake_bus.url, "tok-secret")
    svc = _svc(tmp_path, bus)
    svc.authorize(PRINCIPAL, "src1", "reader")

    assert fake_bus.requests
    req = fake_bus.requests[0]
    assert req["path"] == "/events"
    assert req["auth"] == "Bearer tok-secret"
    assert req["body"]["source_product"] == "toolconnect"


# ----------------------------------------------------------------- never-fatal


def test_unconfigured_bus_is_a_pure_no_op(tmp_path, monkeypatch):
    """No TOOLCONNECT_BUS_URL/_TOKEN -> BusPublisher.from_env() is disabled ->
    the network is never touched at all (not even attempted and swallowed)."""
    monkeypatch.delenv("TOOLCONNECT_BUS_URL", raising=False)
    monkeypatch.delenv("TOOLCONNECT_BUS_TOKEN", raising=False)

    called = {"n": 0}

    def _boom(*a, **k):
        called["n"] += 1
        raise AssertionError("urlopen must never be called by a disabled publisher")

    monkeypatch.setattr("urllib.request.urlopen", _boom)

    store = SqliteStore(tmp_path / "tc.db")
    svc = ToolConnectService(store, CedarPolicyEngine(ALLOW_READS))
    assert svc.bus.enabled is False
    svc.register_source("src1", "known")
    svc.ingest_payload("src1", [{"name": "reader", "claimed": {"read_only_hint": True}}])
    svc.assert_tool("src1", "reader", {"effect": "read", "asserted_by": "test-operator"})
    result = svc.authorize(PRINCIPAL, "src1", "reader")
    assert result["allowed"] is True
    assert called["n"] == 0


def test_dead_bus_leaves_authorize_result_byte_identical(tmp_path):
    """Point the publisher at a port nothing is listening on (connection
    refused) — ToolConnect's own return value/behavior must be unaffected,
    and nothing may raise into the caller."""
    # Grab a free port and immediately release it so nothing listens there.
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    dead_port = probe.getsockname()[1]
    probe.close()

    bus_dead = BusPublisher(f"http://127.0.0.1:{dead_port}", "tok-1", timeout=0.5)
    bus_none = BusPublisher(None, None)

    svc_dead = _svc(tmp_path / "dead", bus_dead)
    svc_none = _svc(tmp_path / "none", bus_none)

    result_dead = svc_dead.authorize(PRINCIPAL, "src1", "reader")
    result_none = svc_none.authorize(PRINCIPAL, "src1", "reader")

    for r in (result_dead, result_none):
        r.pop("decision_id")  # the one field that legitimately differs run-to-run
    assert result_dead == result_none


def test_erroring_bus_response_does_not_raise_or_change_result(tmp_path):
    err_bus = _FakeBus(status=500)
    try:
        bus = BusPublisher(err_bus.url, "tok-1")
        svc = _svc(tmp_path, bus)
        # Must not raise despite the fake bus answering every publish with a 500.
        result = svc.authorize(PRINCIPAL, "src1", "reader")
        assert result["allowed"] is True
        assert err_bus.requests  # the publish really was attempted
    finally:
        err_bus.close()


def test_slow_bus_is_bounded_by_a_short_timeout(tmp_path):
    """A bus that never answers within the publisher's timeout must not hang
    the caller beyond that bound (module docstring's stated tradeoff: bounded,
    not unbounded, blocking)."""
    slow_bus = _FakeBus(delay=2.0)
    try:
        bus = BusPublisher(slow_bus.url, "tok-1", timeout=0.2)
        svc = _svc(tmp_path, bus)
        start = time.monotonic()
        result = svc.authorize(PRINCIPAL, "src1", "reader")
        elapsed = time.monotonic() - start
        assert result["allowed"] is True
        assert elapsed < 1.5  # well under the fake bus's 2s delay
    finally:
        slow_bus.close()


def test_redeem_and_record_outcome_unaffected_by_dead_bus(tmp_path):
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    dead_port = probe.getsockname()[1]
    probe.close()
    bus = BusPublisher(f"http://127.0.0.1:{dead_port}", "tok-1", timeout=0.5)
    svc = _svc(tmp_path, bus)

    decision = svc.authorize(PRINCIPAL, "src1", "reader", args={"q": "hello"})
    grant_id = decision["grant"]["grant_id"]
    redemption = svc.redeem_grant(grant_id, PRINCIPAL, {"q": "hello"})
    assert redemption["redeemed"] is True
    outcome = svc.record_outcome(decision["decision_id"], "executed", grant_id=grant_id)
    assert outcome["grant_closed"] is True


# ------------------------------------------------------------------- no raw args


def test_no_raw_args_in_any_emitted_body_bytes(tmp_path, fake_bus):
    """The canary sits only in the invocation ARGS — authorize()/redeem_grant()
    only ever bind and forward the args_hash. It must never appear in any
    emitted body, checked at the raw-bytes level (not just the parsed JSON, so
    a stray unstructured string field would be caught too)."""
    bus = BusPublisher(fake_bus.url, "tok-1")
    svc = _svc(tmp_path, bus)
    decision = svc.authorize(
        PRINCIPAL, "src1", "reader", args={"secret_field": CANARY_ARG})
    grant_id = decision["grant"]["grant_id"]
    svc.redeem_grant(grant_id, PRINCIPAL, {"secret_field": CANARY_ARG})
    svc.record_outcome(decision["decision_id"], "executed", grant_id=grant_id)

    # Exactly the four emits this flow fires — tool.authorized, grant.issued,
    # grant.redeemed, tool.executed. Pinning the count (not `>= 3`) keeps this the
    # byte-level canary for EVERY emitted body: if a future regression drops one of
    # the four emits, this leak scan notices the missing body instead of silently
    # scanning the survivors.
    assert len(fake_bus.raw_bodies) == 4
    for raw in fake_bus.raw_bodies:
        assert CANARY_ARG.encode("utf-8") not in raw
        assert b"secret_field" not in raw


def test_no_raw_args_leak_even_on_a_denied_authorize(tmp_path, fake_bus):
    bus = BusPublisher(fake_bus.url, "tok-1")
    svc = _svc(tmp_path, bus, policy=FORBID_ALL)
    svc.authorize(PRINCIPAL, "src1", "reader", args={"secret_field": CANARY_ARG})

    assert fake_bus.raw_bodies
    for raw in fake_bus.raw_bodies:
        assert CANARY_ARG.encode("utf-8") not in raw


# ---------------------------------------------------- privacy-tier translation (unit)


def test_bus_tier_for_principal_maps_each_compute_trust_tier():
    # The deliberate compute-trust -> content-sensitivity translation the module
    # docstring documents. Locked so a swapped mapping can't pass silently.
    assert bus_tier_for_principal("local") == "public"
    assert bus_tier_for_principal("trusted-cloud") == "repo_sensitive"
    assert bus_tier_for_principal("rented") == "local_only"


def test_bus_tier_for_principal_unknown_tier_fails_closed():
    # An unrecognized/missing tier MUST fail closed to the tightest content tier,
    # never fail open (e.g. to "public"). This is the security-relevant default.
    assert bus_tier_for_principal("wat-is-this") == "secret_sensitive"
    assert bus_tier_for_principal("") == "secret_sensitive"
    assert bus_tier_for_principal(None) == "secret_sensitive"


# ------------------------------------------- privacy-tier translation (on the wire)


def test_emitted_privacy_tier_reflects_a_trusted_cloud_principal(tmp_path, fake_bus):
    bus = BusPublisher(fake_bus.url, "tok-1")
    svc = _svc(tmp_path, bus)
    principal = {"id": "agent-tc", "privacy_tier": "trusted-cloud"}
    svc.authorize(principal, "src1", "reader", args={"q": "hello"})

    events = [r["body"] for r in fake_bus.requests]
    assert {e["type"] for e in events} == {"tool.authorized", "grant.issued"}
    for e in events:  # both authorize-path emits carry the translated tier
        assert e["privacy_tier"] == "repo_sensitive"


def test_emitted_privacy_tier_reflects_a_rented_principal(tmp_path, fake_bus):
    bus = BusPublisher(fake_bus.url, "tok-1")
    svc = _svc(tmp_path, bus)
    principal = {"id": "agent-rent", "privacy_tier": "rented"}
    svc.authorize(principal, "src1", "reader")

    e = [r["body"] for r in fake_bus.requests if r["body"]["type"] == "tool.authorized"][0]
    assert e["privacy_tier"] == "local_only"


def test_redeemed_event_carries_translated_privacy_tier(tmp_path, fake_bus):
    bus = BusPublisher(fake_bus.url, "tok-1")
    svc = _svc(tmp_path, bus)
    principal = {"id": "agent-tc", "privacy_tier": "trusted-cloud"}
    decision = svc.authorize(principal, "src1", "reader", args={"q": "hello"})
    grant_id = decision["grant"]["grant_id"]
    fake_bus.requests.clear()

    svc.redeem_grant(grant_id, principal, {"q": "hello"})
    e = [r["body"] for r in fake_bus.requests][0]
    assert e["type"] == "grant.redeemed"
    assert e["privacy_tier"] == "repo_sensitive"


def test_tool_executed_uses_no_principal_bus_tier(tmp_path, fake_bus):
    # record_outcome carries no principal, so its event uses the module's
    # NO_PRINCIPAL_BUS_TIER constant. Pin it so a regression can't drift it.
    bus = BusPublisher(fake_bus.url, "tok-1")
    svc = _svc(tmp_path, bus)
    decision = svc.authorize(PRINCIPAL, "src1", "reader", args={"q": "hello"})
    grant_id = decision["grant"]["grant_id"]
    svc.redeem_grant(grant_id, PRINCIPAL, {"q": "hello"})
    fake_bus.requests.clear()

    svc.record_outcome(decision["decision_id"], "executed", grant_id=grant_id)
    e = [r["body"] for r in fake_bus.requests][0]
    assert e["type"] == "tool.executed"
    assert e["privacy_tier"] == NO_PRINCIPAL_BUS_TIER == "public"


# --------------------------------------------- outcome vocabulary mapping (executed)


def test_bus_outcome_for_execution_maps_onto_closed_vocabulary():
    vocab = {"succeeded", "failed", "cancelled", "denied", "timed_out", "unknown"}
    for raw in ("success", "succeeded", "executed", "ok", "completed", "done"):
        assert bus_outcome_for_execution(raw) == "succeeded"
    assert bus_outcome_for_execution("failure") == "failed"
    assert bus_outcome_for_execution("error") == "failed"
    assert bus_outcome_for_execution("cancelled") == "cancelled"
    assert bus_outcome_for_execution("denied") == "denied"
    assert bus_outcome_for_execution("timeout") == "timed_out"
    # Arbitrary caller text never pollutes the closed field — it buckets to "unknown".
    assert bus_outcome_for_execution("a string") == "unknown"
    assert bus_outcome_for_execution("") == "unknown"
    assert bus_outcome_for_execution(None) == "unknown"
    for raw in ("success", "a string", None):
        assert bus_outcome_for_execution(raw) in vocab


def test_arbitrary_record_outcome_string_is_bucketed_not_forwarded(tmp_path, fake_bus):
    bus = BusPublisher(fake_bus.url, "tok-1")
    svc = _svc(tmp_path, bus)
    decision = svc.authorize(PRINCIPAL, "src1", "reader", args={"q": "hello"})
    grant_id = decision["grant"]["grant_id"]
    svc.redeem_grant(grant_id, PRINCIPAL, {"q": "hello"})
    fake_bus.requests.clear()

    svc.record_outcome(decision["decision_id"], "a string", grant_id=grant_id)
    e = [r["body"] for r in fake_bus.requests][0]
    assert e["type"] == "tool.executed"
    assert e["outcome"] == "unknown"  # not the raw "a string"
