"""``toolconnect gateway`` — the one audited path: an MCP stdio enforcement proxy.

This is the Policy Enforcement Point (PEP) the review asked for, sitting in front of
exactly one downstream MCP server command. It speaks MCP to whatever client spawned
it (an agent runtime, an IDE, `claude` itself), and for every ``tools/call`` it runs:

    extract final arguments -> authorize(args=...) -> redeem the grant
        -> forward to the downstream server -> record the outcome -> return the result

Every other message either passes through unchanged (a small, enumerated set of
protocol plumbing that is provably side-effect-free — see ``_PASSTHROUGH_REQUESTS``/
``_PASSTHROUGH_NOTIFICATIONS``) or is refused without ever reaching the downstream
server. ``tools/list`` is answered from the downstream server's own listing, filtered
down to what this gateway's catalog currently has asserted and invocable.

Doctrine (ADR 0003): the *decision* stays a PDP — ``ToolConnectService`` is used
in-process, unmodified, exactly as ``serve`` uses it. The gateway is a separable,
optional PEP that FORWARDS calls; it never implements a tool itself, so this module
still has no ``invoke()`` of its own — it has a ``call()`` on the downstream link,
which is the wire mechanics of forwarding, not a tool implementation.

Fail-closed applies to the whole surface, not just the governed path: a malformed
client message, a deny, a failed redemption, a downstream transport fault, or a
method outside the enumerated allow-list all refuse — nothing is ever forwarded to
the downstream server except an authorized, redeemed ``tools/call`` or one of the
two passthrough requests.

Fail-closed includes resource bounds. The gateway is a long-lived enforcement point,
so nothing on either stream may buffer or loop without limit: a frame larger than
``_MAX_FRAME_BYTES`` from the client or the downstream is refused (never buffered
whole), ``tools/list`` pagination is capped at ``_MAX_LIST_PAGES`` pages /
``_MAX_LIST_TOOLS`` accumulated entries with repeated-cursor cycle detection, and a
downstream-initiated JSON-RPC request (e.g. ``sampling/createMessage``) is answered
with a method-not-found refusal rather than silently dropped, so a downstream blocked
on that reply is never deadlocked.
"""

from __future__ import annotations

import json
import os
import select
import subprocess
import sys
import time
from typing import IO, Any, Mapping, Sequence

from .service import ServiceError, ToolConnectService

# -- JSON-RPC error codes -----------------------------------------------------
#
# Standard codes (JSON-RPC 2.0 spec) for shape failures the gateway itself detects.
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603

# -- hard resource bounds ------------------------------------------------------
#
# The gateway is a single-threaded, long-lived enforcement point: anything unbounded
# on either stream is a denial-of-service against every governed call that would
# follow. These are refusal thresholds, not tuning knobs — exceeding one refuses the
# offending message (fail-closed), it never degrades to partial trust.
_MAX_FRAME_BYTES = 8 * 1024 * 1024  # one newline-delimited JSON-RPC frame, either direction
_MAX_LIST_PAGES = 100               # tools/list pages per single client request
_MAX_LIST_TOOLS = 10_000            # tools accumulated across those pages

# ToolConnect-specific refusals, in the JSON-RPC reserved "server error" range
# (-32000..-32099 per the spec). These never collide with a real downstream server's
# own error codes, which are relayed to the client verbatim rather than reinterpreted
# (see ``DownstreamRpcError``).
DENIED = -32001                  # authorize() denied the call
REDEEM_DENIED = -32002           # the one-use grant could not be redeemed
DOWNSTREAM_UNAVAILABLE = -32003  # a transport-level fault talking to the downstream
NOT_PERMITTED = -32004           # method is outside the gateway's governed/passthrough surface


class DownstreamTransportError(Exception):
    """A transport-level fault talking to the downstream server.

    Distinct from a well-formed JSON-RPC error *response* (see ``DownstreamRpcError``):
    this covers spawn failure, a timeout, a truncated/closed stream, or bytes that do
    not parse as JSON — the call never reached a point where the server made an
    authoritative decision about it. Mirrors ``mcp_source.McpDiscoveryError``'s fault
    taxonomy, adapted for a long-lived connection rather than a one-shot discovery.
    """

    def __init__(self, kind: str, message: str) -> None:
        super().__init__(message)
        self.kind = kind


class DownstreamRpcError(Exception):
    """The downstream server answered with a well-formed JSON-RPC error object.

    The call reached the server and it made an authoritative decision about it —
    the gateway relays that decision to the client verbatim (same code/message/data)
    rather than reinterpreting it. A redeemed grant that ends here is "executed", not
    "error": ToolConnect authorized and forwarded the call; what the tool server did
    with it is the tool server's own business.
    """

    def __init__(self, code: int, message: str, data: Any = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.data = data


class _DownstreamLink:
    """A persistent newline-delimited JSON-RPC stdio connection to the downstream
    server, alive for the gateway's whole lifetime.

    ``mcp_source._StdioTransport`` is built for one bounded discovery run: a single
    deadline covers its entire lifetime, which is wrong for a connection that may sit
    idle for minutes between calls. This gives every ``call()`` its own fresh
    timeout instead, while reusing the same real wire shape (newline-delimited JSON-RPC
    2.0 over stdio) mcp_source already speaks.
    """

    def __init__(self, command: Sequence[str]) -> None:
        try:
            self._proc = subprocess.Popen(
                list(command), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, env={**os.environ})
        except (OSError, ValueError) as exc:
            raise DownstreamTransportError(
                "spawn_failed", f"could not start {list(command)!r}: {exc}")
        self._buf = b""
        self._eof = False
        self._next_id = 1

    def close(self) -> None:
        proc = self._proc
        for stream in (proc.stdin, proc.stdout):
            try:
                if stream:
                    stream.close()
            except OSError:
                pass
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()

    def _send(self, message: dict) -> None:
        line = json.dumps(message, separators=(",", ":")) + "\n"
        try:
            assert self._proc.stdin is not None
            self._proc.stdin.write(line.encode("utf-8"))
            self._proc.stdin.flush()
        except (BrokenPipeError, OSError) as exc:
            raise DownstreamTransportError(
                "broken_pipe", f"downstream server closed stdin: {exc}")

    def _read_line(self, deadline: float) -> bytes:
        assert self._proc.stdout is not None
        fd = self._proc.stdout.fileno()
        while b"\n" not in self._buf:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise DownstreamTransportError(
                    "timeout", "downstream server did not respond before the deadline")
            if self._eof:
                raise DownstreamTransportError(
                    "truncated_response",
                    f"downstream stream ended mid-message ({len(self._buf)} "
                    f"unterminated bytes)")
            ready, _, _ = select.select([fd], [], [], min(remaining, 0.25))
            if not ready:
                continue
            chunk = os.read(fd, 65536)
            if chunk == b"":
                self._eof = True
                if not self._buf:
                    raise DownstreamTransportError(
                        "truncated_response",
                        "downstream closed the stream with no response")
                continue
            self._buf += chunk
            if b"\n" not in self._buf and len(self._buf) > _MAX_FRAME_BYTES:
                # An oversized frame must be refused, not buffered without bound:
                # this link lives for the gateway's whole lifetime, so an unbounded
                # buffer is a memory-exhaustion DoS against every call that follows.
                # Drop the buffer (the stream is mid-frame and unrecoverable anyway)
                # so the memory is released, then fail the call.
                size = len(self._buf)
                self._buf = b""
                raise DownstreamTransportError(
                    "oversized_frame",
                    f"downstream frame exceeded {_MAX_FRAME_BYTES} bytes "
                    f"({size} buffered with no newline)")
        line, self._buf = self._buf.split(b"\n", 1)
        return line

    def _receive(self, deadline: float) -> dict:
        line = self._read_line(deadline)
        try:
            msg = json.loads(line)
        except json.JSONDecodeError as exc:
            raise DownstreamTransportError(
                "malformed_json", f"unparseable frame from downstream: {exc}")
        if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0":
            raise DownstreamTransportError(
                "protocol_error",
                f"frame is not a JSON-RPC 2.0 message: {line[:200]!r}")
        return msg

    def call(self, method: str, params: dict | None, timeout: float) -> dict:
        """One request/response round trip. Returns the response's ``result`` object.

        Raises ``DownstreamRpcError`` for a well-formed JSON-RPC error reply, or
        ``DownstreamTransportError`` for any transport-level fault. A frame whose
        ``id`` does not match this call (a stray notification, an unrelated push) is
        skipped over — the same discipline ``mcp_source._StdioTransport.request``
        uses, so out-of-band server chatter can never be mistaken for this call's
        answer.
        """
        req_id = self._next_id
        self._next_id += 1
        deadline = time.monotonic() + timeout
        self._send({"jsonrpc": "2.0", "id": req_id, "method": method,
                   "params": params if params is not None else {}})
        while True:
            msg = self._receive(deadline)
            if msg.get("id") != req_id:
                if "method" in msg and msg.get("id") is not None:
                    # A server-initiated request (sampling/createMessage, roots/list,
                    # elicitation, ...). This gateway brokers client->server tool calls
                    # only and has no basis to answer on the client's behalf — but a
                    # silent drop would deadlock a well-behaved downstream blocked on
                    # the reply. Refuse it explicitly instead.
                    self._send({"jsonrpc": "2.0", "id": msg["id"], "error": {
                        "code": METHOD_NOT_FOUND,
                        "message": "server-initiated requests are not supported "
                                   "through the ToolConnect gateway"}})
                continue
            if "error" in msg:
                err = msg["error"] if isinstance(msg["error"], dict) else {}
                raise DownstreamRpcError(
                    int(err.get("code") or INTERNAL_ERROR),
                    str(err.get("message") or "downstream error"),
                    err.get("data"))
            if "result" not in msg:
                raise DownstreamTransportError(
                    "protocol_error", f"{method} response has neither result nor error")
            result = msg["result"]
            return result if isinstance(result, dict) else {}

    def notify(self, method: str, params: dict | None = None) -> None:
        """Fire-and-forget notification; no response is expected or awaited."""
        self._send({"jsonrpc": "2.0", "method": method,
                   "params": params if params is not None else {}})


# -- the gateway's enumerated protocol surface --------------------------------------
#
# Every MCP request/notification method is enumerated below into exactly one bucket.
# Nothing reaches the downstream server through any other path.
#
# initialize / ping (requests): forwarded verbatim, result/error relayed as-is. Both
#   are provably side-effect-free protocol plumbing — a capability handshake and a
#   liveness probe — neither can smuggle a tool invocation.
# notifications/initialized: forwarded verbatim; it is the handshake completion the
#   MCP spec requires before a server will answer tools/list. No response exists to
#   refuse it with even if it were unwanted.
# tools/list: NOT forwarded raw. The gateway performs its own paginated tools/list
#   against the downstream server, then answers with only the tools that are
#   currently asserted+invocable in this gateway's catalog — an unasserted or
#   never-registered tool is invisible to the client, never merely uncallable.
# tools/call: the governed path (see ``_handle_tools_call``).
# Every other request method (resources/*, prompts/*, completion/*, logging/*,
#   sampling/*, roots/*, and anything unrecognized): refused with NOT_PERMITTED,
#   never forwarded. This gateway governs tool calls; it has no basis to reason
#   about what any other capability class would do downstream, so it does not
#   guess — it refuses.
# Every other notification: silently dropped (not forwarded, and nothing is sent
#   back — notifications carry no response to refuse with under JSON-RPC). Dropping
#   is the fail-closed choice for anything not explicitly vetted above.
# Downstream-initiated requests (a server request arriving on the same duplex link,
#   e.g. sampling/createMessage): answered toward the DOWNSTREAM with
#   METHOD_NOT_FOUND, never relayed to the client — see ``_DownstreamLink.call``.
#   Refusing (rather than dropping) keeps a downstream that blocks on the reply
#   from deadlocking its connection.
# JSON-RPC batch requests (a top-level JSON array): refused whole. MCP's
#   2025-06-18 revision dropped batch support, and admitting one here would mean
#   proving no entry in the array smuggles a tools/call past the governed path
#   before the gateway could safely process any of them — refuse rather than
#   partially trust it.

_PASSTHROUGH_REQUESTS = frozenset({"initialize", "ping"})
_PASSTHROUGH_NOTIFICATIONS = frozenset({"notifications/initialized"})
_FILTERED_LIST = "tools/list"
_GOVERNED_CALL = "tools/call"


class Gateway:
    """Speaks MCP to a client over stdio; enforces authorize -> redeem -> forward
    for every ``tools/call`` against one downstream MCP server subprocess.

    Uses ``ToolConnectService`` in-process (the same object ``serve`` uses over
    HTTP) — no HTTP round trip, one process, and the decision core stays exactly
    what it always was: a PDP that is never itself in the invocation data path.
    """

    def __init__(self, service: ToolConnectService, *, principal: Mapping[str, Any],
                 source_id: str, command: Sequence[str],
                 client_in: IO[str], client_out: IO[str],
                 timeout: float = 30.0) -> None:
        if not source_id:
            raise ValueError("gateway requires a source_id")
        if not command:
            raise ValueError("gateway requires a downstream command")
        self.service = service
        self.principal = dict(principal)
        self.source_id = source_id
        self.timeout = timeout
        self._in = client_in
        self._out = client_out
        self._downstream = _DownstreamLink(command)

    def run(self) -> int:
        """Read client messages until EOF, dispatching each. Never raises: any bug
        reaching here is logged to stderr (never stdout — that would corrupt the MCP
        stream) and the session continues with the next message."""
        try:
            while True:
                # Bounded read: never buffer an arbitrarily large client line whole.
                # readline(n) returns at most n characters, so a frame is held in
                # memory only up to the cap before it is refused.
                line = self._in.readline(_MAX_FRAME_BYTES + 1)
                if line == "":
                    break
                if len(line) > _MAX_FRAME_BYTES and not line.endswith("\n"):
                    # Oversized frame. Drain the rest of the line in bounded chunks
                    # (discarding, never accumulating), refuse it — the id is
                    # unknowable without parsing, so JSON-RPC prescribes null — and
                    # resync on the next line.
                    while True:
                        rest = self._in.readline(_MAX_FRAME_BYTES)
                        if rest == "" or rest.endswith("\n"):
                            break
                    try:
                        self._refuse(None, INVALID_REQUEST,
                                    f"frame exceeds {_MAX_FRAME_BYTES} bytes; refused")
                    except Exception as exc:  # never crash the session from a refusal
                        print(f"toolconnect gateway: internal error: {exc}",
                             file=sys.stderr, flush=True)
                    continue
                line = line.strip()
                if not line:
                    continue
                try:
                    self._handle_line(line)
                except Exception as exc:  # a bug here must never crash the session
                    print(f"toolconnect gateway: internal error: {exc}",
                         file=sys.stderr, flush=True)
        finally:
            self._downstream.close()
        return 0

    # -- wire plumbing ----------------------------------------------------------

    def _write(self, message: dict) -> None:
        self._out.write(json.dumps(message, separators=(",", ":")) + "\n")
        self._out.flush()

    def _respond(self, req_id: Any, result: Any) -> None:
        self._write({"jsonrpc": "2.0", "id": req_id, "result": result})

    def _refuse(self, req_id: Any, code: int, message: str, data: Any = None) -> None:
        err: dict = {"code": code, "message": message}
        if data is not None:
            err["data"] = data
        self._write({"jsonrpc": "2.0", "id": req_id, "error": err})

    def _handle_line(self, line: str) -> None:
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            # The id is unknowable from unparseable bytes; JSON-RPC prescribes `null`.
            self._refuse(None, PARSE_ERROR, "invalid JSON")
            return
        if isinstance(msg, list):
            self._refuse(None, INVALID_REQUEST,
                        "batched requests are not permitted through this gateway")
            return
        if not isinstance(msg, dict):
            self._refuse(None, INVALID_REQUEST, "message must be a JSON object")
            return
        has_id = "id" in msg
        req_id = msg.get("id") if has_id else None
        if msg.get("jsonrpc") != "2.0":
            if has_id:
                self._refuse(req_id, INVALID_REQUEST, "missing or wrong jsonrpc version")
            return
        method = msg.get("method")
        if not isinstance(method, str) or not method:
            if has_id:
                self._refuse(req_id, INVALID_REQUEST, "missing or invalid method")
            return
        params = msg.get("params")
        if params is not None and not isinstance(params, Mapping):
            if has_id:
                self._refuse(req_id, INVALID_PARAMS, "params must be an object")
            return
        try:
            if not has_id:
                self._dispatch_notification(method, params)
            else:
                self._dispatch_request(req_id, method, params or {})
        except Exception as exc:  # a bug in dispatch must still answer, never hang the client
            if has_id:
                self._refuse(req_id, INTERNAL_ERROR, f"gateway internal error: {exc}")

    # -- dispatch -----------------------------------------------------------------

    def _dispatch_notification(self, method: str, params: Mapping[str, Any] | None) -> None:
        if method in _PASSTHROUGH_NOTIFICATIONS:
            try:
                self._downstream.notify(method, dict(params or {}))
            except DownstreamTransportError:
                pass  # no response channel exists to carry this failure back on
        # Every other notification is dropped — see the surface enumeration above.

    def _dispatch_request(self, req_id: Any, method: str, params: Mapping[str, Any]) -> None:
        if method in _PASSTHROUGH_REQUESTS:
            self._forward_passthrough(req_id, method, dict(params))
            return
        if method == _FILTERED_LIST:
            self._handle_tools_list(req_id)
            return
        if method == _GOVERNED_CALL:
            self._handle_tools_call(req_id, params)
            return
        self._refuse(req_id, NOT_PERMITTED,
                    f"method {method!r} is not permitted through the ToolConnect gateway")

    def _forward_passthrough(self, req_id: Any, method: str, params: dict) -> None:
        try:
            result = self._downstream.call(method, params, self.timeout)
        except DownstreamRpcError as exc:
            self._refuse(req_id, exc.code, exc.message, exc.data)
        except DownstreamTransportError as exc:
            self._refuse(req_id, DOWNSTREAM_UNAVAILABLE, f"downstream unavailable: {exc}")
        else:
            self._respond(req_id, result)

    def _handle_tools_list(self, req_id: Any) -> None:
        tools: list[Any] = []
        cursor: str | None = None
        seen_cursors: set[str] = set()
        pages = 0
        try:
            while True:
                params = {"cursor": cursor} if cursor is not None else {}
                result = self._downstream.call("tools/list", params, self.timeout)
                page = result.get("tools")
                if not isinstance(page, list):
                    raise DownstreamTransportError(
                        "protocol_error", "tools/list result lacks a tools array")
                tools.extend(page)
                pages += 1
                if len(tools) > _MAX_LIST_TOOLS:
                    raise DownstreamTransportError(
                        "protocol_error",
                        f"tools/list accumulated more than {_MAX_LIST_TOOLS} tools "
                        f"— refusing rather than growing without bound")
                next_cursor = result.get("nextCursor")
                if next_cursor is None:
                    break
                # Pagination termination is downstream-controlled data, and the
                # downstream is not trusted (this gateway already refuses to trust
                # its listing content). A cycling cursor or an endless page stream
                # would otherwise wedge this single-threaded gateway forever —
                # refuse instead; the handler below turns it into a clean
                # DOWNSTREAM_UNAVAILABLE.
                if not isinstance(next_cursor, str):
                    raise DownstreamTransportError(
                        "protocol_error", "tools/list nextCursor is not a string")
                if next_cursor in seen_cursors:
                    raise DownstreamTransportError(
                        "protocol_error",
                        "tools/list pagination cycled (cursor repeated) — refusing "
                        "rather than looping forever")
                if pages >= _MAX_LIST_PAGES:
                    raise DownstreamTransportError(
                        "protocol_error",
                        f"tools/list exceeded {_MAX_LIST_PAGES} pages — refusing "
                        f"rather than paginating forever")
                seen_cursors.add(next_cursor)
                cursor = next_cursor
        except DownstreamRpcError as exc:
            self._refuse(req_id, exc.code, exc.message, exc.data)
            return
        except DownstreamTransportError as exc:
            self._refuse(req_id, DOWNSTREAM_UNAVAILABLE, f"downstream unavailable: {exc}")
            return
        # Filtered to what THIS gateway's catalog currently has asserted+invocable —
        # not what the source declares, not what the server claims. An unasserted or
        # never-registered tool is invisible here, never merely refused at call time.
        filtered = [
            t for t in tools
            if isinstance(t, Mapping) and isinstance(t.get("name"), str)
            and self.service.catalog.invocable(self.source_id, t["name"])
        ]
        self._respond(req_id, {"tools": filtered})

    def _handle_tools_call(self, req_id: Any, params: Mapping[str, Any]) -> None:
        name = params.get("name")
        arguments = params.get("arguments", {})
        if not isinstance(name, str) or not name:
            self._refuse(req_id, INVALID_PARAMS, "tools/call requires a string 'name'")
            return
        if arguments is None:
            arguments = {}
        if not isinstance(arguments, Mapping):
            self._refuse(req_id, INVALID_PARAMS, "'arguments' must be an object")
            return
        # The one mapping used for authorize, redeem, AND the forwarded call. There
        # is no second read of `params` anywhere below: authorize hashes this exact
        # object, redeem presents this exact object, and the downstream call forwards
        # this exact object — tampering between authorize and forward is impossible
        # by construction because nothing after this line ever looks at `params` again.
        frozen_args = dict(arguments)

        try:
            decision = self.service.authorize(
                self.principal, self.source_id, name, args=frozen_args)
        except ServiceError as exc:
            self._refuse(req_id, INVALID_PARAMS, str(exc))
            return
        if not decision["allowed"]:
            self._refuse(req_id, DENIED, decision["reason"] or "denied",
                        {"decision_id": decision["decision_id"]})
            return
        grant = decision.get("grant")
        if grant is None:
            # Structurally unreachable: authorize() with args always issues a grant
            # on allow (contract 1.1). Refuse rather than forward ungoverned if this
            # invariant is ever violated — the same rule the client SDK's
            # governed_invoke enforces on the caller's side.
            self._refuse(req_id, INTERNAL_ERROR, "authorize allowed but issued no grant")
            return
        grant_id = grant["grant_id"]
        decision_id = decision["decision_id"]

        try:
            redemption = self.service.redeem_grant(grant_id, self.principal, frozen_args)
        except ServiceError as exc:
            self._refuse(req_id, INVALID_PARAMS, str(exc))
            return
        if not redemption["redeemed"]:
            self._refuse(req_id, REDEEM_DENIED, redemption["reason"] or "redeem denied",
                        {"decision_id": decision_id, "grant_id": grant_id})
            return

        try:
            result = self._downstream.call(
                "tools/call", {"name": name, "arguments": frozen_args}, self.timeout)
        except DownstreamRpcError as exc:
            # The call reached the server, which made its own authoritative decision
            # about it — relay it verbatim; the grant is "executed", not "error".
            self._best_effort_outcome(decision_id, grant_id, "executed", detail={
                "downstream_error": {"code": exc.code, "message": exc.message}})
            self._refuse(req_id, exc.code, exc.message, exc.data)
            return
        except DownstreamTransportError as exc:
            self._best_effort_outcome(decision_id, grant_id, "error",
                                      detail={"fault_kind": exc.kind, "error": str(exc)})
            self._refuse(req_id, DOWNSTREAM_UNAVAILABLE, f"downstream unavailable: {exc}")
            return

        self._best_effort_outcome(decision_id, grant_id, "executed")
        self._respond(req_id, result)

    def _best_effort_outcome(self, decision_id: str, grant_id: str, outcome: str,
                             detail: Mapping[str, Any] | None = None) -> None:
        # Mirrors the client SDK's governed_invoke: pre-execution failures are
        # fail-closed and refuse; but the call already ran (or definitively failed
        # downstream) by the time we get here, so an audit-path hiccup recording that
        # must never itself crash the gateway or block the response reaching the
        # client — it is the one place in this method where best-effort is correct.
        # "Best-effort" must cover EVERYTHING the store layer can raise, not just
        # ServiceError: record_outcome runs raw SQLite statements that can surface
        # sqlite3.OperationalError ("database is locked", disk I/O faults). Letting
        # one of those escape here would discard an already-executed downstream
        # result and report a false failure — inviting a client retry that
        # double-executes a non-idempotent action whose one-use grant is already
        # spent. Swallow, but never silently: log to stderr (never stdout — that
        # would corrupt the MCP stream).
        try:
            self.service.record_outcome(decision_id, outcome, detail=detail, grant_id=grant_id)
        except Exception as exc:
            print(f"toolconnect gateway: outcome recording failed for decision "
                  f"{decision_id} (grant {grant_id}, outcome {outcome!r}): {exc}",
                  file=sys.stderr, flush=True)
