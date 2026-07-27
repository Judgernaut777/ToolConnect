#!/usr/bin/env python3
"""A real MCP stdio server that DOES implement ``tools/call`` — a test fixture
standing in for a downstream tool server behind ``toolconnect gateway``.

Unlike ``mini_mcp_server.py``/``db_mcp_server.py`` (discovery-only fixtures, no
``tools/call`` handler by design — ToolConnect's discovery adapter never invokes),
this one exists specifically to exercise the gateway's forward path: authorize ->
redeem -> forward -> outcome. Three tools are advertised (``reader``, ``writer``,
``ghost``) so a test can enroll only some of them in a ToolConnect catalog and prove
``tools/list`` filtering hides the rest, independent of what the tool server itself
claims to offer.

Fault modes (``--mode``) exercise the gateway's downstream-fault handling (the
handshake always behaves; ``tools/list`` behaves except in the two list_* modes):

  normal        tools/call echoes its arguments back in the result (default)
  crash         tools/call reads the request, then the process exits immediately with
                no response at all — a crash mid-call
  error         tools/call replies with a well-formed JSON-RPC error object
  hang          tools/call never replies
  malformed     tools/call replies with bytes that are not JSON
  reverse       tools/call first issues a server-initiated request (a
                ``sampling/createMessage``), waits for the gateway's reply to it, then
                answers normally with the reply's error code included in the result —
                proving the gateway refuses rather than silently drops reverse requests
  flood         tools/call writes a megabyte of non-newline bytes and hangs — an
                oversized-frame attack against the gateway's downstream read buffer
  list_cycle    tools/list always returns the same nextCursor — a pagination cycle
  list_forever  tools/list returns a fresh nextCursor forever — endless pagination

Stdlib only.
"""

from __future__ import annotations

import argparse
import json
import sys
import time

PROTOCOL_VERSION = "2025-06-18"

TOOLS = [
    {
        "name": "reader",
        "description": "Read something back",
        "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}},
        "annotations": {"readOnlyHint": True, "idempotentHint": True},
    },
    {
        "name": "writer",
        "description": "Write something",
        "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}},
        "annotations": {"readOnlyHint": False, "destructiveHint": False},
    },
    {
        # Advertised by the server but deliberately never enrolled in the test
        # catalogs that use this fixture, so tools/list filtering has something to
        # hide regardless of what the server itself claims.
        "name": "ghost",
        "description": "A tool the catalog never asserted",
        "inputSchema": {"type": "object", "properties": {}},
        "annotations": {"readOnlyHint": True},
    },
]


def _emit(obj: dict) -> None:
    sys.stdout.write(json.dumps(obj, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def _result(req_id, result: dict) -> None:
    _emit({"jsonrpc": "2.0", "id": req_id, "result": result})


def _error(req_id, code: int, message: str) -> None:
    _emit({"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}})


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", default="normal",
                        choices=["normal", "crash", "error", "hang", "malformed",
                                 "reverse", "flood", "list_cycle", "list_forever"])
    args = parser.parse_args()
    mode = args.mode
    list_pages_served = 0

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        method = msg.get("method")
        req_id = msg.get("id")

        if method == "initialize":
            _result(req_id, {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "callable-mcp-fixture", "version": "1.0.0"},
            })
        elif method == "notifications/initialized":
            continue  # a notification; no reply
        elif method == "ping":
            _result(req_id, {})
        elif method == "tools/list":
            if mode == "list_cycle":
                _result(req_id, {"tools": TOOLS, "nextCursor": "same-cursor"})
            elif mode == "list_forever":
                list_pages_served += 1
                _result(req_id, {"tools": TOOLS,
                                 "nextCursor": f"page-{list_pages_served}"})
            else:
                _result(req_id, {"tools": TOOLS})
        elif method == "tools/call":
            params = msg.get("params") or {}
            name = params.get("name")
            arguments = params.get("arguments") or {}
            if mode == "crash":
                return 1  # exit with no response at all: a crash mid-call
            elif mode == "error":
                _error(req_id, -32050, f"tool {name!r} refused: fixture error mode")
            elif mode == "hang":
                time.sleep(3600)
            elif mode == "malformed":
                sys.stdout.write("this is { not json\n")
                sys.stdout.flush()
            elif mode == "reverse":
                # A server-initiated request mid-call, as the MCP spec permits.
                # Block on the gateway's reply exactly like a real server would —
                # if the gateway silently dropped this, the test would time out.
                _emit({"jsonrpc": "2.0", "id": 999,
                       "method": "sampling/createMessage", "params": {}})
                try:
                    reply = json.loads(sys.stdin.readline())
                except (json.JSONDecodeError, TypeError):
                    reply = {}
                err = reply.get("error") if isinstance(reply, dict) else None
                _result(req_id, {
                    "content": [{"type": "text", "text": f"called {name}"}],
                    "structuredContent": {
                        "tool": name, "echoed_arguments": arguments,
                        "reverse_reply_error_code":
                            (err or {}).get("code") if isinstance(err, dict) else None},
                    "isError": False,
                })
            elif mode == "flood":
                # One giant frame with no newline: an oversized-frame attack.
                sys.stdout.write("x" * (1 << 20))
                sys.stdout.flush()
                time.sleep(3600)
            else:  # normal — echo the exact arguments received back to the caller
                _result(req_id, {
                    "content": [{"type": "text", "text": f"called {name}"}],
                    "structuredContent": {"tool": name, "echoed_arguments": arguments},
                    "isError": False,
                })
        elif req_id is not None:
            _error(req_id, -32601, f"method not found: {method}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
