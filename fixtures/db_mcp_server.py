#!/usr/bin/env python3
"""A second, independent real MCP server over stdio — a database-flavoured surface.

This exists so discovery, normalization, namespacing, and transport-fault handling
are proven against MORE THAN ONE real server, not just `mini_mcp_server.py`. It is a
genuinely separate process speaking newline-delimited JSON-RPC 2.0 over the MCP stdio
transport, with a different tool set, a different server identity, and a different
pagination shape (a single page rather than two).

Its tool set deliberately overlaps `mini_mcp_server.py` on exactly one bare name —
``fetch_url`` — with different semantics. Registering both servers therefore creates a
cross-source name collision, which is exactly the shadowing hazard that namespaced
(source_id, name) identity and fail-closed `resolve()` exist to defeat.

Fault modes (``--mode``) mirror the mini server so the six transport-fault classes can
be exercised against a second real wire:

  normal    one page of well-formed tools (default)
  empty     zero tools
  malformed replies to tools/list with bytes that are not JSON
  truncate  writes half a JSON frame, then exits
  hang      accepts initialize, then never answers tools/list
  dup       announces the same tool name twice
  partial   page 1 is fine; page 2 is a JSON-RPC error
  slowinit  never answers initialize

Stdlib only. No `tools/call` handler exists, on purpose: this is a discovery target,
never an execution engine.
"""

from __future__ import annotations

import argparse
import json
import sys
import time

PROTOCOL_VERSION = "2025-06-18"

# Distinct tools from the mini server, except `fetch_url` (shared bare name, different
# meaning: here it fetches a row by URL-shaped key, not a web page).
PAGE_ONE = [
    {
        "name": "sql_query",
        "description": "Run a read-only SQL query against the analytics warehouse",
        "inputSchema": {"type": "object",
                        "properties": {"sql": {"type": "string"}},
                        "required": ["sql"]},
        "annotations": {"readOnlyHint": True, "idempotentHint": True},
    },
    {
        "name": "list_tables",
        "description": "List tables in a schema",
        "inputSchema": {"type": "object",
                        "properties": {"schema": {"type": "string"}}},
        "annotations": {"readOnlyHint": True, "idempotentHint": True},
    },
    {
        "name": "delete_row",
        "description": "Delete a row by primary key — irreversible",
        "inputSchema": {"type": "object",
                        "properties": {"table": {"type": "string"},
                                       "pk": {"type": "string"}},
                        "required": ["table", "pk"]},
        "annotations": {"readOnlyHint": False, "destructiveHint": True,
                        "openWorldHint": False},
    },
    {
        "name": "fetch_url",
        "description": "Fetch a stored blob by its object-store URL",
        "inputSchema": {"type": "object", "properties": {"url": {"type": "string"}},
                        "required": ["url"]},
        "annotations": {"readOnlyHint": True, "idempotentHint": True},
    },
]

# For the `partial` fault: a first page that points at a second page which then errors.
PARTIAL_PAGE_ONE = [PAGE_ONE[0]]


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
                        choices=["normal", "empty", "malformed", "truncate",
                                 "hang", "dup", "partial", "slowinit"])
    args = parser.parse_args()
    mode = args.mode

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
            if mode == "slowinit":
                time.sleep(3600)  # the client's deadline fires first
            _result(req_id, {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "db-mcp-fixture", "version": "2.0.1"},
            })
        elif method == "notifications/initialized":
            continue  # a notification; no reply
        elif method == "tools/list":
            cursor = (msg.get("params") or {}).get("cursor")
            if mode == "malformed":
                sys.stdout.write("definitely } not { json\n")
                sys.stdout.flush()
            elif mode == "truncate":
                frame = json.dumps(
                    {"jsonrpc": "2.0", "id": req_id, "result": {"tools": PAGE_ONE}})
                sys.stdout.write(frame[: len(frame) // 2])
                sys.stdout.flush()
                return 0  # exit mid-frame
            elif mode == "hang":
                time.sleep(3600)
            elif mode == "empty":
                _result(req_id, {"tools": []})
            elif mode == "dup":
                _result(req_id, {"tools": [PAGE_ONE[0], PAGE_ONE[0]]})
            elif mode == "partial":
                if cursor is None:
                    _result(req_id, {"tools": PARTIAL_PAGE_ONE, "nextCursor": "page2"})
                else:
                    _error(req_id, -32603, "internal error while listing page 2")
            else:  # normal — a single well-formed page
                _result(req_id, {"tools": PAGE_ONE})
        elif req_id is not None:
            _error(req_id, -32601, f"method not found: {method}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
