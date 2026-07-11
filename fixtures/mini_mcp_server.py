#!/usr/bin/env python3
"""A minimal but real MCP server over stdio, used as a live test fixture.

This is not an in-process fake: it is a separate process speaking newline-delimited
JSON-RPC 2.0 per the MCP stdio transport — initialize handshake, capability
announcement, and a paginated tools/list. ToolConnect's adapter talks to it exactly
as it would to any third-party MCP server.

Fault modes (``--mode``) let the transport-fault tests exercise real wire failures
rather than monkeypatched ones:

  normal    two pages of well-formed tools (default)
  empty     zero tools
  malformed replies to tools/list with bytes that are not JSON
  truncate  writes half a JSON frame, then exits
  hang      accepts initialize, then never answers tools/list
  dup       announces the same tool name twice
  partial   page 1 is fine; page 2 is a JSON-RPC error
  slowinit  never answers initialize

Stdlib only. Never invokes anything; it has no tools/call handler on purpose.
"""

from __future__ import annotations

import argparse
import json
import sys
import time

PROTOCOL_VERSION = "2025-06-18"

PAGE_ONE = [
    {
        "name": "read_file",
        "description": "Read a file from the workspace",
        "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}},
                        "required": ["path"]},
        "annotations": {"readOnlyHint": True, "idempotentHint": True},
    },
    {
        "name": "write_file",
        "description": "Write a file into the workspace",
        "inputSchema": {"type": "object",
                        "properties": {"path": {"type": "string"},
                                       "content": {"type": "string"}},
                        "required": ["path", "content"]},
        "annotations": {"readOnlyHint": False, "destructiveHint": False,
                        "openWorldHint": False},
    },
]

PAGE_TWO = [
    {
        "name": "fetch_url",
        "description": "Fetch a URL from the open web",
        "inputSchema": {"type": "object", "properties": {"url": {"type": "string"}},
                        "required": ["url"]},
        "annotations": {"readOnlyHint": False, "destructiveHint": False,
                        "openWorldHint": True},
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
                "serverInfo": {"name": "mini-mcp-fixture", "version": "1.2.3"},
            })
        elif method == "notifications/initialized":
            continue  # a notification; no reply
        elif method == "tools/list":
            cursor = (msg.get("params") or {}).get("cursor")
            if mode == "malformed":
                sys.stdout.write("this is { not json\n")
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
                    _result(req_id, {"tools": PAGE_ONE, "nextCursor": "page2"})
                else:
                    _error(req_id, -32603, "internal error while listing page 2")
            else:  # normal
                if cursor is None:
                    _result(req_id, {"tools": PAGE_ONE, "nextCursor": "page2"})
                else:
                    _result(req_id, {"tools": PAGE_TWO})
        elif req_id is not None:
            _error(req_id, -32601, f"method not found: {method}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
