"""MCP source adapter — discovery only, over real JSON-RPC stdio.

This module speaks the actual Model Context Protocol to a real server subprocess:
``initialize`` handshake, ``notifications/initialized``, then paginated
``tools/list``. It normalizes what the server *claims* into ToolConnect-owned
:class:`~toolconnect.descriptor.ClaimedMetadata` — recorded, diffed, never trusted.

Note what is absent: ``tools/call``. This adapter ingests and probes; it never
invokes. That is the architecture (ARCHITECTURE §5, §8).

Every failure mode fails closed as a typed :class:`McpDiscoveryError` carrying a
machine-readable ``kind``, so callers can record an auditable outcome. Partial
discovery is discarded whole — a catalog must never contain half of what a server
serves, because the missing half is exactly where a shadowing tool hides.
"""

from __future__ import annotations

import json
import os
import select
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any, Mapping

from .descriptor import ClaimedMetadata

PROTOCOL_VERSION = "2025-06-18"
CLIENT_INFO = {"name": "toolconnect", "version": "0.1.0"}

#: Fault taxonomy. Every discovery failure is one of these, and each is auditable.
FAULT_KINDS = (
    "spawn_failed",       # the server process could not be started
    "timeout",            # the server did not answer within the deadline
    "malformed_json",     # the server emitted bytes that do not parse
    "truncated_response", # the stream ended mid-message
    "protocol_error",     # a JSON-RPC error, or a response violating MCP shape
    "duplicate_tool",     # one server announced the same tool name twice
)


class McpDiscoveryError(Exception):
    """A failed discovery. `kind` is one of FAULT_KINDS; always fail closed."""

    def __init__(self, kind: str, message: str) -> None:
        assert kind in FAULT_KINDS, kind
        super().__init__(message)
        self.kind = kind


@dataclass(frozen=True)
class DiscoveredTool:
    """One tool as announced by a server — a claim, not an authorization."""

    name: str
    claimed: ClaimedMetadata
    input_schema: Mapping[str, Any] = field(default_factory=dict)
    version: str = "0.0.0"


@dataclass(frozen=True)
class DiscoveryResult:
    server_name: str
    server_version: str
    protocol_version: str
    tools: tuple[DiscoveredTool, ...]


class _StdioTransport:
    """Newline-delimited JSON-RPC over a subprocess's stdio, with a hard deadline."""

    def __init__(self, command: list[str], deadline: float) -> None:
        self._deadline = deadline
        try:
            self._proc = subprocess.Popen(
                command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, env={**os.environ})
        except (OSError, ValueError) as exc:
            raise McpDiscoveryError("spawn_failed", f"could not start {command!r}: {exc}")
        self._buf = b""
        self._eof = False

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

    def send(self, message: dict) -> None:
        line = json.dumps(message, separators=(",", ":")) + "\n"
        try:
            assert self._proc.stdin is not None
            self._proc.stdin.write(line.encode("utf-8"))
            self._proc.stdin.flush()
        except (BrokenPipeError, OSError) as exc:
            raise McpDiscoveryError(
                "truncated_response", f"server closed stdin pipe: {exc}")

    def _read_line(self) -> bytes:
        """One newline-terminated frame, or a typed failure. Never blocks past the deadline."""
        assert self._proc.stdout is not None
        fd = self._proc.stdout.fileno()
        while b"\n" not in self._buf:
            remaining = self._deadline - time.monotonic()
            if remaining <= 0:
                raise McpDiscoveryError("timeout", "server did not respond before the deadline")
            if self._eof:
                raise McpDiscoveryError(
                    "truncated_response",
                    f"stream ended mid-message ({len(self._buf)} unterminated bytes)")
            ready, _, _ = select.select([fd], [], [], min(remaining, 0.25))
            if not ready:
                continue
            chunk = os.read(fd, 65536)
            if chunk == b"":
                self._eof = True
                if not self._buf:
                    raise McpDiscoveryError(
                        "truncated_response", "server closed the stream with no response")
                continue
            self._buf += chunk
        line, self._buf = self._buf.split(b"\n", 1)
        return line

    def receive(self) -> dict:
        line = self._read_line()
        try:
            msg = json.loads(line)
        except json.JSONDecodeError as exc:
            raise McpDiscoveryError(
                "malformed_json", f"unparseable frame from server: {exc}")
        if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0":
            raise McpDiscoveryError(
                "protocol_error", f"frame is not a JSON-RPC 2.0 message: {line[:200]!r}")
        return msg

    def request(self, req_id: int, method: str, params: dict | None = None) -> dict:
        """One round trip. Server-initiated requests/notifications are skipped over."""
        self.send({"jsonrpc": "2.0", "id": req_id, "method": method,
                   "params": params if params is not None else {}})
        while True:
            msg = self.receive()
            if msg.get("id") != req_id:
                continue  # a notification or an unrelated server message
            if "error" in msg:
                err = msg["error"]
                raise McpDiscoveryError(
                    "protocol_error",
                    f"{method} failed: [{err.get('code')}] {err.get('message')}")
            if "result" not in msg:
                raise McpDiscoveryError(
                    "protocol_error", f"{method} response has neither result nor error")
            return msg["result"]


def _normalize(tool: Mapping[str, Any], server_version: str) -> DiscoveredTool:
    name = tool.get("name")
    if not isinstance(name, str) or not name:
        raise McpDiscoveryError("protocol_error", f"tool without a usable name: {tool!r}")
    annotations = tool.get("annotations") or {}
    if not isinstance(annotations, Mapping):
        raise McpDiscoveryError(
            "protocol_error", f"tool {name!r} annotations are not an object")
    claimed = ClaimedMetadata(
        description=str(tool.get("description") or ""),
        read_only_hint=annotations.get("readOnlyHint"),
        destructive_hint=annotations.get("destructiveHint"),
        idempotent_hint=annotations.get("idempotentHint"),
        open_world_hint=annotations.get("openWorldHint"),
    )
    schema = tool.get("inputSchema") or {}
    if not isinstance(schema, Mapping):
        schema = {}
    return DiscoveredTool(name=name, claimed=claimed,
                          input_schema=dict(schema), version=server_version)


def discover(command: list[str], timeout: float = 10.0) -> DiscoveryResult:
    """Run one full MCP discovery against a real server subprocess.

    initialize -> notifications/initialized -> tools/list (following nextCursor).
    Returns the complete tool list or raises McpDiscoveryError. Never returns a
    partial catalog: a failure on page N discards pages 1..N-1.
    """
    deadline = time.monotonic() + timeout
    transport = _StdioTransport(command, deadline)
    try:
        init = transport.request(1, "initialize", {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": CLIENT_INFO,
        })
        server_info = init.get("serverInfo") or {}
        proto = init.get("protocolVersion")
        if not isinstance(proto, str):
            raise McpDiscoveryError(
                "protocol_error", "initialize result lacks protocolVersion")
        transport.send({"jsonrpc": "2.0", "method": "notifications/initialized"})

        server_version = str(server_info.get("version") or "0.0.0")
        tools: list[DiscoveredTool] = []
        seen: set[str] = set()
        cursor: str | None = None
        req_id = 2
        while True:
            params: dict = {"cursor": cursor} if cursor is not None else {}
            page = transport.request(req_id, "tools/list", params)
            req_id += 1
            raw = page.get("tools")
            if not isinstance(raw, list):
                raise McpDiscoveryError(
                    "protocol_error", "tools/list result lacks a tools array")
            for t in raw:
                dt = _normalize(t, server_version)
                if dt.name in seen:
                    # One server, one namespace: the same name twice is either a
                    # server bug or a shadowing attempt. Fail the whole discovery.
                    raise McpDiscoveryError(
                        "duplicate_tool",
                        f"server announced {dt.name!r} more than once")
                seen.add(dt.name)
                tools.append(dt)
            cursor = page.get("nextCursor")
            if cursor is None:
                break
        return DiscoveryResult(
            server_name=str(server_info.get("name") or "unknown"),
            server_version=server_version,
            protocol_version=proto,
            tools=tuple(tools),
        )
    finally:
        transport.close()
