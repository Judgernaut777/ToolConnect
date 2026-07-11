"""`toolconnect serve` — a small stdlib HTTP front over ToolConnectService.

Default bind is 127.0.0.1:8095 (8080, 8090, and 8787 are taken on the reference
host). Routes and shapes are documented in docs/SERVICE.md; where the AgentConnect
contract pins a shape (the Decision explanation, the record() loop-closure), the
JSON mirrors it.

Deliberately stdlib `http.server`: the repository's only runtime dependency is the
policy engine, and a decision point that cannot start without a web framework has
gained an availability risk in a fail-closed path for no expressive benefit.

There is no invocation route. `/authorize` answers "may this principal call this
tool"; the caller performs the call itself and closes the loop via
`/decisions/{id}/outcome`.
"""

from __future__ import annotations

import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlparse

from .service import ServiceError, ToolConnectService

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8095

_MAX_BODY = 1 << 20  # 1 MiB — descriptors and principals, not payloads


class _Handler(BaseHTTPRequestHandler):
    server_version = "toolconnect"
    protocol_version = "HTTP/1.1"

    # populated by make_server()
    service: ToolConnectService = None  # type: ignore[assignment]
    lock: threading.Lock = None  # type: ignore[assignment]

    def log_message(self, fmt: str, *args) -> None:  # noqa: D102 — quiet by default
        pass

    # -- plumbing ---------------------------------------------------------------

    def _json(self, status: int, payload) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _error(self, status: int, message: str) -> None:
        self._json(status, {"error": {"status": status, "message": message}})

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if length > _MAX_BODY:
            raise ServiceError(413, "request body too large")
        raw = self.rfile.read(length) if length else b"{}"
        try:
            parsed = json.loads(raw or b"{}")
        except json.JSONDecodeError as exc:
            raise ServiceError(400, f"request body is not valid JSON: {exc}")
        if not isinstance(parsed, dict):
            raise ServiceError(400, "request body must be a JSON object")
        return parsed

    def _dispatch(self, method: str) -> None:
        url = urlparse(self.path)
        query = {k: v[-1] for k, v in parse_qs(url.query).items()}
        try:
            with self.lock:
                result = self._route(method, unquote(url.path), query)
        except ServiceError as exc:
            self._error(exc.status, str(exc))
        except Exception as exc:  # a crash must never look like an allow
            self._error(500, f"internal error: {exc}")
        else:
            self._json(200, result)

    # -- routing ------------------------------------------------------------------
    #
    # Source ids follow the MCP registry's reverse-DNS convention and may contain
    # slashes (io.github.owner/server), so parametrized routes match with a greedy
    # source-id capture rather than by path-segment splitting. Tool names are the
    # trailing segment and must not contain '/'.

    _INGEST = re.compile(r"^/sources/(?P<sid>.+)/ingest$")
    _PUSH = re.compile(r"^/sources/(?P<sid>.+)/tools$")
    _CATALOG = re.compile(r"^/catalog/(?P<sid>.+)/(?P<name>[^/]+)$")
    _ASSERTION = re.compile(r"^/assertions/(?P<sid>.+)/(?P<name>[^/]+)$")
    _DRIFT = re.compile(r"^/drift/(?P<sid>.+)$")
    _OUTCOME = re.compile(r"^/decisions/(?P<decision_id>[^/]+)/outcome$")

    def _route(self, method: str, path: str, query: dict):
        svc = self.service
        path = path.rstrip("/") or "/"

        if method == "GET":
            if path == "/health":
                return svc.health()
            if path == "/sources":
                return {"sources": svc.list_sources()}
            if path == "/catalog":
                return {"tools": svc.list_catalog()}
            if path == "/audit":
                limit = int(query.get("limit", "100"))
                kind = query.get("kind")
                if kind is not None and not re.fullmatch(r"[a-z_]+", kind):
                    raise ServiceError(400, f"invalid audit kind {kind!r}")
                return {"records": svc.read_audit(kind=kind, limit=max(1, min(limit, 1000)))}
            if path == "/audit/verify":
                return svc.verify_audit()
            if m := self._CATALOG.match(path):
                return svc.get_tool(m["sid"], m["name"])
            if m := self._ASSERTION.match(path):
                return svc.get_assertion(m["sid"], m["name"])
            if m := self._DRIFT.match(path):
                return svc.drift(m["sid"])

        if method == "POST":
            if path == "/sources":
                b = self._body()
                return svc.register_source(
                    source_id=str(b.get("source_id", "")),
                    tier=str(b.get("tier", "untrusted")),
                    transport=str(b.get("transport", "mcp")),
                    declares=b.get("declares"),
                    command=b.get("command"),
                )
            if path == "/authorize":
                b = self._body()
                return svc.authorize(
                    b.get("principal") or {}, str(b.get("source_id", "")),
                    str(b.get("name", "")), b.get("context"))
            if m := self._INGEST.match(path):
                b = self._body()
                timeout = float(b.get("timeout", 10.0))
                return svc.ingest(m["sid"], timeout=min(timeout, 60.0))
            if m := self._PUSH.match(path):
                b = self._body()
                return svc.ingest_payload(m["sid"], b.get("tools", []))
            if path == "/assertions":
                b = self._body()
                return svc.assert_tool(
                    str(b.get("source_id", "")), str(b.get("name", "")),
                    b.get("descriptor") or {})
            if m := self._OUTCOME.match(path):
                b = self._body()
                return svc.record_outcome(m["decision_id"], str(b.get("outcome", "")),
                                          b.get("detail"))

        raise ServiceError(404, f"no route {method} {path}")

    def do_GET(self) -> None:  # noqa: N802
        self._dispatch("GET")

    def do_POST(self) -> None:  # noqa: N802
        self._dispatch("POST")


def make_server(service: ToolConnectService, host: str = DEFAULT_HOST,
                port: int = DEFAULT_PORT) -> ThreadingHTTPServer:
    handler = type("BoundHandler", (_Handler,), {
        "service": service, "lock": threading.Lock()})
    return ThreadingHTTPServer((host, port), handler)


def serve(service: ToolConnectService, host: str = DEFAULT_HOST,
          port: int = DEFAULT_PORT) -> None:
    httpd = make_server(service, host, port)
    try:
        httpd.serve_forever()
    finally:
        httpd.server_close()
