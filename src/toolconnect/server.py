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

import hmac
import json
import re
import threading
import time
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlparse

from .service import ServiceError, ToolConnectService

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8095

_MAX_BODY = 1 << 20  # 1 MiB — descriptors and principals, not payloads


class _RateLimiter:
    """A fixed-window per-client request limiter.

    Non-local deployments need a cheap availability guard so a fail-closed decision
    point cannot be trivially exhausted. This keeps a bounded sliding window of recent
    request timestamps per client key (remote IP) and rejects once the window is full.
    Off by default (``per_window <= 0`` disables it); loopback-only deployments do not
    need it and pay nothing.
    """

    def __init__(self, per_window: int, window_seconds: float = 60.0) -> None:
        self.per_window = per_window
        self.window = window_seconds
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    @property
    def enabled(self) -> bool:
        return self.per_window > 0

    def check(self, key: str, now: float | None = None) -> tuple[bool, float]:
        """Return ``(allowed, retry_after_seconds)``. Records the hit when allowed."""
        if not self.enabled:
            return True, 0.0
        now = time.monotonic() if now is None else now
        cutoff = now - self.window
        with self._lock:
            dq = self._hits.setdefault(key, deque())
            while dq and dq[0] < cutoff:
                dq.popleft()
            if len(dq) >= self.per_window:
                retry = self.window - (now - dq[0])
                return False, max(0.0, retry)
            dq.append(now)
            return True, 0.0


class _Handler(BaseHTTPRequestHandler):
    server_version = "toolconnect"
    protocol_version = "HTTP/1.1"

    # populated by make_server()
    service: ToolConnectService = None  # type: ignore[assignment]
    lock: threading.Lock = None  # type: ignore[assignment]
    token: str | None = None
    limiter: _RateLimiter = None  # type: ignore[assignment]

    def log_message(self, fmt: str, *args) -> None:  # noqa: D102 — quiet by default
        pass

    # -- plumbing ---------------------------------------------------------------

    def _json(self, status: int, payload, extra_headers: dict | None = None) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _error(self, status: int, message: str, extra_headers: dict | None = None) -> None:
        self._json(status, {"error": {"status": status, "message": message}}, extra_headers)

    def _client_key(self) -> str:
        return self.client_address[0] if self.client_address else "unknown"

    def _authenticated(self) -> bool:
        """True when no token is required, or the presented bearer token matches.

        Comparison is constant-time. When a token is configured, EVERY route requires
        it — a fail-closed decision point does not leave its catalog, drift state, or
        audit log readable to an unauthenticated caller. Loopback-only deployments
        configure no token and this is a no-op.
        """
        if not self.token:
            return True
        header = self.headers.get("Authorization", "")
        scheme, _, presented = header.partition(" ")
        if scheme.lower() != "bearer" or not presented:
            return False
        return hmac.compare_digest(presented.strip(), self.token)

    def _drain_body(self) -> None:
        """Consume any request body so the keep-alive connection stays in sync.

        A 401/429 rejection still has to read the bytes the client already sent, or the
        next request on the same HTTP/1.1 connection would be misframed.
        """
        length = int(self.headers.get("Content-Length") or 0)
        remaining = min(length, _MAX_BODY + 1)
        while remaining > 0:
            chunk = self.rfile.read(min(remaining, 65536))
            if not chunk:
                break
            remaining -= len(chunk)

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
        # Rate limiting first: an attacker who cannot authenticate should not even be
        # able to make us do work proving it. Then authentication. Both precede routing.
        if self.limiter is not None and self.limiter.enabled:
            allowed, retry = self.limiter.check(self._client_key())
            if not allowed:
                self._drain_body()
                self._error(429, "rate limit exceeded",
                            {"Retry-After": str(int(retry) + 1)})
                return
        if not self._authenticated():
            self._drain_body()
            self._error(401, "missing or invalid bearer token",
                        {"WWW-Authenticate": "Bearer"})
            return
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
                port: int = DEFAULT_PORT, *, token: str | None = None,
                rate_limit_per_min: int = 0) -> ThreadingHTTPServer:
    """Build the HTTP server.

    ``token``: when set, every request must present ``Authorization: Bearer <token>``.
    Unset (the default, matching the loopback-only bind) leaves the surface open.
    ``rate_limit_per_min``: requests per rolling 60 s window per client IP; ``0``
    disables the limiter.
    """
    handler = type("BoundHandler", (_Handler,), {
        "service": service, "lock": threading.Lock(),
        "token": token or None,
        "limiter": _RateLimiter(rate_limit_per_min)})
    return ThreadingHTTPServer((host, port), handler)


def serve(service: ToolConnectService, host: str = DEFAULT_HOST,
          port: int = DEFAULT_PORT, *, token: str | None = None,
          rate_limit_per_min: int = 0) -> None:
    httpd = make_server(service, host, port, token=token,
                        rate_limit_per_min=rate_limit_per_min)
    try:
        httpd.serve_forever()
    finally:
        httpd.server_close()
