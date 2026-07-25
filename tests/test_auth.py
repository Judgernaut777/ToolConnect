"""Bearer-token auth and per-client rate limiting, over a real loopback socket.

These start the actual ``ThreadingHTTPServer`` with a token and/or a rate limit set,
and drive it with urllib — no in-process handler calls. Under the offline gate variant
(``unshare -rn``) loopback is down and the module skips, like ``test_http_api``.
"""

from __future__ import annotations

import json
import socket
import threading
import urllib.error
import urllib.request

import pytest

from toolconnect.policy import CedarPolicyEngine
from toolconnect.server import make_server
from toolconnect.service import ToolConnectService
from toolconnect.store import SqliteStore


def _loopback_available() -> bool:
    # A bind alone is not enough: under `unshare -rn` bind succeeds but the loopback
    # interface is down, so an actual connect must be proven (matches test_http_api).
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

ALLOW_READS = """
@id("allow-reads")
permit(principal, action == Action::"invoke", resource)
when { resource.effect == "read" };
"""

TOKEN = "s3cr3t-bearer-token-value"


def _serve(tmp_path, *, token=None, rate_limit_per_min=0):
    store = SqliteStore(tmp_path / "tc.db")
    service = ToolConnectService(store, CedarPolicyEngine(ALLOW_READS))
    httpd = make_server(service, host="127.0.0.1", port=0,
                        token=token, rate_limit_per_min=rate_limit_per_min)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    host, port = httpd.server_address[:2]
    return httpd, store, f"http://{host}:{port}"


def _call(method, url, body=None, headers=None):
    data = json.dumps(body).encode() if body is not None else None
    h = {"Content-Type": "application/json"}
    h.update(headers or {})
    req = urllib.request.Request(url, data=data, method=method, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, dict(resp.headers), json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers), json.loads(exc.read())


class TestBearerAuth:
    def test_no_token_configured_is_open(self, tmp_path):
        httpd, store, base = _serve(tmp_path)
        try:
            status, _, body = _call("GET", f"{base}/health")
            assert status == 200 and body["status"] == "ok"
        finally:
            httpd.shutdown(); httpd.server_close(); store.close()

    def test_missing_token_is_401_when_required(self, tmp_path):
        httpd, store, base = _serve(tmp_path, token=TOKEN)
        try:
            status, headers, body = _call("GET", f"{base}/health")
            assert status == 401
            assert headers.get("WWW-Authenticate") == "Bearer"
            assert body["error"]["status"] == 401
        finally:
            httpd.shutdown(); httpd.server_close(); store.close()

    def test_wrong_token_is_401(self, tmp_path):
        httpd, store, base = _serve(tmp_path, token=TOKEN)
        try:
            status, _, _ = _call("GET", f"{base}/health",
                                 headers={"Authorization": "Bearer not-the-token"})
            assert status == 401
        finally:
            httpd.shutdown(); httpd.server_close(); store.close()

    def test_malformed_authorization_header_is_401(self, tmp_path):
        httpd, store, base = _serve(tmp_path, token=TOKEN)
        try:
            for bad in ("token-without-scheme", "Basic abc", "Bearer", "bearer "):
                status, _, _ = _call("GET", f"{base}/health",
                                     headers={"Authorization": bad})
                assert status == 401, f"{bad!r} should be rejected"
        finally:
            httpd.shutdown(); httpd.server_close(); store.close()

    def test_correct_token_authorizes_a_full_flow(self, tmp_path):
        httpd, store, base = _serve(tmp_path, token=TOKEN)
        auth = {"Authorization": f"Bearer {TOKEN}"}
        try:
            status, _, _ = _call("GET", f"{base}/health", headers=auth)
            assert status == 200
            # A write path (POST with a body) also passes and stays framed on keep-alive.
            status, _, body = _call("POST", f"{base}/sources",
                                    {"source_id": "s", "tier": "known"}, headers=auth)
            assert status == 200 and body["source_id"] == "s"
            status, _, body = _call("POST", f"{base}/sources/s/tools",
                                    {"tools": [{"name": "r",
                                                "claimed": {"read_only_hint": True}}]},
                                    headers=auth)
            assert status == 200
            status, _, body = _call("POST", f"{base}/assertions",
                                    {"source_id": "s", "name": "r",
                                     "descriptor": {"effect": "read",
                                                    "asserted_by": "op"}},
                                    headers=auth)
            assert status == 200 and body["invocable"] is True
            status, _, body = _call("POST", f"{base}/authorize",
                                    {"principal": {"id": "a"},
                                     "source_id": "s", "name": "r"}, headers=auth)
            assert status == 200 and body["allowed"] is True
        finally:
            httpd.shutdown(); httpd.server_close(); store.close()

    def test_auth_check_precedes_body_parse(self, tmp_path):
        """A rejected request with a malformed body is still a clean 401, and the
        connection is left usable (the body is drained)."""
        httpd, store, base = _serve(tmp_path, token=TOKEN)
        try:
            req = urllib.request.Request(
                f"{base}/authorize", data=b"{not valid json", method="POST",
                headers={"Content-Type": "application/json"})
            with pytest.raises(urllib.error.HTTPError) as exc:
                urllib.request.urlopen(req, timeout=10)
            assert exc.value.code == 401  # not a 400: auth is checked first
        finally:
            httpd.shutdown(); httpd.server_close(); store.close()


class TestKeepAliveFraming:
    def test_oversized_body_413_closes_the_connection(self, tmp_path):
        """A >1 MiB body is refused in _body() before the socket is read, so the server
        cannot drain it (_drain_body caps at _MAX_BODY+1). It must close the keep-alive
        connection, or the undrained body would be parsed as the next request from a
        connection-pooling client. Mirrors test_auth_check_precedes_body_parse's intent
        for the oversized-body refusal path."""
        httpd, store, base = _serve(tmp_path)
        sock = None
        try:
            host, port = httpd.server_address[:2]
            sock = socket.create_connection((host, port), timeout=10)
            oversize = (1 << 20) + 1  # one byte past _MAX_BODY
            req = (
                f"POST /authorize HTTP/1.1\r\n"
                f"Host: {host}:{port}\r\n"
                f"Content-Type: application/json\r\n"
                f"Content-Length: {oversize}\r\n"
                f"\r\n"
            ).encode()
            sock.sendall(req)
            # Read until the server closes (EOF) or we give up. With the fix the server
            # closes after the 413; without it the connection stays open and blocks on
            # the next request line, so the client's read times out instead of seeing
            # EOF. Reading to EOF (rather than a single recv) is robust to the 413
            # response arriving across multiple TCP segments under load.
            sock.settimeout(4.0)
            data = b""
            closed = False
            try:
                while True:
                    chunk = sock.recv(4096)
                    if chunk == b"":
                        closed = True
                        break
                    data += chunk
            except socket.timeout:
                closed = False
            assert b" 413 " in data
            assert closed, "413 left the keep-alive connection open (undrained body)"
        finally:
            if sock is not None:
                sock.close()
            httpd.shutdown(); httpd.server_close(); store.close()


class TestRateLimiting:
    def test_exceeding_the_window_returns_429(self, tmp_path):
        httpd, store, base = _serve(tmp_path, rate_limit_per_min=5)
        try:
            codes = [_call("GET", f"{base}/health")[0] for _ in range(8)]
            assert codes[:5] == [200] * 5
            assert 429 in codes[5:]
            # The 429 carries a Retry-After.
            status, headers, _ = _call("GET", f"{base}/health")
            assert status == 429
            assert int(headers.get("Retry-After", "0")) >= 1
        finally:
            httpd.shutdown(); httpd.server_close(); store.close()

    def test_limiter_off_by_default(self, tmp_path):
        httpd, store, base = _serve(tmp_path)  # no rate limit
        try:
            codes = [_call("GET", f"{base}/health")[0] for _ in range(30)]
            assert codes == [200] * 30
        finally:
            httpd.shutdown(); httpd.server_close(); store.close()

    def test_rate_limit_precedes_auth(self, tmp_path):
        """An unauthenticated flood is rate-limited before we spend effort on it."""
        httpd, store, base = _serve(tmp_path, token=TOKEN, rate_limit_per_min=3)
        try:
            codes = [_call("GET", f"{base}/health")[0] for _ in range(6)]
            # First few are 401 (bad/no auth), then 429 once the window fills.
            assert 401 in codes and 429 in codes
            assert codes.index(429) >= 3
        finally:
            httpd.shutdown(); httpd.server_close(); store.close()
