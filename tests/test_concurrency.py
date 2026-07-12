"""Concurrent access to the SQLite store, and to the service over a real socket.

Deliverable 1 has two halves and both are exercised here on real threads (and, for the
HTTP half, a real loopback server driven by many concurrent urllib clients):

* **No corruption under concurrent writers.** The store is single-connection and
  serializes every mutation behind one ``RLock`` (see ``SqliteStore``), and the audit
  log's read-prev-hash-then-insert must be atomic or the hash chain breaks. Many
  threads hammering ``append_audit``/``upsert_*`` concurrently must leave a chain that
  still verifies and a row count that matches exactly what was written.

* **WAL lets readers run during writes.** With ``journal_mode=WAL`` a separate reader
  connection can read the audit table while the writer is mid-burst without erroring or
  blocking, and sees a monotonically growing, self-consistent view.

The serialization guarantee (single writer + WAL) is documented, not merely asserted:
``docs/SERVICE.md`` → *Concurrency & durability*.
"""

from __future__ import annotations

import socket
import sqlite3
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from toolconnect.policy import CedarPolicyEngine
from toolconnect.store import SqliteStore

REPO = Path(__file__).resolve().parent.parent
MINI = str(REPO / "fixtures" / "mini_mcp_server.py")


class TestStoreConcurrency:
    def test_parallel_audit_appends_keep_the_chain_intact(self, tmp_path):
        store = SqliteStore(tmp_path / "tc.db")
        writers, per_writer = 12, 40
        errors: list[Exception] = []

        def worker(w: int) -> None:
            try:
                for i in range(per_writer):
                    store.append_audit("decision",
                                       {"writer": w, "i": i, "allowed": i % 2 == 0})
            except Exception as exc:  # pragma: no cover - failure path
                errors.append(exc)

        with ThreadPoolExecutor(max_workers=writers) as pool:
            list(pool.map(worker, range(writers)))

        assert not errors, f"concurrent writers raised: {errors}"
        chain = store.verify_chain()
        assert chain.ok, f"chain broke at {chain.broken_at}: {chain.detail}"
        # Every append is present exactly once — no lost or double writes.
        assert chain.records == writers * per_writer
        assert len(store.read_audit(kind="decision", limit=10_000)) == writers * per_writer
        store.close()

    def test_mixed_mutations_do_not_corrupt(self, tmp_path):
        """Interleave source/tool upserts, assertions, discovery records, and audit
        appends across threads. The chain must verify and every source must persist."""
        from toolconnect.catalog import AssertionRecord, Catalog
        from toolconnect.descriptor import (
            AssertedDescriptor, ClaimedMetadata, Effect, ToolRef, ToolVersion,
            TrustedSource, TrustTier,
        )

        store = SqliteStore(tmp_path / "tc.db")
        n = 30
        errors: list[Exception] = []

        def worker(k: int) -> None:
            try:
                sid = f"src-{k}"
                store.upsert_source(TrustedSource(sid, TrustTier.KNOWN),
                                    declares=[f"t{k}"])
                claimed = ClaimedMetadata(description=f"d{k}", read_only_hint=True)
                tv = ToolVersion(ToolRef(f"t{k}", "1.0.0"), sid, claimed)
                store.upsert_tool(tv)
                desc = AssertedDescriptor(effect=Effect.READ, asserted_by="op")
                asserted = ToolVersion(ToolRef(f"t{k}", "1.0.0"), sid, claimed, desc)
                store.upsert_tool(asserted)
                store.upsert_assertion(sid, f"t{k}",
                                       AssertionRecord(desc, Catalog._fingerprint(asserted)))
                store.record_discovery(sid, {f"t{k}"})
                store.append_audit("assertion", {"src": sid})
            except Exception as exc:  # pragma: no cover
                errors.append(exc)

        with ThreadPoolExecutor(max_workers=16) as pool:
            list(pool.map(worker, range(n)))

        assert not errors, f"concurrent mixed mutations raised: {errors}"
        assert store.verify_chain().ok
        for k in range(n):
            assert store.has_source(f"src-{k}")
        # Hydration after the concurrent burst reconstructs a coherent catalog.
        cat = store.load_catalog()
        assert len(cat.sources) == n
        assert all(cat.invocable(f"src-{k}", f"t{k}") for k in range(n))
        store.close()

    def test_reader_connection_runs_during_writes(self, tmp_path):
        """WAL: a separate read-only connection reads while the writer bursts, never
        erroring and seeing a monotonically growing count."""
        path = str(tmp_path / "tc.db")
        store = SqliteStore(path)
        store.append_audit("decision", {"seed": True})

        stop = threading.Event()
        counts: list[int] = []
        reader_errors: list[Exception] = []

        def reader() -> None:
            conn = sqlite3.connect(path)
            try:
                while not stop.is_set():
                    try:
                        (c,) = conn.execute("SELECT COUNT(*) FROM audit").fetchone()
                        counts.append(c)
                    except sqlite3.Error as exc:  # pragma: no cover
                        reader_errors.append(exc)
                    time.sleep(0.001)
            finally:
                conn.close()

        t = threading.Thread(target=reader, daemon=True)
        t.start()
        for i in range(300):
            store.append_audit("decision", {"i": i})
        stop.set()
        t.join(timeout=5)

        assert not reader_errors, f"reader hit errors during writes: {reader_errors}"
        assert counts, "reader never observed the table"
        assert counts == sorted(counts), "reader saw a non-monotonic count (corruption)"
        assert store.verify_chain().ok
        store.close()


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


@pytest.mark.skipif(not _loopback_available(),
                    reason="loopback networking unavailable (offline gate variant)")
class TestServiceConcurrencyOverHttp:
    ALLOW_READS = (
        '@id("allow-reads")\n'
        'permit(principal, action == Action::"invoke", resource)\n'
        'when { resource.effect == "read" };\n'
    )

    def test_many_clients_register_assert_authorize(self, tmp_path):
        import json
        import urllib.request
        from toolconnect.server import make_server
        from toolconnect.service import ToolConnectService

        store = SqliteStore(tmp_path / "tc.db")
        service = ToolConnectService(store, CedarPolicyEngine(self.ALLOW_READS))
        httpd = make_server(service, host="127.0.0.1", port=0)
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        host, port = httpd.server_address[:2]
        base = f"http://{host}:{port}"

        def call(method, path, body=None):
            data = json.dumps(body).encode() if body is not None else None
            req = urllib.request.Request(
                base + path, data=data, method=method,
                headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                return resp.status, json.loads(resp.read())

        n = 24
        errors: list[Exception] = []

        def client(k: int) -> None:
            try:
                sid = f"c{k}"
                call("POST", "/sources", {"source_id": sid, "tier": "known"})
                call("POST", f"/sources/{sid}/tools",
                     {"tools": [{"name": "read_it",
                                 "claimed": {"read_only_hint": True}}]})
                call("POST", "/assertions",
                     {"source_id": sid, "name": "read_it",
                      "descriptor": {"effect": "read", "asserted_by": "op"}})
                st, body = call("POST", "/authorize",
                                {"principal": {"id": f"a{k}"},
                                 "source_id": sid, "name": "read_it"})
                assert st == 200 and body["allowed"] is True
            except Exception as exc:  # pragma: no cover
                errors.append(exc)

        with ThreadPoolExecutor(max_workers=n) as pool:
            list(pool.map(client, range(n)))

        try:
            assert not errors, f"concurrent clients raised: {errors}"
            _, health = call("GET", "/health")
            assert health["audit_chain_ok"] is True
            assert health["sources"] == n
            _, verify = call("GET", "/audit/verify")
            assert verify["ok"] is True
        finally:
            httpd.shutdown()
            httpd.server_close()
            store.close()
