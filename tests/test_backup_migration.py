"""Backup/restore round-trip, and forward schema migration on a copy.

Deliverable 12. A backup must be a complete, openable database whose audit chain still
verifies; a restore is opening that file. A legacy (RC1 / schema v1) database must
migrate forward to the current schema on open, on a copy, preserving every row and the
hash chain, and a database newer than this build must be refused.
"""

from __future__ import annotations

import shutil
import sqlite3

import pytest

from toolconnect.policy import CedarPolicyEngine
from toolconnect.service import ToolConnectService
from toolconnect.store import (
    BASELINE_VERSION,
    SCHEMA_VERSION,
    _SCHEMA,
    SqliteStore,
)

ALLOW_READS = """
@id("allow-reads")
permit(principal, action == Action::"invoke", resource)
when { resource.effect == "read" };
"""


def _populated_service(path):
    store = SqliteStore(path)
    svc = ToolConnectService(store, CedarPolicyEngine(ALLOW_READS))
    svc.register_source("s", tier="known")
    svc.ingest_payload("s", [
        {"name": "reader", "claimed": {"read_only_hint": True}},
        {"name": "writer", "claimed": {"read_only_hint": False,
                                       "destructive_hint": False}},
    ])
    svc.assert_tool("s", "reader", {"effect": "read", "asserted_by": "op"})
    d = svc.authorize({"id": "a"}, "s", "reader")
    svc.record_outcome(d["decision_id"], "success")
    return store, svc


class TestBackupRestore:
    def test_backup_round_trip_preserves_chain_and_catalog(self, tmp_path):
        store, svc = _populated_service(tmp_path / "live.db")
        before_health = svc.health()
        dest = store.backup(tmp_path / "backup.db")
        store.close()

        # Restore == open the backup. It is a complete, working database.
        restored = SqliteStore(dest)
        rsvc = ToolConnectService(restored, CedarPolicyEngine(ALLOW_READS))
        assert restored.verify_chain().ok
        rhealth = rsvc.health()
        assert rhealth["sources"] == before_health["sources"]
        assert rhealth["tools"] == before_health["tools"]
        assert rhealth["audit_records"] == before_health["audit_records"]
        # Governance answers survive the restore.
        assert rsvc.catalog.invocable("s", "reader") is True
        assert rsvc.catalog.invocable("s", "writer") is False
        assert rsvc.authorize({"id": "a"}, "s", "reader")["allowed"] is True
        restored.close()

    def test_backup_is_consistent_during_concurrent_writes(self, tmp_path):
        """The online-backup snapshot verifies even while another thread writes."""
        import threading
        store, svc = _populated_service(tmp_path / "live.db")
        stop = threading.Event()

        def churn():
            i = 0
            while not stop.is_set():
                store.append_audit("decision", {"churn": i})
                i += 1

        t = threading.Thread(target=churn, daemon=True)
        t.start()
        try:
            dest = store.backup(tmp_path / "snap.db")
        finally:
            stop.set(); t.join(timeout=5)
        snap = SqliteStore(dest)
        assert snap.verify_chain().ok  # a torn write would break this
        snap.close()
        store.close()


class TestMigration:
    def _make_legacy_v1(self, path):
        """Write a database exactly as RC1 (schema v1) would have: the baseline DDL,
        version pinned at 1, and NO v2 additions (no `label` column, no kind index)."""
        conn = sqlite3.connect(path)
        conn.executescript(_SCHEMA)
        conn.execute("INSERT INTO meta(key, value) VALUES ('schema_version', ?)",
                     (str(BASELINE_VERSION),))
        conn.commit()
        conn.close()

    def test_v1_migrates_forward_on_open(self, tmp_path):
        legacy = tmp_path / "legacy.db"
        self._make_legacy_v1(legacy)

        # Populate it through a normal service while it is still "v1 shaped" — the open
        # itself migrates it, so use a second raw connection to seed pre-migration rows.
        raw = sqlite3.connect(legacy)
        cols = [r[1] for r in raw.execute("PRAGMA table_info(sources)")]
        assert "label" not in cols  # genuinely pre-v2
        raw.close()

        # Opening with current code migrates in place.
        store = SqliteStore(legacy)
        assert store.schema_version == SCHEMA_VERSION
        with store._lock:
            cols = [r[1] for r in store._conn.execute("PRAGMA table_info(sources)")]
            idx = store._conn.execute(
                "SELECT name FROM sqlite_master WHERE type='index' "
                "AND name='idx_audit_kind'").fetchone()
            ver = store._conn.execute(
                "SELECT value FROM meta WHERE key='schema_version'").fetchone()[0]
        assert "label" in cols
        assert idx is not None
        assert ver == str(SCHEMA_VERSION)
        store.close()

    def test_migration_preserves_data_and_chain(self, tmp_path):
        # Build a fully-populated CURRENT db, then forge it back to a v1 marker so we can
        # prove the migrator preserves real content, not just an empty schema.
        store, svc = _populated_service(tmp_path / "src.db")
        health = svc.health()
        store.close()

        legacy = tmp_path / "asif_v1.db"
        shutil.copy(tmp_path / "src.db", legacy)
        # Pretend it predates v2: drop the marker back to 1. (The v2 columns already
        # exist here, so the migration's ALTER would clash — instead simulate a genuine
        # v1 by rebuilding onto the baseline schema and re-inserting the audit rows.)
        conn = sqlite3.connect(legacy)
        rows = conn.execute(
            "SELECT kind, body, created_at, prev_hash, record_hash FROM audit "
            "ORDER BY seq").fetchall()
        conn.close()

        fresh_v1 = tmp_path / "fresh_v1.db"
        c = sqlite3.connect(fresh_v1)
        c.executescript(_SCHEMA)
        c.execute("INSERT INTO meta(key, value) VALUES ('schema_version','1')")
        c.execute("INSERT INTO sources(source_id, tier, transport, declared, command, "
                  "registered_at) VALUES ('s','known','mcp','[]',NULL,'t0')")
        c.executemany(
            "INSERT INTO audit(kind, body, created_at, prev_hash, record_hash) "
            "VALUES (?,?,?,?,?)", rows)
        c.commit(); c.close()

        migrated = SqliteStore(fresh_v1)
        assert migrated.schema_version == SCHEMA_VERSION
        chain = migrated.verify_chain()
        assert chain.ok, f"migration broke the chain at {chain.broken_at}"
        assert chain.records == health["audit_records"]
        assert migrated.has_source("s")
        migrated.close()

    def test_reopen_after_migration_is_a_noop(self, tmp_path):
        legacy = tmp_path / "legacy.db"
        self._make_legacy_v1(legacy)
        SqliteStore(legacy).close()          # migrates to v2
        store = SqliteStore(legacy)          # must not try to migrate again
        assert store.schema_version == SCHEMA_VERSION
        assert store.verify_chain().ok
        store.close()

    def test_future_schema_is_refused(self, tmp_path):
        path = tmp_path / "future.db"
        SqliteStore(path).close()
        conn = sqlite3.connect(path)
        conn.execute("UPDATE meta SET value=? WHERE key='schema_version'",
                     (str(SCHEMA_VERSION + 5),))
        conn.commit(); conn.close()
        with pytest.raises(RuntimeError, match="schema version"):
            SqliteStore(path)
