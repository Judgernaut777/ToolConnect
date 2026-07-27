"""Argument-bound one-use grants at the store layer (schema v4).

``status`` is never a stored column — it is always computed from the timestamp
latches (``redeemed_at``/``closed_at``/``expires_at``), matching the repo's doctrine
that persisted state is re-derived, never trusted as its own authority (see
``load_catalog``). These tests exercise ``SqliteStore.issue_grant``/``redeem_grant``/
``close_grant``/``list_grants``/``get_grant`` directly, without the service or HTTP
layers, plus the schema-v3 -> v4 migration.
"""

from __future__ import annotations

import hashlib
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import pytest

from toolconnect.hashing import args_hash
from toolconnect.store import SqliteStore


@pytest.fixture()
def store(tmp_path):
    s = SqliteStore(tmp_path / "tc.db")
    yield s
    s.close()


def _issue(store: SqliteStore, *, grant_id="g1", decision_id="d1",
          principal_id="p1", source_id="s", name="tool",
          args=None, ttl=60) -> str:
    h = args_hash(args or {"x": 1})
    issued = datetime.now(timezone.utc)
    expires = issued + timedelta(seconds=ttl)
    store.issue_grant(
        grant_id=grant_id, decision_id=decision_id, principal_id=principal_id,
        source_id=source_id, name=name, args_hash=h,
        issued_at=issued.isoformat(), expires_at=expires.isoformat())
    return h


class TestIssueAndGet:
    def test_issue_then_get_round_trips_and_status_is_issued(self, store):
        h = _issue(store)
        row = store.get_grant("g1")
        assert row is not None
        assert row["status"] == "issued"
        assert row["args_hash"] == h
        assert row["decision_id"] == "d1"
        assert row["source_id"] == "s"
        assert row["name"] == "tool"
        assert row["redeemed_at"] is None
        assert row["closed_at"] is None

    def test_get_unknown_grant_is_none(self, store):
        assert store.get_grant("nope") is None


class TestRedeem:
    def test_redeem_ok_returns_stored_identity_and_sets_redeemed_at(self, store):
        h = _issue(store)
        result = store.redeem_grant("g1", args_hash=h, principal_id="p1")
        assert result == {
            "redeemed": True, "reason": "ok", "decision_id": "d1",
            "source_id": "s", "name": "tool",
        }
        row = store.get_grant("g1")
        assert row["status"] == "redeemed"
        assert row["redeemed_at"] is not None

    def test_replay_with_identical_args_is_already_redeemed(self, store):
        h = _issue(store)
        store.redeem_grant("g1", args_hash=h, principal_id="p1")
        result = store.redeem_grant("g1", args_hash=h, principal_id="p1")
        assert result["redeemed"] is False
        assert result["reason"] == "already_redeemed"
        assert result["decision_id"] == "d1"

    def test_args_mismatch_denies(self, store):
        _issue(store)
        wrong = args_hash({"x": 2})
        result = store.redeem_grant("g1", args_hash=wrong, principal_id="p1")
        assert result["redeemed"] is False
        assert result["reason"] == "args_mismatch"

    def test_expiry_boundary_exactly_at_expiry_is_denied(self, store):
        # Crafted expires_at in the past: no clock mocking needed.
        h = args_hash({"x": 1})
        issued = datetime.now(timezone.utc) - timedelta(seconds=10)
        store.issue_grant(grant_id="g2", decision_id="d2", principal_id="p1",
                          source_id="s", name="tool", args_hash=h,
                          issued_at=issued.isoformat(),
                          expires_at=(issued + timedelta(seconds=5)).isoformat())
        result = store.redeem_grant("g2", args_hash=h, principal_id="p1")
        assert result["redeemed"] is False
        assert result["reason"] == "expired"

    def test_expiry_boundary_one_microsecond_before_is_allowed(self, store):
        h = args_hash({"x": 1})
        now = datetime.now(timezone.utc)
        store.issue_grant(
            grant_id="g3", decision_id="d3", principal_id="p1",
            source_id="s", name="tool", args_hash=h,
            issued_at=now.isoformat(),
            expires_at=(now + timedelta(microseconds=1) + timedelta(seconds=30)).isoformat())
        result = store.redeem_grant("g3", args_hash=h, principal_id="p1")
        assert result["redeemed"] is True

    def test_expiry_clock_reads_after_lock_acquisition_not_before(self, store):
        """A redeem that queues behind another grant operation past the grant's
        expiry must be judged EXPIRED against the time the check actually runs —
        a pre-lock `now` snapshot would let an already-expired grant redeem
        (inclusive-deny TTL boundary violated under lock contention)."""
        h = args_hash({"x": 1})
        now = datetime.now(timezone.utc)
        store.issue_grant(
            grant_id="g-ttl", decision_id="d-ttl", principal_id="p1",
            source_id="s", name="tool", args_hash=h,
            issued_at=now.isoformat(),
            expires_at=(now + timedelta(milliseconds=200)).isoformat())

        lock_held = threading.Event()
        release = threading.Event()

        def hold_lock():
            with store._lock:
                lock_held.set()
                release.wait(timeout=5)

        holder = threading.Thread(target=hold_lock)
        holder.start()
        assert lock_held.wait(timeout=5)
        # Redeem starts BEFORE expiry (its entry timestamp would still be fresh)
        # but can only proceed after the lock is released, past expires_at.
        result_box = {}

        def redeem():
            result_box["r"] = store.redeem_grant("g-ttl", args_hash=h, principal_id="p1")

        redeemer = threading.Thread(target=redeem)
        redeemer.start()
        # Hold the lock until the grant is unambiguously expired.
        import time
        time.sleep(0.4)
        release.set()
        holder.join(timeout=5)
        redeemer.join(timeout=5)
        assert result_box["r"]["redeemed"] is False
        assert result_box["r"]["reason"] == "expired"

    def test_principal_mismatch_denies(self, store):
        h = _issue(store, principal_id="alice")
        result = store.redeem_grant("g1", args_hash=h, principal_id="mallory")
        assert result["redeemed"] is False
        assert result["reason"] == "principal_mismatch"

    def test_close_then_redeem_denies_closed_M1(self, store):
        h = _issue(store)
        closed = store.close_grant("g1")
        assert closed is not None and closed["already_closed"] is False
        result = store.redeem_grant("g1", args_hash=h, principal_id="p1")
        assert result["redeemed"] is False
        assert result["reason"] == "closed"

    def test_invocable_check_false_closes_grant_and_denies_not_invocable(self, store):
        h = _issue(store)
        result = store.redeem_grant(
            "g1", args_hash=h, principal_id="p1", invocable_check=lambda sid, nm: False)
        assert result["redeemed"] is False
        assert result["reason"] == "not_invocable"
        row = store.get_grant("g1")
        assert row["status"] == "closed"
        # Second redeem attempt (e.g. after re-assertion) still denies as closed, not
        # a fresh not_invocable — the grant is permanently dead.
        result2 = store.redeem_grant(
            "g1", args_hash=h, principal_id="p1", invocable_check=lambda sid, nm: True)
        assert result2["redeemed"] is False
        assert result2["reason"] == "closed"

    def test_unknown_grant_is_not_found(self, store):
        result = store.redeem_grant("ghost", args_hash="x", principal_id="p1")
        assert result == {"redeemed": False, "reason": "not_found",
                          "decision_id": None, "source_id": None, "name": None}

    def test_concurrent_double_redeem_exactly_one_succeeds(self, store):
        h = _issue(store, ttl=300)
        results: list[dict] = []
        lock = threading.Lock()

        def attempt():
            r = store.redeem_grant("g1", args_hash=h, principal_id="p1")
            with lock:
                results.append(r)

        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(lambda _: attempt(), range(8)))

        oks = [r for r in results if r["redeemed"]]
        denied = [r for r in results if not r["redeemed"]]
        assert len(oks) == 1
        assert len(denied) == 7
        assert all(r["reason"] == "already_redeemed" for r in denied)


class TestClose:
    def test_close_is_idempotent(self, store):
        _issue(store)
        first = store.close_grant("g1")
        second = store.close_grant("g1")
        assert first["already_closed"] is False
        assert second["already_closed"] is True

    def test_close_on_expired_unredeemed_succeeds(self, store):
        h = args_hash({"x": 1})
        past = datetime.now(timezone.utc) - timedelta(seconds=100)
        store.issue_grant(grant_id="ge", decision_id="de", principal_id="p1",
                          source_id="s", name="tool", args_hash=h,
                          issued_at=past.isoformat(),
                          expires_at=(past + timedelta(seconds=1)).isoformat())
        closed = store.close_grant("ge")
        assert closed is not None and closed["already_closed"] is False
        assert store.get_grant("ge")["status"] == "closed"

    def test_close_unknown_grant_returns_none(self, store):
        assert store.close_grant("ghost") is None


class TestListGrants:
    def test_never_redeemed_grant_is_findable_by_state(self, store):
        _issue(store)
        rows = store.list_grants(state="issued")
        assert any(r["grant_id"] == "g1" for r in rows)

    def test_list_filters_by_computed_status(self, store):
        h = _issue(store)
        store.redeem_grant("g1", args_hash=h, principal_id="p1")
        assert [r["grant_id"] for r in store.list_grants(state="redeemed")] == ["g1"]
        assert store.list_grants(state="issued") == []


class TestMigration:
    def test_v3_database_migrates_to_v4_with_grants_table_and_chain_intact(self, tmp_path):
        path = tmp_path / "legacy.db"
        # Build a v3-shaped database by hand (pre-grants schema), then open it with
        # the current SqliteStore and confirm it migrates cleanly.
        conn = sqlite3.connect(str(path))
        conn.executescript("""
            CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE sources (
                source_id TEXT PRIMARY KEY, tier TEXT NOT NULL, transport TEXT NOT NULL,
                declared TEXT NOT NULL, command TEXT, registered_at TEXT NOT NULL,
                label TEXT);
            CREATE TABLE tools (
                source_id TEXT NOT NULL, name TEXT NOT NULL, version TEXT NOT NULL,
                claimed TEXT NOT NULL, asserted TEXT, input_schema TEXT NOT NULL DEFAULT '{}',
                updated_at TEXT NOT NULL, PRIMARY KEY (source_id, name));
            CREATE TABLE assertions (
                source_id TEXT NOT NULL, name TEXT NOT NULL, descriptor TEXT NOT NULL,
                fingerprint TEXT NOT NULL, asserted_at TEXT NOT NULL,
                PRIMARY KEY (source_id, name));
            CREATE TABLE discoveries (
                source_id TEXT PRIMARY KEY, discovered TEXT NOT NULL, observed_at TEXT NOT NULL);
            CREATE TABLE audit (
                seq INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL,
                body TEXT NOT NULL, created_at TEXT NOT NULL, prev_hash TEXT NOT NULL,
                record_hash TEXT NOT NULL);
            CREATE INDEX idx_audit_kind ON audit(kind);
            INSERT INTO meta(key, value) VALUES ('schema_version', '3');
        """)
        genesis = "0" * 64
        kind, body, created = "decision", "{}", "2026-01-01T00:00:00+00:00"
        record_hash = hashlib.sha256(
            f"{kind}\x1f{body}\x1f{created}\x1f{genesis}".encode("utf-8")).hexdigest()
        conn.execute(
            "INSERT INTO audit(kind, body, created_at, prev_hash, record_hash) "
            "VALUES (?,?,?,?,?)", (kind, body, created, genesis, record_hash))
        conn.commit()
        conn.close()

        store = SqliteStore(path)
        try:
            assert store.schema_version == 4
            chain = store.verify_chain()
            assert chain.ok, chain.detail
            assert chain.records == 1
            # grants table exists and is usable
            _issue(store)
            assert store.get_grant("g1") is not None
        finally:
            store.close()
