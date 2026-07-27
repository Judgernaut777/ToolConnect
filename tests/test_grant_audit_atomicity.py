"""ADR 0002 §4 deferral, closed: a grant mutation and its paired audit record must
commit or roll back together, never one without the other.

Before this fix, ``issue_grant``/``redeem_grant``/``close_grant`` wrote the ``grants``
row in one SQLite transaction and their caller (``ToolConnectService``) appended the
matching audit record in a separate, later transaction. A crash in that window left a
grant mutated with no audit trace — silently unauditable state. ``SqliteStore`` now
appends each paired audit record itself, inside the SAME transaction as the mutation,
via the internal ``_append_audit_in_txn`` helper.

These tests inject a fault directly into that helper (the one seam every paired
mutation goes through) and prove the grant-table write rolls back with it — fail
closed, exactly as a crash between the two writes should behave. They also prove the
hash chain still verifies after a run mixing grant and non-grant audit traffic, and
that a rolled-back attempt leaves no partial trace in either table.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from toolconnect.hashing import args_hash
from toolconnect.store import SqliteStore


@pytest.fixture()
def store(tmp_path):
    s = SqliteStore(tmp_path / "tc.db")
    yield s
    s.close()


def _boom(*_a, **_kw):
    raise RuntimeError("injected audit-append failure")


def _issue(store: SqliteStore, *, grant_id="g1", decision_id="d1",
          principal_id="p1", source_id="s", name="tool",
          args=None, ttl=300) -> str:
    h = args_hash(args or {"x": 1})
    issued = datetime.now(timezone.utc)
    expires = issued + timedelta(seconds=ttl)
    store.issue_grant(
        grant_id=grant_id, decision_id=decision_id, principal_id=principal_id,
        source_id=source_id, name=name, args_hash=h,
        issued_at=issued.isoformat(), expires_at=expires.isoformat(),
        ttl_seconds=ttl)
    return h


class TestIssueRollsBackOnAuditFailure:
    def test_failed_audit_append_leaves_no_grant_row(self, store, monkeypatch):
        monkeypatch.setattr(store, "_append_audit_in_txn", _boom)
        with pytest.raises(RuntimeError, match="injected audit-append failure"):
            _issue(store, grant_id="ghost")
        assert store.get_grant("ghost") is None

    def test_failed_audit_append_leaves_the_chain_untouched(self, store, monkeypatch):
        store.append_audit("decision", {"n": 1})
        before = store.verify_chain()
        monkeypatch.setattr(store, "_append_audit_in_txn", _boom)
        with pytest.raises(RuntimeError):
            _issue(store, grant_id="ghost")
        monkeypatch.undo()
        after = store.verify_chain()
        assert after.ok
        assert after.records == before.records == 1


class TestRedeemRollsBackOnAuditFailure:
    def test_failed_audit_append_leaves_grant_unredeemed(self, store, monkeypatch):
        h = _issue(store)
        monkeypatch.setattr(store, "_append_audit_in_txn", _boom)
        with pytest.raises(RuntimeError, match="injected audit-append failure"):
            store.redeem_grant("g1", args_hash=h, principal_id="p1")
        monkeypatch.undo()
        row = store.get_grant("g1")
        assert row["status"] == "issued"
        assert row["redeemed_at"] is None

    def test_failed_audit_append_on_not_invocable_leaves_grant_open(self, store, monkeypatch):
        h = _issue(store)
        monkeypatch.setattr(store, "_append_audit_in_txn", _boom)
        with pytest.raises(RuntimeError, match="injected audit-append failure"):
            store.redeem_grant("g1", args_hash=h, principal_id="p1",
                              invocable_check=lambda sid, nm: False)
        monkeypatch.undo()
        row = store.get_grant("g1")
        # The invocable_check's close must not have taken effect either: still open.
        assert row["status"] == "issued"
        assert row["closed_at"] is None

    def test_a_genuine_redeem_still_works_after_a_prior_injected_failure(self, store, monkeypatch):
        """The fault is transient (this call's audit append); the NEXT attempt on the
        same grant, with the fault lifted, must succeed normally — proving the earlier
        rollback left the grant in a clean, still-redeemable state."""
        h = _issue(store)
        monkeypatch.setattr(store, "_append_audit_in_txn", _boom)
        with pytest.raises(RuntimeError):
            store.redeem_grant("g1", args_hash=h, principal_id="p1")
        monkeypatch.undo()
        result = store.redeem_grant("g1", args_hash=h, principal_id="p1")
        assert result == {"redeemed": True, "reason": "ok", "decision_id": "d1",
                          "source_id": "s", "name": "tool"}


class TestCloseRollsBackOnAuditFailure:
    def test_failed_audit_append_leaves_grant_open(self, store, monkeypatch):
        _issue(store)
        monkeypatch.setattr(store, "_append_audit_in_txn", _boom)
        with pytest.raises(RuntimeError, match="injected audit-append failure"):
            store.close_grant("g1")
        monkeypatch.undo()
        row = store.get_grant("g1")
        assert row["status"] == "issued"
        assert row["closed_at"] is None

    def test_failed_audit_append_on_idempotent_reclose_leaves_state_unchanged(
            self, store, monkeypatch):
        """Even the no-op (already-closed) branch pairs its audit atomically: if that
        audit append fails, nothing about the already-closed row may change either."""
        _issue(store)
        store.close_grant("g1")
        closed_at_before = store.get_grant("g1")["closed_at"]
        monkeypatch.setattr(store, "_append_audit_in_txn", _boom)
        with pytest.raises(RuntimeError, match="injected audit-append failure"):
            store.close_grant("g1")
        monkeypatch.undo()
        row = store.get_grant("g1")
        assert row["status"] == "closed"
        assert row["closed_at"] == closed_at_before


class TestChainIntegrityAcrossMixedTraffic:
    def test_chain_verifies_after_interleaved_grant_and_plain_audit_records(self, store):
        store.append_audit("source", {"source_id": "s"})
        h1 = _issue(store, grant_id="g1", decision_id="d1")
        store.append_audit("ingest", {"source_id": "s", "n": 1})
        redeemed = store.redeem_grant("g1", args_hash=h1, principal_id="p1")
        assert redeemed["redeemed"] is True
        store.append_audit("outcome", {"decision_id": "d1", "outcome": "executed"})
        closed = store.close_grant("g1", reason="outcome_reported")
        assert closed["already_closed"] is False

        # A second, independent grant that ends up denied (not_invocable) rather
        # than redeemed, plus an unrelated decision record, further interleaved.
        h2 = _issue(store, grant_id="g2", decision_id="d2")
        store.append_audit("decision", {"decision_id": "d2", "allowed": True})
        denied = store.redeem_grant("g2", args_hash=h2, principal_id="p1",
                                    invocable_check=lambda sid, nm: False)
        assert denied["reason"] == "not_invocable"

        chain = store.verify_chain()
        assert chain.ok, chain.detail
        kinds = [r["kind"] for r in store.read_audit(limit=100)]
        # Every paired mutation left its own audit kind in the chain.
        assert kinds.count("grant_issue") == 2
        assert kinds.count("grant_redeem") == 1
        assert kinds.count("grant_close") == 2  # outcome_reported close + not_invocable close
        assert "source" in kinds and "ingest" in kinds and "outcome" in kinds
        assert "decision" in kinds

    def test_rolled_back_attempts_are_absent_from_the_chain_not_half_written(
            self, store, monkeypatch):
        """A failed paired append must not appear in the chain at all — not as a
        broken link, not as an orphan row — since the whole transaction rolled back."""
        store.append_audit("decision", {"n": 1})
        h = _issue(store, grant_id="g1")
        monkeypatch.setattr(store, "_append_audit_in_txn", _boom)
        with pytest.raises(RuntimeError):
            store.redeem_grant("g1", args_hash=h, principal_id="p1")
        with pytest.raises(RuntimeError):
            store.close_grant("g1")
        monkeypatch.undo()
        store.append_audit("ingest", {"n": 2})

        chain = store.verify_chain()
        assert chain.ok, chain.detail
        kinds = [r["kind"] for r in store.read_audit(limit=100)]
        # Exactly: decision, grant_issue (g1) — and nothing from the two failed
        # attempts, which never committed.
        assert kinds.count("grant_redeem") == 0
        assert kinds.count("grant_close") == 0
        assert kinds == ["ingest", "grant_issue", "decision"]
