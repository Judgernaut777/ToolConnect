"""Operator CLI surface: verify-audit, drift, backup, audit.

Deliverables 5 (drift observable AND actionable — an operator command that exits
non-zero on drift) and 9 (audit-chain verification exposed operationally — a command an
operator or cron job runs, with tamper detection). These call ``toolconnect.cli.main``
with argv, exactly as the installed ``toolconnect`` entry point would.
"""

from __future__ import annotations

import json
import sqlite3

import pytest

from toolconnect.cli import main
from toolconnect.policy import CedarPolicyEngine
from toolconnect.service import ToolConnectService
from toolconnect.store import SqliteStore

ALLOW_READS = """
@id("allow-reads")
permit(principal, action == Action::"invoke", resource)
when { resource.effect == "read" };
"""


@pytest.fixture()
def db(tmp_path):
    """A populated database: one source, an ingest observation, a mix of asserted and
    unasserted tools, and a decision — so drift and audit have something to report."""
    path = tmp_path / "tc.db"
    store = SqliteStore(path)
    svc = ToolConnectService(store, CedarPolicyEngine(ALLOW_READS))
    svc.register_source("io.test/s", tier="known", declares=["reader", "gone"])
    svc.ingest_payload("io.test/s", [
        {"name": "reader", "claimed": {"read_only_hint": True}},
        {"name": "extra", "claimed": {"read_only_hint": True}},  # undeclared-present
    ])
    svc.assert_tool("io.test/s", "reader", {"effect": "read", "asserted_by": "op"})
    d = svc.authorize({"id": "a"}, "io.test/s", "reader")
    svc.record_outcome(d["decision_id"], "success")
    store.close()
    return str(path)


class TestVerifyAuditCli:
    def test_clean_chain_exits_zero(self, db, capsys):
        rc = main(["verify-audit", "--db", db])
        assert rc == 0
        assert "audit chain OK" in capsys.readouterr().out

    def test_json_output(self, db, capsys):
        rc = main(["verify-audit", "--db", db, "--json"])
        assert rc == 0
        assert json.loads(capsys.readouterr().out)["ok"] is True

    def test_tampered_chain_exits_nonzero(self, db, capsys):
        conn = sqlite3.connect(db)
        conn.execute("UPDATE audit SET body=? WHERE seq=1",
                     (json.dumps({"tampered": True}),))
        conn.commit(); conn.close()
        rc = main(["verify-audit", "--db", db])
        out = capsys.readouterr().out
        assert rc == 1
        assert "BROKEN" in out

    def test_deleted_record_is_detected(self, db):
        conn = sqlite3.connect(db)
        # Delete a middle record to break the prev-hash linkage.
        seqs = [r[0] for r in conn.execute("SELECT seq FROM audit ORDER BY seq")]
        conn.execute("DELETE FROM audit WHERE seq=?", (seqs[1],))
        conn.commit(); conn.close()
        assert main(["verify-audit", "--db", db]) == 1


class TestDriftCli:
    def test_drift_reports_and_exits_two(self, db, capsys):
        # `gone` was declared but not discovered; `extra` discovered but not declared;
        # `reader` asserted; `extra` unasserted → drift exists.
        rc = main(["drift", "--db", db, "--source", "io.test/s"])
        out = capsys.readouterr().out
        assert rc == 2, "drift present must exit non-zero so an operator can gate on it"
        assert "advertised-missing: gone" in out
        assert "undeclared-present: extra" in out
        assert "unasserted: extra" in out

    def test_drift_json(self, db, capsys):
        rc = main(["drift", "--db", db, "--source", "io.test/s", "--json"])
        payload = json.loads(capsys.readouterr().out)
        assert rc == 2
        assert payload["clean"] is False
        assert "gone" in payload["advertised_missing"]
        assert payload["observed_at"]

    def test_clean_source_exits_zero(self, tmp_path, capsys):
        path = tmp_path / "clean.db"
        store = SqliteStore(path)
        svc = ToolConnectService(store, CedarPolicyEngine(ALLOW_READS))
        svc.register_source("s", tier="known", declares=["only"])
        svc.ingest_payload("s", [{"name": "only", "claimed": {"read_only_hint": True}}])
        svc.assert_tool("s", "only", {"effect": "read", "asserted_by": "op"})
        store.close()
        rc = main(["drift", "--db", str(path), "--source", "s"])
        assert rc == 0
        assert "no drift" in capsys.readouterr().out

    def test_unobserved_source_is_an_error_not_a_guess(self, tmp_path):
        path = tmp_path / "u.db"
        store = SqliteStore(path)
        svc = ToolConnectService(store, CedarPolicyEngine(ALLOW_READS))
        svc.register_source("s", tier="known")
        store.close()
        with pytest.raises(SystemExit) as exc:
            main(["drift", "--db", str(path), "--source", "s"])
        assert "no discovery" in str(exc.value)

    def test_unknown_source_errors(self, db):
        with pytest.raises(SystemExit) as exc:
            main(["drift", "--db", db, "--source", "nope"])
        assert "unknown source" in str(exc.value)


class TestBackupCli:
    def test_backup_creates_verifiable_copy(self, db, tmp_path, capsys):
        out_path = tmp_path / "backup.db"
        rc = main(["backup", "--db", db, "--out", str(out_path)])
        assert rc == 0
        assert out_path.exists()
        assert "audit chain ok=True" in capsys.readouterr().out
        # The copy is independently openable and verifies.
        store = SqliteStore(out_path)
        assert store.verify_chain().ok
        store.close()


class TestAuditCli:
    def test_audit_lists_records(self, db, capsys):
        rc = main(["audit", "--db", db, "--limit", "50"])
        out = capsys.readouterr().out
        assert rc == 0
        assert "decision" in out and "assertion" in out and "source" in out

    def test_audit_filters_by_kind(self, db, capsys):
        rc = main(["audit", "--db", db, "--kind", "decision", "--json"])
        records = json.loads(capsys.readouterr().out)
        assert rc == 0
        assert records and all(r["kind"] == "decision" for r in records)
