"""The `toolconnect` CLI, run as real subprocesses."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def _run(*args: str, cwd=None) -> subprocess.CompletedProcess:
    env = {**os.environ, "PYTHONPATH": str(REPO / "src")}
    return subprocess.run([sys.executable, "-m", "toolconnect.cli", *args],
                          capture_output=True, text=True, env=env, cwd=cwd)


class TestCli:
    def test_version(self):
        out = _run("version")
        assert out.returncode == 0
        assert out.stdout.strip() == "toolconnect 0.1.0"

    def test_init_db_creates_a_fresh_database(self, tmp_path):
        db = tmp_path / "data" / "tc.db"  # parent does not exist yet
        out = _run("init-db", "--db", str(db))
        assert out.returncode == 0, out.stderr
        assert db.exists()
        assert "audit chain ok=True" in out.stdout
        # The reported schema version must be the store's actual version, not a
        # hardcoded literal that rots on a schema bump (a fresh DB is at SCHEMA_VERSION).
        from toolconnect.store import SCHEMA_VERSION
        assert f"schema v{SCHEMA_VERSION}" in out.stdout
        # Idempotent: opening again succeeds and reports the same clean chain.
        out2 = _run("init-db", "--db", str(db))
        assert out2.returncode == 0

    def test_init_db_requires_a_path(self):
        out = _run("init-db")
        assert out.returncode != 0
        assert "--db" in out.stderr

    def test_init_db_reads_config_file(self, tmp_path):
        cfg = tmp_path / "toolconnect.toml"
        db = tmp_path / "from-config.db"
        cfg.write_text(f'db = "{db}"\n')
        out = _run("init-db", "--config", str(cfg))
        assert out.returncode == 0, out.stderr
        assert db.exists()

    def test_serve_refuses_to_start_without_policies(self, tmp_path):
        out = _run("serve", "--db", str(tmp_path / "tc.db"))
        assert out.returncode != 0
        assert "--policies" in out.stderr

    def test_serve_refuses_an_unparseable_policy_set(self, tmp_path):
        bad = tmp_path / "bad.cedar"
        bad.write_text("this is not cedar {{{")
        out = _run("serve", "--db", str(tmp_path / "tc.db"), "--policies", str(bad))
        assert out.returncode != 0
        # A policy set that does not parse must never become an allow-all server.
        assert "invalid Cedar policy set" in out.stderr
        # ...and the refusal is one actionable line, not a raw traceback.
        assert "Traceback" not in out.stderr
        assert str(bad) in out.stderr

    def test_store_subcommand_refuses_a_newer_than_build_db_cleanly(self, tmp_path):
        """A database written by a newer build fails closed (exit 1) with one clean,
        actionable line — never a raw Python traceback dumped on the operator."""
        import sqlite3

        from toolconnect.store import SCHEMA_VERSION

        db = tmp_path / "tc.db"
        assert _run("init-db", "--db", str(db)).returncode == 0
        # Forge a database from the future: bump the recorded schema version past what
        # this build supports, exactly as a newer release's migration would leave it.
        conn = sqlite3.connect(db)
        conn.execute("UPDATE meta SET value=? WHERE key='schema_version'",
                     (str(SCHEMA_VERSION + 1),))
        conn.commit()
        conn.close()

        out = _run("verify-audit", "--db", str(db))
        assert out.returncode == 1, out.stderr
        assert "Traceback" not in out.stderr
        # One actionable line: what went wrong and which database.
        assert "newer than this build" in out.stderr
        assert str(db) in out.stderr
        assert out.stderr.strip().count("\n") == 0


class TestGatewayCli:
    """The `toolconnect gateway` subcommand run as a real subprocess — end-to-end
    coverage of the CLI wiring itself (arg parsing, config/policy loading, the
    downstream REMAINDER handling, store cleanup), not just the Gateway class."""

    ALLOW_READS = (
        '@id("allow-reads")\n'
        'permit(principal, action == Action::"invoke", resource)\n'
        'when { resource.effect == "read" };\n'
    )

    def _prepare(self, tmp_path):
        from toolconnect.policy import CedarPolicyEngine
        from toolconnect.service import ToolConnectService
        from toolconnect.store import SqliteStore
        db = tmp_path / "tc.db"
        pol = tmp_path / "policies.cedar"
        pol.write_text(self.ALLOW_READS)
        store = SqliteStore(db)
        svc = ToolConnectService(store, CedarPolicyEngine(self.ALLOW_READS))
        svc.register_source("downstream-1", "known")
        svc.ingest_payload("downstream-1",
                           [{"name": "reader", "claimed": {"read_only_hint": True}}])
        svc.assert_tool("downstream-1", "reader",
                        {"effect": "read", "asserted_by": "op"})
        store.close()
        return db, pol

    def test_gateway_end_to_end_over_real_stdio(self, tmp_path):
        import json
        db, pol = self._prepare(tmp_path)
        fixture = REPO / "fixtures" / "callable_mcp_server.py"
        env = {**os.environ, "PYTHONPATH": str(REPO / "src")}
        client_session = "\n".join([
            json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                        "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                                   "clientInfo": {"name": "cli-test", "version": "0"}}}),
            json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                        "params": {"name": "reader", "arguments": {"path": "/x"}}}),
        ]) + "\n"
        proc = subprocess.run(
            [sys.executable, "-m", "toolconnect.cli", "gateway",
             "--db", str(db), "--policies", str(pol),
             "--principal-id", "agent-1", "--source-id", "downstream-1",
             "--", sys.executable, str(fixture)],
            input=client_session, capture_output=True, text=True, env=env, timeout=120)
        assert proc.returncode == 0, proc.stderr
        replies = [json.loads(ln) for ln in proc.stdout.splitlines() if ln.strip()]
        assert len(replies) == 2
        assert replies[0]["result"]["serverInfo"]["name"] == "callable-mcp-fixture"
        assert (replies[1]["result"]["structuredContent"]["echoed_arguments"]
                == {"path": "/x"})

    def test_gateway_spawn_failure_is_a_clean_refusal_not_a_traceback(self, tmp_path):
        db, pol = self._prepare(tmp_path)
        out = _run("gateway", "--db", str(db), "--policies", str(pol),
                   "--principal-id", "agent-1", "--source-id", "downstream-1",
                   "--", "/no/such/binary-xyz")
        assert out.returncode != 0
        assert "could not start downstream command" in out.stderr
        assert "Traceback" not in out.stderr

    def test_gateway_requires_a_downstream_command(self, tmp_path):
        db, pol = self._prepare(tmp_path)
        out = _run("gateway", "--db", str(db), "--policies", str(pol),
                   "--principal-id", "agent-1", "--source-id", "downstream-1")
        assert out.returncode != 0
        assert "downstream command" in out.stderr


class TestExamples:
    def test_example_policy_set_parses(self):
        from toolconnect.policy import CedarPolicyEngine
        CedarPolicyEngine((REPO / "examples" / "policies.cedar").read_text())

    def test_example_config_parses(self):
        import tomllib
        with (REPO / "examples" / "toolconnect.toml").open("rb") as fh:
            cfg = tomllib.load(fh)
        assert {"db", "policies", "host", "port"} <= set(cfg)
        assert cfg["port"] == 8095
