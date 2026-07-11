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
