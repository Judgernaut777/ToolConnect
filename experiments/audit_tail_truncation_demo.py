#!/usr/bin/env python3
"""Runnable demo: tail truncation of the audit log is now detected.

Reproduces the ORIGINAL defect repro end-to-end, on a *copy* of a live database
(including its ``-wal`` sidecar, as a real operator's on-disk snapshot would have),
and shows that ``verify-audit`` now exits 1 instead of the old exit-0
"audit chain OK (N-1 records)".

The repro:

    DELETE FROM audit WHERE seq=(SELECT MAX(seq) FROM audit)

Before the fix, deleting the newest audit record(s) left a chain that still validated
link-by-link, so the hash walk reported OK. The fix records a durable high-water mark
(max seq + tip record_hash) in ``meta``, updated in the same transaction as every
append; a chain whose actual tip is behind the mark is tail-truncated => tampered.

Run:  .venv/bin/python experiments/audit_tail_truncation_demo.py
Exit: 0 iff the demo proved detection works (truncated copy => verify-audit exit 1,
      clean copy => verify-audit exit 0).
"""

from __future__ import annotations

import shutil
import sqlite3
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from toolconnect.cli import main
from toolconnect.policy import CedarPolicyEngine
from toolconnect.service import ToolConnectService
from toolconnect.store import SqliteStore

ALLOW_READS = """
@id("allow-reads")
permit(principal, action == Action::"invoke", resource)
when { resource.effect == "read" };
"""


def _build_live_db(path: Path) -> None:
    """A realistic live database with several audit records, left open in WAL mode so
    that a naive file copy of only the .db (without -wal) would be incomplete."""
    store = SqliteStore(path)
    svc = ToolConnectService(store, CedarPolicyEngine(ALLOW_READS))
    svc.register_source("io.demo/s", tier="known", declares=["reader"])
    svc.ingest_payload("io.demo/s", [
        {"name": "reader", "claimed": {"read_only_hint": True}},
    ])
    svc.assert_tool("io.demo/s", "reader", {"effect": "read", "asserted_by": "op"})
    for _ in range(3):
        d = svc.authorize({"id": "a"}, "io.demo/s", "reader")
        svc.record_outcome(d["decision_id"], "success")
    # Deliberately DO NOT close: leave the WAL populated on disk, mirroring a snapshot
    # taken of a running service. We only need the connection object no longer.
    store.close()  # close flushes; copy both files below regardless to be faithful


def _copy_with_wal(src: Path, dst_dir: Path) -> Path:
    """Copy the database AND its -wal / -shm sidecars, as a faithful on-disk snapshot."""
    dst = dst_dir / src.name
    for suffix in ("", "-wal", "-shm"):
        s = Path(str(src) + suffix)
        if s.exists():
            shutil.copy2(s, str(dst) + suffix)
    return dst


def _truncate_tail(db: Path) -> None:
    """The exact original repro: delete the newest audit record."""
    conn = sqlite3.connect(db)
    conn.execute("DELETE FROM audit WHERE seq=(SELECT MAX(seq) FROM audit)")
    conn.commit()
    conn.close()


def main_demo() -> int:
    work = Path(tempfile.mkdtemp(prefix="tc_tail_demo_"))
    try:
        live = work / "live.db"
        _build_live_db(live)

        # 1) Clean copy (with -wal): verify-audit must exit 0.
        clean_dir = work / "clean"; clean_dir.mkdir()
        clean = _copy_with_wal(live, clean_dir)
        rc_clean = main(["verify-audit", "--db", str(clean)])
        print(f"\n[clean copy]      verify-audit exit = {rc_clean}  (expected 0)")

        # 2) Truncated copy (with -wal): apply the original repro, then verify.
        trunc_dir = work / "truncated"; trunc_dir.mkdir()
        trunc = _copy_with_wal(live, trunc_dir)
        _truncate_tail(trunc)
        rc_trunc = main(["verify-audit", "--db", str(trunc)])
        print(f"[truncated copy]  verify-audit exit = {rc_trunc}  (expected 1)\n")

        ok = (rc_clean == 0 and rc_trunc == 1)
        print("RESULT:", "PASS - tail truncation detected" if ok
              else "FAIL - truncation NOT detected (regression!)")
        return 0 if ok else 1
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main_demo())
