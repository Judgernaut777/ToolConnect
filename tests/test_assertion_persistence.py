"""Assertions bind to an exact SHA-256 fingerprint — across a real process boundary,
and against database tampering.

Deliverable 4. The in-process fingerprint semantics are covered elsewhere; here the
binding is proven to survive being written to disk and read back in a *separate Python
process*, and to fail closed when the persisted state is tampered with.
"""

from __future__ import annotations

import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from toolconnect.catalog import AssertionStatus, Catalog
from toolconnect.descriptor import (
    AssertedDescriptor, ClaimedMetadata, Effect, TrustedSource, TrustTier,
)
from toolconnect.store import SqliteStore

REPO = Path(__file__).resolve().parent.parent


def _persist(cat: Catalog, store: SqliteStore) -> None:
    for sid, src in cat.sources.items():
        store.upsert_source(src, declares=cat.declared.get(sid, ()))
    for tv in cat.tools.values():
        store.upsert_tool(tv)
    for (sid, name), record in cat._assertions.items():
        store.upsert_assertion(sid, name, record)


def _seed(path) -> None:
    cat = Catalog()
    cat.register_source(TrustedSource("s", TrustTier.KNOWN), declares={"t"})
    cat.ingest_claimed("s", "t", ClaimedMetadata(description="v1", read_only_hint=True))
    cat.assert_descriptor("s", "t", AssertedDescriptor(effect=Effect.READ,
                                                       asserted_by="op"))
    store = SqliteStore(path)
    _persist(cat, store)
    store.close()


class TestCrossProcessBinding:
    def test_fingerprint_binding_survives_a_separate_process(self, tmp_path):
        db = tmp_path / "tc.db"
        _seed(db)
        # A genuinely separate interpreter loads the DB and reports the state.
        snippet = (
            "from toolconnect.store import SqliteStore\n"
            "from toolconnect.catalog import Catalog\n"
            f"s = SqliteStore({str(db)!r})\n"
            "cat = s.load_catalog()\n"
            "tv = cat.get('s','t')\n"
            "rec = cat._assertions[('s','t')]\n"
            "print(cat.assertion_status('s','t').value)\n"
            "print(cat.invocable('s','t'))\n"
            "print(Catalog._fingerprint(tv) == rec.fingerprint)\n"
        )
        out = subprocess.run(
            [sys.executable, "-c", snippet],
            capture_output=True, text=True, check=True,
            env={"PYTHONPATH": str(REPO / "src"), "PATH": "/usr/bin",
                 "PYTHONHASHSEED": "12345"})
        status, invocable, fp_match = out.stdout.split()
        assert status == "asserted"
        assert invocable == "True"
        assert fp_match == "True", "persisted fingerprint must equal the recomputed one"

    def test_rug_pull_after_restart_drops_invocability(self, tmp_path):
        db = tmp_path / "tc.db"
        _seed(db)
        store = SqliteStore(db)
        loaded = store.load_catalog()  # the "restart"
        assert loaded.invocable("s", "t")
        # The server changes the tool under a standing assertion.
        loaded.ingest_claimed("s", "t", ClaimedMetadata(description="CHANGED",
                                                        read_only_hint=True))
        assert not loaded.invocable("s", "t")
        assert loaded.assertion_status("s", "t") is AssertionStatus.CHANGED
        store.close()


class TestTamperDetection:
    def test_tampering_the_claim_drops_the_assertion_on_reload(self, tmp_path):
        """Edit the stored claim underneath a standing assertion. On hydration the
        fingerprint no longer matches, so the tool is NOT invocable — hydration derives
        assertion validity from the fingerprint, it does not trust the stored column."""
        db = tmp_path / "tc.db"
        _seed(db)
        # Confirm it is invocable when untouched.
        s0 = SqliteStore(db)
        assert s0.load_catalog().invocable("s", "t")
        s0.close()

        # Tamper: rewrite the tool's claimed metadata (a different description → a
        # different fingerprint) while leaving the `asserted` column populated.
        conn = sqlite3.connect(db)
        import json as _json
        tampered = _json.dumps({"description": "EVIL", "read_only_hint": True,
                                "destructive_hint": None, "idempotent_hint": None,
                                "open_world_hint": None}, sort_keys=True,
                               separators=(",", ":"))
        conn.execute("UPDATE tools SET claimed=? WHERE source_id='s' AND name='t'",
                     (tampered,))
        conn.commit(); conn.close()

        s1 = SqliteStore(db)
        cat = s1.load_catalog()
        assert cat.invocable("s", "t") is False, "tampered claim must not stay invocable"
        assert cat.assertion_status("s", "t") is AssertionStatus.CHANGED
        # And the integrity probe reports it explicitly.
        report = s1.verify_assertions()
        assert report["ok"] is False
        assert report["mismatches"][0]["name"] == "t"
        s1.close()

    def test_injecting_an_asserted_column_without_evidence_is_ignored(self, tmp_path):
        """Forge an `asserted` column on a never-asserted tool. With no matching
        assertion record, hydration must leave it unasserted."""
        db = tmp_path / "tc.db"
        store = SqliteStore(db)
        cat = Catalog()
        cat.register_source(TrustedSource("s", TrustTier.KNOWN), declares={"t"})
        cat.ingest_claimed("s", "t", ClaimedMetadata(description="v1"))
        _persist(cat, store)  # no assertion recorded
        store.close()

        conn = sqlite3.connect(db)
        import json as _json
        forged = _json.dumps({"effect": "read", "reads": [], "writes": [], "scopes": [],
                              "reversible": True, "idempotent": False,
                              "requires_approval": False, "declassifies": False,
                              "asserted_by": "attacker"}, sort_keys=True,
                             separators=(",", ":"))
        conn.execute("UPDATE tools SET asserted=? WHERE source_id='s' AND name='t'",
                     (forged,))
        conn.commit(); conn.close()

        s1 = SqliteStore(db)
        cat = s1.load_catalog()
        assert cat.invocable("s", "t") is False
        assert cat.assertion_status("s", "t") is AssertionStatus.NEVER
        s1.close()

    def test_verify_assertions_ok_on_clean_db(self, tmp_path):
        db = tmp_path / "tc.db"
        _seed(db)
        store = SqliteStore(db)
        report = store.verify_assertions()
        assert report["ok"] is True and report["checked"] == 1
        assert report["mismatches"] == []
        store.close()
