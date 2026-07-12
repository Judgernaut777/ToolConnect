"""Persistence: the store must round-trip the decision core without forking it.

The bar for hydration is behavioral equivalence: a catalog loaded from disk must
answer every governance question exactly as the in-memory catalog it persisted
would have. The four assertion states, fail-closed ambiguity, and fingerprint
semantics all live in `catalog.py`; these tests prove they survive a restart.
"""

from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from toolconnect.catalog import AmbiguousToolName, AssertionStatus, Catalog
from toolconnect.descriptor import (
    AssertedDescriptor, ClaimedMetadata, DataClass, Effect, ToolRef, ToolVersion,
    TrustedSource, TrustTier,
)
from toolconnect.store import SqliteStore

REPO = Path(__file__).resolve().parent.parent


@pytest.fixture()
def store(tmp_path):
    s = SqliteStore(tmp_path / "tc.db")
    yield s
    s.close()


def _persist_catalog(cat: Catalog, store: SqliteStore,
                     commands: dict[str, list[str]] | None = None) -> None:
    for sid, src in cat.sources.items():
        store.upsert_source(src, declares=cat.declared.get(sid, ()),
                            command=(commands or {}).get(sid))
    for tv in cat.tools.values():
        store.upsert_tool(tv)
    for (sid, name), record in cat._assertions.items():
        store.upsert_assertion(sid, name, record)


class TestFingerprintStability:
    """The claim fingerprint must mean the same thing in every process."""

    SNIPPET = (
        "from toolconnect.catalog import Catalog\n"
        "from toolconnect.descriptor import ClaimedMetadata, ToolRef, ToolVersion\n"
        "tv = ToolVersion(ref=ToolRef('t', '1.0.0'), source_id='s',\n"
        "                 claimed=ClaimedMetadata(description='d', read_only_hint=True))\n"
        "print(Catalog._fingerprint(tv))\n"
    )

    def _run(self, seed: str) -> int:
        out = subprocess.run(
            [sys.executable, "-c", self.SNIPPET],
            capture_output=True, text=True, check=True,
            env={"PYTHONHASHSEED": seed, "PYTHONPATH": str(REPO / "src"), "PATH": "/usr/bin"},
        )
        return int(out.stdout.strip())

    def test_identical_across_hash_seeds(self):
        # The builtin hash() would differ across these; SHA-256 must not.
        assert self._run("1") == self._run("2") == self._run("999")

    def test_still_discriminates_changed_claims(self):
        a = ToolVersion(ref=ToolRef("t", "1.0.0"), source_id="s",
                        claimed=ClaimedMetadata(description="v1"))
        b = ToolVersion(ref=ToolRef("t", "1.0.0"), source_id="s",
                        claimed=ClaimedMetadata(description="v2"))
        assert Catalog._fingerprint(a) != Catalog._fingerprint(b)
        assert Catalog._fingerprint(a) == Catalog._fingerprint(a)


class TestHydration:
    def test_round_trip_preserves_all_four_assertion_states(self, store, tmp_path):
        cat = Catalog()
        cat.register_source(TrustedSource("s", TrustTier.KNOWN),
                            declares={"stable", "moved", "never", "gone"})
        desc = AssertedDescriptor(effect=Effect.READ, asserted_by="op")

        # State: asserted, claim unchanged.
        cat.ingest_claimed("s", "stable", ClaimedMetadata(description="v1"))
        cat.assert_descriptor("s", "stable", desc)
        # State: asserted, then re-ingested changed (rug pull).
        cat.ingest_claimed("s", "moved", ClaimedMetadata(description="v1"))
        cat.assert_descriptor("s", "moved", desc)
        cat.ingest_claimed("s", "moved", ClaimedMetadata(description="v2-CHANGED"))
        # State: never asserted.
        cat.ingest_claimed("s", "never", ClaimedMetadata(description="v1"))

        _persist_catalog(cat, store)
        loaded = store.load_catalog()

        for name in ("stable", "moved", "never"):
            assert loaded.assertion_status("s", name) is cat.assertion_status("s", name)
            assert loaded.invocable("s", name) == cat.invocable("s", name)
        assert loaded.assertion_status("s", "stable") is AssertionStatus.ASSERTED
        assert loaded.invocable("s", "stable")
        assert loaded.assertion_status("s", "moved") is AssertionStatus.CHANGED
        assert not loaded.invocable("s", "moved")
        assert loaded.assertion_status("s", "never") is AssertionStatus.NEVER

    def test_assertion_evidence_survives_a_restart_then_reingestion(self, store):
        """The rug-pull detector must work across a process boundary.

        Assert before "restart"; re-ingest the identical claim after hydration.
        The assertion must carry over (identical re-announcement is a no-op),
        and a changed claim after hydration must drop invocability.
        """
        cat = Catalog()
        cat.register_source(TrustedSource("s", TrustTier.KNOWN), declares={"t"})
        claim = ClaimedMetadata(description="stable claim", read_only_hint=True)
        cat.ingest_claimed("s", "t", claim)
        cat.assert_descriptor("s", "t", AssertedDescriptor(effect=Effect.READ, asserted_by="op"))
        _persist_catalog(cat, store)

        loaded = store.load_catalog()  # the "restart"
        loaded.ingest_claimed("s", "t", claim)  # identical re-announcement
        assert loaded.invocable("s", "t"), "assertion must survive restart + identical claim"

        loaded.ingest_claimed("s", "t", ClaimedMetadata(description="CHANGED", read_only_hint=True))
        assert not loaded.invocable("s", "t")
        assert loaded.assertion_status("s", "t") is AssertionStatus.CHANGED

    def test_namespaced_identity_and_ambiguity_survive_hydration(self, store):
        cat = Catalog()
        cat.register_source(TrustedSource("a", TrustTier.KNOWN), declares={"search"})
        cat.register_source(TrustedSource("b", TrustTier.UNTRUSTED), declares={"search"})
        cat.ingest_claimed("a", "search", ClaimedMetadata(description="a's"))
        cat.ingest_claimed("b", "search", ClaimedMetadata(description="b's"))
        _persist_catalog(cat, store)

        loaded = store.load_catalog()
        assert loaded.get("a", "search").claimed.description == "a's"
        assert loaded.get("b", "search").claimed.description == "b's"
        with pytest.raises(AmbiguousToolName):
            loaded.resolve("search")

    def test_descriptor_fields_round_trip_exactly(self, store):
        cat = Catalog()
        cat.register_source(TrustedSource("s", TrustTier.VERIFIED), declares={"t"})
        cat.ingest_claimed("s", "t", ClaimedMetadata(
            description="d", read_only_hint=False, destructive_hint=True,
            idempotent_hint=False, open_world_hint=True))
        desc = AssertedDescriptor(
            effect=Effect.DESTRUCTIVE,
            reads=frozenset({DataClass.SECRET, DataClass.PII}),
            writes=frozenset({DataClass.EXTERNAL}),
            scopes=frozenset({"/etc", "db:users"}),
            reversible=False, idempotent=True, requires_approval=True,
            declassifies=False, asserted_by="op@example",
        )
        cat.assert_descriptor("s", "t", desc)
        _persist_catalog(cat, store)
        loaded = store.load_catalog()
        assert loaded.get("s", "t").asserted == desc
        assert loaded.get("s", "t").claimed == cat.get("s", "t").claimed
        assert loaded.get("s", "t").claim_conflicts() == cat.get("s", "t").claim_conflicts()

    def test_schema_version_mismatch_refuses_to_open(self, tmp_path):
        path = tmp_path / "tc.db"
        SqliteStore(path).close()
        conn = sqlite3.connect(path)
        conn.execute("UPDATE meta SET value='999' WHERE key='schema_version'")
        conn.commit()
        conn.close()
        with pytest.raises(RuntimeError, match="schema version"):
            SqliteStore(path)


class TestDiscoveryObservations:
    def test_last_discovery_round_trips(self, store):
        assert store.last_discovery("s") is None
        store.upsert_source(TrustedSource("s", TrustTier.KNOWN))
        store.record_discovery("s", {"b", "a"})
        names, observed_at = store.last_discovery("s")
        assert names == {"a", "b"}
        assert observed_at  # ISO timestamp


class TestAuditChain:
    def test_append_and_verify(self, store):
        for i in range(5):
            store.append_audit("decision", {"n": i, "allowed": i % 2 == 0})
        v = store.verify_chain()
        assert v.ok and v.records == 5

    def test_tampering_with_a_body_breaks_the_chain(self, store, tmp_path):
        for i in range(3):
            store.append_audit("decision", {"n": i})
        conn = sqlite3.connect(store.path)
        conn.execute("UPDATE audit SET body=? WHERE seq=2", (json.dumps({"n": 999}),))
        conn.commit()
        conn.close()
        v = store.verify_chain()
        assert not v.ok
        assert v.broken_at == 2

    def test_deleting_a_record_breaks_the_chain(self, store):
        for i in range(3):
            store.append_audit("decision", {"n": i})
        conn = sqlite3.connect(store.path)
        conn.execute("DELETE FROM audit WHERE seq=2")
        conn.commit()
        conn.close()
        v = store.verify_chain()
        assert not v.ok

    def test_tail_truncation_of_one_record_is_detected(self, store):
        # Regression: deleting the NEWEST record leaves a chain that is still internally
        # consistent (every surviving link validates), so the hash walk alone reported
        # "OK (N-1 records)". The durable high-water mark must catch it.
        for i in range(5):
            store.append_audit("decision", {"n": i})
        conn = sqlite3.connect(store.path)
        conn.execute("DELETE FROM audit WHERE seq=(SELECT MAX(seq) FROM audit)")
        conn.commit()
        conn.close()
        v = store.verify_chain()
        assert not v.ok
        assert "tail truncation" in v.detail

    def test_tail_truncation_of_k_records_is_detected(self, store):
        for i in range(6):
            store.append_audit("decision", {"n": i})
        conn = sqlite3.connect(store.path)
        # Delete the 3 newest records.
        for _ in range(3):
            conn.execute("DELETE FROM audit WHERE seq=(SELECT MAX(seq) FROM audit)")
        conn.commit()
        conn.close()
        v = store.verify_chain()
        assert not v.ok
        assert "tail truncation" in v.detail
        assert v.records == 3  # the survivors still verified before the mark caught it

    def test_deleting_entire_tail_to_empty_is_detected(self, store):
        for i in range(3):
            store.append_audit("decision", {"n": i})
        conn = sqlite3.connect(store.path)
        conn.execute("DELETE FROM audit")
        conn.commit()
        conn.close()
        v = store.verify_chain()
        assert not v.ok
        assert "tail truncation" in v.detail

    def test_clean_chain_still_verifies_after_head_tracking(self, store):
        for i in range(4):
            store.append_audit("decision", {"n": i})
        v = store.verify_chain()
        assert v.ok and v.records == 4

    def test_read_audit_filters_by_kind(self, store):
        store.append_audit("decision", {"a": 1})
        store.append_audit("ingest", {"b": 2})
        store.append_audit("decision", {"c": 3})
        assert len(store.read_audit(kind="decision")) == 2
        assert len(store.read_audit(kind="ingest")) == 1
        assert len(store.read_audit()) == 3
        assert store.read_audit()[0]["body"] == {"c": 3}  # newest first
