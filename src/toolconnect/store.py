"""SQLite persistence for the decision core. Hydrates and stores; never decides.

The in-memory :class:`~toolconnect.catalog.Catalog` remains the semantic authority.
This module does exactly two jobs:

* **Store** the catalog's state (sources, tool versions, durable assertion evidence,
  last discovery observations) as the service mutates it.
* **Hydrate** a byte-faithful :class:`Catalog` back from disk, so that behavior after
  a restart continues exactly where the in-memory core left off. No governance logic
  is reimplemented here — the four assertion states, fail-closed ambiguity, and
  fingerprint semantics all live in `catalog.py` and are merely round-tripped.

The audit log is append-only and hash-chained: ``record_hash = SHA-256(kind ‖ body ‖
created_at ‖ prev_hash)``. Verification walks the chain and reports the first broken
link. This follows ARCHITECTURE §4.8 — a single-writer SQLite log with a hash chain,
not a Merkle tree, because a single box has no untrusted verifiers.

Uses stdlib ``sqlite3`` — the existing code style is stdlib dataclasses with one
deliberate dependency (cedarpy); an ORM would be the heavier fit.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

from .catalog import AssertionRecord, Catalog, ToolId
from .descriptor import (
    AssertedDescriptor,
    ClaimedMetadata,
    DataClass,
    Effect,
    ToolRef,
    ToolVersion,
    TrustedSource,
    TrustTier,
)

#: The oldest schema this code can open and upgrade from. RC1 (v0.1.0-rc1) shipped
#: schema v1; the baseline DDL below IS that v1 shape, so a fresh database and a
#: migrated legacy database converge on byte-identical structure.
BASELINE_VERSION = 1

#: The current schema version. A database at an older version is migrated forward on
#: open (see ``_MIGRATIONS``); a database at a *newer* version is refused, because this
#: code cannot know what a future migration changed.
SCHEMA_VERSION = 2

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sources (
    source_id     TEXT PRIMARY KEY,
    tier          TEXT NOT NULL,
    transport     TEXT NOT NULL,
    declared      TEXT NOT NULL,          -- JSON array of declared tool names
    command       TEXT,                   -- JSON argv for stdio discovery, or NULL
    registered_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS tools (
    source_id    TEXT NOT NULL,
    name         TEXT NOT NULL,
    version      TEXT NOT NULL,
    claimed      TEXT NOT NULL,           -- JSON ClaimedMetadata
    asserted     TEXT,                    -- JSON AssertedDescriptor, or NULL
    input_schema TEXT NOT NULL DEFAULT '{}',
    updated_at   TEXT NOT NULL,
    PRIMARY KEY (source_id, name)
);
CREATE TABLE IF NOT EXISTS assertions (
    source_id   TEXT NOT NULL,
    name        TEXT NOT NULL,
    descriptor  TEXT NOT NULL,            -- JSON AssertedDescriptor that was vouched
    fingerprint TEXT NOT NULL,            -- stable claim fingerprint (decimal string)
    asserted_at TEXT NOT NULL,
    PRIMARY KEY (source_id, name)
);
CREATE TABLE IF NOT EXISTS discoveries (
    source_id   TEXT PRIMARY KEY,
    discovered  TEXT NOT NULL,            -- JSON array: last successful tools/list
    observed_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit (
    seq         INTEGER PRIMARY KEY AUTOINCREMENT,
    kind        TEXT NOT NULL,            -- decision | outcome | ingest | assertion | drift | source
    body        TEXT NOT NULL,            -- JSON
    created_at  TEXT NOT NULL,
    prev_hash   TEXT NOT NULL,
    record_hash TEXT NOT NULL
);
"""

#: Forward-only migrations, keyed by the version they PRODUCE. Applied in ascending
#: order for any stored version < SCHEMA_VERSION. Each statement must be additive and
#: idempotent-safe under a single application (they run exactly once per version step,
#: inside a transaction, and only when the stored version is strictly below the key).
#:
#: v2 (this release): an operator-facing display ``label`` on sources, and an index on
#: ``audit(kind)`` that turns the kind-filtered audit reads and decision lookups from a
#: table scan into an index seek. Both are purely additive: no existing column changes,
#: no row is rewritten, and the hash chain is untouched, so a migrated database verifies
#: exactly as it did before.
_MIGRATIONS: dict[int, list[str]] = {
    2: [
        "ALTER TABLE sources ADD COLUMN label TEXT",
        "CREATE INDEX IF NOT EXISTS idx_audit_kind ON audit(kind)",
    ],
}

_GENESIS = "0" * 64


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


# ------------------------------------------------------------------ serialization

def claimed_to_json(c: ClaimedMetadata) -> str:
    return _canonical({
        "description": c.description,
        "read_only_hint": c.read_only_hint,
        "destructive_hint": c.destructive_hint,
        "idempotent_hint": c.idempotent_hint,
        "open_world_hint": c.open_world_hint,
    })


def claimed_from_json(raw: str) -> ClaimedMetadata:
    d = json.loads(raw)
    return ClaimedMetadata(
        description=d.get("description", ""),
        read_only_hint=d.get("read_only_hint"),
        destructive_hint=d.get("destructive_hint"),
        idempotent_hint=d.get("idempotent_hint"),
        open_world_hint=d.get("open_world_hint"),
    )


def asserted_to_json(a: AssertedDescriptor) -> str:
    return _canonical({
        "effect": a.effect.value,
        "reads": sorted(c.value for c in a.reads),
        "writes": sorted(c.value for c in a.writes),
        "scopes": sorted(a.scopes),
        "reversible": a.reversible,
        "idempotent": a.idempotent,
        "requires_approval": a.requires_approval,
        "declassifies": a.declassifies,
        "asserted_by": a.asserted_by,
    })


def asserted_from_json(raw: str) -> AssertedDescriptor:
    d = json.loads(raw)
    return AssertedDescriptor(
        effect=Effect(d["effect"]),
        reads=frozenset(DataClass(c) for c in d.get("reads", ())),
        writes=frozenset(DataClass(c) for c in d.get("writes", ())),
        scopes=frozenset(d.get("scopes", ())),
        reversible=d.get("reversible", True),
        idempotent=d.get("idempotent", False),
        requires_approval=d.get("requires_approval", False),
        declassifies=d.get("declassifies", False),
        asserted_by=d.get("asserted_by", ""),
    )


# ------------------------------------------------------------------------- store

class ChainVerification:
    """Result of walking the audit hash chain."""

    def __init__(self, ok: bool, records: int, broken_at: int | None = None,
                 detail: str = "") -> None:
        self.ok = ok
        self.records = records
        self.broken_at = broken_at
        self.detail = detail

    def as_dict(self) -> dict:
        return {"ok": self.ok, "records": self.records,
                "broken_at": self.broken_at, "detail": self.detail}


class SqliteStore:
    """Single-writer SQLite persistence. Thread-safe via one internal lock."""

    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        with self._lock, self._conn:
            self._conn.executescript(_SCHEMA)
            row = self._conn.execute(
                "SELECT value FROM meta WHERE key='schema_version'").fetchone()
            if row is None:
                # Fresh database: the baseline DDL above created the v1 shape. Record
                # v1, then run forward migrations so a new DB and an upgraded legacy DB
                # converge on identical structure.
                self._conn.execute(
                    "INSERT INTO meta(key, value) VALUES ('schema_version', ?)",
                    (str(BASELINE_VERSION),))
                current = BASELINE_VERSION
            else:
                current = int(row[0])
            if current > SCHEMA_VERSION:
                # A database written by newer code. We cannot know what it changed, so
                # refuse rather than risk misreading it — fail closed on schema too.
                raise RuntimeError(
                    f"database schema version {current} != supported {SCHEMA_VERSION} "
                    f"(newer than this build; refusing to open)")
            if current < SCHEMA_VERSION:
                self._migrate(current)
        self.schema_version = SCHEMA_VERSION

    def _migrate(self, from_version: int) -> None:
        """Apply forward migrations in-place, from ``from_version`` up to current.

        Runs inside the caller's transaction/lock. Each version step is applied atomically
        and the recorded ``schema_version`` advances only after its statements succeed, so
        an interrupted upgrade leaves the database at a known, still-openable version.
        """
        for target in range(from_version + 1, SCHEMA_VERSION + 1):
            for statement in _MIGRATIONS.get(target, ()):
                self._conn.execute(statement)
            self._conn.execute(
                "UPDATE meta SET value=? WHERE key='schema_version'", (str(target),))

    def backup(self, dest_path: str | Path) -> str:
        """Write a consistent snapshot of the database to ``dest_path``.

        Uses SQLite's online-backup API, which produces a transactionally consistent
        copy even while other threads are writing — no need to quiesce the service. The
        copy is a complete, openable ToolConnect database (schema + catalog + audit
        chain). Restore is simply opening (or moving into place) the resulting file;
        the round trip preserves the hash chain byte-for-byte, so a restored backup
        verifies. Returns the destination path.
        """
        dest_path = str(dest_path)
        if dest_path != ":memory:":
            Path(dest_path).parent.mkdir(parents=True, exist_ok=True)
        dest = sqlite3.connect(dest_path)
        try:
            with self._lock:
                self._conn.backup(dest)
        finally:
            dest.close()
        return dest_path

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # -- sources ----------------------------------------------------------------

    def upsert_source(self, source: TrustedSource, declares: Iterable[str] = (),
                      command: list[str] | None = None) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO sources(source_id, tier, transport, declared, command, registered_at) "
                "VALUES (?,?,?,?,?,?) "
                "ON CONFLICT(source_id) DO UPDATE SET tier=excluded.tier, "
                "transport=excluded.transport, declared=excluded.declared, "
                "command=excluded.command",
                (source.source_id, source.tier.value, source.transport,
                 _canonical(sorted(declares)),
                 _canonical(command) if command is not None else None, _now()))

    def get_source_command(self, source_id: str) -> list[str] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT command FROM sources WHERE source_id=?", (source_id,)).fetchone()
        if row is None or row[0] is None:
            return None
        return list(json.loads(row[0]))

    def has_source(self, source_id: str) -> bool:
        with self._lock:
            return self._conn.execute(
                "SELECT 1 FROM sources WHERE source_id=?", (source_id,)).fetchone() is not None

    # -- tools and assertions ------------------------------------------------------

    def upsert_tool(self, tv: ToolVersion) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO tools(source_id, name, version, claimed, asserted, input_schema, updated_at) "
                "VALUES (?,?,?,?,?,?,?) "
                "ON CONFLICT(source_id, name) DO UPDATE SET version=excluded.version, "
                "claimed=excluded.claimed, asserted=excluded.asserted, "
                "input_schema=excluded.input_schema, updated_at=excluded.updated_at",
                (tv.source_id, tv.ref.name, tv.ref.version,
                 claimed_to_json(tv.claimed),
                 asserted_to_json(tv.asserted) if tv.asserted is not None else None,
                 _canonical(dict(tv.input_schema)), _now()))

    def upsert_assertion(self, source_id: str, name: str, record: AssertionRecord) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO assertions(source_id, name, descriptor, fingerprint, asserted_at) "
                "VALUES (?,?,?,?,?) "
                "ON CONFLICT(source_id, name) DO UPDATE SET descriptor=excluded.descriptor, "
                "fingerprint=excluded.fingerprint, asserted_at=excluded.asserted_at",
                (source_id, name, asserted_to_json(record.descriptor),
                 str(record.fingerprint), _now()))

    # -- discovery observations ---------------------------------------------------

    def record_discovery(self, source_id: str, discovered: Iterable[str]) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO discoveries(source_id, discovered, observed_at) VALUES (?,?,?) "
                "ON CONFLICT(source_id) DO UPDATE SET discovered=excluded.discovered, "
                "observed_at=excluded.observed_at",
                (source_id, _canonical(sorted(discovered)), _now()))

    def last_discovery(self, source_id: str) -> tuple[set[str], str] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT discovered, observed_at FROM discoveries WHERE source_id=?",
                (source_id,)).fetchone()
        if row is None:
            return None
        return set(json.loads(row[0])), row[1]

    # -- hydration ----------------------------------------------------------------

    def load_catalog(self) -> Catalog:
        """Reconstruct the in-memory catalog exactly as it was last persisted.

        Hydration is literal: the persisted `asserted` column on a tool already
        reflects every decision the in-memory core made (assertion carry-over on
        identical re-ingestion, assertion drop on a changed claim), so no governance
        logic runs here. The AssertionRecord table restores the durable evidence
        that distinguishes never-asserted from asserted-then-changed.
        """
        cat = Catalog()
        with self._lock:
            for sid, tier, transport, declared in self._conn.execute(
                    "SELECT source_id, tier, transport, declared FROM sources"):
                cat.sources[sid] = TrustedSource(
                    source_id=sid, tier=TrustTier(tier), transport=transport)
                cat.declared[sid] = set(json.loads(declared))
            # Load tools with their claim and schema, but NOT their asserted state yet.
            # Assertion validity is re-derived below from the fingerprint, never trusted
            # from the stored `asserted` column — so a tampered database (an `asserted`
            # column edited to inject an authorization, or a claim edited underneath a
            # standing assertion) cannot resurrect invocability. This mirrors the
            # in-memory ingest rule (assert stands iff the claim fingerprint matches) so
            # hydration and ingest agree, and it fails closed on any inconsistency.
            for sid, name, version, claimed, asserted, schema in self._conn.execute(
                    "SELECT source_id, name, version, claimed, asserted, input_schema FROM tools"):
                cat.tools[(sid, name)] = ToolVersion(
                    ref=ToolRef(name, version), source_id=sid,
                    claimed=claimed_from_json(claimed),
                    asserted=None,
                    input_schema=json.loads(schema))
            for sid, name, descriptor, fingerprint in self._conn.execute(
                    "SELECT source_id, name, descriptor, fingerprint FROM assertions"):
                tid: ToolId = (sid, name)
                cat._assertions[tid] = AssertionRecord(
                    descriptor=asserted_from_json(descriptor),
                    fingerprint=int(fingerprint))
            # An assertion carries over ONLY when the persisted evidence's fingerprint
            # matches the tool's current claim. A mismatch (a rug-pull, or tampering)
            # leaves the tool unasserted — CHANGED, not ASSERTED.
            for tid, record in cat._assertions.items():
                tv = cat.tools.get(tid)
                if tv is not None and cat._fingerprint(tv) == record.fingerprint:
                    cat.tools[tid] = replace(tv, asserted=record.descriptor)
        return cat

    def verify_assertions(self) -> dict:
        """Cross-check every persisted assertion against its tool's current claim.

        Returns ``{"ok": bool, "checked": int, "mismatches": [{source_id, name,
        stored_fingerprint, actual_fingerprint}]}``. A mismatch means either the server
        redefined the tool after it was vouched for (a rug-pull that ``ingest`` would
        catch live) or the database was tampered with. Either way the tool is not
        currently invocable, and this is the operator-facing integrity probe for it.
        """
        cat = self.load_catalog()
        mismatches = []
        for tid, record in cat._assertions.items():
            tv = cat.tools.get(tid)
            actual = cat._fingerprint(tv) if tv is not None else None
            if actual != record.fingerprint:
                mismatches.append({
                    "source_id": tid[0], "name": tid[1],
                    "stored_fingerprint": str(record.fingerprint),
                    "actual_fingerprint": None if actual is None else str(actual),
                })
        return {"ok": not mismatches, "checked": len(cat._assertions),
                "mismatches": mismatches}

    # -- audit ----------------------------------------------------------------------

    def append_audit(self, kind: str, body: Mapping[str, Any]) -> int:
        """Append one hash-chained audit record; returns its sequence number."""
        payload = _canonical(dict(body))
        created = _now()
        with self._lock, self._conn:
            row = self._conn.execute(
                "SELECT record_hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
            prev = row[0] if row is not None else _GENESIS
            record_hash = hashlib.sha256(
                f"{kind}\x1f{payload}\x1f{created}\x1f{prev}".encode("utf-8")).hexdigest()
            cur = self._conn.execute(
                "INSERT INTO audit(kind, body, created_at, prev_hash, record_hash) "
                "VALUES (?,?,?,?,?)", (kind, payload, created, prev, record_hash))
            return int(cur.lastrowid)

    def read_audit(self, kind: str | None = None, limit: int = 100) -> list[dict]:
        q = "SELECT seq, kind, body, created_at, record_hash FROM audit"
        args: tuple = ()
        if kind is not None:
            q += " WHERE kind=?"
            args = (kind,)
        q += " ORDER BY seq DESC LIMIT ?"
        with self._lock:
            rows = self._conn.execute(q, args + (limit,)).fetchall()
        return [
            {"seq": seq, "kind": k, "body": json.loads(body),
             "created_at": created, "record_hash": rh}
            for seq, k, body, created, rh in rows
        ]

    def find_decision(self, decision_id: str) -> dict | None:
        """Locate a persisted authorization decision by its id."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT seq, body FROM audit WHERE kind='decision'").fetchall()
        for seq, body in rows:
            parsed = json.loads(body)
            if parsed.get("decision_id") == decision_id:
                return {"seq": seq, "body": parsed}
        return None

    def verify_chain(self) -> ChainVerification:
        prev = _GENESIS
        count = 0
        with self._lock:
            rows = self._conn.execute(
                "SELECT seq, kind, body, created_at, prev_hash, record_hash "
                "FROM audit ORDER BY seq").fetchall()
        for seq, kind, body, created, prev_hash, record_hash in rows:
            if prev_hash != prev:
                return ChainVerification(False, count, seq, "prev_hash mismatch")
            expect = hashlib.sha256(
                f"{kind}\x1f{body}\x1f{created}\x1f{prev_hash}".encode("utf-8")).hexdigest()
            if record_hash != expect:
                return ChainVerification(False, count, seq, "record_hash mismatch")
            prev = record_hash
            count += 1
        return ChainVerification(True, count)
