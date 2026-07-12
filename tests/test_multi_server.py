"""Discovery, normalization, namespacing, and faults against TWO real MCP servers.

Everything here drives real subprocess MCP servers over stdio — `mini_mcp_server.py`
and `db_mcp_server.py`, two independent processes with different tool sets, server
identities, and pagination shapes. Nothing is monkeypatched.

The two servers overlap on exactly one bare name, `fetch_url`, with different meanings.
That collision is the point: it proves that namespaced (source_id, name) identity keeps
the two tools distinct and that bare-name resolution fails closed on the ambiguity
instead of silently shadowing one server with the other.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from toolconnect.catalog import AmbiguousToolName
from toolconnect.policy import CedarPolicyEngine
from toolconnect.service import ServiceError, ToolConnectService
from toolconnect.store import SqliteStore

REPO = Path(__file__).resolve().parent.parent
MINI = str(REPO / "fixtures" / "mini_mcp_server.py")
DB = str(REPO / "fixtures" / "db_mcp_server.py")


def mini_cmd(mode: str = "normal") -> list[str]:
    return [sys.executable, MINI, "--mode", mode]


def db_cmd(mode: str = "normal") -> list[str]:
    return [sys.executable, DB, "--mode", mode]


@pytest.fixture()
def service(tmp_path):
    store = SqliteStore(tmp_path / "tc.db")
    svc = ToolConnectService(store, CedarPolicyEngine(""))
    yield svc
    store.close()


def _register_both(service) -> None:
    service.register_source("io.test/mini", tier="known", transport="mcp",
                            declares=["read_file", "write_file", "fetch_url"],
                            command=mini_cmd("normal"))
    service.register_source("io.test/db", tier="known", transport="mcp",
                            declares=["sql_query", "list_tables", "delete_row",
                                      "fetch_url"],
                            command=db_cmd("normal"))


class TestTwoRealServers:
    def test_both_servers_ingest_and_normalize(self, service):
        _register_both(service)
        r1 = service.ingest("io.test/mini")
        r2 = service.ingest("io.test/db")

        assert r1["server"]["name"] == "mini-mcp-fixture"
        assert r2["server"]["name"] == "db-mcp-fixture"
        assert r1["ingested"] == ["fetch_url", "read_file", "write_file"]
        assert r2["ingested"] == ["delete_row", "fetch_url", "list_tables", "sql_query"]

        # Every ingested tool is keyed by namespaced identity, never bare name.
        ids = set(service.catalog.tools)
        assert ("io.test/mini", "read_file") in ids
        assert ("io.test/db", "sql_query") in ids
        assert ("io.test/mini", "fetch_url") in ids
        assert ("io.test/db", "fetch_url") in ids
        assert len(ids) == 7  # 3 + 4, no collision collapsed them

    def test_annotations_normalize_per_server(self, service):
        _register_both(service)
        service.ingest("io.test/mini")
        service.ingest("io.test/db")

        # The mini server's read_file claims readOnlyHint=true; the db server's
        # delete_row claims destructiveHint=true. Both normalize into ClaimedMetadata.
        rf = service.catalog.get("io.test/mini", "read_file")
        assert rf.claimed.read_only_hint is True
        dr = service.catalog.get("io.test/db", "delete_row")
        assert dr.claimed.destructive_hint is True
        assert dr.claimed.read_only_hint is False

    def test_shared_bare_name_stays_distinct(self, service):
        """Both servers expose `fetch_url`; the two are different tools and neither
        overwrites the other. Their claimed descriptions differ, proving no shadowing."""
        _register_both(service)
        service.ingest("io.test/mini")
        service.ingest("io.test/db")

        mini_fetch = service.catalog.get("io.test/mini", "fetch_url")
        db_fetch = service.catalog.get("io.test/db", "fetch_url")
        assert mini_fetch is not None and db_fetch is not None
        assert mini_fetch.claimed.description != db_fetch.claimed.description
        assert "web" in mini_fetch.claimed.description.lower()
        assert "blob" in db_fetch.claimed.description.lower()

    def test_ambiguous_bare_name_fails_closed(self, service):
        """Bare-name resolution across the collision must refuse, not guess."""
        _register_both(service)
        service.ingest("io.test/mini")
        service.ingest("io.test/db")

        with pytest.raises(AmbiguousToolName) as exc:
            service.catalog.resolve("fetch_url")
        assert "io.test/db" in str(exc.value) and "io.test/mini" in str(exc.value)

        # A non-colliding name still resolves to its single owner.
        assert service.catalog.resolve("sql_query") == ("io.test/db", "sql_query")
        assert service.catalog.resolve("read_file") == ("io.test/mini", "read_file")

    def test_ambiguity_survives_restart(self, service, tmp_path):
        """The collision is durable: after a restart the ambiguity is still fatal."""
        _register_both(service)
        service.ingest("io.test/mini")
        service.ingest("io.test/db")
        service.store.close()

        store2 = SqliteStore(tmp_path / "tc.db")
        svc2 = ToolConnectService(store2, CedarPolicyEngine(""))
        try:
            with pytest.raises(AmbiguousToolName):
                svc2.catalog.resolve("fetch_url")
            assert svc2.catalog.get("io.test/mini", "fetch_url") is not None
            assert svc2.catalog.get("io.test/db", "fetch_url") is not None
        finally:
            store2.close()

    def test_asserting_one_does_not_authorize_the_other(self, service):
        """Vouching for io.test/db:fetch_url must never make io.test/mini:fetch_url
        invocable. Assertion is source-qualified."""
        _register_both(service)
        service.ingest("io.test/mini")
        service.ingest("io.test/db")

        service.assert_tool("io.test/db", "fetch_url",
                            {"effect": "read", "asserted_by": "op"})
        assert service.catalog.invocable("io.test/db", "fetch_url") is True
        assert service.catalog.invocable("io.test/mini", "fetch_url") is False


class TestSecondServerTransportFaults:
    """The six transport-fault classes, produced by the *second* real server."""

    def _register(self, service, command):
        service.register_source("io.test/db-faulty", tier="known", transport="mcp",
                                declares=["sql_query"], command=command)

    @pytest.mark.parametrize("mode,kind", [
        ("malformed", "malformed_json"),
        ("truncate", "truncated_response"),
        ("dup", "duplicate_tool"),
        ("partial", "protocol_error"),
    ])
    def test_wire_fault_fails_closed(self, service, mode, kind):
        self._register(service, db_cmd(mode))
        before = dict(service.catalog.tools)
        with pytest.raises(ServiceError) as exc:
            service.ingest("io.test/db-faulty", timeout=15.0)
        assert exc.value.status == 502
        assert kind in str(exc.value)
        # Nothing ingested; the failure is on the same audit chain.
        assert dict(service.catalog.tools) == before
        rec = service.read_audit(kind="ingest")[0]["body"]
        assert rec["ok"] is False and rec["fault_kind"] == kind
        assert service.verify_audit()["ok"] is True

    def test_timeout_fails_closed(self, service):
        self._register(service, db_cmd("hang"))
        with pytest.raises(ServiceError) as exc:
            service.ingest("io.test/db-faulty", timeout=1.5)
        assert exc.value.status == 502 and "timeout" in str(exc.value)

    def test_slowinit_times_out(self, service):
        self._register(service, db_cmd("slowinit"))
        with pytest.raises(ServiceError) as exc:
            service.ingest("io.test/db-faulty", timeout=1.5)
        assert "timeout" in str(exc.value)

    def test_spawn_failure_fails_closed(self, service):
        self._register(service, ["/nonexistent/db-server-nope"])
        with pytest.raises(ServiceError) as exc:
            service.ingest("io.test/db-faulty")
        assert "spawn_failed" in str(exc.value)
