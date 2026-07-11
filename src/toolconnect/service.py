"""The service layer: one object that owns the store, the catalog, and the broker.

The in-memory decision core (`Catalog`, `Broker`, `CedarPolicyEngine`) remains the
semantic authority — every governance question is answered by calling it, never by
querying SQL. The service's job is coordination: hydrate the core from the store at
startup, write every mutation through, and give every decision an id so its outcome can
be recorded later. There is no `invoke()` here and never will be.
"""

from __future__ import annotations

import uuid
from dataclasses import replace
from typing import Any, Mapping

from . import mcp_source
from .catalog import AmbiguousToolName, AssertionStatus  # noqa: F401  (re-export convenience)
from .descriptor import ClaimedMetadata, TrustedSource, TrustTier
from .policy import Broker, Decision, PolicyEngine, Principal
from .store import SqliteStore, asserted_from_json, asserted_to_json  # noqa: F401


class ServiceError(Exception):
    """A client-visible failure with an HTTP-ish status."""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status


class _PersistentAuditLog(list):
    """A list that write-throughs Broker audit records into the store.

    The Broker appends plain dicts and knows nothing about persistence — this keeps
    the verified decision core untouched while every decision it records becomes a
    durable, hash-chained audit row with a stable ``decision_id``.
    """

    def __init__(self, store: SqliteStore) -> None:
        super().__init__()
        self._store = store

    def append(self, record: dict) -> None:  # type: ignore[override]
        record = dict(record)
        record.setdefault("decision_id", uuid.uuid4().hex)
        self._store.append_audit("decision", record)
        super().append(record)


def _parse_principal(data: Mapping[str, Any]) -> Principal:
    if not isinstance(data, Mapping) or not data.get("id"):
        raise ServiceError(400, "principal requires at least an 'id'")
    chain = data.get("on_behalf_of")
    parent = _parse_principal(chain) if chain else None
    return Principal(
        id=str(data["id"]),
        privacy_tier=str(data.get("privacy_tier", "local")),
        kind=str(data.get("kind", "agent")),
        on_behalf_of=parent,
    )


def _decision_payload(d: Decision, decision_id: str) -> dict:
    return {
        "decision_id": decision_id,
        "allowed": d.allowed,
        "reason": d.reason,
        "determining_policies": list(d.determining_policies),
        "default_deny": d.is_default_deny,
        "errors": list(d.errors),
    }


def _tool_payload(svc: "ToolConnectService", source_id: str, name: str) -> dict:
    tv = svc.catalog.get(source_id, name)
    assert tv is not None
    return {
        "source_id": source_id,
        "name": name,
        "qualified_name": tv.qualified_name,
        "version": tv.ref.version,
        "claimed": {
            "description": tv.claimed.description,
            "read_only_hint": tv.claimed.read_only_hint,
            "destructive_hint": tv.claimed.destructive_hint,
            "idempotent_hint": tv.claimed.idempotent_hint,
            "open_world_hint": tv.claimed.open_world_hint,
        },
        "asserted": None if tv.asserted is None else {
            "effect": tv.asserted.effect.value,
            "reads": sorted(c.value for c in tv.asserted.reads),
            "writes": sorted(c.value for c in tv.asserted.writes),
            "scopes": sorted(tv.asserted.scopes),
            "reversible": tv.asserted.reversible,
            "idempotent": tv.asserted.idempotent,
            "requires_approval": tv.asserted.requires_approval,
            "declassifies": tv.asserted.declassifies,
            "asserted_by": tv.asserted.asserted_by,
        },
        "assertion_status": svc.catalog.assertion_status(source_id, name).value,
        "invocable": svc.catalog.invocable(source_id, name),
        "claim_conflicts": tv.claim_conflicts(),
        "input_schema": dict(tv.input_schema),
    }


class ToolConnectService:
    """Everything `toolconnect serve` exposes, callable in-process too."""

    def __init__(self, store: SqliteStore, engine: PolicyEngine) -> None:
        self.store = store
        self.catalog = store.load_catalog()
        self.engine = engine
        self._audit_log = _PersistentAuditLog(store)
        self.broker = Broker(catalog=self.catalog, engine=engine, audit=self._audit_log)

    # -- health -------------------------------------------------------------------

    def health(self) -> dict:
        from . import __version__
        chain = self.store.verify_chain()
        return {
            "status": "ok" if chain.ok else "audit_chain_broken",
            "version": __version__,
            "sources": len(self.catalog.sources),
            "tools": len(self.catalog.tools),
            "audit_records": chain.records,
            "audit_chain_ok": chain.ok,
        }

    # -- sources ------------------------------------------------------------------

    def register_source(self, source_id: str, tier: str, transport: str = "mcp",
                        declares: list[str] | None = None,
                        command: list[str] | None = None) -> dict:
        if not source_id:
            raise ServiceError(400, "source_id is required")
        try:
            trust = TrustTier(tier)
        except ValueError:
            raise ServiceError(
                400, f"unknown trust tier {tier!r}; one of "
                     f"{[t.value for t in TrustTier]}")
        if command is not None and (
                not isinstance(command, list) or not all(isinstance(c, str) for c in command)):
            raise ServiceError(400, "command must be a list of argv strings")
        source = TrustedSource(source_id=source_id, tier=trust, transport=transport)
        self.catalog.register_source(source, declares=set(declares or ()))
        self.store.upsert_source(source, declares=declares or (), command=command)
        self.store.append_audit("source", {
            "event": "registered", "source_id": source_id, "tier": trust.value,
            "transport": transport, "declares": sorted(declares or ()),
            "has_command": command is not None,
        })
        return {"source_id": source_id, "tier": trust.value, "transport": transport}

    def list_sources(self) -> list[dict]:
        return [
            {"source_id": s.source_id, "tier": s.tier.value, "transport": s.transport,
             "declares": sorted(self.catalog.declared.get(s.source_id, ())),
             "tools": sorted(n for (sid, n) in self.catalog.tools if sid == s.source_id)}
            for s in self.catalog.sources.values()
        ]

    # -- discovery / ingest ---------------------------------------------------------

    def ingest(self, source_id: str, timeout: float = 10.0) -> dict:
        """Run real MCP discovery against the source's configured stdio command.

        Fails closed: any transport fault discards the whole discovery, mutates
        nothing, and records an auditable `ingest` failure with a typed kind.
        """
        if source_id not in self.catalog.sources:
            raise ServiceError(404, f"unknown source {source_id!r}")
        command = self.store.get_source_command(source_id)
        if command is None:
            raise ServiceError(
                409, f"source {source_id!r} has no discovery command configured")
        try:
            result = mcp_source.discover(command, timeout=timeout)
        except mcp_source.McpDiscoveryError as exc:
            self.store.append_audit("ingest", {
                "source_id": source_id, "ok": False,
                "fault_kind": exc.kind, "error": str(exc),
            })
            raise ServiceError(502, f"discovery failed ({exc.kind}): {exc}")

        ingested = []
        for dt in result.tools:
            self.catalog.ingest_claimed(source_id, dt.name, dt.claimed, version=dt.version)
            tv = self.catalog.get(source_id, dt.name)
            assert tv is not None
            # input_schema is carried alongside; the catalog's semantics are untouched.
            tv = replace(tv, input_schema=dict(dt.input_schema))
            self.catalog.tools[(source_id, dt.name)] = tv
            self.store.upsert_tool(tv)
            ingested.append(dt.name)
        discovered = {dt.name for dt in result.tools}
        self.store.record_discovery(source_id, discovered)
        self.store.append_audit("ingest", {
            "source_id": source_id, "ok": True,
            "server_name": result.server_name,
            "server_version": result.server_version,
            "protocol_version": result.protocol_version,
            "tools": sorted(ingested),
        })
        drift = self.catalog.drift(source_id, discovered)
        self.store.append_audit("drift", {
            "source_id": source_id, "clean": drift.clean, "summary": drift.summary(),
        })
        return {
            "source_id": source_id,
            "server": {"name": result.server_name, "version": result.server_version},
            "ingested": sorted(ingested),
            "drift": self._drift_payload(drift),
        }

    def ingest_payload(self, source_id: str, tools: list[Mapping[str, Any]]) -> dict:
        """Push-style ingest for non-stdio sources: the caller supplies the claims."""
        if source_id not in self.catalog.sources:
            raise ServiceError(404, f"unknown source {source_id!r}")
        if not isinstance(tools, list):
            raise ServiceError(400, "tools must be a list")
        parsed = []
        seen: set[str] = set()
        for t in tools:
            name = t.get("name")
            if not isinstance(name, str) or not name:
                raise ServiceError(400, f"tool without a usable name: {t!r}")
            if name in seen:
                raise ServiceError(409, f"duplicate tool name {name!r} in payload")
            seen.add(name)
            claimed_raw = t.get("claimed") or {}
            parsed.append((name, str(t.get("version", "0.0.0")), ClaimedMetadata(
                description=str(claimed_raw.get("description", "")),
                read_only_hint=claimed_raw.get("read_only_hint"),
                destructive_hint=claimed_raw.get("destructive_hint"),
                idempotent_hint=claimed_raw.get("idempotent_hint"),
                open_world_hint=claimed_raw.get("open_world_hint"),
            ), t.get("input_schema") or {}))
        ingested = []
        for name, version, claimed, schema in parsed:
            self.catalog.ingest_claimed(source_id, name, claimed, version=version)
            tv = self.catalog.get(source_id, name)
            assert tv is not None
            tv = replace(tv, input_schema=dict(schema))
            self.catalog.tools[(source_id, name)] = tv
            self.store.upsert_tool(tv)
            ingested.append(name)
        self.store.record_discovery(source_id, set(ingested))
        self.store.append_audit("ingest", {
            "source_id": source_id, "ok": True, "push": True,
            "tools": sorted(ingested),
        })
        return {"source_id": source_id, "ingested": sorted(ingested)}

    # -- catalog --------------------------------------------------------------------

    def get_tool(self, source_id: str, name: str) -> dict:
        if self.catalog.get(source_id, name) is None:
            raise ServiceError(404, f"unknown tool {source_id}:{name}")
        return _tool_payload(self, source_id, name)

    def list_catalog(self) -> list[dict]:
        return [_tool_payload(self, sid, name) for (sid, name) in sorted(self.catalog.tools)]

    # -- assertions -------------------------------------------------------------------

    def assert_tool(self, source_id: str, name: str, descriptor: Mapping[str, Any]) -> dict:
        if not isinstance(descriptor, Mapping):
            raise ServiceError(400, "descriptor must be an object")
        try:
            desc = asserted_from_json(_to_json(descriptor))
        except (KeyError, ValueError, TypeError) as exc:
            raise ServiceError(400, f"invalid descriptor: {exc!r}")
        try:
            tv = self.catalog.assert_descriptor(source_id, name, desc)
        except ValueError as exc:  # promotion is human-only: asserted_by required
            raise ServiceError(400, str(exc))
        except KeyError:
            raise ServiceError(404, f"unknown tool {source_id}:{name} — ingest before asserting")
        self.store.upsert_tool(tv)
        record = self.catalog._assertions[(source_id, name)]
        self.store.upsert_assertion(source_id, name, record)
        self.store.append_audit("assertion", {
            "source_id": source_id, "name": name,
            "asserted_by": desc.asserted_by, "effect": desc.effect.value,
            "fingerprint": str(record.fingerprint),
        })
        return self.get_tool(source_id, name)

    def get_assertion(self, source_id: str, name: str) -> dict:
        if self.catalog.get(source_id, name) is None:
            raise ServiceError(404, f"unknown tool {source_id}:{name}")
        status = self.catalog.assertion_status(source_id, name)
        record = self.catalog._assertions.get((source_id, name))
        return {
            "source_id": source_id,
            "name": name,
            "status": status.value,
            "invocable": self.catalog.invocable(source_id, name),
            "record": None if record is None else {
                "asserted_by": record.asserted_by,
                "fingerprint": str(record.fingerprint),
                "effect": record.descriptor.effect.value,
            },
        }

    # -- drift ---------------------------------------------------------------------

    @staticmethod
    def _drift_payload(drift) -> dict:
        return {
            "source_id": drift.source_id,
            "clean": drift.clean,
            "summary": drift.summary(),
            "advertised_missing": list(drift.advertised_missing),
            "undeclared_present": list(drift.undeclared_present),
            "unasserted": list(drift.unasserted),
            "claim_conflicts": [list(c) for c in drift.claim_conflicts],
            "redefined_after_assertion": list(drift.redefined_after_assertion),
        }

    def drift(self, source_id: str) -> dict:
        """Drift against the last successful discovery. Refuses to guess when
        no observation exists — an unobserved source has unknown drift, not none."""
        if source_id not in self.catalog.sources:
            raise ServiceError(404, f"unknown source {source_id!r}")
        obs = self.store.last_discovery(source_id)
        if obs is None:
            raise ServiceError(
                409, f"no discovery has been observed for {source_id!r}; "
                     f"trigger ingest first")
        discovered, observed_at = obs
        drift = self.catalog.drift(source_id, discovered)
        payload = self._drift_payload(drift)
        payload["observed_at"] = observed_at
        return payload

    # -- authorization ----------------------------------------------------------------

    def authorize(self, principal: Mapping[str, Any], source_id: str, name: str,
                  context: Mapping[str, Any] | None = None) -> dict:
        p = _parse_principal(principal)
        d = self.broker.authorize(p, source_id, name, dict(context or {}))
        decision_id = self._audit_log[-1]["decision_id"]
        return _decision_payload(d, decision_id)

    def record_outcome(self, decision_id: str, outcome: str,
                       detail: Mapping[str, Any] | None = None) -> dict:
        """Close the loop on an issued decision (contract §3: record())."""
        if not decision_id:
            raise ServiceError(400, "decision_id is required")
        found = self.store.find_decision(decision_id)
        if found is None:
            raise ServiceError(404, f"unknown decision {decision_id!r}")
        seq = self.store.append_audit("outcome", {
            "decision_id": decision_id, "decision_seq": found["seq"],
            "outcome": str(outcome), "detail": dict(detail or {}),
        })
        return {"decision_id": decision_id, "audit_seq": seq}

    # -- audit --------------------------------------------------------------------------

    def read_audit(self, kind: str | None = None, limit: int = 100) -> list[dict]:
        return self.store.read_audit(kind=kind, limit=limit)

    def verify_audit(self) -> dict:
        return self.store.verify_chain().as_dict()


def _to_json(mapping: Mapping[str, Any]) -> str:
    import json
    return json.dumps(dict(mapping))
