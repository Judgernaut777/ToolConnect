"""The service layer: one object that owns the store, the catalog, and the broker.

The in-memory decision core (`Catalog`, `Broker`, `CedarPolicyEngine`) remains the
semantic authority — every governance question is answered by calling it, never by
querying SQL. The service's job is coordination: hydrate the core from the store at
startup, write every mutation through, and give every decision an id so its outcome can
be recorded later. There is no `invoke()` here and never will be.
"""

from __future__ import annotations

import threading
import uuid
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping

from . import hashing, mcp_source
from .catalog import AmbiguousToolName, AssertionStatus  # noqa: F401  (re-export convenience)
from .descriptor import ClaimedMetadata, TrustedSource, TrustTier
from .policy import Broker, Decision, PolicyEngine, Principal
from .schema import SchemaValidationError, validate_input_schema
from .store import SqliteStore, asserted_from_json, asserted_to_json  # noqa: F401


#: The versioned shape of an authorization Decision on the wire. Bumped only on a
#: breaking change to the Decision JSON (a removed/renamed field or changed meaning);
#: additive fields keep the same major. Clients compare the MAJOR component and fail
#: closed on a mismatch (see ``toolconnect.client.ToolConnectClient``). Pinned by a
#: golden contract fixture in ``tests/test_contract.py``.
#:
#: Bumped 1.0 -> 1.1 for argument-bound one-use grants: ``authorize`` may bind exact
#: final arguments (a canonical-JSON SHA-256 ``args_hash``) and, on permit, issue a
#: one-use grant; a new ``/grants/{id}/redeem`` route atomically consumes it
#: immediately before execution. Additive only — the legacy no-args key set
#: (``DECISION_KEYS`` in tests/test_contract.py) is untouched; a ``grant`` key
#: appears iff the caller sent ``args``.
DECISION_CONTRACT_VERSION = "1.1"

#: Grant TTL bounds and default, in seconds. Out-of-range values are refused (400),
#: never silently clamped — this repo's idiom is to refuse rather than guess.
DEFAULT_GRANT_TTL_SECONDS = 60
MIN_GRANT_TTL_SECONDS = 1
MAX_GRANT_TTL_SECONDS = 300


class ServiceError(Exception):
    """A client-visible failure with an HTTP-ish status."""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status


#: Sentinel distinguishing "the caller did not mention args at all" (legacy no-grant
#: authorize) from "the caller explicitly passed args=None" (an explicit JSON `null`,
#: which is malformed shape, not an omission) — plain ``None`` cannot carry that
#: distinction on its own. Refuse rather than guess (R4).
_UNSET = object()


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
        "contract_version": DECISION_CONTRACT_VERSION,
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
        # Held across broker-call -> decision_id read -> grant insert -> grant_issue
        # append, so a concurrent in-process embedder (the HTTP server already
        # serializes via one global handler lock) can never bind a grant to another
        # call's decision_id, nor interleave a grant_issue away from its decision.
        self._authz_lock = threading.Lock()

    # -- health -------------------------------------------------------------------

    def health(self) -> dict:
        from . import __version__
        chain = self.store.verify_chain()
        return {
            "status": "ok" if chain.ok else "audit_chain_broken",
            "version": __version__,
            "contract_version": DECISION_CONTRACT_VERSION,
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
        # Grant-time schema validation (deliverable 11): refuse to let an operator vouch
        # for a tool whose own declared input contract is structurally incoherent. This
        # inspects only the static schema shape, never runtime arguments — those are the
        # caller's to validate, because ToolConnect is never in the data path.
        existing = self.catalog.get(source_id, name)
        if existing is not None:
            try:
                validate_input_schema(existing.input_schema)
            except SchemaValidationError as exc:
                raise ServiceError(
                    422, f"cannot assert {source_id}:{name}: declared input_schema is "
                         f"invalid ({exc})")
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
                  context: Mapping[str, Any] | None = None,
                  args: Mapping[str, Any] | None = _UNSET,
                  ttl_seconds: int | None = None) -> dict:
        if context is not None and not isinstance(context, Mapping):
            raise ServiceError(400, "context must be a JSON object")
        # `args` requested iff the caller mentioned it at all — including an explicit
        # `args=None` (JSON `null`), which is then malformed shape (400), NOT the
        # legacy no-grant path. Only truly omitting the keyword takes the legacy path.
        grant_requested = args is not _UNSET
        if ttl_seconds is not None and not grant_requested:
            raise ServiceError(400, "ttl_seconds requires args")
        bound_hash = None
        ttl = DEFAULT_GRANT_TTL_SECONDS
        if grant_requested:
            if not isinstance(args, Mapping):
                raise ServiceError(400, "args must be a JSON object")
            try:
                bound_hash = hashing.args_hash(args)
            except hashing.ArgsNotHashable as exc:
                raise ServiceError(400, f"args cannot be canonicalized: {exc}")
            ttl = DEFAULT_GRANT_TTL_SECONDS if ttl_seconds is None else ttl_seconds
            if isinstance(ttl, bool) or not isinstance(ttl, int) or not (
                    MIN_GRANT_TTL_SECONDS <= ttl <= MAX_GRANT_TTL_SECONDS):
                raise ServiceError(
                    400, f"ttl_seconds must be an integer in "
                         f"[{MIN_GRANT_TTL_SECONDS}, {MAX_GRANT_TTL_SECONDS}]")
        # All shape/hash/ttl validation happens BEFORE the broker call, so a malformed
        # request never leaves a phantom `decision` audit record behind it.
        p = _parse_principal(principal)
        with self._authz_lock:  # decision_id read -> grant insert -> grant_issue append
            d = self.broker.authorize(p, source_id, name, dict(context or {}))
            decision_id = self._audit_log[-1]["decision_id"]
            grant_payload = None
            if grant_requested and d.allowed:
                issued = datetime.now(timezone.utc)
                expires = issued + timedelta(seconds=ttl)
                grant_id = uuid.uuid4().hex
                self.store.issue_grant(
                    grant_id=grant_id, decision_id=decision_id, principal_id=p.id,
                    source_id=source_id, name=name, args_hash=bound_hash,
                    issued_at=issued.isoformat(), expires_at=expires.isoformat())
                self.store.append_audit("grant_issue", {
                    "grant_id": grant_id, "decision_id": decision_id,
                    "principal_id": p.id, "source_id": source_id, "name": name,
                    "args_hash": bound_hash, "issued_at": issued.isoformat(),
                    "expires_at": expires.isoformat(), "ttl_seconds": ttl,
                })
                grant_payload = {
                    "grant_id": grant_id, "args_hash": bound_hash,
                    "expires_at": expires.isoformat(), "ttl_seconds": ttl,
                }
        payload = _decision_payload(d, decision_id)
        if grant_requested:
            # Present iff args were sent; explicit null on deny (mixed-fleet detector:
            # a stale pre-1.1 server never sends this key at all).
            payload["grant"] = grant_payload
        return payload

    def redeem_grant(self, grant_id: str, principal: Mapping[str, Any],
                     args: Mapping[str, Any]) -> dict:
        """Atomically consume a one-use, argument-bound grant. Always a decision, not
        an error, for every reachable deny reason — only malformed request shape 400s."""
        if not grant_id:
            raise ServiceError(400, "grant_id is required")
        p = _parse_principal(principal)
        if not isinstance(args, Mapping):
            raise ServiceError(400, "args must be a JSON object")
        try:
            presented_hash = hashing.args_hash(args)
        except hashing.ArgsNotHashable as exc:
            raise ServiceError(400, f"args cannot be canonicalized: {exc}")
        result = self.store.redeem_grant(
            grant_id, args_hash=presented_hash, principal_id=p.id,
            invocable_check=lambda sid, nm: self.catalog.invocable(sid, nm))
        if result["redeemed"]:
            self.store.append_audit("grant_redeem", {
                "grant_id": grant_id, "decision_id": result["decision_id"],
                "principal_id": p.id, "source_id": result["source_id"],
                "name": result["name"],
            })
        else:
            if result["reason"] == "not_invocable":
                self.store.append_audit("grant_close", {
                    "grant_id": grant_id, "decision_id": result["decision_id"],
                    "reason": "not_invocable", "already_closed": False,
                })
            self.store.append_audit("grant_redeem_denied", {
                "grant_id": grant_id, "decision_id": result["decision_id"],
                "principal_id": p.id, "reason": result["reason"],
            })
        return {
            "grant_id": grant_id, "decision_id": result["decision_id"],
            "redeemed": result["redeemed"], "reason": result["reason"],
            "source_id": result["source_id"], "name": result["name"],
            "contract_version": DECISION_CONTRACT_VERSION,
        }

    def close_grant(self, grant_id: str, reason: str = "explicit_close") -> dict:
        closed = self.store.close_grant(grant_id)
        if closed is None:
            raise ServiceError(404, f"unknown grant {grant_id!r}")
        self.store.append_audit("grant_close", {
            "grant_id": grant_id, "decision_id": closed["decision_id"],
            "reason": str(reason), "already_closed": closed["already_closed"],
        })
        return {
            "grant_id": grant_id, "decision_id": closed["decision_id"],
            "closed": True, "already_closed": closed["already_closed"],
            "contract_version": DECISION_CONTRACT_VERSION,
        }

    def get_grant(self, grant_id: str) -> dict:
        found = self.store.get_grant(grant_id)
        if found is None:
            raise ServiceError(404, f"unknown grant {grant_id!r}")
        return found

    _GRANT_STATES = frozenset({"issued", "redeemed", "expired", "closed"})

    def list_grants(self, state: str | None = None, limit: int = 100) -> list[dict]:
        if state is not None and state not in self._GRANT_STATES:
            raise ServiceError(
                400, f"unknown grant state {state!r}; one of "
                     f"{sorted(self._GRANT_STATES)}")
        return self.store.list_grants(state=state, limit=max(1, min(limit, 1000)))

    def record_outcome(self, decision_id: str, outcome: str,
                       detail: Mapping[str, Any] | None = None,
                       grant_id: str | None = None) -> dict:
        """Close the loop on an issued decision (contract §3: record())."""
        if not decision_id:
            raise ServiceError(400, "decision_id is required")
        if detail is not None and not isinstance(detail, Mapping):
            raise ServiceError(400, "detail must be a JSON object")
        found = self.store.find_decision(decision_id)
        if found is None:
            raise ServiceError(404, f"unknown decision {decision_id!r}")
        seq = self.store.append_audit("outcome", {
            "decision_id": decision_id, "decision_seq": found["seq"],
            "outcome": str(outcome), "detail": dict(detail or {}),
        })
        response = {"decision_id": decision_id, "audit_seq": seq}
        if grant_id is not None:
            grant = self.store.get_grant(grant_id)
            if grant is None:
                raise ServiceError(404, f"unknown grant {grant_id!r}")
            if grant["decision_id"] != decision_id:
                raise ServiceError(
                    400, f"grant {grant_id!r} does not belong to decision "
                         f"{decision_id!r}")
            closed = self.store.close_grant(grant_id)
            self.store.append_audit("grant_close", {
                "grant_id": grant_id, "decision_id": decision_id,
                "reason": "outcome_reported", "already_closed": closed["already_closed"],
            })
            response["grant_closed"] = True
        return response

    # -- audit --------------------------------------------------------------------------

    def read_audit(self, kind: str | None = None, limit: int = 100) -> list[dict]:
        return self.store.read_audit(kind=kind, limit=limit)

    def verify_audit(self) -> dict:
        return self.store.verify_chain().as_dict()


def _to_json(mapping: Mapping[str, Any]) -> str:
    import json
    return json.dumps(dict(mapping))
