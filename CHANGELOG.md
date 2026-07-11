# Changelog

## 0.1.0 — 2026-07-12

First release with a runtime. ToolConnect remains a decision and governance point:
there is no `invoke()`, no execution proxy, and no tool data path anywhere in this
package.

### Added

* **Persistence** (`toolconnect.store`): stdlib-SQLite storage for sources, tool
  descriptors, durable assertion evidence (claim fingerprints), discovery
  observations, and a hash-chained append-only audit log with tamper detection
  (`GET /audit/verify`). The verified in-memory decision core stays the semantic
  authority; the store hydrates and write-throughs it without forking any logic.
* **Service layer** (`toolconnect.service`): `ToolConnectService` coordinating store,
  catalog, policy engine, and broker; every decision gets a `decision_id` whose
  outcome can be recorded, closing the contract's audit loop.
* **HTTP surface** (`toolconnect.server`): `toolconnect serve` on 127.0.0.1:8095 —
  health, source registration, MCP discovery trigger, push ingest, catalog lookup,
  assertion create/read, drift state, authorization decisions, outcome recording,
  audit retrieval and chain verification. Stdlib `http.server`; no new dependencies.
  Documented in docs/SERVICE.md.
* **Real MCP source adapter** (`toolconnect.mcp_source`): JSON-RPC 2.0 over stdio to a
  live server subprocess — initialize handshake, paginated `tools/list`, annotation
  normalization into `ClaimedMetadata`. Discovery only; no `tools/call`.
* **Transport fault handling**, fail-closed and auditable: `timeout`,
  `malformed_json`, `truncated_response`, `spawn_failed`, `protocol_error`,
  `duplicate_tool`. A failed discovery ingests nothing (partial pages are discarded
  whole) and leaves a hash-chained `ingest` audit record with the fault kind.
* **CLI** (`toolconnect`): `init-db`, `serve`, `version`; TOML config support with
  a worked example in `examples/toolconnect.toml` and a commented Cedar policy set in
  `examples/policies.cedar`.
* **Test fixture**: `fixtures/mini_mcp_server.py`, a real stdlib MCP stdio server with
  deliberate fault modes, used by 34 new adapter/fault/HTTP tests. Suite grows from
  175 to 229 (2 pre-existing skips; HTTP-socket tests self-skip under the offline
  `unshare -rn` gate variant where loopback is down).

### Changed

* `Catalog._fingerprint` now uses SHA-256 over a canonical encoding instead of the
  process-salted builtin `hash()`, so persisted assertion evidence keeps meaning the
  same claim across restarts. Fingerprint semantics are unchanged and the equivalence
  is proven cross-process in `tests/test_store.py`.
* Package version 0.0.0 → 0.1.0; `toolconnect` console script added.

### Known limits

* No authentication on the HTTP surface (loopback bind only).
* `resolve_toolset`/ToolsetPack and grant-time schema validation are not yet exposed.
* ~~`pyproject.toml` declares MIT but the repository has no LICENSE file yet (an
  ecosystem-level decision, tracked at release level).~~ Resolved: the ecosystem
  license decision landed — ToolConnect is Apache-2.0, with the full license text
  at the repository root and shipped in the wheel.
