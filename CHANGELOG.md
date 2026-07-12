# Changelog

## Unreleased — production hardening (from v0.1.0-rc1)

Hardening pass for the Connect production-readiness program. ToolConnect is still a
decision-and-governance point: no `invoke`/`execute`/`route` was added and the negative
contract is still tested end-to-end. Gate: **322 passed, 2 skipped** (288 passed / 36
skipped under the offline `unshare -rn` variant). Rationale in
`docs/adr/0001-production-hardening.md`.

### Added

* **Bearer-token auth + rate limiting** on the HTTP surface (`toolconnect.server`):
  off by default (loopback-open), required for every route when a token is configured;
  `401` + `WWW-Authenticate` on failure, constant-time compare. Fixed-window per-IP rate
  limiter (`--rate-limit`, `429` + `Retry-After`), checked before auth. `serve` refuses
  a non-loopback bind with no token. TLS-termination guidance in docs/SERVICE.md.
* **Reference client library** (`toolconnect.client.ToolConnectClient`): stdlib-only,
  importable, fail-closed (deny is a value; unreachable/non-200/incompatible-contract
  raises, never allows), no `invoke`. Config surface `base_url`/`token`/`timeout` with
  env fallback. AgentConnect-side wiring documented in docs/AGENTCONNECT_CONTRACT.md.
* **Versioned decision contract**: every Decision carries `contract_version` (`"1.0"`);
  clients fail closed on an unknown major. Golden fixture pins the shape
  (`tests/test_contract.py`).
* **Grant-time `input_schema` validation** (`toolconnect.schema`): an operator cannot
  assert a tool whose declared schema is structurally incoherent (`422`). The
  validate-vs-caller boundary is documented; argument validation stays the caller's job.
* **Backup / restore / migration** (`toolconnect.store`): `backup()` via SQLite's online
  backup (consistent under live writes); forward-only schema migrations on open (RC1 v1
  → current v2, additive, chain-preserving) with newer-than-build databases refused.
* **Operator CLI**: `verify-audit` (exit 1 on a broken chain), `drift` (exit 2 on drift),
  `backup`, `audit`.
* **Second real MCP server fixture** (`fixtures/db_mcp_server.py`): discovery,
  namespacing, and all six transport-fault classes now proven against two independent
  real stdio servers that collide on one bare name.
* **`SqliteStore.verify_assertions()`**: operator integrity probe cross-checking each
  persisted assertion's fingerprint against its tool's current claim.
* ~90 new tests across concurrency, multi-server, auth/rate-limit, client, contract,
  schema validation, backup/migration, cross-process assertion tamper, and CLI ops.

### Changed

* **Hydration re-derives assertion validity from the SHA-256 fingerprint** rather than
  trusting the persisted `asserted` column — a rug-pull or direct DB edit leaves a tool
  non-invocable (`asserted_then_changed`). Fail-closed on tampering, proven cross-process.

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
