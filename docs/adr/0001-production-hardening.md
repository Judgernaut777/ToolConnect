# ADR 0001 — Production hardening from v0.1.0-rc1

Status: accepted (2026-07-12). Context: the Connect production-readiness program.

This records the consequential engineering decisions taken while hardening ToolConnect
for production, so a later reader (or the Wave-B verifier) sees the reasoning, not just
the diff. ToolConnect remains a **decision-and-governance point that is never in the
invocation data path** — no `invoke`/`execute`/`route` was added, and the negative
contract is still tested (`tests/test_http_api.py::test_no_invocation_route_exists`,
and end-to-end against a live server in `demo_client_auth.py`).

## 1. HTTP auth is bearer-token; non-loopback bind without a token is refused

A fail-closed decision point that is reachable off-box must not have an open surface.
We added `Authorization: Bearer <token>` auth (constant-time compare, `hmac`) that is
**off by default and required when a token is configured** — and when configured it
guards *every* route, including `/health` and `/catalog`, because the catalog, drift
state, and audit log are themselves sensitive. The token is taken from an env var
(default `TOOLCONNECT_AUTH_TOKEN`) or the config file, never a bare argv flag (argv is
world-readable in `ps`). `serve` **refuses to bind a non-loopback host with no token**:
the operator must either bind loopback or set a token. This is the same fail-closed
posture as the rest of the system, applied to deployment.

TLS is **terminated by a reverse proxy** (nginx/Caddy/a cloud LB), not in-process. A
stdlib `http.server` doing its own TLS would be a worse security surface than a
purpose-built proxy, and the repo's one-dependency discipline forbids pulling in a web
framework. Guidance is in `docs/SERVICE.md` → *Non-local deployment*.

## 2. Rate limiting is a fixed-window per-client limiter, off by default

A cheap availability guard so a fail-closed endpoint cannot be trivially exhausted.
Fixed window per remote IP, `0` disables it, checked *before* auth so an unauthenticated
flood is shed before we spend work on it. It is intentionally minimal — real
edge-scale rate limiting belongs at the same proxy that terminates TLS; this is a
backstop, not the primary control.

## 3. The decision shape is versioned (`contract_version`, currently `"1.0"`)

Callers need to detect a server they do not understand and **fail closed** rather than
misread a future shape. Every authorization Decision now carries `contract_version`; the
shipped client compares the *major* component and raises `ToolConnectUnavailable` on a
mismatch (never an allow). The full key set is pinned by a golden fixture
(`tests/test_contract.py`) so any change to the shape must be deliberate. Adding a field
keeps the major; removing/renaming one bumps it.

## 4. A client library ships in this repo (`toolconnect.client`)

Deliverable 7 asks for an AgentConnect-adoptable client. AgentConnect is a sibling repo
we cannot edit, so the client lives here as a clean, stdlib-only, importable library
with a documented config surface (`base_url`, `token`, `timeout`; env fallback via
`TOOLCONNECT_URL`/`TOOLCONNECT_TOKEN`/`TOOLCONNECT_TIMEOUT`). It is **fail-closed by
construction**: a deny is a normal return value, but unreachable/non-200/incompatible-
contract raises rather than returning an allow, and there is deliberately no
`invoke`/`call` method. The AgentConnect-side wiring is a thin `ToolGovernor` adapter
that holds a `ToolConnectClient` and maps `resolve_toolset`/`authorize`/`record` onto
it; see `docs/AGENTCONNECT_CONTRACT.md` → *Reference client & wiring*.

## 5. Hydration re-derives assertion validity from the fingerprint (fail closed)

Previously `load_catalog` trusted the persisted `asserted` column to decide whether a
tool was asserted. That made two tampering paths possible: editing a tool's stored
`claimed` underneath a standing assertion, or injecting an `asserted` column with no
matching assertion record. Hydration now **re-derives** the asserted state exactly as
in-memory ingest does — an assertion stands only if the persisted evidence's SHA-256
fingerprint matches the tool's current claim — so a rug-pull or DB edit leaves the tool
non-invocable (`asserted_then_changed`). A new `SqliteStore.verify_assertions()` exposes
this as an operator integrity probe. Proven cross-process and against direct DB edits in
`tests/test_assertion_persistence.py`.

## 6. Schema/parameter validation boundary: ToolConnect validates the *schema shape*

ToolConnect validates a tool's **declared `input_schema`** at grant (assertion) time —
an operator cannot vouch for a tool whose own input contract is structurally incoherent
(a non-object schema, a `properties` that is not an object, a `required` naming a field
`properties` does not define, an unknown top-level `type`). It is a cheap static check
over a small object and refuses with `422`. ToolConnect does **not** validate a call's
*arguments* against the schema — it is never in the data path and never sees the
arguments; that is the invoking runtime's job. This boundary is documented in
`docs/SERVICE.md` → *Schema validation boundary* and implemented in
`toolconnect/schema.py`.

## 7. Schema migration is forward-only with a baseline; newer schemas are refused

The store now migrates a legacy database forward on open. The baseline DDL is the RC1
(v1) shape, so a fresh database records v1 and then applies the same forward migrations
a legacy database does — the two converge on byte-identical structure. v2 is additive
(a `sources.label` column and an `audit(kind)` index); no row is rewritten and the hash
chain is untouched, so a migrated database verifies exactly as before. A database at a
version **newer** than this build is refused, not opened — fail closed on schema too.
`backup()` uses SQLite's online-backup API for a transactionally consistent snapshot;
restore is opening (or moving into place) that file. Proven in
`tests/test_backup_migration.py` and `demo_persistence.py`.

## 8. A second real MCP server fixture, not a second mock

Discovery, namespacing, and transport-fault handling are now proven against **two**
independent real stdio MCP servers (`fixtures/mini_mcp_server.py`,
`fixtures/db_mcp_server.py`) with different tool sets and server identities. They
overlap on exactly one bare name (`fetch_url`) to force a cross-source collision, which
proves namespaced `(source_id, name)` identity keeps them distinct and that bare-name
`resolve()` fails closed on the ambiguity instead of shadowing. The six transport-fault
classes run against both wires.
