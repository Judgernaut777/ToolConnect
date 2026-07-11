# ToolConnect service — persistence, HTTP surface, MCP ingest

**Status:** implemented in 0.1.0. This documents what `toolconnect serve` actually
exposes. Where [AGENTCONNECT_CONTRACT.md](AGENTCONNECT_CONTRACT.md) pins a shape (the
Decision explanation, the outcome-recording loop closure, fail-closed unavailability),
the JSON mirrors it; everything else here is deliberately minimal and may change before
the contract is agreed by AgentConnect's side.

There is **no invocation route**. `/authorize` answers "may this principal call this
tool"; the caller performs the call itself and closes the loop via
`/decisions/{id}/outcome`. This is ARCHITECTURE rule 2 made concrete.

## Running it

```
toolconnect init-db --db ./toolconnect.db
toolconnect serve --db ./toolconnect.db --policies examples/policies.cedar
# → http://127.0.0.1:8095
```

Default bind is `127.0.0.1:8095` (loopback only; 8080, 8090, and 8787 are taken on the
reference host). `--config examples/toolconnect.toml` supplies the same settings from
TOML; explicit flags win. `serve` refuses to start without a policy file, and refuses an
unparseable one — a policy set that does not parse must never become an allow-all server.
An *empty* policy set is valid and denies everything (Cedar default-deny).

## Architecture of the layer

```
SqliteStore  ──hydrates──►  Catalog / Broker / CedarPolicyEngine  (the verified core)
     ▲                            │
     └──────── write-through ─────┘
                    ToolConnectService (service.py)
                            │
                    stdlib HTTP front (server.py)
```

The in-memory decision core is the semantic authority. The store never answers a
governance question; it persists what the core decided and reconstructs the core's
exact state at startup. Assertion fingerprints are stable SHA-256 digests (see
*Amendments* below), so the rug-pull detector works across restarts.

The audit log is append-only and hash-chained
(`record_hash = SHA-256(kind ‖ body ‖ created_at ‖ prev_hash)`); `GET /audit/verify`
walks the chain. Decisions, denials, ingest failures, assertions, and outcomes are all
records on the same chain — an audit log that only contains successes is not an audit
log.

## Routes

Source ids follow the MCP registry's reverse-DNS convention and may contain `/`
(`io.github.owner/server`); parametrized routes capture them greedily. Tool names are
the trailing path segment and must not contain `/`. All bodies and responses are JSON.
Errors are `{"error": {"status": N, "message": "..."}}`.

| Route | Purpose |
|---|---|
| `GET /health` | status, version, source/tool counts, audit-chain state |
| `POST /sources` | register a source: `{source_id, tier, transport?, declares?, command?}`; `tier` is one of `verified` \| `known` \| `untrusted` \| `quarantined` (anything else is a `400`; only `verified`/`known` tools can ever become invocable) |
| `GET /sources` | list sources with their declared and ingested tools |
| `POST /sources/{source_id}/ingest` | run real MCP stdio discovery against the source's configured `command`; body `{timeout?}` (capped at 60 s) |
| `POST /sources/{source_id}/tools` | push-style ingest for non-stdio sources: `{tools: [{name, version?, claimed?, input_schema?}]}` |
| `GET /catalog` | every tool with claimed/asserted metadata, assertion status, invocability, claim conflicts |
| `GET /catalog/{source_id}/{name}` | one tool |
| `POST /assertions` | operator vouches: `{source_id, name, descriptor}`; `descriptor.asserted_by` is required — promotion is human-only |
| `GET /assertions/{source_id}/{name}` | assertion status, fingerprint evidence, invocability |
| `GET /drift/{source_id}` | drift against the **last successful discovery**; `409` if no discovery was ever observed — an unobserved source has unknown drift, not none |
| `POST /authorize` | `{principal, source_id, name, context?}` → a Decision |
| `POST /decisions/{decision_id}/outcome` | close the loop: `{outcome, detail?}`; `detail`, when present, must be a JSON object (`400` otherwise); unknown ids are `404` |
| `GET /audit?kind=&limit=` | newest-first audit records (kinds: `decision`, `outcome`, `ingest`, `assertion`, `drift`, `source`) |
| `GET /audit/verify` | walk the hash chain; reports the first broken record |

### The Decision shape

```json
{
  "decision_id": "0f3a…",
  "allowed": false,
  "reason": "forbidden by no-sensitive-reads-for-rented",
  "determining_policies": ["no-sensitive-reads-for-rented"],
  "default_deny": false,
  "errors": []
}
```

`determining_policies` is empty on a **default deny** — no policy matched — and
`default_deny` is true, which the contract requires to stay distinguishable from an
explicit `forbid`. A denial is returned as HTTP `200`: it is a decision, not an error.
Requests that cannot be evaluated at all (unknown tool, unregistered source) are also
decisions — recorded, denied, explained.

`principal` is `{id, privacy_tier?, kind?, on_behalf_of?}` and `on_behalf_of` nests
recursively; authority is the intersection of the delegation chain
(`Principal.effective_tier()`), so delegation cannot launder privilege.

### Failure semantics (fail closed, everywhere)

* MCP discovery faults — `timeout`, `malformed_json`, `truncated_response`,
  `spawn_failed`, `protocol_error`, `duplicate_tool` — discard the **whole** discovery
  (a partial page ingests nothing), mutate no catalog state, return `502`, and append an
  auditable `ingest` record carrying the fault kind.
* A tool discovered but never asserted is not invocable, and `/authorize` says why.
* A vouched tool whose claim changed (`redefined_after_assertion`) loses invocability
  until a human re-asserts; re-announcing the identical claim is a no-op.
* An engine error is a denial. A missing decision is never an allow.

## MCP source adapter

`toolconnect.mcp_source.discover(command, timeout)` speaks actual MCP over a child
process's stdio: `initialize` (protocol `2025-06-18`) → `notifications/initialized` →
paginated `tools/list`. Server annotations (`readOnlyHint`, `destructiveHint`,
`idempotentHint`, `openWorldHint`) are normalized into `ClaimedMetadata` — recorded,
diffed, never consulted for policy. There is no `tools/call` in the adapter, by design.

`fixtures/mini_mcp_server.py` is a real stdlib MCP server used by the test suite, with
fault modes (`--mode malformed|truncate|hang|dup|partial|slowinit|empty`) so transport
faults are produced on a real wire rather than by monkeypatching.

## Amendments over the Phase 1 prototype

1. **Stable claim fingerprints.** `Catalog._fingerprint` previously used the builtin
   `hash()`, which is salted per process — correct in memory, meaningless on disk. It
   now uses SHA-256 over a canonical encoding. Semantics are unchanged (fingerprints are
   equal iff the `(version, claim)` tuples are equal) and the change is proven
   cross-process in `tests/test_store.py::TestFingerprintStability`.
2. **`input_schema` is carried through ingest** onto the persisted `ToolVersion`. It is
   stored and served, not yet validated at authorization time (ARCHITECTURE §2.3's
   grant-time schema validation remains future work).
3. **`decision_id` and outcome recording.** Every Broker audit record gains a
   `decision_id` so the contract's `record()` loop closure has something to reference.
   The Broker itself is unmodified; the id is attached by the persistence layer.

## Known limits (0.1.0)

* **No authentication on the HTTP surface.** Loopback bind is the only guard. Do not
  expose it beyond localhost; token auth is a pre-adoption requirement for the
  AgentConnect integration.
* One process, one writer. WAL SQLite; no coordination story beyond the internal lock.
* `resolve_toolset` / ToolsetPack (contract §3) is not yet an HTTP route; toolset flow
  analysis exists in the library (`analyze_toolset`) but is not exposed.
* Health probing (ARCHITECTURE §4.6) is not implemented; drift uses the last discovery.
