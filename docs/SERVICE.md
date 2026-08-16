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
| `POST /authorize` | `{principal, source_id, name, context?, args?, ttl_seconds?}` → a Decision. `args` binds an argument-bound one-use grant on allow (contract 1.1); omitted, behavior is byte-identical to contract 1.0 |
| `POST /grants/{grant_id}/redeem` | atomically consume a one-use grant immediately before executing the call: `{principal, args}` → always `200` with a decision outcome (`redeemed: true/false` + `reason`); `400` only on malformed shape |
| `POST /grants/{grant_id}/close` | explicitly close a grant (e.g. abandon in a `finally`); idempotent; unknown id is `404` |
| `GET /grants/{grant_id}` | one grant's stored fields plus its **computed** status (`issued`\|`redeemed`\|`expired`\|`closed`) |
| `GET /grants?state=&limit=` | grants filtered by computed status, newest-issued-first — how an operator finds a dangling (never redeemed or closed) grant |
| `POST /redemptions` | redeem a **Connect-Governance execution grant** at the point of effect: `{grant, principal, source_id, name, args, at?}` → verifies the Ed25519 signature against the configured governance trust root, binds grant scope to the tool call, consumes the grant one-use atomically, and writes a `provider_enforcement` record (a Provider Enforcement Record) either way — see *Governance grant redemption* below |
| `POST /decisions/{decision_id}/outcome` | close the loop: `{outcome, detail?, grant_id?}`; `detail`, when present, must be a JSON object (`400` otherwise); unknown ids are `404`; `grant_id`, when given, closes that grant in the same call and adds `"grant_closed": true` to the response |
| `GET /audit?kind=&limit=` | newest-first audit records (kinds: `decision`, `outcome`, `ingest`, `assertion`, `drift`, `source`, `grant_issue`, `grant_redeem`, `grant_redeem_denied`, `grant_close`, `provider_enforcement`) |
| `GET /audit/verify` | walk the hash chain; reports the first broken record |

### The Decision shape

```json
{
  "decision_id": "0f3a…",
  "allowed": false,
  "reason": "forbidden by no-sensitive-reads-for-rented",
  "determining_policies": ["no-sensitive-reads-for-rented"],
  "default_deny": false,
  "errors": [],
  "contract_version": "1.1"
}
```

When the caller sends `args`, an allow additionally carries a `grant`:

```json
{
  "...": "as above, contract_version \"1.1\"",
  "grant": {
    "grant_id": "9c2e…",
    "args_hash": "sha256 hex of the canonical args",
    "expires_at": "2026-…Z",
    "ttl_seconds": 60
  }
}
```

`grant` is present **iff** the request sent `args` — never omitted, `null` on a deny —
which doubles as the mixed-fleet detector: a pre-1.1 server never sends the key at all,
so a caller that asked for a grant and got no `grant` key back knows to refuse rather than
execute ungoverned (see *Argument-bound one-use grants* below).

`determining_policies` is empty on a **default deny** — no policy matched — and
`default_deny` is true, which the contract requires to stay distinguishable from an
explicit `forbid`. A denial is returned as HTTP `200`: it is a decision, not an error.
Requests that cannot be evaluated at all (unknown tool, unregistered source) are also
decisions — recorded, denied, explained.

`contract_version` is the versioned shape of the Decision itself. The **major** component
is a compatibility signal: an additive field keeps the major, a removed/renamed field or
a changed meaning bumps it. A client that does not recognize the major must **fail closed**
(treat it as unavailable), never guess. `toolconnect.client.ToolConnectClient` does exactly
this. The exact key set is pinned by a golden fixture (`tests/test_contract.py`), so the
shape cannot drift silently.

`principal` is `{id, privacy_tier?, kind?, on_behalf_of?}` and `on_behalf_of` nests
recursively; authority is the intersection of the delegation chain
(`Principal.effective_tier()`), so delegation cannot launder privilege.

### Argument-bound one-use grants (contract 1.1)

Authorization moves from worker-dispatch time to the **final invocation boundary**.
`POST /authorize` may bind the exact final arguments the caller is about to execute
(`args`), and — on allow — issue a one-use `grant`. Immediately before executing, the
caller redeems that grant with the **same raw args** via `POST /grants/{id}/redeem`;
only a successful redeem may proceed to execution. This is additive: an `/authorize`
call with no `args` behaves exactly as contract 1.0 did.

**Canonicalization (the args-hash rule).** ToolConnect is the *only* hasher — a client
never computes or transmits a hash, it resubmits raw `args` at redeem time and the
server re-derives the hash to compare. The rule (`toolconnect.hashing`):
`json.dumps(args, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
allow_nan=False)`, SHA-256 over the UTF-8 bytes. Consequences worth naming: object keys
sort in code-point order at every nesting level; array order is significant; no Unicode
normalization is applied (NFC and NFD forms of the same visible string hash
differently — a documented non-goal, not a bug); `1` and `1.0` never conflate, nor do
`5` and `"5"`; non-finite floats (`NaN`/`Infinity`) and non-string object keys are
rejected with `400` before any audit record is written.

**Grant status is always computed, never a stored authority** — `issued` /
`redeemed` / `expired` / `closed`, derived from three timestamp latches
(`redeemed_at`, `closed_at`, `expires_at`) exactly the way `load_catalog` re-derives
assertion validity rather than trusting a persisted flag. Grant rows are **never
deleted**, so a dangling (issued, never redeemed or closed) grant stays queryable via
`GET /grants?state=issued` — that is deliberately how an operator finds a tool call
that was authorized but never actually happened (or happened without being reported).
**No raw call arguments are ever persisted or audited** — only the hash.

**Redeem is atomic and every branch is an explicit deny** (`reason` on a non-redeem):
`not_found`, `already_redeemed` (replay), `closed` (see below), `expired`
(inclusive — `now >= expires_at` denies), `principal_mismatch` (a grant is bound to the
principal that requested it, not a bearer capability — a leaked `grant_id` in a log line
is not redeemable by someone else), `args_mismatch`, `not_invocable` (the catalog
dropped the tool's assertion between issue and redeem — a rug-pull or drift — checked
**inside** the same transaction that would otherwise redeem, and the grant is
permanently closed in that same transaction rather than left redeemable later). A grant
that has been closed (explicitly, via outcome, or by a failed `not_invocable` check)
**cannot** subsequently redeem even if none of the other conditions would have denied
it — close always wins.

**TTL**: `ttl_seconds` is only meaningful alongside `args` (a `400` otherwise); bounds
are `[1, 300]`, default `60`; out-of-range or non-integer (a JSON `bool` is rejected —
`bool` is an `int` subclass in Python and would otherwise silently pass) is a `400`,
never silently clamped.

**TOCTOU, honestly stated:** ToolConnect is a PDP, not a proxy — nothing here can stop
a caller from mutating its own arguments after a successful redeem and before it
actually executes the call. The client SDK's `governed_invoke` helper (below) closes
this as tightly as a non-proxying design can: it deep-copies `args` once at entry and
uses that frozen snapshot for authorize, redeem, **and** the executor call, so the
three can never see different arguments. Skipping redeem altogether is *detectable*
(the grant sits dangling, auditable) but not *preventable* — the enforcement point has
to actually call redeem for the enforcement to exist. See `docs/adr/0002-argument-bound-grants.md`.

**Governed invocation (client SDK).** `toolconnect.client.ToolConnectClient.governed_invoke(
principal, source_id, name, args, executor, *, context=None, ttl_seconds=None)` performs
authorize(final args) → redeem → `executor(frozen_args)` → outcome, fail-closed at every
step before execution: an authorize-deny raises `ToolConnectDenied`; a stale pre-1.1
server (allow, no `grant` key) or a redeem-deny raises `ToolConnectUnavailable` /
`GrantRedeemDenied` and `executor` is never called. If `executor` raises, the original
exception propagates after best-effort cleanup (close the grant, record an `"error"`
outcome — failures there never mask the real exception). After a successful execution,
outcome reporting is best-effort: an audit-path outage never destroys a result that
already ran; the grant is left visibly "redeemed but never closed" instead, which is
truthful and auditable.

### Governance grant redemption (Connect-Governance execution grants)

`POST /redemptions` is the point-of-effect redemption of a **Connect-Governance
execution grant** (R4 artifact: canonical JSON + Ed25519 signature, issued only over an
`Allowed` Decision Record). This is the first cross-plane enforcement seam: governance
authorizes the organizational commitment, ToolConnect enforces it where the tool call
would happen. The artifact format and provider obligations are pinned by
Connect-Governance's `docs/REDEMPTION_CONTRACT.md`; ToolConnect verifies offline with a
vendored Ed25519 verifier (`toolconnect.govgrants`, `cryptography>=42`) — there is **no
import or network dependency** on the governance repo, and byte-compatibility is proven
against all five governance conformance vectors (`tests/test_govgrant_vectors.py`).

* **Trust root.** `serve` takes the governance public key(s) as configuration
  (`gov_trust_root_pem`, plus `gov_provider_id` naming this provider in records). A
  server with no trust root configured denies every redemption with
  `missing_trust_root`. An optional expected-key-id pin distinguishes `unknown_issuer`
  from `signature_mismatch` — a forged attribution fails as the wrong key, not as a bad
  signature.
* **Trust-root posture in `GET /health`.** The health surface reports
  `gov_trust_root: {"configured": bool, "key_ids": [...]}` — the governance key ids
  (`ed25519:` + sha256 of the raw public key, derived via
  `govgrants.public_key_id`), never the PEM itself — and `gov_provider_id`, the
  service's configured provider id. A server with no trust root reports
  `configured: false` with an empty `key_ids`; the key is never omitted, so a
  control plane can distinguish "no trust root" from "old server". These fields
  are additive: the decision contract version does not bump, because `/health`
  is a posture surface, not the decision contract. The classification rule a
  control plane relies on: **"enforcing" classification over HTTP requires
  `gov_trust_root.configured == true` AND observable `provider_enforcement`
  audit records via `GET /audit?kind=provider_enforcement`.**
* **Verification is pure.** No wall clock: the validity window is checked against the
  request's `at` instant (half-open, same rule as the issuer); no network, no
  filesystem. Malformed grants, unsupported schemes, and wrong formats are typed
  failure codes, never exceptions.
* **Scope binding.** The grant's authorized scope must cover this exact call:
  `provider_id`, `tool.invoke` in `permitted_operations`, the principal, and
  `argument_constraints["tool"]` (required) naming the tool; any other constraint key
  demands exact equality with the submitted `args`. A scope miss denies.
* **One-use, atomically.** The grant id is the primary key of the `grant_redemptions`
  table (schema v5); claim and audit record commit in one `BEGIN IMMEDIATE`
  transaction. A replay — even racing on 12 threads — gets exactly one winner;
  `already_redeemed` denies the rest with the chain intact. A *failed* verification
  does not consume the grant.
* **Every outcome is a Provider Enforcement Record.** Success or deny, a
  `provider_enforcement` record lands on the same hash-chained audit log:
  `grant_id`, `decision_record_id`, `correlation_id`, verification result, outcome
  (`redeemed` / `denied:<reason>`), failure codes, args hash, and the `at` instant used.
  Denials are decisions, not errors — HTTP `200` with the reason, mirroring `/authorize`.

### Failure semantics (fail closed, everywhere)

* MCP discovery faults — `timeout`, `malformed_json`, `truncated_response`,
  `spawn_failed`, `protocol_error`, `duplicate_tool` — discard the **whole** discovery
  (a partial page ingests nothing), mutate no catalog state, return `502`, and append an
  auditable `ingest` record carrying the fault kind.
* A tool discovered but never asserted is not invocable, and `/authorize` says why.
* A vouched tool whose claim changed (`redefined_after_assertion`) loses invocability
  until a human re-asserts; re-announcing the identical claim is a no-op.
* An engine error is a denial. A missing decision is never an allow.
* A governance-grant redemption that cannot be positively verified — bad signature,
  unknown issuer, expired or not-yet-valid window, scope mismatch, replay, or a missing
  trust root — is a denial, and the denial itself is recorded as a
  `provider_enforcement` record.

## MCP source adapter

`toolconnect.mcp_source.discover(command, timeout)` speaks actual MCP over a child
process's stdio: `initialize` (protocol `2025-06-18`) → `notifications/initialized` →
paginated `tools/list`. Server annotations (`readOnlyHint`, `destructiveHint`,
`idempotentHint`, `openWorldHint`) are normalized into `ClaimedMetadata` — recorded,
diffed, never consulted for policy. There is no `tools/call` in the adapter, by design.

`fixtures/mini_mcp_server.py` and `fixtures/db_mcp_server.py` are **two** independent
real stdlib MCP servers used by the test suite, with different tool sets and server
identities and the same fault modes (`--mode malformed|truncate|hang|dup|partial|
slowinit|empty`) so transport faults are produced on a real wire rather than by
monkeypatching. They overlap on one bare name (`fetch_url`) on purpose: it forces a
cross-source collision, proving namespaced `(source_id, name)` identity keeps the two
distinct and that bare-name resolution fails closed on the ambiguity. Discovery,
normalization, and all six fault classes are exercised against both
(`tests/test_multi_server.py`, `demo_multi_server.py`).

## OpenAPI source adapter (protocol-neutral proof)

`toolconnect.openapi_source.load_openapi(path)` parses a **local** OpenAPI 3.x spec
file (JSON, or YAML when PyYAML is installed — JSON never depends on it) and normalizes
it into the same `DiscoveryResult` / `DiscoveredTool` / `ClaimedMetadata` structures the
MCP adapter produces: one capability per `operationId` (`{method}_{path}` fallback when
absent), parameters and a JSON `requestBody` schema merged into the descriptor's input
schema, and HTTP-method semantics crosswalked into `claimed_*` hints (GET/HEAD/OPTIONS →
`read_only_hint`; DELETE → `destructive_hint`; other writes → `open_world_hint`) —
recorded, diffed, never consulted for policy, exactly like MCP annotations. Ingest then
goes through the unchanged push path (`ingest_payload`), so assertion, Cedar
authorization, drift, and audit behave identically with no special-casing.

The operator surface is `toolconnect ingest-openapi --db DB --source SID --spec
path/to/spec.yaml [--tier T]`. There is deliberately **no network fetch and no endpoint
execution** — the adapter reads a file and never calls what it ingests, so the offline
gate stays offline and `grep -rn "def invoke" src/` still returns nothing. Failures
fail closed as a typed `OpenAPISpecError` (`not_openapi`, `malformed_document`,
`no_operations`, `duplicate_operation`, `invalid_parameter`, `unreadable`) and never
ingest a partial document. Covered by `tests/test_openapi_source.py` against
`fixtures/petstore_openapi.json` / `.yaml`.

## MCP enforcement gateway

```
toolconnect gateway --db X --policies Y --principal-id P --source-id SID -- <downstream command...>
```

An optional stdio proxy in front of **one** downstream MCP server command. It speaks MCP
to whatever spawned it and, for every `tools/call`, runs
`authorize(args=...) -> redeem_grant -> forward -> record_outcome` before the downstream
server ever sees the call — a deny, a redeem denial, or a malformed request refuses
without forwarding. `tools/list` is answered from the downstream server's own listing,
filtered to tools this gateway's catalog currently has asserted and invocable.
`initialize`/`ping`/`notifications/initialized` pass through verbatim (provably
side-effect-free protocol plumbing); every other MCP method is refused rather than
forwarded. Uses `ToolConnectService` in-process — same object `serve` wraps, no second
decision core, no HTTP hop. Full design and the "still not an `invoke()`" reasoning:
[docs/adr/0003-mcp-enforcement-gateway.md](adr/0003-mcp-enforcement-gateway.md). Tested
end-to-end against a real `tools/call`-capable fixture server in `tests/test_gateway.py`.

## Amendments over the Phase 1 prototype

1. **Stable claim fingerprints.** `Catalog._fingerprint` previously used the builtin
   `hash()`, which is salted per process — correct in memory, meaningless on disk. It
   now uses SHA-256 over a canonical encoding. Semantics are unchanged (fingerprints are
   equal iff the `(version, claim)` tuples are equal) and the change is proven
   cross-process in `tests/test_store.py::TestFingerprintStability`.
2. **`input_schema` is carried through ingest** onto the persisted `ToolVersion`, and is
   **validated for structural coherence at grant (assertion) time** (see *Schema
   validation boundary* below). Argument-vs-schema validation at call time remains the
   caller's responsibility — ToolConnect is never in the data path.
3. **`decision_id` and outcome recording.** Every Broker audit record gains a
   `decision_id` so the contract's `record()` loop closure has something to reference.
   The Broker itself is unmodified; the id is attached by the persistence layer.

## Non-local deployment (auth, rate limiting, TLS)

The default bind is loopback with an open surface — correct for a co-located decision
point, unsafe anywhere else. For a reachable deployment:

* **Bearer-token auth.** Set a token via `$TOOLCONNECT_AUTH_TOKEN` (or `token` in the
  config, or name a different env var with `--token-env NAME`). When a token is set,
  **every** route requires `Authorization: Bearer <token>` (constant-time compared);
  a missing/wrong token is `401` with `WWW-Authenticate: Bearer`. The token is never a
  bare flag — argv is visible in `ps`. `serve` **refuses to bind a non-loopback host
  with no token**: bind `127.0.0.1`, or set a token. `/health` is *not* exempt — the
  catalog and audit state are sensitive; probe liveness over loopback or via the proxy.
* **Rate limiting.** `--rate-limit N` (or `rate_limit_per_min` in config) caps requests
  per rolling 60 s window per client IP; over the cap is `429` with `Retry-After`. `0`
  (default) disables it. It is a backstop — do primary rate limiting at the proxy.
* **TLS is terminated by a reverse proxy** (nginx/Caddy/a cloud LB), never in-process.
  Put ToolConnect on loopback (or a private interface) behind the proxy, which
  terminates TLS and forwards to it. The stdlib server does not and will not do its own
  TLS. Prove auth end-to-end: `demo_client_auth.py`.

## Concurrency & durability

One process, one writer. `SqliteStore` holds a single connection and serializes every
mutation behind one re-entrant lock, so concurrent callers cannot interleave a partial
write — in particular the audit log's *read-prev-hash → insert* is atomic, which is what
keeps the hash chain intact under load. `journal_mode=WAL` lets separate reader
connections read while the writer is mid-burst without blocking or erroring. The HTTP
server is threaded and additionally serializes request handling behind a per-server lock.
Proven with real threads (and concurrent HTTP clients) in `tests/test_concurrency.py`
and `demo_persistence.py`. This is a single-box story: there is no multi-writer or
multi-node coordination, by design (ARCHITECTURE §4.8).

## Schema validation boundary

**ToolConnect validates the *shape of a tool's declared schema*; the caller validates
*arguments*.** At grant (assertion) time, `toolconnect.schema.validate_input_schema`
checks that the tool's declared `input_schema` is a structurally coherent JSON Schema —
an object, with a `properties` that is an object, a `required` that lists names present
in `properties`, and a known top-level `type`. An incoherent schema makes the assertion
fail with `422`: an operator cannot vouch for a tool whose own input contract is broken.
ToolConnect does **not** validate a call's arguments against the schema — it never sees
the arguments, because it is never in the data path. Argument validation is the invoking
runtime's job (ARCHITECTURE §5/§8). See `demo_ops.py`.

## Backup, restore, and migration

* **Backup:** `toolconnect backup --db X --out Y` writes a transactionally consistent
  snapshot via SQLite's online-backup API — safe against a live service, no quiesce
  needed. The command re-opens the copy and verifies its audit chain before reporting
  success.
* **Restore:** open (or move into place) the snapshot. It is a complete, governing
  database; the hash chain round-trips byte-for-byte, so a restored backup verifies.
* **Migration:** the store migrates a legacy database forward on open. The baseline is
  the RC1 (schema v1) shape, so a fresh database and a migrated legacy one converge on
  identical structure. Migrations are additive and leave the hash chain untouched; a
  database at a version **newer** than the running build is refused, not opened.

Proven in `tests/test_backup_migration.py` and `demo_persistence.py`.

## Operator CLI

Beyond `serve` and `init-db`, for operators and cron jobs (all read a `--db`, exit
non-zero on a finding so they can gate a pipeline):

| Command | Purpose |
|---|---|
| `toolconnect ingest-openapi --db X --source SID --spec F [--tier T]` | ingest a local OpenAPI 3.x spec (JSON/YAML) as claimed capabilities; exit non-zero on a spec fault, nothing partially ingested |
| `toolconnect verify-audit --db X` | walk the hash chain; exit `1` if broken (tamper/loss detection) |
| `toolconnect drift --db X --source SID` | drift vs. the last discovery; exit `2` if drift exists |
| `toolconnect backup --db X --out Y` | consistent snapshot; verifies the copy |
| `toolconnect audit --db X [--kind K] [--limit N]` | print recent audit records, newest first |

## Reference client

`toolconnect.client.ToolConnectClient` is a stdlib-only, importable, fail-closed client
for a running service — the artifact AgentConnect adopts. Config surface: `base_url`,
`token`, `timeout`, with env fallback (`TOOLCONNECT_URL`/`TOOLCONNECT_TOKEN`/
`TOOLCONNECT_TIMEOUT`) via `ToolConnectClient.from_config(...)`. A deny is a normal
return value; unreachable / non-200 / incompatible-contract raises rather than returning
an allow. There is no `invoke`. See `docs/AGENTCONNECT_CONTRACT.md` → *Reference client
& wiring* and `demo_client_auth.py`.

## Known limits (0.1.0)

* `resolve_toolset` / ToolsetPack (contract §3) is not yet an HTTP route; toolset flow
  analysis exists in the library (`analyze_toolset`) but is not exposed.
* Active health probing (ARCHITECTURE §4.6) is not implemented; drift uses the last
  discovery observation.
* Single box: no multi-writer or multi-node coordination beyond the internal lock + WAL.
* Argument-bound grants (contract 1.1) are, on their own, a PDP boundary rather than a
  proxy: ToolConnect can make skipping `redeem` before execution *detectable* (a
  dangling grant, auditable via `GET /grants?state=issued`) but cannot *prevent* a
  caller that integrates directly against `authorize`/`redeem` and never calls redeem, nor
  a caller that mutates its arguments after a successful redeem. The `gateway` (above)
  closes this specific gap for any caller willing to run its tool traffic through it —
  it physically forwards the call, so skipping authorize/redeem is not an option for a
  gateway-routed caller — but a caller that talks to a downstream MCP server directly,
  bypassing the gateway, is outside what any component in this repo can enforce. Cedar
  policy itself is process-static (loaded once, at engine construction) — if policy
  hot-reload is ever added, both `redeem`'s `invocable_check` and the gateway would need
  to re-evaluate policy too, not just the catalog's assertion state.
* Governance-grant revocation is **window-based only** for the slice (ADR-052 in
  Connect-Governance): an issued grant is revocable in practice by keeping validity
  windows short and rotating the issuer key (the kill switch); revocation-list
  *propagation* to providers is defined but deliberately not built until the audit-trail
  phase. The redemption `at` instant is caller-settable by design (deterministic
  verification); a production caller must supply a trusted timestamp — ToolConnect does
  not yet pin one for it.
