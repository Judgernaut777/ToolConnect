# toolconnect serve — operator reference

`toolconnect serve` runs the ToolConnect decision point as a small HTTP service.
This document is the contract: routes, wire shapes, configuration, and the security
model. It is aimed at two readers — the operator running the service, and the
AgentConnect integrator deciding whether to call it (see
[AGENTCONNECT_CONTRACT.md](AGENTCONNECT_CONTRACT.md) for the latter's checklist).

## Configuration

Precedence: explicit flags > `--config FILE` (TOML) > defaults.

| Key / flag | Default | Meaning |
|---|---|---|
| `db` / `--db` | — (required) | SQLite database path |
| `policies` / `--policies` | — (required for `serve`) | Cedar policy file |
| `host` / `--host` | `127.0.0.1` | bind host |
| `port` / `--port` | `8095` | bind port (8080/8090/8787 are taken on the reference host) |
| `token` (config) or `$TOOLCONNECT_AUTH_TOKEN` | unset | bearer token; required for a non-loopback bind |
| `token_env` / `--token-env` | `TOOLCONNECT_AUTH_TOKEN` | name of the env var holding the token |
| `rate_limit_per_min` / `--rate-limit` | `0` (off) | requests per rolling 60 s per client IP |

A worked example lives in `examples/toolconnect.toml` and `examples/policies.cedar`.

`serve` refuses to start without an explicit, parseable policy file. A decision point
with no policies would default-deny everything — safe, but almost certainly a
misconfiguration, so the operator must say what they meant.

## Operator CLI

| Command | Behavior |
|---|---|
| `toolconnect init-db --db X` | create/open the database; print schema version + audit-chain status |
| `toolconnect serve --db X --policies P` | run the HTTP service |
| `toolconnect gateway --db X --policies P --principal-id A --source-id S -- CMD...` | run the MCP enforcement gateway in front of one downstream MCP server |
| `toolconnect drift --db X --source S` | report drift against the last discovery; exit `2` when drift exists |
| `toolconnect backup --db X --out Y` | consistent snapshot (schema + catalog + chain); verifies the copy |
| `toolconnect audit --db X [--kind K] [--limit N]` | recent audit records, newest first |
| `toolconnect ingest-openapi --db X --source SID --spec F [--tier T]` | ingest a local OpenAPI 3.x spec (JSON/YAML) as claimed capabilities; exit non-zero on a spec fault, nothing partially ingested |
| `toolconnect verify-audit --db X` | walk the hash chain; exit `1` if broken (tamper/loss detection) |
| `toolconnect version` | print version |

## Security model

* **Fail closed, always.** Every authorization path that does not produce an explicit
  permit produces a denial — unknown tool, unasserted tool, engine error, malformed
  request. A denial is a decision, not an error, and is recorded identically.
* **Loopback by default.** The default bind is `127.0.0.1`. Binding any other host
  without a bearer token is refused at startup and again at server construction — an
  open decision point on a reachable interface is not a configuration this code will
  run.
* **Authentication.** When a token is configured, *every* route (including `/health`)
  requires `Authorization: Bearer <token>`; comparison is constant-time. When no token
  is configured (the loopback default), the surface is open to local processes — by
  design, and the reason non-loopback requires a token.
* **Availability.** The request body is capped at 1 MiB; per-IP rate limiting is
  available for non-local deployments. The listen backlog is 128 (the stdlib default
  of 5 overflows under connection bursts).
* **No invocation.** There is no route that executes a tool. `/authorize` answers a
  question; the caller performs the call and closes the loop via
  `/decisions/{id}/outcome`.

## Non-local deployment

1. Set a bearer token via `$TOOLCONNECT_AUTH_TOKEN` (or `token` in the config file).
2. Consider `--rate-limit` (e.g. `600`) so a hostile or broken client cannot exhaust
   the decision point.
3. Terminate TLS in front of it (a reverse proxy); `toolconnect serve` speaks plain
   HTTP and does not intend to grow a TLS stack.

## Routes

### Read surface

| Method | Path | Returns |
|---|---|---|
| GET | `/health` | service status, version, contract version, audit-chain status |
| GET | `/sources` | registered sources, tiers, declared tool names |
| GET | `/catalog` | every tool with claimed + asserted metadata |
| GET | `/catalog/{source_id}/{name}` | one tool (404 if unknown) |
| GET | `/assertions/{source_id}/{name}` | assertion status (`never_asserted` / `asserted` / `asserted_then_changed`) + evidence |
| GET | `/drift/{source_id}` | drift vs last discovery (409 if never observed — unknown, not clean) |
| GET | `/audit?kind=K&limit=N` | audit records, newest first |
| GET | `/audit/verify` | hash-chain verification result |
| GET | `/grants?state=S&limit=N` | grant rows (state = `issued`/`redeemed`/`expired`/`closed`) |
| GET | `/grants/{grant_id}` | one grant (404 if unknown) |

Source ids follow the MCP registry's reverse-DNS convention and may contain slashes
(`io.github.owner/server`); routes capture them greedily.

### Write surface

| Method | Path | Body | Returns |
|---|---|---|---|
| POST | `/sources` | `{source_id, tier, transport?, declares?, command?}` | the registered source |
| POST | `/sources/{source_id}/ingest` | `{timeout?}` | real MCP stdio discovery against the source's configured `command` (502 + typed `fault_kind` on failure; nothing partial is ingested) |
| POST | `/sources/{source_id}/tools` | `{tools: [...]}` | push-style ingest for non-stdio sources (claims supplied by the caller) |
| POST | `/assertions` | `{source_id, name, descriptor}` | operator assertion (422 if the tool's declared `input_schema` is incoherent — see *Grant-time schema validation*) |
| POST | `/authorize` | `{principal, source_id, name, context?, args?, ttl_seconds?}` | a Decision (see below); with `args`, also a one-use grant on allow (contract 1.1, below) |
| POST | `/grants/{grant_id}/redeem` | `{principal, args}` | atomic one-use redemption; every deny is a decision, not an error |
| POST | `/grants/{grant_id}/close` | `{reason?}` | idempotent close |
| POST | `/decisions/{decision_id}/outcome` | `{outcome, detail?, grant_id?}` | closes the loop on a decision (contract §3 `record()`); `grant_id` closes the grant in the same call |

### The Decision shape (contract v1.1)

```json
{
  "decision_id": "…",
  "allowed": true,
  "reason": "permitted by allow-reads",
  "determining_policies": ["allow-reads"],
  "default_deny": false,
  "errors": [],
  "contract_version": "1.1"
}
```

The key set is pinned by golden fixtures in `tests/test_contract.py`. Additive fields
keep the major version; a removed/renamed field bumps it. Clients compare the MAJOR
component and fail closed on a mismatch (`ToolConnectClient.EXPECTED_CONTRACT_MAJOR`).

`default_deny: true` means *no policy matched at all* — materially different from an
explicit `forbid` (which names its determining policies). A policy bug and a policy
decision are never conflated.

### Argument-bound one-use grants (contract 1.1)

When `/authorize` is called with `args` (the exact final arguments of the intended
call), an allow additionally returns:

```json
{
  "grant": {
    "grant_id": "…",
    "args_hash": "<sha256 of canonical-args>",
    "expires_at": "<iso8601>",
    "ttl_seconds": 60
  }
}
```

The grant binds *(principal, source_id, name, args)* and must be **redeemed**
atomically — once, by the same principal, with arguments hashing to the same
`args_hash`, before expiry — immediately before the call executes:

```
POST /grants/{grant_id}/redeem  {"principal": {"id": "…"}, "args": {…}}
```

Redeem resubmits the raw `args`; the server is the only hasher, so no client ever
needs to reproduce the canonicalization rule. Every reachable deny (`not_found`,
`already_redeemed`, `closed`, `expired`, `principal_mismatch`, `args_mismatch`,
`not_invocable`) returns `{"redeemed": false, "reason": …}` with a 200 — redemption
is a decision, not an error. `not_invocable` (the tool lost its assertion or its
source's tier dropped between authorize and redeem) also permanently closes the
grant. `ttl_seconds` is optional, 1–300, default 60; out-of-range values are refused
(400), never silently clamped.

#### The canonical-args rule (the ONLY rule; server-side)

`sort_keys=True` (recursive), `separators=(",", ":")`, `ensure_ascii=True`,
`allow_nan=False`; arrays keep caller order; **no Unicode normalization** (NFC and
NFD forms hash differently, by design); `int` and `float` never conflate (`1 ≠ 1.0`);
non-string object keys, non-finite floats, and unsupported types are rejected (400).
Implemented once, in `toolconnect.hashing`; pinned by `tests/test_hashing.py`.

#### Mixed-fleet rule

An allow with `"grant": null` (deny, or args not sent) is distinguishable from a
stale pre-1.1 server, which never sends the key at all. A caller that sent `args` and
got an allow with **no grant** must treat it as unusable — `ToolConnectClient.governed_invoke`
raises `ToolConnectUnavailable` rather than executing ungoverned.

## Audit log

Append-only, hash-chained: `record_hash = SHA-256(kind ␟ body ␟ created_at ␟ prev_hash)`.
Kinds: `source`, `ingest`, `drift`, `assertion`, `decision`, `outcome`, `grant_issue`,
`grant_redeem`, `grant_redeem_denied`, `grant_close`. A durable high-water mark in
`meta` makes tail truncation (deleting the newest records) detectable — a truncated
chain still validates internally, so the tip is compared against the recorded head.
`toolconnect verify-audit` exits `1` on any break.

Grant mutations and their audit records commit as ONE SQLite transaction (ADR 0002
§4): a grant can never exist, be redeemed, or be closed with no matching audit trace.

## Grant-time schema validation (deliverable 11)

ToolConnect validates the *shape* of a tool's declared `input_schema` when an operator
asserts it; the **caller** validates *arguments* against that schema at invocation
time, because ToolConnect is never in the data path and never sees arguments (except
hashes). An assertion over a structurally incoherent schema (a non-object schema,
`properties` that is not an object, `required` names absent from `properties`, an
unknown top-level `type`) is refused with 422. It is deliberately not a full JSON
Schema meta-validator: an empty `{}` schema is valid and means "no declared
constraints".

## MCP source adapter

`toolconnect.mcp_source.discover(command, timeout)` speaks real MCP over stdio to a
server subprocess: `initialize` handshake, `notifications/initialized`, paginated
`tools/list` (following `nextCursor`). Annotations (`readOnlyHint` etc.) normalize into
`ClaimedMetadata` — recorded, diffed, never consulted for policy. There is deliberately
no `tools/call`: the adapter ingests and probes, it never invokes.

Every transport fault fails closed as a typed `McpDiscoveryError.kind`
(`spawn_failed`, `timeout`, `malformed_json`, `truncated_response`, `protocol_error`,
`duplicate_tool`), mutates nothing, and leaves a hash-chained `ingest` audit record
with `ok: false`. A partial discovery (page 1 fine, page 2 errors) is discarded whole.

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

`toolconnect gateway --db D --policies P --principal-id A --source-id S -- <downstream
command>` is the PEP: an MCP stdio proxy in front of ONE downstream MCP server
([adr/0003](adr/0003-mcp-enforcement-gateway.md)). For every `tools/call`:

```
extract final args -> authorize(args=...) -> redeem the grant -> forward -> record outcome
```

* `tools/list` is answered from the downstream's own listing, filtered to what the
  gateway's catalog currently has asserted + invocable — an unasserted tool is
  invisible, never merely uncallable.
* `initialize` / `ping` / `notifications/initialized` pass through verbatim. Every
  other request method is refused (`NOT_PERMITTED`, -32004); every other notification
  is dropped; batched requests are refused whole; downstream-initiated requests (e.g.
  `sampling/createMessage`) are refused toward the downstream so it never deadlocks.
* The one argument mapping extracted from the request is the same object authorized,
  redeemed, and forwarded — no second read, so tampering between authorize and
  forward is impossible by construction.
* Fail-closed resource bounds: frames over 8 MiB refused, `tools/list` capped at 100
  pages / 10 000 tools with repeated-cursor detection.
* Decision refusals use ToolConnect-specific JSON-RPC codes: `DENIED` -32001,
  `REDEEM_DENIED` -32002, `DOWNSTREAM_UNAVAILABLE` -32003, `NOT_PERMITTED` -32004.
  A well-formed downstream error is relayed verbatim.
