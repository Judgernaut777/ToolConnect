# ToolConnect — Status

**As of**: 2026-07-22 (pre-Phase-2)
**Phase**: Phase 1 (prove the premise) — exit review complete

## Where we are

Phase 1 is done. 11/11 deliverables shipped and verified offline, plus the
follow-through items the RC1 exit review surfaced (contract pins, tail-truncation
detection, operator CLI, assertion integrity probe, conformance sweep). **516 tests
pass, 3 skipped** (loopback HTTP self-skips under network namespace isolation; the
suite is offline-safe). The gate is reproducible: clone, venv, `pip install -e .[dev]`,
`pytest`.

The repo now includes the full service hardening (`serve` on 127.0.0.1:8095 with
opt-in bearer token, rate limiting, body cap, and refuse-to-bind-insecure for
non-loopback hosts), the client SDK (`ToolConnectClient`, `governed_invoke`), the
`toolconnect gateway` MCP enforcement proxy in front of one downstream MCP tool
server ([adr/0003](adr/0003-mcp-enforcement-gateway.md)), and an OpenAPI 3.x ingest
adapter (`openapi_source`, `toolconnect ingest-openapi`) that loads a local spec file
into the same descriptor/claim model as the MCP adapter — the Phase-2 gate's
protocol-neutral proof. See [SERVICE.md](SERVICE.md).

What has **not** changed: ToolConnect still implements no tool of its own. `grep -rn "def invoke"
src/` returns nothing (the OpenAPI adapter included — it parses a document into claims
and never calls one of its endpoints) and the discovery adapter has no `tools/call`.

## Verified claims (Phase 1 exit review)

| Claim | Verdict | Evidence |
|---|---|---|
| Gate reproducible | **confirmed** | `.venv/bin/python -m pytest` — **516 passing, 3 skipped** (519 collected); under `unshare -rn` HTTP-loopback tests also skip (loopback down), everything else passes offline |
| Fail-closed under coercion | **confirmed** | 71-test adversarial suite; no path to an allow on an unasserted tool, unknown source, or engine error |
| Tamper-evident audit | **confirmed** | body edits, row deletion, and tail truncation all detected (`verify_chain`, `verify-audit` CLI) |
| Hash-chain survives restart | **confirmed** | hydration round-trips all four assertion states; fingerprints stable across `PYTHONHASHSEED` |
| Catalog performance | **confirmed** | 1000 tools: authorize p50 ≈ 0.04 ms; hydrate ≈ 0.2 s |
| Drift detection | **confirmed** | shadow tools, unasserted discoveries, claim conflicts, and redefinition-after-assertion (rug-pull) all caught |
| Cross-source shadowing | **contained** | namespaced identity + fail-closed ambiguity; 27 property examples, 0 counterexamples |
| Write-safety limits | **documented** | argument-dependent tools over-approximated to worst case; the limit is inherent, not a bug |
| Contract discoverable from tests | **confirmed** | decision contract pinned as golden fixtures (`test_contract.py`) |
| Fail-closed high-level review | **confirmed** | authorized-reviewer follow-through pass; all P0/P1 items closed |

## Phase 1 conclusion

Every exit-review check passed. The three load-bearing claims —

1. deny-by-default holds under adversarial pressure,
2. the audit chain is tamper-evident and restart-safe,
3. the decision core is protocol-agnostic in its semantics (claim vs assertion, trust tiers, drift) —

are all verified as designed. (Claim 3's *ingest* side was proven only for MCP at Phase 1;
see "Open questions" below — it is now proven for OpenAPI 3.x as well.) Phase 1's
recommendation: **proceed to Phase 2.**

## What is NOT decided

* Whether AgentConnect should call ToolConnect on the hot path (`required` mode) or
  only at session construction (`advisory` mode). That is Phase 2's observability
  experiment.
* Whether the Cedar adapter is the long-term engine. The `PolicyEngine` protocol and
  conformance suite exist so a swap is provable, not just possible.
* Whether ToolConnect should be built at all. Phase 1 applied the
  [abandonment condition](ROADMAP.md#the-condition-under-which-this-roadmap-should-be-abandoned)
  honestly: no claim failed, and the previously **unproven** "protocol-neutral" claim is now
  **proven for OpenAPI 3.x ingest on the read-only registry path** — `openapi_source` parses a
  local spec document straight into ToolConnect's own claim model (no MCP-shaped intermediate,
  no FastMCP detour), and an OpenAPI-derived capability registers, is asserted, authorizes
  through the same Cedar policy set, and audits identically to an MCP-discovered one
  (`tests/test_openapi_source.py`). What this does **not** establish: ingest of any other
  protocol (gRPC, GraphQL, JSON-RPC-over-HTTP), spec-driven *execution* (deliberately absent),
  or proof that operators will write assertions for OpenAPI-derived tools at scale.

## Known limits (unchanged by passing the exit review)

* Single-writer, single-host. No replication, no multi-node consensus.
* The PEP (`gateway`) covers MCP stdio only, in front of one downstream server.
  Non-MCP enforcement points are Phase 2+.
* Argument-dependent tools (`read_file`, `run_command`) are labeled at their worst
  case; per-argument granularity is out of scope for a static descriptor.
* The hash chain is tamper-evident, not tamper-proof: an attacker with write access
  to the database file can rewrite history wholesale (it will not verify afterward,
  which is the detection guarantee).
* Property tests use fixed seeds; the adversarial suite is hand-written. Neither is
  a substitute for a real red team.

## Open questions for Phase 2

1. Does `required`-mode authorization latency survive contact with a real agent
   loop? (Perf tripwires suggest yes; measurement will tell.)
2. ~~Does an OpenAPI document survive ingest without an MCP-shaped detour?~~ — **answered.**
   Yes: `openapi_source` normalizes an OpenAPI 3.x document directly into `DiscoveredTool`/
   `ClaimedMetadata` (one capability per `operationId`, parameters and JSON request bodies
   merged into the descriptor input schema) and the whole downstream path — namespaced
   identity, assertion evidence, fail-closed Cedar authorization, drift, hash-chained audit —
   works over it unmodified. The "protocol-neutral" claim is upgraded from unproven to proven
   for OpenAPI 3.x ingest (read-only registry path); the abandonment rule does not trigger.
3. Does the flow-analysis signal hold up when the catalog is an order of magnitude
   larger and not curated by the author?
