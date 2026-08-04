# ToolConnect — Roadmap

Phases, not dates. Each phase names what it proves and what would make it a failure. Nothing
below is committed; the current phase is the only one that is real.

The ordering principle: **the registry and the audit log are load-bearing for everything else, and
the flow-control analysis is the riskiest idea in the design.** Prove the risky idea early, on
paper, before building the platform that depends on it.

---

> **Where we are.** Phase 0 complete. Phase 1 **executed** — see
> [PHASE1_VALIDATION.md](PHASE1_VALIDATION.md). Cedar validated, flow analysis prototyped and
> materially revised, differentiation reassessed at 2-of-3-with-one-unproven. Phase 2 is gated on
> one product question and one technical proof, both listed under Phase 1 below.

## Phase 0 — Architecture and interfaces *(complete)*

**Goal.** Establish scope, boundaries, object model, and the seams to the sibling projects. No
runtime.

**Done when:** README, ARCHITECTURE, ROADMAP, STATUS exist and the six open questions in
[ARCHITECTURE §9](ARCHITECTURE.md#9-open-questions) are stated clearly enough for the user to
answer them.

**Failure mode:** documents that describe a system nobody has agreed to build, against sibling
components whose names are guesses. Two of the six open questions are exactly this.

---

## Phase 1 — Validate the assumptions *(executed 2026-07-10)*

Full report: **[PHASE1_VALIDATION.md](PHASE1_VALIDATION.md)**. Summary:

* ✅ **Cedar via `cedarpy` is suitable.** Prebuilt aarch64 wheel, in-process, no Rust toolchain.
  Determining policy IDs and `@id` annotations on every decision. 52 tests pass under
  `unshare -rn` — no network in the decision path. `pycasbin` not needed.
* ⚠️ **Flow analysis works, and is smaller than claimed.** 3 findings vs 110 pairwise paths on a
  53-tool catalog. But every finding on a realistic toolset traced to a worst-case label a static
  descriptor cannot justify, and it is a **grant-time review artifact, not a runtime denial rule.**
  Descriptors must bind to `(tool, scope)`.
* ⚠️ **Differentiation: 2 of 3 claims hold; the third is now proven, narrowly.** "Protocol-neutral"
  passed its Phase-2 gate for OpenAPI 3.x ingest (read-only registry path, local spec files,
  no execution). It remains unproven for every other protocol.
* ➕ **Catalog drift found in a real repository.** AgentConnect's spec §17 documents a review loop
  (`claim_review`, `complete_review`, `get_manager_inbox`) that its MCP adapter does not expose.
  Detected by comparing two lists; no tool was invoked. AgentConnect was not modified.

**Two gates before Phase 2 begins, in order:**

1. **Product question (the user's).** Does a grant-time review artifact justify a separate
   platform, rather than a feature contributed to IBM ContextForge?
2. **Technical proof (ours).** Ingest a real OpenAPI document into the same catalog beside the
   MCP tools, without an MCP-shaped intermediate representation. ~~If it needs one,
   "protocol-neutral" has failed and the abandonment rule applies.~~ **Proven** (see
   [STATUS.md](STATUS.md) → Open questions): `openapi_source` parses an OpenAPI 3.x document
   directly into ToolConnect's own descriptor/claim model — one capability per `operationId`
   (or `{method}_{path}` fallback), parameters and JSON request bodies merged into the input
   schema, HTTP-method semantics crosswalked into `claimed_*` hints exactly as MCP annotations
   are — and the same assertion, Cedar authorization, drift, and audit path works over it with
   no special-casing. `toolconnect ingest-openapi path/to/spec.yaml` is the operator surface.
   Scope of the proof: OpenAPI 3.x, local spec files (no network fetch), the read-only
   registry path only — nothing about execution, which remains deliberately absent. The proof
   deliberately does **not** use `FastMCP.from_openapi`, because routing the document through
   an MCP-shaped intermediate would have conceded the gate instead of passing it.

---

## Phase 2 — Registry and descriptor

The catalog, and the artifact that does not exist in any standard.

* **A Cedar schema** declaring the `Agent` and `Tool` entity types. Phase 1's engine parse-checks
  policies but cannot type-check them, so `resource.efect` silently evaluates to "attribute absent"
  and produces an invisible deny. This is the highest-value follow-up in the repository.
* **Ingest `server.json`** as the declared manifest. Phase 1's drift run produced 11 false
  "undeclared-present" findings because it diffed against spec *prose*. Prose is not a manifest.
* `CapabilityDescriptor` as a versioned JSON Schema 2020-12 document, published in-repo, with
  `reads`/`writes` bound to a `(tool, scope)` pair rather than to a tool.
* Crosswalk table: MCP annotations → `claimed_*` fields; the `claimed_*` vs `asserted_*` diff as a
  first-class query.
* SQLite catalog, reconciler loop, monotonic cursor for `watch()`.
* Trust tiers and human promotion. Catalog and health as separate records.
* `ToolSourceAdapter` for MCP (`tools/list` ingest over stdio) and OpenAPI (direct document
  parse in `openapi_source` — the original `FastMCP.from_openapi` sketch was rejected because
  an MCP-shaped intermediate would concede the protocol-neutral gate).
* The `x-toolconnect-*` extension convention, applied to third-party specs via OpenAPI Overlay
  1.1.0 rather than by forking them.

**Proves:** that capability metadata can be asserted independently of what a server claims, and
that drift between the two is detectable across a version bump — the rug-pull detector.

**Deliberately not in this phase:** policy, health probing, invocation.

---

## Phase 3 — Policy and decision

* Cedar schema for `Principal × Action × ToolVersion × Context`, evaluated in-process via
  `cedarpy`. Pinned; re-verified against upstream Cedar.
* Structured decision explanations — determining policy IDs, failed gates, rejected alternatives —
  in the same genre as AgentConnect's persisted route explanation.
* Argument validation against the **canonical** schema before any grant is issued, with the
  per-provider downcompilation diff recorded as tool metadata (the two-schema hazard).
* Delegation chains: `on_behalf_of` attenuating, depth-bounded, intersecting.
* `list_tools()` as a filtered catalog — discovery as an authorization decision.

**Proves:** that a denial can always be explained, and that a grant names an exact
`(principal, tool@version, argument_digest)` triple.

**Gate:** policy tests run offline with no network in the decision path. If that is not true, the
engine choice was wrong.

---

## Phase 4 — Health

* The four-state machine (`unknown` / `healthy` / `degraded` / `unhealthy`), with `unhealthy →
  degraded → healthy` recovery that cannot short-circuit.
* Active probes (MCP `ping` for liveness, periodic `tools/list` for connected-but-broken and for
  descriptor drift) plus passive observation fed from `broker.record()`.
* Per-tool circuit breaking via `pybreaker`, never per-source.

**Blocked on:** the MCP `2026-07-28` release candidate, which reportedly makes the core protocol
stateless. Do not build session-assuming probes before that lands and is read.

---

## Phase 5 — Brokerage and audit

* `authorize()` / `record()`. Rate limits, budgets, and quotas as policy inputs.
* Unclosed grants surfaced as audit findings.
* The audit composite: CloudEvents 1.0.2 envelope, OPA-shaped decision body, OCSF `api_activity`
  field naming, OTel `gen_ai.*` / `mcp.*` attributes pinned to a commit.
* Hash-chained records over SQLite, with a pluggable external anchor.
* Chain verification (`verify()`) as a first-class operation, not a script.

**Proves:** the fourth first principle. An audit log containing only successes is not an audit log —
so the acceptance test is a *denial* that round-trips through the chain and verifies.

---

## Phase 6 — Adapters outward

Only after the core is real.

* MCP server adapter, so an agent can reach ToolConnect the same way it reaches any tool. This is
  the one place ToolConnect speaks MCP as a *server*, and it must not become the only interface —
  the same rule AgentConnect enforces.
* HTTP and CLI adapters over the identical service object. No logic duplicated per protocol.
* A PDP-backed policy plugin for ContextForge or agentgateway, for deployments that genuinely need
  an in-path proxy.

---

## Explicitly deferred

Not "later" as a euphemism for "never" — these are real, and out of scope until the core exists.

| Deferred | Until |
|---|---|
| Biscuit-encoded grants | Callers are cross-process. In-process grants are objects. |
| Apicurio or any external descriptor registry | Local-first stops being enough. |
| Merkle trees, Rekor, Tessera anchoring | There is an untrusted verifier or a second writer. |
| Partial evaluation for candidate filtering | The catalog is large enough that filtering is slow. Cedar's is experimental. |
| Arazzo multi-step workflow governance | Single-invocation governance works. Workflows are AgentConnect's. |
| A2A, cross-instance federation | There is a second instance. |
| Attestation path for descriptors | Human promotion is demonstrably the bottleneck (open question 4). |

## Non-goals, restated

No tool execution. No MCP replacement. No task state, memory, workflows, model routing, or secrets
storage. No general API gateway. These do not become goals in a later phase.

## The condition under which this roadmap should be abandoned

From [ARCHITECTURE §7](ARCHITECTURE.md#why-not-just-use-contextforge-or-agentgateway): ToolConnect
justifies its existence on three claims — that it is an in-process library rather than a proxy,
that it is protocol-neutral rather than MCP-shaped, and that it governs toolsets rather than
calls. **If two of the three fail, adopt IBM ContextForge or agentgateway and contribute the
remaining idea upstream.**

Check this at the end of Phase 1, when the flow-control prototype either works or does not. It is
much cheaper to abandon a design than a platform.
