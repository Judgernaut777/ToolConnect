# ToolConnect — Roadmap

Phases, not dates. Each phase names what it proves and what would make it a failure. Nothing
below is committed; the current phase is the only one that is real.

The ordering principle: **the registry and the audit log are load-bearing for everything else, and
the flow-control analysis is the riskiest idea in the design.** Prove the risky idea early, on
paper, before building the platform that depends on it.

---

## Phase 0 — Architecture and interfaces *(current)*

**Goal.** Establish scope, boundaries, object model, and the seams to the sibling projects. No
runtime.

**Done when:** README, ARCHITECTURE, ROADMAP, STATUS exist and the six open questions in
[ARCHITECTURE §9](ARCHITECTURE.md#9-open-questions) are stated clearly enough for the user to
answer them.

**Failure mode:** documents that describe a system nobody has agreed to build, against sibling
components whose names are guesses. Two of the six open questions are exactly this.

---

## Phase 1 — Resolve the boundaries

Nothing should be implemented before these are settled, because each one changes the shape of the
code.

* **Answer open questions 1–3.** Is BrainConnect real? Is `Connect` the umbrella? Does AgentConnect
  accept a fail-closed dependency in its execution path?
* **Validate the fail-closed rule against AgentConnect.** Every adapter AgentConnect has defined so
  far is optional and fails open. Tool authorization cannot be. This is a genuine architectural
  disagreement between the two projects and it must be resolved in AgentConnect's favor or
  ToolConnect's, explicitly, in writing.
* **Prototype the flow-control analysis on paper** (open question 5). Take a realistic toolset —
  the 26 tools in the FloJack brain-router, say, or AgentConnect's worker tools — classify their
  reads and writes, and compute the exfiltration paths. Count the false positives.

**Done when:** the exfiltration analysis either produces a usably small set of true findings on a
real toolset, or is demoted from a core claim to a future experiment.

**Failure mode:** building the registry first, then discovering that its most distinctive feature
does not work.

---

## Phase 2 — Registry and descriptor

The catalog, and the artifact that does not exist in any standard.

* `CapabilityDescriptor` as a versioned JSON Schema 2020-12 document, published in-repo.
* Crosswalk table: MCP annotations → `claimed_*` fields; the `claimed_*` vs `asserted_*` diff as a
  first-class query.
* SQLite catalog, reconciler loop, monotonic cursor for `watch()`.
* Trust tiers and human promotion. Catalog and health as separate records.
* `ToolSourceAdapter` for MCP (`tools/list` ingest via the MCP Python SDK) and OpenAPI (via
  FastMCP's `from_openapi`).
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
