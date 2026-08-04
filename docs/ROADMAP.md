# Connect Ecosystem — Forward Plan (revised)

**Date**: 2026-07-10
**Status**: Proposal under active review — replaces the 2026-07-08 draft and the first revision
**Scope**: AgentConnect, BrainConnect (formerly WikiBrain), ToolConnect, and the empty fourth slot

This revision is a direct response to the validation document of the same date
(`CONNECT_ECOSYSTEM_VALIDATION_2026-07-10.md`). It corrects three overclaims in the
original roadmap and re-orders the work accordingly.

## What changed from the original proposal

1. **WikiBrain is renamed BrainConnect** and its reframe is stated correctly. It is not
   "the memory layer with hybrid search" as a differentiator. It is an MCP bridge to a
   mature knowledge substrate (kine + Graphine) that predates the Connect naming, with
   trust-tiered memory and federation as its distinguishing properties.

2. **ToolConnect is reframed from capability broker to tool governance decision point.**
   Its original claim — "capability broker with scoped grants and policy" — was already
   deployed and running in AgentConnect as an MCP adapter with Cedar policies and scoped
   grants. ToolConnect's existence is now justified only by what that adapter does not
   do: fail-closed authorization, a tamper-evident audit chain, and enforcement
   *outside* the tool's own trust domain.

3. **The Hub is deferred to phase 3+** and will not be built as a monorepo. Premature
   convergence is the stated failure mode of the original plan.

4. **The four-component model is retained** (Knowledge, Orchestration, Capability,
   Interface) as an organizing frame, not as a build order.

## Phase 1 — prove the premise, not the architecture (now)

Build only the things whose failure would invalidate the ecosystem thesis. Timebox: 3–4 weeks.

### 1. ToolConnect Core — the tool governance decision point

The central question ToolConnect must answer: **is there governance value in separating
the decision from the tool's own trust domain?**

Deliverables:

* A capability descriptor schema (tool, version, effect, data classes, reversibility)
  that is protocol-neutral — it describes *what a tool claims to do*, not which
  protocol it speaks.
* `ToolSourceAdapter` for MCP (`tools/list` ingest over stdio) and OpenAPI (direct document
  parse in `openapi_source` — the original `FastMCP.from_openapi` sketch was rejected because
  an MCP-shaped intermediate would concede the protocol-neutral gate).
* A `PolicyEngine` interface with a Cedar reference implementation, evaluated
  **in-process** (cedarpy), not via a sidecar.
* A tamper-evident audit log (hash-chained, single-writer) recording every allow and
  every deny with its determining policies.
* **Explicit non-goals, written down**: not an execution engine, not a proxy, not an
  MCP gateway, not multi-tenant. There is deliberately no `invoke()` method anywhere
  in the system.

Exit review (all checks passed — see docs/STATUS.md):

* Deny-by-default holds under adversarial pressure (71-test adversarial suite).
* The audit chain is tamper-evident and survives restarts.
* Drift detection catches shadow tools, unasserted discoveries, and rug-pulls.
* Cross-source shadowing is contained by namespaced identity.

### 2. Two gates before phase 2

1. **AgentConnect adoption decision (external).** AgentConnect chooses `required` or
   `advisory` integration, or declines, with reasons recorded either way.
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

### The condition under which this roadmap should be abandoned

If the two phase-1 claims do not hold, the remaining claims do not matter, and the
correct move is to stop and write down what was learned.

## Phase 2 — enforcement point and ecosystem integration (only if phase 1 holds)

* An MCP gateway as the enforcement point for MCP stdio: a proxy in front of one
  downstream server, authorizing and redeeming a grant per `tools/call`
  ([adr/0003](adr/0003-mcp-enforcement-gateway.md)). Shipped.
* Non-MCP enforcement points, informed by what the OpenAPI ingest proof
  demonstrated about protocol-neutral claims.
* AgentConnect integration in the mode chosen at the phase-1 gate, with latency
  measured on a real agent loop.

## Phase 3+ — deferred

* Hub, Interface layer, monorepo convergence: deferred until the components have
  proven independent value. Premature convergence is the failure mode to avoid.
