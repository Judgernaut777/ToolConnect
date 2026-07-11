# Status

**Read this before trusting a spec, and before proposing work.**

ToolConnect is at Phase 1. There is a **validation prototype** — an in-memory library built to
test three assumptions, not to be the product. There is no runtime, no server, no daemon, no
database, no HTTP service, and no tool execution. `grep -rn "def invoke" src/` returns nothing,
and a test asserts it.

| | |
|---|---|
| Phase | **1 — validation** ([PHASE1_VALIDATION.md](PHASE1_VALIDATION.md)) |
| Code | in-memory prototype, ~600 lines under `src/toolconnect/` |
| Gate | `.venv/bin/python -m pytest` — **175 passing, 2 skipped**, offline (verified under `unshare -rn`) |
| Language | Python 3.11 |
| Deployment target | single box, local-first, offline decision path |
| Blocking | five go/no-go questions; the decisive one is whether a grant-time review artifact justifies a separate platform |

**Phase 1 results in brief.** Cedar is suitable and proven on aarch64. Flow analysis is real,
novel, and smaller than advertised. The differentiation claim survives at 2 of 3, with the third
unproven rather than failed. Full detail, including the false positives, in
[PHASE1_VALIDATION.md](PHASE1_VALIDATION.md).

---

## What is decided

These are settled by the mission brief and the research, and should not be relitigated without new
information.

* **Scope.** ToolConnect owns the tool registry, discovery, capability metadata, permissions,
  policy, health, invocation brokerage, and audit. It does not own task management, memory,
  workflows, model routing, or secrets storage.
* **ToolConnect is a decision point, not a data path.** It never executes a tool. There is no
  `invoke()` in any interface. The policy enforcement point lives in the caller.
* **Capability metadata is a registry assertion, never a server claim.** This follows directly
  from MCP's own normative rule that clients must treat tool annotations as untrusted.
* **Tool authorization fails closed.** Unlike AgentConnect's memory adapter, ToolConnect may not
  degrade to permissive behavior when unavailable.
* **Policy engine: Cedar via `cedarpy`.** Apache-2.0, in-process, aarch64 wheels, structured
  explanations. **Validated in Phase 1**: prebuilt wheel, no Rust toolchain, decisions carry
  determining policy IDs, and the suite passes with no network. `pycasbin` remains the untested
  fallback. Rationale and rejected set in
  [ARCHITECTURE §4.5](ARCHITECTURE.md#44-permissions-and-45-policy).
* **A default deny is not a `forbid`.** Cedar returns `Deny` with empty reasons when no policy
  matched. That is a missing policy, not a policy decision, and the audit record distinguishes them.
* **Descriptors bind to `(tool, scope)`, not to a tool.** Forced by Phase 1 measurement.
* **Tool identity is `(source_id, name)`.** Bare-name lookup fails closed on ambiguity; two
  sources cannot collide on a name (ARCHITECTURE §2.4). Fixes verification Finding A.
* **Assertions vouch for a claim fingerprint, and that evidence is durable.** Re-ingesting an
  identical claim keeps the assertion; a changed claim drops invocability and is reported as a
  vouched-tool change, distinct from never-asserted (ARCHITECTURE §2.4). Fixes Finding B.

## What is NOT decided

* Whether ToolConnect should be built at all. Phase 1 applied the
  [abandonment condition](ROADMAP.md#the-condition-under-which-this-roadmap-should-be-abandoned)
  honestly: no claim failed, but "protocol-neutral" is **unproven** — every tool ingested so far
  was MCP-shaped. Phase 2 must ingest an OpenAPI document or the claim collapses.
* Whether flow analysis justifies a separate platform now that it is understood to be a grant-time
  review artifact rather than a runtime control. It is genuinely novel; it is also much smaller
  than the Phase 0 documents implied.
* Whether AgentConnect will accept a fail-closed dependency in its execution path. Proposed, not
  agreed: [AGENTCONNECT_CONTRACT.md](AGENTCONNECT_CONTRACT.md).
* Who writes the assertions. Phase 1 measured the labeling bottleneck at **100% of tools**.
* Packaging and distribution beyond the prototype's `pyproject.toml`.

## Open questions

Stated in full in [PHASE1_VALIDATION.md](PHASE1_VALIDATION.md#remaining-go-no-go-questions). The
two that were Phase 0 blockers are now closed:

* ~~ToolConnect contradicts the Connect umbrella~~ — **resolved.** Connect `@f0cff5c` lists it as
  *"Design phase — tool-governance platform, no runtime"* and states the decision-point rule.
* ~~Is flow analysis tractable?~~ — **prototyped.** Yes, with the caveats above.

What remains, decisive first:

1. **Does a grant-time review artifact justify a separate platform?** Answer before Phase 2.
2. **Does an OpenAPI document survive ingest without an MCP-shaped detour?** The "protocol-neutral"
   claim is unproven and is the one that would break the premise.
3. **Is a `(tool, scope)` descriptor assertable in practice?** Trivial for `filesystem`, unclear
   for `postgres`, meaningless for `run_command`.
4. **Who writes 53 assertions?** Attestation is the only proposed path and has no design.
5. **Does AgentConnect accept a fail-closed dependency?** Requires consent from that project.

## Research provenance

The architecture rests on a landscape review conducted **2026-07-10** across four parallel
research streams: MCP's current state, OpenAPI/JSON Schema/generators, policy engines, and
registries/health/audit. Findings were verified against primary sources — specifications, LICENSE
files, and repository metadata — rather than recalled.

Facts with a shelf life, and when to recheck them:

| Fact | As of 2026-07-10 | Recheck |
|---|---|---|
| MCP spec revision | `2025-11-25` stable; `2026-07-28` is a release candidate | End of July 2026 |
| MCP RC makes the core stateless | *Unverified* — RC text unpublished at research time | Before building health probes |
| MCP Registry | Preview, API frozen at `v0.1`, index not host, not self-hostable | Before any runtime dependency |
| OTel GenAI conventions | Moved to `semantic-conventions-genai` (v1.42.0, 2026-06-12); **all attributes at `Development`** | Pin to a commit; expect churn |
| `cedarpy` | Apache-2.0, community-maintained by k9 Security, tracking upstream within days | Periodically; it is not an official AWS package |
| Cedar partial evaluation | Experimental; mid-migration to a type-aware evaluator | Before relying on it |
| JSON Schema | 2020-12 still latest; the "stable spec" transition has not shipped | Before committing to a dialect |
| OpenAPI | 3.2.0 (Sept 2025); Overlay 1.1.0 (Jan 2026); 4.0 "Moonwalk" has no release target | — |
| Portkey | MIT, with a Palo Alto Networks acquisition pending | Post-acquisition |

**Licensing constraints confirmed and honored.** No AGPL dependency was found anywhere in this
landscape. Two BUSL traps were found and are excluded: **Consul** (BUSL 1.1, licensor now IBM
Corp; unlike Vault→OpenBao there is no community fork) and **immudb** (BUSL 1.1). Enterprise-gated
components — Cerbos's embedded PDP, Kong's MCP plugins, LiteLLM's `enterprise/` directory — are
excluded. Full table in [ARCHITECTURE §7](ARCHITECTURE.md#7-reuse-verdicts).

## What the documents do and do not prove

They prove that the gap is real: MCP's specification, read directly, provides no tool-level
authorization, no health beyond a bare `ping`, no audit schema, no capability metadata beyond four
untrusted booleans, no rate-limit mechanism, and no federation.

They do **not** prove that ToolConnect is the right thing to build in that gap. IBM ContextForge
and agentgateway are both Apache-2.0, actively maintained, and already occupy much of it. The
three claims that distinguish ToolConnect from them are stated in
[ARCHITECTURE §7](ARCHITECTURE.md#why-not-just-use-contextforge-or-agentgateway) along with the
conditions under which each collapses. **If two of the three fail, the correct move is to adopt one
of those projects and contribute the third upstream.** That check happens at the end of Phase 1.
