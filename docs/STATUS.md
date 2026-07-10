# Status

**Read this before trusting a spec, and before proposing work.**

ToolConnect is at Phase 0. There is **no implementation** — no runtime, no server, no package, no
tests, no gate. The repository contains four documents and nothing else. Every interface in
[ARCHITECTURE.md](ARCHITECTURE.md#5-interfaces) is an illustrative signature, not a committed API.

| | |
|---|---|
| Phase | **0 — architecture and interfaces** |
| Code | none |
| Gate | none defined |
| Language | Python (assumed, matching the sibling projects — not yet decided) |
| Deployment target | single box, local-first, offline decision path |
| Blocking | six open questions, of which three are questions for the user |

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
  explanations. Runner-up `pycasbin`. Rationale and the full rejected set are in
  [ARCHITECTURE §4.5](ARCHITECTURE.md#44-permissions-and-45-policy).

## What is NOT decided

* Whether ToolConnect should be built at all. See the abandonment condition in
  [ROADMAP.md](ROADMAP.md#the-condition-under-which-this-roadmap-should-be-abandoned).
* Whether AgentConnect will accept a fail-closed dependency in its execution path. This is a real
  architectural disagreement with every adapter boundary AgentConnect has defined so far, and it
  has not been raised with that project.
* Whether the flow-control analysis — the claim that toolset composition can be statically analyzed
  for exfiltration paths — is tractable. It is the most distinctive idea in the design and the
  least validated. It has never been run against a real toolset.
* Language, packaging, and gate. Python is assumed because the siblings are Python. Nothing has
  been chosen.

## Open questions

Three of the six require an answer from the user, not a decision by the architecture. They are
stated in full in [ARCHITECTURE §9](ARCHITECTURE.md#9-open-questions); in brief:

1. **This repository contradicts the umbrella.** [Connect](https://github.com/Judgernaut777/Connect)
   records ToolConnect as *"Reserved. Scope undefined. Nothing"* and holds as policy that a
   reserved name gets no prose. These four documents are prose. Connect's `README`,
   `ARCHITECTURE`, and `COMPATIBILITY` are now stale with respect to this repository — updating
   them was outside the scope of this work.
2. **Does ToolConnect belong in the family?** Connect's `ARCHITECTURE.md` draws
   AgentConnect → ToolConnect as a dashed arrow labeled "no contract exists." This repository
   proposes that contract. Neither side has agreed to it.
3. **Does AgentConnect adopt ToolConnect?** Specifically the fail-closed rule. Requires consent
   from that project, not an assumption from this one.

The remaining three — descriptor attestation, flow-control tractability, and grant encoding — are
engineering questions that Phase 1 is designed to answer.

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
