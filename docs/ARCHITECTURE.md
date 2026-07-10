# ToolConnect — Architecture

**Status:** design. Nothing here is implemented. Interfaces below are illustrative signatures,
not committed APIs. See [STATUS.md](STATUS.md).

**Research basis:** landscape verified 2026-07-10 against primary sources. Claims that could not
be verified from a primary source are marked *(unverified)*.

---

## 1. First principles

Four rules, in priority order. Where they conflict, the earlier one wins.

1. **A tool's self-description is evidence, not authority.** The registry decides what a tool is
   allowed to do. Nothing a tool server sends can escalate its own privileges.
2. **ToolConnect is a decision point, not a data path.** It never carries an invocation. It
   authorizes, and it records. The enforcement point lives in the caller.
3. **Define contracts, not engines.** Policy languages, tool transports, schema validators, and
   audit stores are all adapters behind protocols. None of them is ToolConnect.
4. **A denial is a decision, not an error.** Denied invocations are first-class audit records
   with the same shape as allowed ones. An audit log that only contains successes is not an
   audit log.

A corollary that falls out of (1) and (4): **discovery is an authorization decision.** Listing
the tools a principal may see is the same computation as deciding whether it may call one. This
is the platform's cheapest and most valuable security primitive, because a tool absent from an
agent's context cannot be prompt-injected into being called.

## 2. Trust model

### 2.1 The untrusted-annotation problem

MCP defines four boolean hints on a tool: `readOnlyHint`, `destructiveHint` (defaults **true**),
`idempotentHint`, and `openWorldHint`. The specification's own schema file says they are hints,
and the prose is normative:

> Clients **MUST** consider tool annotations to be untrusted unless they come from trusted servers.
> — MCP specification, revision `2025-11-25`

This is not a footnote. It means the entire vocabulary a tool has for describing its own risk is
inadmissible as an authorization input. A compromised or merely careless server can claim
`readOnlyHint: true` on a tool that deletes a database. The known attacks — tool poisoning, tool
shadowing, rug-pull redefinition after approval — all exploit exactly this.

MCP has five open Specification Enhancement Proposals extending the annotation vocabulary
(trust/sensitivity, `unsafeOutputHint`, `secretHint`, `trustedHint`, governance annotations).
None is merged, and *(unverified, per the March 2026 MCP blog)* none addresses cost, latency, or
data classification. Even if all five landed, they would remain self-reported hints and would
remain untrusted.

**ToolConnect's answer:** capability metadata is a **registry assertion**, not a server claim.

```
server-reported annotations ──► ingested as `claimed_*` fields, never consulted for policy
                                        │
                                        ▼
                          registry curation (human or attested)
                                        │
                                        ▼
                    `asserted_*` capability descriptor ──► the ONLY policy input
```

When they disagree, that disagreement is itself a signal: a tool whose `claimed_effect` is
`read_only` and whose `asserted_effect` is `destructive` is either mislabeled or hostile, and the
registry should surface it. Drift between the two across a version bump is the rug-pull detector.

### 2.2 Trust tiers

Trust attaches to the **source**, not the tool. A tool inherits the ceiling of its source's tier
and may be pinned lower, never higher.

| Tier | Meaning | Effect |
|---|---|---|
| `verified` | Signed, pinned digest, reviewed descriptor. | Claimed annotations may seed the descriptor, still subject to review. |
| `known` | Registered by an operator, unsigned, pinned version. | Descriptor must be asserted by a human. Claims ignored. |
| `untrusted` | Discovered, unpinned, or drifted. | Discoverable only; not invocable. Requires promotion. |
| `quarantined` | Failed a check, or drifted post-approval. | Invisible and uninvocable until re-reviewed. |

Promotion between tiers is a **human decision**. This mirrors WikiBrain's rule that promotion is
human-only, and for the same reason: an automated system that can raise its own trust level has
no trust level.

### 2.3 The two-schema hazard

A tool has two schemas, and conflating them is a real vulnerability.

* The **constraint schema** is what the model was constrained to emit. Provider tool-calling APIs
  accept only a subset of JSON Schema. Anthropic's `input_schema` rejects `oneOf`, `if`/`then`,
  `patternProperties`, external `$ref`, recursion, and `minimum`/`maximum`/`minLength`; its SDKs
  **silently strip** unsupported keywords and push them into the description prose. OpenAI's
  `strict` mode demands `additionalProperties: false` and every property in `required`.
* The **validation schema** is what the receiving server actually enforces.

If the registry stores one schema and downcompiles it per provider, then the constraint schema is
*weaker* than the validation schema by construction — and a constraint that vanished during
downcompilation (`maximum: 100` on a `transfer_amount`) was never enforced anywhere. The model
was told about it in prose. Nothing checked it.

**ToolConnect therefore validates arguments against the canonical schema at authorization time,
server-side, before issuing a grant** — and records which keywords were dropped from each
provider projection as part of the tool's audit metadata. The downcompiler is a governance
artifact, not a formatting convenience.

## 3. Object model

```
ToolSource ──1:N──► Tool ──1:N──► ToolVersion ──1:1──► CapabilityDescriptor
    │                                   │
    │                                   └──1:1──► HealthRecord
    │
    └── trust_tier, transport binding, provenance

Principal ──► [ PDP: policy + descriptor + health + context ] ──► Decision
                                                                     │
                                                          allow ─────┤───── deny
                                                                     │
                                                                  Grant
                                                                     │
                                                              (caller executes)
                                                                     │
                                                                 Outcome
                                                                     │
                                                                AuditRecord (either way)
```

### 3.1 ToolSource

An MCP server, an OpenAPI service, or a local function set. Carries the transport binding, the
trust tier, and provenance. Sources are the unit of trust, registration, and health probing.

**Catalog and health are separate records.** A source that fails a probe is *marked failing*, not
deregistered — Consul's design, and the right one. Deregistering on failure destroys the
information you need to explain the outage, and creates a registration storm on recovery.

### 3.2 Tool and ToolVersion

Tool identity is a reverse-DNS name (following the MCP registry's `io.github.owner/server`
convention). **Capability descriptors bind to a version, not a tool.** A tool whose descriptor
changes has a new version, and a new version starts at the source's trust ceiling minus review.
This is the rug-pull defense: approval is granted to `acme/db@1.2.0`, never to `acme/db`.

### 3.3 CapabilityDescriptor

The core artifact, and the thing that does not exist in any standard today. The research was
unambiguous on this point: there is no ratified vocabulary for tool capability metadata. MCP has
four untrusted booleans; W3C Web of Things has `ActionAffordance` but no cost/risk model;
schema.org `Action` is SEO vocabulary. **This must be defined here.**

| Field | Type | Why it exists |
|---|---|---|
| `effect` | `read` \| `write` \| `destructive` \| `external` | The primary policy axis. Crosswalks to MCP's `readOnlyHint`/`destructiveHint`/`openWorldHint`. |
| `reversible` | `bool` \| `compensating_action` | Distinct from `destructive`. Deleting a row with a backup is destructive-but-reversible. |
| `idempotent` | `bool` | Governs retry safety and hedging. Crosswalks to `idempotentHint`. |
| `data_classes_read` | `set[DataClass]` | `public`, `internal`, `pii`, `secret`, `credential`. Drives redaction and privacy-tier gating. |
| `data_classes_written` | `set[DataClass]` | Write-side classification. A tool that reads `secret` and writes `public` is an exfiltration path. |
| `scopes` | `set[str]` | Resource scopes touched — filesystem roots, hostnames, table names. |
| `cost` | `CostEstimate` | Currency and/or tokens per invocation. Enables budget policy. |
| `latency` | `LatencyEstimate` | p50/p99. Enables timeout and hedging policy. |
| `requires_approval` | `bool` \| `PolicyRef` | Human gate, independent of policy outcome. |
| `claimed_*` | mirror fields | What the *server* said. Recorded, diffed, never consulted. |

The `data_classes_read` × `data_classes_written` cross-product is the most useful thing in this
table. It makes exfiltration a *static property of a toolset* rather than a runtime surprise: any
principal granted a tool that reads `secret` and a tool that writes `external` has, transitively,
been granted exfiltration — whether or not either tool is individually dangerous. **Toolset
composition must be analyzed, not just individual grants.** This is the flow-control problem, and
it is the one place ToolConnect must reason about tools in combination.

### 3.4 Principal

Deliberately shaped to match AgentConnect's worker identity (`{harness, model, tools, sandbox,
privacy_tier}`), because these are the same entity seen from two sides.

```python
@dataclass(frozen=True)
class Principal:
    kind: Literal["agent", "application", "human"]
    id: str
    harness: str | None           # claude-code, codex, openclaw, ...
    model: str | None             # never a hardcoded capability signal — an attribute
    privacy_tier: str             # local | trusted-cloud | rented
    sandbox: str | None
    on_behalf_of: "Principal | None"   # delegation chain, bounded depth
    task_ref: str | None          # opaque AgentConnect correlation id, NOT task state
```

`on_behalf_of` is the confused-deputy defense. A subagent invoking a tool on a manager's behalf
must not acquire the manager's authority by default; the chain is explicit, attenuating, and
depth-bounded. Authority is the **intersection** of the chain, never the union. The current
literature is blunt about how badly this is handled in practice — an audit of LangChain,
LlamaIndex, and the Stripe Agent Toolkit found none provides a fail-closed per-call gate by
default *(arXiv 2606.28679, unverified beyond abstract)*.

### 3.5 Decision, Grant, Outcome

A `Decision` is `allow | deny | allow_with_constraints`, and always carries a structured
explanation: which policies were evaluated, which one determined the result, which gates failed.
This deliberately mirrors AgentConnect's persisted route-explanation JSON, which lists every
rejected worker and every failed gate. Same instinct, same reason: **an unexplained denial is
indistinguishable from a bug**, and an unexplained allow is indistinguishable from a breach.

A `Grant` is short-lived, single-use, audience-bound, and names the exact `(principal, tool@version,
argument_digest)` triple it authorizes. It is not a bearer token for a tool — it is proof that a
specific invocation was authorized at a specific instant. Re-authorizing on argument change is
not optional; the digest is in the grant precisely so that a caller cannot obtain permission for
`rm /tmp/x` and execute `rm -rf /`.

## 4. The seven surfaces

### 4.1 Registry

SQLite catalog plus a reconciler loop. Single box means **no consensus, no gossip, no TTL
heartbeat machinery** — the entire Consul/etcd/Zookeeper apparatus exists to solve a distributed
problem ToolConnect does not have. What survives from that lineage is the *shape*: declarative
desired state (registered tools) reconciled against observed state (probe results) by a
background controller, with a monotonic cursor for change watching.

Nacos's registry+config fusion is the closest prior art and settles a design question: **do not
split "what tools exist" from "how to call them."** One record, one source of truth, no drift.

### 4.2 Discovery

`list_tools(principal, scope) -> ToolsetPack` returns a **bounded, policy-filtered** view. Not a
catalog dump. The pack is capped, ranked, and carries the descriptor fields the caller needs to
choose — not the raw registry row.

This mirrors AgentConnect's `get_task_context_pack`, and for the identical reason: an agent's
context is a scarce, attack-prone resource. Managers and subagents ask ToolConnect what they may
use; they never query the registry directly. The filtered catalog *is* least privilege.

### 4.3 Capability metadata

Canonical form is JSON Schema 2020-12 (still the current draft; the "stable spec" transition has
not shipped). Two ingest paths, both reusing maintained software:

* **MCP servers** — ingest `tools/list`, plus the registry's `server.json` schema as the
  packaging manifest. The official MCP Registry is an **index, not a host**, and is still in
  preview with an explicit "breaking changes or data resets may occur" banner. Treat its schema
  as a format to read; do not take a runtime dependency on the hosted service.
* **OpenAPI services** — OpenAPI 3.2.0 (Sept 2025) documents, converted via FastMCP's
  `from_openapi` (MIT). Capability metadata attaches as `x-toolconnect-*` extensions, applied to
  third-party specs through the **Overlay Specification 1.1.0** (Jan 2026) so annotating a
  vendor's spec never requires forking it. This is the single cleanest reuse win found in the
  research.

### 4.4 Permissions and 4.5 Policy

**Engine: AWS Cedar via `cedarpy`.** Apache-2.0 end to end, native in-process evaluation, prebuilt
wheels for CPython 3.9–3.14 on linux-aarch64 (which matters — the MS-R1 host is ARM). Its
`diagnostics` block names determining and erroring policy IDs, which is exactly the structured
explanation requirement. Formal-methods provenance and a symbolic analysis toolkit
(`cedar-policy-symcc`) for detecting policy redundancy and inconsistency are a real bonus.

*Caveat carried forward:* `cedarpy` is community-maintained by k9 Security, not an official AWS
package. It tracked upstream to within days as of 2026-07-09. Pin it; re-verify periodically.

**Runner-up: pycasbin** (Apache-2.0, now ASF-incubating). Pure Python, zero FFI, zero build risk.
Take it if native-extension packaging becomes a problem. Its `enforce_ex()` explanation is thinner
and its partial-evaluation story is weak.

**Rejected, with reasons:** OPA/Rego is the richest ecosystem but has no maintained Python
embedding — the WASM wrappers are stale or unmaintained, and the server is a network hop.
Cerbos, OpenFGA, SpiceDB, Topaz, and Keto are all excellent and all architecturally daemons from
Python's perspective; Cerbos's only embeddable build is paywalled behind Cerbos Hub. Oso is the
best architectural fit in the entire survey and has been dead since December 2023. `py-abac`
(2021) and `vakt` (2023) are unmaintained.

The two engines the industry is actually converging on for agent authorization are Cedar and OPA.
Microsoft's Agent Governance Toolkit wraps precisely those two.

### 4.6 Health

Four states, because three is not enough and five is theatre:

```
unknown ──first success──► healthy ◄──K consecutive successes── degraded
   │                          │                                     ▲
   │ startup grace            │ soft error-rate / breaker half-open │
   │ exhausted                ▼                                     │
   └────────────────────► unhealthy ──breaker cooldown──────────────┘
```

`unhealthy → degraded → healthy` never short-circuits: recovery must be earned. Active probes
continue against unhealthy targets on a long interval so that recovery does not require a user to
attempt an invocation and eat the failure.

Two rules with teeth:

* **Circuit-break per tool, not per source.** One broken tool must not down-rank the seventeen
  healthy tools beside it on the same MCP server.
* **Combine active and passive.** Active probes catch cold tools that nothing is calling.
  Passive observation catches real failure modes at traffic speed. Envoy's outlier detection is
  the reference design; `pybreaker` (BSD-3) or `purgatory` (MIT) supply the breaker itself.

MCP's `ping` is transport liveness only — an empty request returning an empty result. Pair it
with a periodic `tools/list` to catch the connected-but-broken case, and to detect descriptor
drift while you are there.

⚠️ **Forward hazard:** the MCP `2026-07-28` release candidate reportedly makes the core protocol
stateless, dropping the `initialize` handshake and `Mcp-Session-Id` *(unverified — the RC text was
not published at research time)*. A health checker built on the assumption of a persistent
session is building on a legacy assumption. Re-check before implementing probes.

### 4.7 Brokerage

The broker is admission control. Its entire job:

```python
grant = broker.authorize(principal, tool_ref, arguments, context)   # PDP: validate → decide → grant
...                                                                  # caller invokes, ToolConnect absent
broker.record(grant.id, outcome)                                     # audit: close the loop
```

A grant that is issued and never closed is itself an audit finding. Rate limits, budgets, and
quotas are enforced at `authorize()` — they are policy inputs, not proxy middleware.

The one idea worth stealing from the gateway world is **agentgateway's MCP-aware policy key**:
rate-limiting and authorization keyed on the JSON-RPC method *and the tool name*, rather than on
an opaque HTTP request. Everyone else's MCP support is passthrough.

### 4.8 Audit

No single standard covers this. The composite, each layer chosen for a reason:

| Layer | Choice | Why |
|---|---|---|
| Envelope | **CloudEvents 1.0.2** | Apache-2.0, CNCF-graduated, deliberately frozen. Boring is the feature. |
| Decision body | **OPA decision-log shape** | The most mature audit schema in existence. Adopt the shape without adopting the engine. |
| Field naming | **OCSF `api_activity`** | Apache-2.0, Linux Foundation. Makes SIEM export a mapping, not a rewrite. |
| Trace correlation | **OTel `gen_ai.*` / `mcp.*`** | `execute_tool` spans, `gen_ai.tool.name`, `mcp.method.name`. |
| Integrity | **Hash chain** | `record_hash = H(fields ‖ prev_hash)`. ~30 lines of `hashlib`. |

Two warnings the research produced, both worth heeding:

* The OTel GenAI conventions **moved repositories** in v1.42.0 (2026-06-12) to
  `open-telemetry/semantic-conventions-genai`, and *every* attribute remains at `Development` —
  the lowest stability rung. Adopt the names; pin to a commit; expect churn.
* **immudb is BUSL. Consul is BUSL** (licensor now IBM Corp; no community fork exists, unlike
  Vault→OpenBao). Neither may be a dependency. AWS QLDB was shut down in 2025. For a single-writer
  SQLite log, a hash chain plus periodic external anchoring (export the head hash to a signed
  file, syslog, or git) is sufficient and honest. Merkle trees and transparency logs solve
  problems — untrusted verifiers, interleaved writers — that a single box does not have. Keep the
  anchor mechanism pluggable so graduating to Rekor or Tessera later is a change of sink, not of
  record format.

The audit record must answer *why*, not only *what*: `policy_decision`, the determining rule ID,
the descriptor version, and the health state at decision time. Store `request_hash` rather than
raw arguments when a `data_class` says so.

## 5. Interfaces

Illustrative. Every one of these is an adapter seam; none names a concrete engine.

```python
class ToolSourceAdapter(Protocol):
    """MCP, OpenAPI, or local. Ingest only — never invokes."""
    def describe(self) -> SourceDescriptor: ...
    def list_tools(self) -> list[ClaimedTool]: ...      # `claimed_*`, quarantined until asserted
    def probe(self) -> HealthObservation: ...

class PolicyEngine(Protocol):
    """Cedar today. Must return an explanation, always."""
    def decide(self, req: DecisionRequest) -> Decision: ...
    def validate_policies(self) -> list[PolicyDiagnostic]: ...

class ToolRegistry(Protocol):
    def register_source(self, src: SourceDescriptor, tier: TrustTier) -> SourceId: ...
    def assert_descriptor(self, ref: ToolRef, d: CapabilityDescriptor, by: Principal) -> None: ...
    def resolve(self, ref: ToolRef) -> ToolVersion: ...
    def watch(self, cursor: Cursor) -> Iterator[RegistryEvent]: ...

class InvocationBroker(Protocol):
    def authorize(self, p: Principal, ref: ToolRef, args: Mapping, ctx: Context) -> Grant | Denial: ...
    def record(self, grant_id: GrantId, outcome: Outcome) -> AuditRef: ...

class AuditSink(Protocol):
    """Denials are records, not exceptions."""
    def append(self, rec: AuditRecord) -> AuditRef: ...
    def verify(self, since: Seq) -> ChainVerification: ...
    def anchor(self) -> AnchorRef: ...

class HealthMonitor(Protocol):
    def state(self, ref: ToolRef) -> HealthState: ...
    def observe(self, ref: ToolRef, o: Observation) -> None: ...   # passive, from broker.record
```

Note what is absent: there is no `invoke()`. That is the architecture.

## 6. Integration with siblings

No implementation. These are the seams, and each is stated as a boundary rather than a feature.

### AgentConnect — the work ledger

AgentConnect routes subtasks to workers; a worker's identity already includes a `tools` field.
That field becomes a **toolset reference resolved by ToolConnect**.

* ToolConnect exposes `resolve_toolset(principal, scope) -> ToolsetPack` — bounded and filtered,
  the direct analogue of `get_task_context_pack`.
* AgentConnect passes `task_ref` as an **opaque correlation id**. ToolConnect stores it and never
  interprets it. **ToolConnect holds no task state.**
* Tool authorization happens in Temporal **activities**, never in workflow code — the same rule
  AgentConnect applies to memory and LLM calls, for the same determinism reason. A policy decision
  is non-deterministic input; it must be recorded as an activity result, not recomputed on replay.
* AgentConnect's route explanation and ToolConnect's decision explanation are the same genre of
  artifact and should be readable side by side.

**Unlike memory, tool governance may not be optional.** AgentConnect's memory adapter is allowed
to fail open — recall failure yields an empty pack and a warning, and no workflow fails. A policy
engine that fails open is not a policy engine. **Tool authorization fails closed.** If ToolConnect
is unavailable, the correct behavior is to deny, not to proceed unguarded. This is the sharpest
divergence from the sibling adapter pattern and it must be stated loudly wherever it is wired in.

### BrainConnect — memory

Two distinct relationships, easily conflated:

* Memory operations (`recall`, `capture`) are **governed invocations** like any other. A recall
  that reads `secret`-classed memory is subject to the same flow-control analysis as a tool that
  reads a credential file.
* Memory backends may themselves be **exposed as tools**. When they are, they register as an
  ordinary `ToolSource` with no special status.

**ToolConnect's audit log is not memory.** It is an append-only decision record. It must never be
promoted, summarized, or fed back as recalled context. Tool outcomes *may* be offered to
BrainConnect as capture candidates — always `pending`, never promoted, per WikiBrain's rule that
promotion is human-only.

*(Open: no `BrainConnect` repository was observed locally. WikiBrain is the existing memory layer.
Whether BrainConnect is a rename, a successor, or a distinct component is unresolved — see §9.)*

### ComputeConnect — local inference

Inference is **compute, not a tool**, and model routing stays out of ToolConnect entirely. The
seam is narrow and one-directional: when a registered tool is compute-backed (an embedding tool, a
local reranker), ToolConnect asks ComputeConnect for a cost and latency estimate to populate the
`cost`/`latency` fields of a decision context. It does not choose models, manage VRAM, or admit
work to a queue.

Note that AgentConnect's `LocalComputeProvider` protocol (`inventory`, `loaded`, `estimate`, `run`,
`health`) and ToolConnect's `ToolSourceAdapter` are structurally the same shape — describe,
enumerate, estimate, probe. That is not a coincidence and the two should be kept legible to each
other, but they must not be merged. A compute provider that becomes a tool source has quietly made
model routing a policy decision.

### fascia-guard — the shared guard

The authorization boundary is the natural place to run injection, PII, and secret detection over
tool arguments and results. ToolConnect **calls** fascia-guard; it does not implement detection.
Guard verdicts become policy inputs (`context.guard`), which means a guard finding can deny an
invocation through the ordinary policy path rather than through a special case. Layered defense is
mandatory there — a single classifier is provably insufficient — and that is the guard's problem
to solve, not ToolConnect's.

## 7. Reuse verdicts

The mission asked for opportunities to reuse maintained software. The answers, with licenses
verified 2026-07-10.

**Depend on:**

| Software | License | Role |
|---|---|---|
| `cedarpy` / Cedar | Apache-2.0 | Policy engine. aarch64 wheels. Community-maintained binding — pin it. |
| `jsonschema-rs` | MIT | Argument validation, hot path. Rust-backed. |
| `jsonschema` | MIT | Descriptor authoring and meta-validation. Better errors. |
| FastMCP (`from_openapi`) | MIT | OpenAPI → tool ingest. |
| MCP Python SDK | MIT | MCP client for ingest and probing. |
| `pybreaker` | BSD-3 | Circuit breaker. Do not reimplement Nygard. |
| CloudEvents SDK | Apache-2.0 | Audit envelope. |

**Adopt the shape, not the dependency:** OPA's decision-log JSON; OCSF `api_activity` field names;
OTel `gen_ai.*`/`mcp.*` attribute names (pinned to a commit); Consul's catalog↔health separation;
Envoy's xDS push model and outlier detection; Kubernetes' three-probe semantics and reconciler
loop; Nacos's registry+config fusion; agentgateway's MCP-aware policy key.

**Standards to track, not depend on:** the MCP Registry (preview, `v0.1` frozen, index not host);
OpenAPI Overlay 1.1.0 (use it); Arazzo (workflow spec — watch); Biscuit tokens (Eclipse,
Apache-2.0, attenuable capability tokens — a plausible future `Grant` encoding, not needed now);
Apicurio Registry (Apache-2.0, CNCF Sandbox — an optional external descriptor store if local-first
ever stops being enough).

**Do not depend on, licensing:** 🚨 **Consul** (BUSL 1.1, licensor IBM Corp, no community fork).
🚨 **immudb** (BUSL 1.1). ⚠️ Confluent Schema Registry (Confluent Community License, not OSI).
⚠️ Kong's MCP plugins, Bifrost's RBAC, Cerbos's embedded PDP (all enterprise-gated). ⚠️ LiteLLM's
`enterprise/` directory (MIT core is fine; never import from it). ⚠️ MCPJungle is MPL-2.0 — OSI,
weak copyleft, but stricter than the MIT/Apache norm; check before vendoring. ⚠️ Portkey is MIT
today with a Palo Alto Networks acquisition pending — re-verify.

**Notably clean:** no AGPL was found anywhere in this landscape.

### Why not just use ContextForge or agentgateway?

This section exists because the honest answer might be "you should."

Both are Apache-2.0, actively maintained, and solve overlapping problems. IBM ContextForge is the
most feature-complete OSS option — registry, protocol translation, 40+ policy plugins, OTel audit.
agentgateway does tool-level RBAC and cryptographic audit trails, is Linux Foundation governed, and
is the only project treating MCP semantics as a first-class policy dimension.

The distinction ToolConnect claims:

1. **They are proxies; ToolConnect is a library.** Both put a process in the invocation path. For
   a single-box, local-first stack whose components are Python objects calling each other in
   memory, a network hop to a Rust or Go sidecar to answer "may I call this tool" is the wrong
   shape — and a sidecar that is down is an outage in a fail-closed path.
2. **They are MCP-shaped; ToolConnect is protocol-neutral.** MCP servers, OpenAPI services, and
   local Python functions must all be governable by one registry and one policy, exactly as
   AgentConnect made MCP one adapter among several rather than the interface.
3. **They govern calls; ToolConnect governs *toolsets*.** The flow-control analysis in §3.3 — this
   principal holds a `secret`-reading tool and an `external`-writing tool, therefore it holds an
   exfiltration path — is a property of a granted set, not of any single invocation. No surveyed
   project does this.

**And the conditions under which this is the wrong call**, stated up front so they can be checked
later rather than rationalized away: if ToolConnect's consumers turn out to be separate processes
rather than in-process siblings, reason (1) evaporates. If MCP absorbs OpenAPI ingest and becomes
the universal tool protocol, reason (2) weakens considerably. If flow-control analysis proves
intractable in practice, or lands upstream in agentgateway, reason (3) goes with it. If two of the
three fail, **adopt ContextForge or agentgateway and contribute the third upstream.** That is a
better outcome than a redundant platform, and this document should be revisited against those
conditions rather than defended.

An in-path deployment remains available regardless: ToolConnect's PDP can back an agentgateway or
ContextForge policy plugin. Decision point here, enforcement point wherever it must be.

## 8. Non-goals

Restating, because scope creep in a governance layer is how it becomes an execution engine:

* **No tool execution.** No `invoke()`. No transport implementation. No retry loop around a tool.
* **No MCP replacement, extension, or fork.** ToolConnect consumes MCP and may expose an MCP
  adapter. It does not propose protocol changes.
* **No runtime in this repository, for now.** Architecture and interfaces.
* **No task state, no memory, no workflows, no model routing, no secrets storage.** Secrets are
  *classified* by ToolConnect (`data_class: credential`) and *stored* by something else.
* **No general API gateway.** If it is not a tool invocation, it is not ToolConnect's business.

## 9. Open questions

Unresolved, and requiring a decision from the user rather than a guess from the architecture.

1. **BrainConnect's identity.** No such repository was observed. WikiBrain is the memory layer that
   exists. Is BrainConnect a rename, a successor, or a fourth component? §6 is written against a
   name whose referent is unconfirmed.
2. **The `Connect` repository.** It exists, contains only a README, and predates ToolConnect and
   ComputeConnect. Is it the umbrella for the `*Connect` family, or superseded by Fascia-AI-OS?
   The relationship between the `*Connect` family and the Fascia ecosystem is undefined.
3. **Does AgentConnect adopt ToolConnect, or does ToolConnect stand alone?** The fail-closed rule
   in §6 is a real constraint on AgentConnect's execution path, and it contradicts the optional,
   fail-open posture of every adapter AgentConnect has defined so far. This needs consent, not
   assumption.
4. **Who asserts descriptors?** Trust-tier promotion is human-only by design. For a registry of any
   size that is a bottleneck. Is there an attestation path — signed descriptors from a verified
   source — that preserves the property without the toil?
5. **Is flow-control analysis tractable?** §3.3 claims toolset composition can be analyzed for
   exfiltration paths. Combinatorially this is a reachability problem over data classes and it may
   produce unusable false-positive rates on realistic toolsets. This is the most load-bearing and
   least validated idea in the document. It should be prototyped before it is promised.
6. **Grant encoding.** In-process grants can be Python objects. Cross-process, they need to be
   unforgeable and attenuable — which is what Biscuit is for. Deferring this bakes in an assumption
   that ToolConnect's callers are in-process.
