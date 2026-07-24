# Proposed integration contract — AgentConnect ↔ ToolConnect

**Status: adopted. The seam this document proposes is implemented in AgentConnect.**
AgentConnect consumes ToolConnect through its fail-closed governor client
(`ToolConnectGovernor`, wrapping the `toolconnect.client` library of §6b), bound from the
environment and consulted at subtask dispatch. One mapping note from the adoption:
AgentConnect translates `WorkerLocation.cloud` to `privacy_tier` `"trusted-cloud"`;
`local` and `rented` pass through verbatim. The document is kept as the contract's
rationale and shape; the decision it asked for has been made.

**The ask, in one sentence.** AgentConnect gains an optional `ToolGovernor` seam whose
*unavailability is a denial*, which is a different adapter posture from every other
boundary AgentConnect has defined.

---

## 1. Why this is not just another adapter

AgentConnect's established discipline is that adapters are optional and degrade
gracefully. `BACKPLANE_SPEC_ADAPTERS.md` is explicit about memory: recall failure returns
an empty pack with a warning, capture becomes a no-op, and **no core workflow may fail
because memory is unavailable.** That is correct for memory. Missing context makes an
agent dumber.

It is wrong for authorization. **A policy engine that fails open is not a policy engine.**
Missing authorization makes an agent unconstrained. The failure modes are not symmetric,
and a single "adapters are optional" rule cannot cover both.

So this contract does not ask AgentConnect to make ToolConnect mandatory. It asks for one
narrower thing:

> **A missing policy decision must never be interpreted as an allow.**

The caller chooses whether the integration is required. It does not get to choose what
silence means.

---

## 2. The two modes

The **caller** — AgentConnect, per managed surface — declares the mode. ToolConnect
enforces the semantics of whichever is chosen.

### `required`

```
tool authorization unavailable  ->  DENY
```

The subtask fails with a recorded reason. No tool runs. This is the correct default for
any surface that can reach a `write`, `destructive`, or `external` tool.

### `advisory`

```
tool authorization unavailable  ->  continue ONLY for explicitly non-sensitive operations
                                ->  and surface degradation on every affected record
```

Two constraints make this safe, and both are load-bearing:

**(a) "Explicitly non-sensitive" must be decided in advance, not at outage time.**

This is the trap. At the moment ToolConnect is unreachable, AgentConnect cannot ask it
which tools are non-sensitive — that is a policy question, and the policy engine is the
thing that is down. Falling back to "assume read-only tools are fine" reintroduces the
untrusted-annotation problem: `readOnlyHint` is a server's self-report, and MCP requires
clients to treat it as untrusted.

Therefore advisory mode requires a **pre-fetched, cached `ToolsetPack`**, obtained while
ToolConnect was healthy, containing the operator-asserted classification of each tool and
an expiry. Advisory mode is permitted to proceed **only** for tools the cached pack marks
`effect == read` and `reads_sensitive == false`, and **only** while the pack is unexpired.

An expired pack is not a degraded pack. It is no pack, and advisory mode collapses to
`required`. Otherwise "advisory" is a permanent hole that opens the moment a cache is
never refreshed.

**(b) Degradation is recorded, not logged.**

Every attempt, artifact, and worker run produced under a degraded decision carries
`governance: "degraded"` and the reason. It propagates into the handoff summary, so a
manager receiving a task knows which of its artifacts were produced without policy
review. A warning that only reaches stderr has not informed anyone.

### What both modes forbid

| | |
|---|---|
| Unreachable ToolConnect → allow | ❌ never, in either mode |
| Cached pack expired → allow | ❌ collapses to `required` |
| Unasserted tool → allow | ❌ a server's claim is not an authorization |
| Engine error → allow | ❌ an error is a denial |
| Advisory mode on a `write`/`destructive`/`external` tool | ❌ read-only, non-sensitive, or nothing |

---

## 3. The seam

Proposed for `agentconnect.core`, alongside `MemoryAdapter` and `LocalComputeProvider`.
The shape deliberately mirrors them so it is legible to that codebase.

```python
class ToolGovernor(Protocol):
    """Tool governance. Note the absence of `invoke` — AgentConnect still calls tools."""

    mode: Literal["required", "advisory"]

    def resolve_toolset(self, principal: Principal, scope: TaskScope) -> ToolsetPack:
        """Bounded, policy-filtered. The direct analogue of get_task_context_pack().

        Cacheable. Carries an expiry. In advisory mode this is what the caller falls
        back to when the governor is unreachable.
        """

    def authorize(self, principal: Principal, tool: str, args: Mapping, ctx: Context) -> Decision:
        """Allow or deny, always with a determining policy id or an explicit default-deny."""

    def record(self, decision_id: str, outcome: Outcome) -> AuditRef:
        """Close the loop. An issued-but-never-closed decision is an audit finding."""

    def health(self) -> HealthState: ...
```

`Decision` distinguishes an explicit `forbid` (a rule fired) from a default deny (no rule
matched). AgentConnect should surface that distinction, because the first is a policy
decision and the second is very likely a missing policy.

### Identity mapping

AgentConnect's worker identity is `{harness, model, tools, sandbox, privacy_tier}`. The
`tools` field becomes a **`ToolsetPack` reference resolved by ToolConnect** rather than a
free-form list. `privacy_tier` maps directly onto ToolConnect's `Principal.privacy_tier`.

Delegation must attenuate: a subagent acting for a manager has authority equal to the
**intersection** of the chain, never the union. ToolConnect implements this as
`Principal.effective_tier()`, which returns the least-privileged tier in the chain. A
`local` subagent invoked on behalf of a `rented` manager is treated as `rented`.
Hierarchical delegation (AgentConnect Track 4) must not launder privilege.

### Ownership boundary

| | |
|---|---|
| AgentConnect owns | tasks, subtasks, claims, reviews, decisions, attempts, artifacts, route history, worker runs, handoff summaries |
| ToolConnect owns | tool registry, capability metadata, policy decisions, tool health, authorization records |
| Shared | nothing. `task_ref` crosses as an **opaque correlation id**. |

**ToolConnect stores no task state.** It records `task_ref` and never interprets it.
Symmetrically, AgentConnect stores no capability metadata; it holds a `ToolsetPack`
reference and a cached copy.

---

## 4. Temporal placement

This follows AgentConnect's own determinism rule and adds nothing new to it.

* **Authorization is an Activity, never workflow code.** A policy decision is
  non-deterministic input — it depends on registry state, health, and clock. Calling it
  from a workflow would break replay.
* The `Decision` is **recorded as the activity's result** and replayed from history, not
  recomputed. A tool authorized on the first attempt stays authorized through a replay,
  and a policy change mid-workflow does not retroactively rewrite what happened.
* Activities remain idempotent, keyed on `subtask_id + activity_name + attempt`, as
  AgentConnect already requires.
* A `required`-mode authorization failure is a **workflow failure with a recorded
  reason**, not a retry storm. Retrying a denial produces the same denial.

This is precisely the placement AgentConnect already mandates for memory and LLM calls.
The difference is only in what a failure means.

---

## 5. What ToolConnect will not ask for

Stated so the review can be short:

* No change to AgentConnect's task model, ledger, or workflows.
* No dependency inversion — AgentConnect depends on a `ToolGovernor` Protocol it defines,
  and ToolConnect satisfies it. ToolConnect does not import AgentConnect.
* No sidecar, daemon, socket, or HTTP hop. The reference implementation is an in-process
  Python object; [PHASE1_VALIDATION.md](PHASE1_VALIDATION.md) shows the decision path
  running under `unshare -rn` with no network.
* No execution. ToolConnect never invokes a tool. AgentConnect's worker runtime remains
  the only thing that calls anything.
* No adoption before Phase 2. This document is a proposal.

---

## 6. Known drift, offered as evidence

While validating ToolConnect's catalog drift detection against AgentConnect's repository
(read-only, unmodified), the following surfaced and is offered without comment on
priority:

`BACKPLANE_SPEC.md` §17 names the manager-coordination primitives —
`claim_task, release_task, request_review, claim_review, complete_review, record_decision,
record_attempt, get_manager_inbox, get_handoff_summary` — and says managers read results
"through MCP".

`packages/agentconnect-mcp/src/agentconnect/mcp/server.py` registers 18 tools
(`authorize_tool` was added with the governor wiring). Three of those primitives are not
among them:

* `claim_review`
* `complete_review`
* `get_manager_inbox`

All three exist as `AgentConnectService` methods. **The review loop the spec describes
cannot be completed over MCP** — `request_review` is exposed, and the three tools needed
to finish the loop are not. Whether that is a documentation bug or an adapter gap is
AgentConnect's call.

Reproduce: `.venv/bin/python experiments/drift_experiment.py`.

---

## 6b. Reference client & wiring (shipped)

The seam above is a Protocol AgentConnect would own. To make adoption concrete without
modifying AgentConnect, ToolConnect **ships a client library in its own repo**:
`toolconnect.client.ToolConnectClient`. It is stdlib-only, importable, and fail-closed —
a deny is a return value, but unreachable / non-200 / an incompatible decision-contract
major *raises* (`ToolConnectUnavailable`) and never returns an allow. It has no `invoke`.

Config surface (mirrors `LocalComputeProvider`'s connection config):

```python
from toolconnect.client import ToolConnectClient
gov = ToolConnectClient.from_config({"base_url": "http://127.0.0.1:8095",
                                     "token": os.environ["TOOLCONNECT_AUTH_TOKEN"]})
# env fallback: TOOLCONNECT_URL / TOOLCONNECT_TOKEN / TOOLCONNECT_TIMEOUT
```

**AgentConnect-side wiring (for the lead).** Implement the `ToolGovernor` Protocol (§3)
as a thin adapter holding a `ToolConnectClient`:

* `authorize(principal, tool, args, ctx)` → `client.authorize({"id": principal.id,
  "privacy_tier": principal.effective_tier(), "on_behalf_of": ...}, source_id, name,
  ctx)`; map `ClientDecision.allowed`/`.default_deny`/`.determining_policies` onto
  AgentConnect's `Decision`. In `required` mode, a raised `ToolConnectUnavailable` is a
  workflow failure (a denial), never an allow — the client already refuses to fabricate
  one.
* `record(decision_id, outcome)` → `client.record_outcome(decision_id, outcome.status,
  outcome.detail)`.
* `resolve_toolset(...)` → not yet an HTTP route (see SERVICE.md *Known limits*);
  advisory-mode callers cache the last good `/catalog` slice until it is exposed.
* `health()` → `client.health()`.

The `tools` field of a worker identity becomes the toolset the governor resolves; the
delegation-chain intersection is already computed client-side via
`Principal.effective_tier()` before the call. Nothing here imports AgentConnect, and
AgentConnect need not import ToolConnect — it depends only on the Protocol it defines and
this HTTP client. Proven against a live `toolconnect serve` in `demo_client_auth.py`.

## 7. What AgentConnect's maintainer is being asked to decide

1. **Is a fail-closed seam acceptable** in a codebase whose every other adapter fails
   open? If not, ToolConnect stands alone and this contract is withdrawn.
2. **Is `advisory` mode with a pre-fetched, expiring pack an acceptable middle ground**,
   or does the cache-expiry rule make it useless in practice?
3. **Does `worker.tools` become a `ToolsetPack` reference**, or does AgentConnect keep
   free-form tool lists and consult ToolConnect only at invocation time? The first is
   stronger; the second is a smaller change.
4. **Who owns the `ToolGovernor` Protocol definition?** Proposed: AgentConnect, in
   `agentconnect.core`, exactly as it owns `MemoryAdapter` and `LocalComputeProvider`.

A "no" to (1) is a complete and useful answer. It would mean ToolConnect governs
applications and agents that are not AgentConnect workers, which is a smaller product but
not an incoherent one.
