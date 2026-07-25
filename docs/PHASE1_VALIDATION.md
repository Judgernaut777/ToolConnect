# Phase 1 — Validation

**Purpose.** Test the assumptions that determine whether ToolConnect should exist
independently, before building anything that depends on them. Not to build the product.

**Result in one line.** Cedar is suitable and proven on this hardware; flow analysis is
real but is a *grant-time disclosure*, not a runtime alert, and its precision is bounded
by a labeling problem that scoping fixes; the differentiation claim survives at 2 of 3,
with the third unproven rather than failed.

Everything below is reproducible offline:

```
uv venv --python 3.11 .venv && uv pip install --python .venv/bin/python -e ".[dev]"
.venv/bin/python -m pytest                       # 52 tests
.venv/bin/python experiments/flow_experiment.py
.venv/bin/python experiments/drift_experiment.py
```

Prototype constraints, all honored: in-memory only, no daemon, no database, no HTTP
service, no tool invocation. `grep -rn "def invoke" src/` returns nothing, and a test
asserts it. The suite passes under `unshare -rn` — no network in the decision path.

---

## Target 1 — Policy engine suitability

**Verdict: Cedar is suitable. Adopt it. `pycasbin` is not needed.**

`cedarpy==4.8.6` installed on `aarch64` from a **prebuilt wheel** — no Rust toolchain,
no compilation, CPython 3.11. This was the load-bearing risk in the ARCHITECTURE choice
and it is now retired.

| Requirement | Result |
|---|---|
| In-process, no sidecar | ✅ Native extension. `import cedarpy`. |
| No network in the decision path | ✅ Full suite passes under `unshare -rn`. |
| Determining policy ID on every decision | ✅ `diagnostics.reasons` → `['policy0']`. |
| Human-readable reason | ✅ `@id("forbid-destructive-nonlocal")` surfaces via `id_annotations_by_reason`. |
| Deny by default | ✅ Unmatched request → `Deny` with empty reasons. |
| Forbid overrides permit | ✅ Verified: a `permit`-matching read tool is denied by a matching `forbid`. |
| Refuses an unparseable policy set | ✅ `PolicySet.from_str` raises; the engine constructor propagates. |

### The finding that changed the design

**A Cedar `Deny` with empty `reasons` means "no policy matched" — not "a policy forbade
this."** Those are different events and conflating them makes a policy *bug* (nobody
wrote a rule) indistinguishable from a policy *decision* (someone wrote a rule to stop
this). `Decision.is_default_deny` now exposes the distinction, and the audit record
carries it. An audit log that cannot tell them apart cannot answer "why was this
denied?", which was the entire reason for choosing Cedar.

### Limits found, and what they cost

* **Parse-checking is not type-checking.** `validate_policies()` catches
  `resource.efect` (misspelled) — but only against a **Cedar schema** declaring the
  `Agent` and `Tool` entity types. We have no such schema yet, so the prototype
  parse-checks only. A typo'd attribute currently evaluates to "attribute absent" and
  silently fails the `when` clause — a silent deny, which is safe, but invisible.
  **Phase 2 must write the Cedar schema.** This is the single highest-value follow-up.
* **`cedarpy` is community-maintained** by k9 Security, not AWS. Tracking upstream
  within days as of 2026-07-09. Pin it; re-verify on upgrade.
* **Partial evaluation is experimental** upstream and was not exercised. Nothing in
  Phase 1 needs it.

`pycasbin` was **not** benchmarked, because the condition for reaching for it — Cedar
failing to install or run on aarch64 — did not occur. It remains the documented fallback.

---

## Target 2 — Toolset-level flow analysis

**Verdict: the idea is real and no surveyed project does it. But it does not do what
"analysis" implies. It is a disclosure, not a detector — and it must be rebuilt around
scopes.**

Measured against a 53-tool catalog assembled from real surfaces: the 17 tools
AgentConnect's MCP adapter actually registers, the 9 real `brain_*` tools from
BrainConnect, and the reference `filesystem` / `github` / `slack` / `fetch` / `postgres`
/ `shell` MCP servers.

### Useful warnings

| Toolset | Tools | Findings | Pairwise paths | Collapse |
|---|---|---|---|---|
| Everything | 53 | **3** | 110 | 36.7× |
| Realistic coding agent | 16 | **2** | 20 | 10× |

The two findings on the realistic agent are `secret → external` and
`credential → external`, arising because the agent holds `read_file` (which can read
`~/.ssh/id_ed25519`) alongside `push_files`, `create_pull_request`, `create_issue`,
`create_or_update_file`, and `fetch`. **Neither tool is individually dangerous, and no
per-invocation authorization check can see the path.** That is the claim, and it holds.

`fetch` is the sharpest case: it is simultaneously a reader *and* a sink, because data
leaves in the URL. A single tool completes an exfiltration path by itself.

### Obvious false positives

**Formally, near zero. Operationally, nearly all of them — which is the real result.**

Every one of the 20 pairwise paths is a *true statement* about the agent's capability.
None is a mislabeling. But an operator shown 20 alerts for a perfectly ordinary coding
agent will dismiss all 20, and the twenty-first — the one that matters — with them.
Pairwise enumeration is the false-positive generator. Reporting one finding per
*class-pair* collapses 20 decisions into 2, and 110 into 3.

The genuine false-positive source is elsewhere, and it is serious:

```
3b. Are the findings trustworthy? Trace each to its label.
  get_task_context_pack    AMBIGUOUS
  read_artifact_chunk      ARG_DEPENDENT+AMBIGUOUS
  read_file                ARG_DEPENDENT
  -> 3/3 sensitive readers rest on a worst-case guess.
```

**Every finding in the realistic case traces to a label that a static descriptor cannot
justify.** `read_file` is labeled `credential` because it *could* read an SSH key. If
the filesystem server is rooted at a project directory containing no secrets, that label
is simply wrong, and both findings are false. Across the catalog, **13% of tools (7/53)
have a data class determined by their arguments rather than their identity**
(`read_file`, `run_command`, `query`, `fetch`, …), and **11% (6/53) required a judgment
call another operator could reasonably make differently.**

The arg-dependent tools are not a random 13%. **They are exactly the sensitive readers.**
A property that only fires on the tools you cannot statically classify is not much of a
property.

### The fix, tested

Bind the descriptor to **`(tool, scope)`**, not to the tool. `read_file` on a filesystem
server rooted at `/` reads `credential`. The same `read_file` rooted at `~/project`
reads `internal`. The tool did not change; its scope did — and a scope is a *registry
fact you can verify* (the server's `list_allowed_directories`), not a guess.

Re-asserting the three sensitive readers under a narrowed scope takes the realistic
agent from **2 findings and 20 paths to 0 and 0** (`flow_experiment.py` §6).

This is the substantive change Phase 1 makes to
[ARCHITECTURE §3.3](ARCHITECTURE.md#33-capabilitydescriptor): `data_classes_read` and
`data_classes_written` must be asserted per `(tool, scope)` binding. **A descriptor
without a scope is not assertable.**

Two caveats stated plainly, because that "0 findings" number is seductive:

1. Scoping **relocates** trust, it does not remove it. The claim "this filesystem server
   cannot reach a secret" is now the thing an operator must get right, and it is
   falsifiable by inspection — which is the improvement.
2. Argument-level classification (`run_command` with an arbitrary shell string) is **not**
   solved by scoping and may not be statically solvable at all. Such tools should carry
   `requires_approval` and be treated as unbounded sinks. The prototype does this for
   `run_command`.

### Operator configuration burden

* **53/53 tools require a human assertion.** There is no partial-credit mode. This is the
  bottleneck predicted in ARCHITECTURE open question 4, now measured at 100%.
* Suppression is per **class-pair** (2 decisions on the realistic agent), not per
  tool-pair (20). Accepting one class-pair removed 1 finding and 15 pairwise paths.
* **Unlabeled tools produce silence, not safety.** With zero assertions the analysis
  reports zero findings and 16 unlabeled tools. An unasserted catalog looks identical to
  a safe one, which is exactly why unasserted tools must be quarantined rather than
  analyzed. The prototype reports `unlabeled` explicitly rather than skipping.

### Are the labels expressive enough?

No, in two specific ways, both now documented rather than assumed away:

* They cannot express **argument-dependent** classification (13% of tools).
* They cannot express **transitive** sensitivity: `get_task_context_pack` is sensitive
  only because it may embed an artifact that a worker may have filled with a secret.
  Its class is a function of another tool's *behavior*, not of its own signature.

`declassifies` — an operator's assertion that a tool strips sensitive data — is
implemented and breaks a path. It is a security claim by a human, and should be treated
with the same suspicion as any other.

---

## Target 3 — In-process / protocol-neutral differentiation, reassessed

The [abandonment rule](ROADMAP.md#the-condition-under-which-this-roadmap-should-be-abandoned)
says: ToolConnect rests on three claims; **if two fail, adopt IBM ContextForge or
agentgateway and contribute the third upstream.** Applied honestly:

| Claim | Status | Evidence |
|---|---|---|
| 1. In-process library, not a proxy | ✅ **Holds** | 52 tests pass under `unshare -rn`. No daemon, no socket, no `invoke()`. Both alternatives require a running process in the invocation path; a fail-closed dependency on a sidecar makes the sidecar an outage. |
| 2. Protocol-neutral normalized catalog | ⚠️ **Unproven, not failed** | The catalog is protocol-agnostic *by construction* — `ToolSourceAdapter` never appears in `Catalog`, and nothing in `descriptor.py` mentions MCP except the annotation crosswalk. But every tool ingested in Phase 1 was MCP-shaped. **No OpenAPI document was ingested.** The claim is untested. |
| 3. Toolset-level governance | ✅ **Holds, and is the real differentiator** | Confirmed by the research sweep that no surveyed project (ContextForge, agentgateway, Envoy AI Gateway, Obot, Higress, Pomerium) analyzes a *granted set* for flow. All govern individual calls. The property is invisible to per-call authorization by definition. |

**Continue — but claim 2 is on probation.** One claim holds strongly, one holds, one is
unproven. The rule triggers on two *failures*, and there are none. However, "unproven"
must not be allowed to age into "assumed": **Phase 2 must ingest a real OpenAPI document
through `FastMCP.from_openapi` and register it in the same catalog beside the MCP tools.**
If that turns out to require an MCP-shaped intermediate representation, claim 2 has
failed, and with only claim 1 and 3 standing the honest move — per the rule — is to
reassess rather than to defend.

A note on claim 3's strength: it is a *real* differentiator, but a weaker one than the
original document implied. Flow analysis cannot be a runtime denial rule, because at
`authorize()` time the toolset is already granted; the analysis belongs at **grant time**,
as a review artifact an operator reads before approving a toolset. That is a smaller
product than "the platform detects exfiltration," and the documents should say so.

---

## Bonus target — catalog drift, against a real repository

The motivating case, run against `/home/mini/mcp-agentconnect` **without modifying it**.

`BACKPLANE_SPEC.md` §17 names the manager-coordination primitives and says managers read
results "through MCP". The MCP adapter registers 18 tools (`authorize_tool` was added
with the governor wiring). Three of the named primitives are absent from it:

```
ADVERTISED, MISSING AT RUNTIME:
  - claim_review
  - complete_review
  - get_manager_inbox
```

All three exist as `AgentConnectService` methods (`core/service.py`); none is exposed
through `packages/agentconnect-mcp/.../server.py`. **The review loop that spec §17
describes — `request_review` → inbox → `claim_review` → `complete_review` — cannot be
completed over MCP.** A manager that reads the spec and calls `claim_review` gets
tool-not-found.

Detected by comparing two lists. No tool was invoked. This is the cheapest useful thing
the platform does.

**And an honest false positive from the same run.** The report also flagged 11
"undeclared-present" tools. That is an artifact of using spec *prose* (§17, which lists
coordination primitives only) as the declaration source. **Prose is not a manifest.**
Drift detection needs a declared artifact — `server.json`, an OpenAPI document — to diff
against, or it invents findings. Phase 2 should ingest `server.json`.

---

## What was built

| Path | Lines | What |
|---|---|---|
| `src/toolconnect/descriptor.py` | ~160 | `claimed_*` vs `asserted_*`, data classes, trust tiers, conflict detection |
| `src/toolconnect/catalog.py` | ~150 | In-memory catalog, drift, human-only assertion, rug-pull fingerprints |
| `src/toolconnect/flow.py` | ~120 | Toolset flow analysis, both reporting shapes |
| `src/toolconnect/policy.py` | ~170 | Cedar adapter, fail-closed `Decision`, `Broker` with no `invoke()` |
| `fixtures/real_catalog.py` | ~170 | 53 tools from real surfaces, with provenance |
| `experiments/` | ~180 | The two experiments above |
| `tests/` | 52 tests | Offline |

No daemon. No database. No HTTP service. No tool execution.

---

## Remaining go/no-go questions

1. **Does an OpenAPI document survive ingest without an MCP-shaped detour?** Claim 2 is
   unproven and is the one that would break the "protocol-neutral" premise. *Blocking for
   Phase 2.*
2. **Is a `(tool, scope)` descriptor assertable in practice?** Scoping fixed the false
   positives on paper. It requires the registry to know each source's scope — trivially
   available for `filesystem`, unclear for `postgres`, meaningless for `run_command`.
3. **Who writes 53 assertions?** The labeling bottleneck is measured at 100% of tools and
   is unresolved. Attestation (signed descriptors from a verified source) is the only
   proposed path and has no design.
4. **Does AgentConnect accept a fail-closed dependency?** Unchanged from Phase 0. See
   [AGENTCONNECT_CONTRACT.md](AGENTCONNECT_CONTRACT.md), which proposes the semantics
   without modifying AgentConnect.
5. **Is flow analysis worth a product, given it is a grant-time review artifact rather
   than a runtime control?** It is genuinely novel. It is also much smaller than the
   Phase 0 documents implied. Reasonable people could call this a feature of
   ContextForge rather than a reason for a separate platform.

Question 5 is the one to answer before Phase 2 begins.
