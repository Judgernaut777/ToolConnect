# Verification

**What this proves, and what it deliberately does not.** ToolConnect is a Phase 1
validation prototype — an in-memory decision core (registry, descriptors, flow analysis,
policy) with no transport, no provider adapters, and no execution path. This suite proves
the contracts of *that* surface exhaustively. Where the verification handoff asked for
tests of components that do not exist yet, those areas are marked **blocked** with the
reason, rather than tested against a fake implementation. Testing vaporware produces false
confidence, which is worse than a visible gap.

**Run it:**

```
.venv/bin/python -m pytest              # full suite
.venv/bin/python -m pytest -m "not perf"  # skip performance tripwires
unshare -rn .venv/bin/python -m pytest  # proof it needs no network
```

**Result:** 152 passed, 2 skipped (unbuilt provider types), 0 xfailed. Deterministic
(`hypothesis` derandomized, fixed profile) and offline.

**Findings A and B are fixed** (namespaced identity + durable assertion evidence). The
strict-xfail that guarded Finding A's intended contract is now a passing regression test; the
marker is gone. History and the fixed contract are below and in ARCHITECTURE §2.4.

---

## Coverage against the handoff's eight areas

| # | Area | Status | Where |
|---|---|---|---|
| 1 | Contract tests (provider conformance) | ⚠️ **Partial** — one Protocol exists | `test_conformance_policy_engine.py` |
| 2 | Property tests | ✅ **Covered** | `test_property_{registry,flow,metadata}.py` |
| 3 | Fault injection | ⚠️ **Partial** — no transport to fault | `test_fault_injection.py` |
| 4 | End-to-end | ⚠️ **Reframed** — `invoke` forbidden by design | `test_e2e_lifecycle.py` |
| 5 | Compatibility fixtures | ⚠️ **Fixtures only** — no adapters exist | `test_compat_providers.py` |
| 6 | Security boundaries | ✅ **Covered** (except signatures) | `test_security_boundaries.py` |
| 7 | Regression | ✅ **Two defects fixed + guarded** | `test_regression.py` |
| 8 | Performance sanity | ✅ **Tripwires** | `test_perf_sanity.py` |

### 1 — Contract / provider conformance

The handoff wants "every provider implementation passes the same shared test suite."
**There are no provider implementations.** `ToolSourceAdapter` is a documented Protocol
(ARCHITECTURE §5), implemented by nothing. So a provider conformance suite has nothing to
run against.

What *does* exist is one behavioral Protocol with two implementations: `PolicyEngine`
(`CedarPolicyEngine` + a `ReferencePolicyEngine` double). The shared conformance suite
runs against both and nails the fail-closed contract — no engine may allow an unasserted
tool, none may raise out of `decide`, every decision carries a reason. When real
`ToolSourceAdapter` implementations land, this file is the template: parametrize the
fixture over them, assert the shared contract once.

### 2 — Property tests

Fully covered, over randomized inputs with a derandomized (reproducible) profile:

* **Registry consistency** — ingest never authorizes; invocable ⟺ asserted ∧ tier permits;
  assertion requires a named operator; drift is exact set arithmetic; report lists sorted
  and unique.
* **Flow analysis** — every pairwise path connects a real reader and sink; a finding
  requires a tracked reader *and* an external sink; capability is monotonic (a larger grant
  never exfiltrates less); accepting a class-pair suppresses exactly that class; a
  declassifying reader is never a source; path accounting is exact.
* **Metadata normalization** — the MCP-hint→Effect crosswalk is total, deterministic, and
  never raises for any of the 81 hint combinations; claim-conflict detection is total.

**Blocked sub-items:** *dependency resolution* and *parameter validation* are named in the
handoff but unbuilt. There is no dependency graph in the prototype, and argument validation
against the canonical schema (ARCHITECTURE §2.3) is designed but not implemented — the
`input_schema` field is stored, never enforced. No test can cover them yet; they are Phase
2 work and are flagged in ROADMAP.

### 3 — Fault injection

Covered at every seam that exists: unparseable policy refuses to construct (no allow-all
engine), an engine exception becomes a denial, unknown sources raise, duplicate and
conflicting tool identities are pinned, missing metadata fails closed, and hostile
argument/principal strings (`\n`, `\x00`, injection-shaped, 5 KB) yield denials rather than
crashes.

**Blocked:** *provider crash mid-stream, socket timeout, slow responses, truncated JSON on
the wire.* All require a transport/provider layer that does not exist — there is no wire to
truncate and no socket to time out. Faking these would assert behavior of code that is not
written. They become testable the moment `ToolSourceAdapter` has a real HTTP/MCP
implementation, and this file names them so the gap is tracked.

### 4 — End-to-end

The handoff's flow is `discover → register → list → invoke → shutdown`. Three steps are
unbuilt and **one is forbidden by the architecture the handoff also says not to change:**

* `discover` — no provider layer to discover from.
* **`invoke` — ToolConnect is a decision point, not a data path. There is no `invoke`, by
  design (ARCHITECTURE §1, §8). Encoding an invoke contract would contradict the core
  design.** Per the "if tests and implementation disagree, find the correct contract" rule:
  the architecture is correct, the handoff example is not. This is a mistake in the handoff,
  not a missing feature.
* `shutdown` — no service lifecycle exists.

So the E2E test exercises the *real* lifecycle end to end
(`register → assert → list → authorize → record`, denial included in the audit) and
separately asserts the correct contract for the forbidden step: no `invoke`/`execute`/
`route`/`call_tool` surface anywhere in the package.

### 5 — Compatibility fixtures

Fixtures for MCP tools and OpenAPI operations exist, with reference adapter functions that
translate each into `ClaimedMetadata`, and the crosswalk is proven provider-independent (a
destructive tool is destructive whether MCP or OpenAPI described it). **A2A and generic HTTP
are `skip`-marked with reasons** — no adapter and no agreed provider shape exist. The
"identical behavioral suite across all providers" cannot run until the adapters are real;
the fixtures are its seed.

### 6 — Security boundaries

Covered: untrusted/quarantined sources are uninvocable even with a valid assertion; no
self-reported claim (any of 16 hint combinations) makes a tool invocable; a lying tool is
caught by the conflict check; delegation attenuates to the least-privileged tier in the
chain (property-tested); every unhappy path fails closed; arbitrary names never crash drift.

**Blocked:** *invalid-signature rejection.* There is no cryptographic attestation in the
prototype — `TrustTier` is operator-assigned, not signed. A test documents the absence so it
is visible; it must become real when signatures land.

### 7 — Regression

Two defects were found *by this suite during verification*, then fixed, and are now guarded by
permanent regression tests. See Findings below.

### 8 — Performance sanity

Six tripwires (`-m perf`), each ceiling ~100× the measured baseline so they fire on an
algorithmic regression, not on jitter. Best-of-N minimum for robustness on a shared box.
*Routing latency* from the handoff is **N/A** — ToolConnect does not route; there is no
proxy path to measure.

---

## Findings — both FIXED

Found by this suite during verification, then fixed in the namespaced-identity +
assertion-evidence change. The contract is documented in ARCHITECTURE §2.4.

### Finding A — tool-name collision (correctness, security-relevant) — FIXED

**Was:** `Catalog.tools` was keyed by bare tool name. Two sources offering a same-named tool
collided; the second silently overwrote the first (`len(tools) == 1`). An `untrusted` source
could shadow a `verified` source's tool by reusing its name, and the bare-name conflation
also reached flow analysis (two distinct tools sharing a name merged reader/sink identities).
This contradicted ARCHITECTURE §3.2's namespaced-identity contract.

**Fix:** the catalog is keyed by `ToolId = (source_id, name)`; `ToolVersion.id` and
`.qualified_name` expose it. Same-named tools from different sources coexist and are
independently addressable. Bare-name lookup survives only as `resolve()`/`select()`, which
raise `AmbiguousToolName` rather than silently pick — fail-closed on ambiguity. `assert_descriptor`,
`invocable`, `get`, and `Broker.authorize` are all source-qualified.

**Guarded by:** `test_regression.py::TestFindingA_NamespacedIdentity` (the assertion that was
a strict `xfail` at checkpoint `7be628f` now passes) and
`test_security_boundaries.py::TestNamespacedIdentityPreventsShadowing`.

### Finding B — re-ingestion after assertion — FIXED

**Was:** re-ingesting an already-asserted tool reset it to unasserted (fail-closed, safe) but
`drift()` reported it as plain `unasserted`, collapsing "never asserted" with "asserted, then
the server changed the tool."

**Fix:** an assertion now records the *claim fingerprint* it vouched for, as durable evidence
(`AssertionRecord`) that survives re-ingestion. The catalog distinguishes four states via
`assertion_status()` — never / asserted / re-ingested-unchanged / re-ingested-changed:

* **Never asserted** → `drift.unasserted`; not invocable.
* **Re-ingested unchanged** (same claim the operator vouched for) → assertion *stands*; still
  invocable. Identical re-announcement is a no-op, not a forced re-review.
* **Re-ingested changed** → not invocable until re-asserted, and reported as
  `drift.redefined_after_assertion` — a vouched-tool change, **distinct** from never-asserted.
* **Re-asserted** → invocability restored, bound to the *new* fingerprint only; reverting to an
  un-vouched prior claim does not restore it.

The chosen contract is the handoff's **preferred** contract (fingerprint as assertion
evidence), documented in ARCHITECTURE §2.4.

**Guarded by:** `test_regression.py::TestFindingB_ReingestionAfterAssertion` — six cases
covering never-asserted, re-ingested-unchanged, re-ingested-changed, changed-cannot-invoke,
provenance-preserved, and re-assertion-restores-for-new-fingerprint-only.

---

## Non-negotiables honored

* **No test was weakened.** The verification suite's assertions were preserved or
  strengthened; call sites were migrated to the source-qualified API, and the strict-xfail
  became a passing regression test rather than being deleted.
* **No invocation surface was added.** `grep -rn "def invoke|def execute|def route" src/`
  is empty, and `test_e2e_lifecycle.py` asserts the absence.
* **Deterministic and offline.** Derandomized hypothesis profile; the whole suite passes
  under `unshare -rn`.
* **No persistence/schema change.** The model change is in-memory only: a `ToolId` key and an
  `AssertionRecord` map. ToolConnect remains a decision point with no database.

## When the blocked areas unblock

Each blocked item is gated on a specific unbuilt component. In priority order for whoever
builds Phase 2:

1. A real `ToolSourceAdapter` (MCP first) → unblocks provider conformance (1), transport
   fault injection (3), and the identical-behavior compatibility suite (5).
2. Canonical-schema argument validation → unblocks parameter-validation property tests (2).
3. Cryptographic source attestation → unblocks invalid-signature security tests (6).
