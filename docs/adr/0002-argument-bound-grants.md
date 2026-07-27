# ADR 0002 — Argument-bound one-use grants (contract 1.0 → 1.1)

Status: accepted (2026-07-27). Context: moving authorization from worker-dispatch time
to the final invocation boundary, across ToolConnect and its AgentConnect adopter.

ToolConnect remains a **decision-and-governance point that is never in the invocation
data path**. This ADR adds a second, optional layer of authorization — bound to exact
final arguments, one-use, atomically redeemed — on top of the existing per-call
`authorize`/`record` loop. It does not add an `invoke` route or an execution path; the
caller still performs the call itself.

## 1. Why worker-dispatch-time authorization was not enough

Contract 1.0's `authorize` answers "may this principal call this tool" once, typically
at the point a worker's toolset is resolved. Every actual tool call the worker then makes
runs without ToolConnect seeing its arguments — a declared-toolset check is a cheap early
gate, not enforcement of what actually executes. A tool call whose *arguments* matter
(a `write_file` path, a `shell` command) was ungoverned at the point it mattered.

## 2. Design

`authorize` may now bind exact final arguments: the caller sends `args`, ToolConnect
computes a canonical-JSON SHA-256 hash of them (`toolconnect.hashing`, the **only**
implementation of this rule, used on both the issue and redeem paths), and on allow
issues a one-use `grant` alongside the Decision. A new `POST /grants/{id}/redeem` route,
called by the runtime immediately before it actually executes the call, atomically
consumes the grant: a second redeem, an args mismatch, expiry, a principal mismatch, or
the tool having become non-invocable since issue all deny, explicitly and by reason.
Everything is additive: `authorize` with no `args` behaves exactly as 1.0 did, proven by
the unmodified `DECISION_KEYS` golden fixture in `tests/test_contract.py`.

## 3. Rulings on points the two candidate designs disagreed on

| # | Question | Ruling | Why |
|---|---|---|---|
| R1 | `grant` nested, present iff `args` sent | **Yes** | Gives an unambiguous stale-server detector (a pre-1.1 server never sends the key) and keeps the legacy key set byte-identical. |
| R2 | Grant status: stored column vs. computed from timestamp latches | **Computed** | Matches the codebase's existing doctrine (`load_catalog` re-derives assertion validity, never trusts a persisted flag); a stored status can silently disagree with its own timestamps. |
| R3 | Grant bound to principal at redeem, not a pure bearer capability | **Bound** | A leaked `grant_id` (a log line, a transcript) must not be redeemable by a different principal. Cheap, strictly fail-closed. |
| R4 | Out-of-range TTL: clamp vs. `400` | **`400`** | Silent coercion contradicts the repo's refuse-rather-than-guess idiom. Bounds `[1, 300]`, default `60`; `bool` is explicitly rejected (it is an `int` subclass in Python). |
| R5 | Thread `args_hash` into the Broker's decision record, or leave the Broker untouched | **Untouched** | The verified Cedar core and the `test_contract.py` golden shape stay exactly as they were; correlation via `decision_id → grant_issue` is sufficient and fully additive. |
| R6 | One `grant_redeem` audit kind with a `redeemed` flag, or split success/denied kinds | **Split** (`grant_redeem` / `grant_redeem_denied`) | `read_audit` filters by `kind` only; an operator hunting replay attempts needs to query denials directly. |
| R7 | Dedicated `POST /grants/{id}/close` route, or close only via `outcome` | **Both** | An explicit close route (for abandon-in-`finally`) and `outcome` accepting `grant_id`. |
| R8 | `ToolGovernor.redeem`: optional sub-protocol with silent decision-only fallback, or required | **Required, hardened** | An optional/degrading `redeem` recreates exactly the enforcement gap this project exists to close — an old governor would execute final arguments ungoverned. A bound governor lacking a usable grant/redeem path refuses execution instead of degrading. |
| R9 | `governed_invoke` executor: zero-arg closure, or `executor(args)` | **`executor(args)`** | A zero-arg closure can drift from the redeemed arguments (TOCTOU). The executor receives the exact deep-copied mapping that was hashed and redeemed. |
| R10 | Hashing location: reuse `store._canonical`, or a new module | **New `hashing.py`; `store._canonical` untouched** | Repointing the existing canonicalizer (e.g. to add `allow_nan=False`) would silently change the hash of every existing audit body — an unforced regression risk. |
| R11 | Runtime seam location (AgentConnect side): `RuntimeConfig`, or constructor/graph parameters | **Constructor/graph parameters** | `agent.py`'s own idiom: seams are wiring and live outside the frozen, data-only `RuntimeConfig`. |
| R12 | TTL wire key name | `ttl_seconds` | Matches the response field name. |
| R13 | A new runtime `EventType.tool_call_authorized` | **Deferred** | AgentConnect's runtime package has no observability provider to emit through yet. ToolConnect's own `grant_issue`/`grant_redeem*`/`grant_close` audit chain is the authoritative per-call trail today; cross-package observability plumbing is a follow-up, not blocking. |

Points both candidate designs already agreed on, adopted as-is: redeem resubmits **raw
args** (the server is the only hasher — AgentConnect never learns the canonicalization
rule, which kills cross-repo canonicalizer drift as a risk entirely); redeem is always
HTTP `200` for decision outcomes — a denial is a decision — with `400` reserved for
malformed request shape; redeem echoes `source_id`/`name`/`decision_id` from the
**stored** grant row, never the caller's claim; an allow with no grant when `args` was
sent is a refusal (the mixed-fleet rule); expiry is inclusive-deny (`now >= expires_at`);
no client-supplied timestamps anywhere; `BEGIN IMMEDIATE` is kept as defense-in-depth
over the store's `RLock`; grant rows are never deleted (auditable); no raw call
arguments are ever persisted or audited, only their hash.

## 4. Gaps both candidate designs missed, and how they're closed

* **Close-then-redeem hole.** A grant closed (explicitly, via outcome, or by a failed
  `not_invocable` check) must never subsequently redeem. `redeem_grant` checks
  `closed_at IS NOT NULL` and denies with reason `closed` before checking anything else
  that would otherwise have allowed it.
* **Catalog drift between issue and redeem.** A grant issued while a tool is invocable
  can outlive that invocability (a re-ingest that drops the assertion — a rug-pull, or
  ordinary drift) before it is redeemed. Because Cedar policy itself is loaded once at
  engine construction (process-static — there is no reload route), the catalog's
  assertion state is the only *mutable* authority left to re-check. `redeem` therefore
  runs an `invocable_check` **inside** the same transaction that would otherwise redeem;
  on failure it closes the grant permanently in that same transaction and denies with
  `not_invocable`. If policy hot-reload is ever added, `redeem` must additionally
  re-evaluate policy, not just the catalog.
* **Decision-id race under concurrency.** `ToolConnectService.authorize` reads
  `self._audit_log[-1]["decision_id"]` after calling the Broker. The HTTP server is safe
  because one global handler lock serializes `_route`, but a concurrent **in-process**
  embedder (no HTTP layer) could otherwise bind a grant to a different call's
  `decision_id`. `ToolConnectService._authz_lock` now holds the broker call, the
  decision-id read, the grant insert, and the `grant_issue` audit append together as one
  critical section. This was a genuine pre-existing latent bug that the grant feature
  would have weaponized; it is fixed for both callers, not just the grant path.
* **Hash malleability via non-string keys.** `json.dumps` coerces non-string dict keys
  to strings, so `{1: "x"}` and `{"1": "x"}` would otherwise collide, and mixed-type keys
  raise from inside `sort_keys`. Unreachable over the wire (JSON object keys are always
  strings) but reachable in-process. `hashing._check` recursively validates key/value
  types *before* `json.dumps` runs, and this also subsumes the NaN/Infinity backstop —
  Python's `json.loads` happily parses the non-conforming `NaN`/`Infinity` literals that
  `json.dumps` itself will emit by default, so a caller could otherwise smuggle one
  through — with a clean `400` before any decision audit record exists.
* **TOCTOU between redeem and execute.** Structural, and stated rather than hidden:
  ToolConnect is a PDP, never a proxy, so nothing can stop a caller mutating its own
  arguments after redeeming. `governed_invoke` deep-copies `args` once at entry and uses
  that frozen copy for authorize, redeem, and the executor call; AgentConnect's runtime
  loop is expected to do the equivalent with `final_args`.
* **Success-path outcome reporting must not destroy a completed execution.** Calling
  `record_outcome` unwrapped after a successful `executor()` would let an audit-path
  outage raise away a result that already executed. Fail-closed applies strictly
  *before* execution; after it, outcome reporting is best-effort. The grant is left
  visibly "redeemed but never closed" in that case — truthful, and auditable via
  `GET /grants?state=redeemed`.
* **One-way schema door.** Schema `v4` (the `grants` table) means an older ToolConnect
  binary refuses to open a `v4` database (`SchemaTooNewError`) — noted in `CHANGELOG.md`.

## 5. What did not change

The Cedar policy engine, the `Broker`, the `Catalog`'s assertion/invocability semantics,
the existing Decision key set (`DECISION_KEYS`), `store._canonical` (used for existing
audit bodies), and `EXPECTED_CONTRACT_MAJOR` (still `"1"` in both repos) are all
untouched. That the major stayed `"1"` is itself the proof the bump is additive.
