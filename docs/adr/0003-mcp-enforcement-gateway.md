# ADR 0003 — The MCP enforcement gateway (a PEP, not a change to the PDP)

Status: accepted (2026-07-27). Context: the ecosystem review asked for one audited
path — a component that actually stands between a client and a tool server, so that
an authorize/redeem decision cannot simply be skipped by a caller who forgets to make
it.

## 1. The doctrine this has to reconcile

ToolConnect's foundational rule, restated in every module docstring in this repo, is
that the decision service is a **Policy Decision Point (PDP)**: it authorizes and
records, and it is never in the invocation data path. There is no `invoke()`. Contract
1.1 (ADR 0002) went as far as a one-use, argument-bound grant precisely so that
*whoever does perform the call* has to have redeemed one immediately beforehand — but
it still assumed that whoever performs the call is a cooperating caller who chooses to
follow the authorize → redeem → execute sequence. Nothing stopped an uncooperative or
buggy caller from calling a tool directly and never asking at all.

A **gateway** closes that gap by becoming the thing the client's tool calls physically
pass through — a **Policy Enforcement Point (PEP)** sitting in front of one downstream
MCP server. This is new: it is the first component in this codebase that forwards a
call to a real tool server. Whether that violates "no invoke()" is the question this
ADR answers.

## 2. The ruling

**It does not**, for one load-bearing reason: the gateway does not *decide* anything
and it does not *implement* any tool. Every governance question — is this principal
allowed to call this tool, with these exact arguments, right now — is still answered
by calling `ToolConnectService.authorize()`/`redeem_grant()` in-process, completely
unmodified from what `serve` already does over HTTP. `toolconnect/gateway.py` has
exactly the same relationship to the decision core that `toolconnect/server.py` does:
neither one is the PDP, both call it.

What the gateway adds is mechanical, not decisional: it forwards the *exact* frozen
arguments it just had authorized and redeemed to a subprocess over stdio, and relays
the subprocess's answer back. That is proxying, not invocation — the gateway has no
tool implementations of its own, no knowledge of what any given tool *does*, and would
work identically in front of any downstream MCP server. The distinction that matters is
the one the whole codebase already draws between `claimed` and `asserted`: a server's
own behavior is never ToolConnect's to author. The gateway only ever forwards to a
server someone else wrote; ToolConnect writes zero tool logic before or after this ADR.

Consequently: **the gateway is optional and separable.** `toolconnect serve` needs no
gateway to be a complete, correct decision point — a caller can integrate directly
against `/authorize` + `/grants/{id}/redeem` (or the in-process `ToolConnectService`)
exactly as `governed_invoke` already does, and get the identical enforcement
guarantee. The gateway exists for the caller that *cannot* be trusted, or trivially
audited, to make that sequence of calls itself — an off-the-shelf MCP client, for
instance, that only knows how to speak MCP to a single configured server command. It
ships alongside ToolConnect as one more front end over the same service, the way
`server.py` (HTTP) and `client.py` (SDK) already are two front ends over the same
core; it is not a new layer the core depends on.

## 3. What "one audited path" means concretely

`toolconnect gateway --db ... --policies ... --principal-id ... --source-id ... --
<downstream command...>` speaks MCP to whatever spawned it, and for every
`tools/call`:

```
extract final (name, arguments)
  -> ToolConnectService.authorize(principal, source_id, name, args=arguments)
  -> on allow: redeem_grant(grant_id, principal, arguments)   [same object, no re-read]
  -> on redeemed: forward tools/call to the downstream subprocess
  -> record_outcome(decision_id, "executed" | "error", grant_id=...)
  -> return the downstream's result (or a refusal) to the client
```

Every step before the forward fails closed: a parse failure, a deny, a redeem denial,
or a malformed request refuses without ever writing a byte to the downstream process.
`tools/list` is intercepted rather than forwarded raw: the gateway performs its own
paginated listing against the downstream server and returns only the tools that are
currently asserted *and* invocable in this gateway's catalog — a tool that is merely
declared, or ingested but never asserted, or advertised by the server but never
registered at all, is invisible to the client, not merely refused if it later tries to
call it.

Every other MCP method is enumerated exactly once in `gateway.py` into one of three
buckets, not left as a residual "everything else forwards" default:

* **Passthrough** (`initialize`, `ping`, `notifications/initialized`) — forwarded
  verbatim. Each is provably side-effect-free protocol plumbing: a capability
  handshake, a liveness probe, and the handshake's completion notification. None of
  the three can smuggle a tool invocation, because none of them names a tool.
* **Governed** (`tools/list`, `tools/call`) — handled specially, per above.
* **Refused** (every other request method: `resources/*`, `prompts/*`,
  `completion/*`, `logging/*`, `sampling/*`, `roots/*`, and anything unrecognized) —
  never forwarded. The gateway has no basis to reason about what any other MCP
  capability class would do to the downstream server, so it does not guess.

Two protocol shapes get a dedicated ruling rather than falling through a generic
default:

* **JSON-RPC batch requests** (a top-level array) are refused whole. MCP's
  `2025-06-18` revision dropped batch support from the spec, and admitting one here
  would require proving no entry in the array smuggles a `tools/call` past the
  governed path before any entry could be safely processed — refuse rather than
  partially trust it.
* **Notifications outside the one passthrough** (e.g. `notifications/cancelled`) are
  silently dropped: JSON-RPC notifications carry no response to refuse them with, so
  silence is the fail-closed choice for anything not explicitly vetted.

## 4. Points settled along the way

| # | Question | Ruling | Why |
|---|---|---|---|
| G1 | In-process service, or the gateway talks to `serve` over HTTP | **In-process** | One process, no new network hop, and it is the same `ToolConnectService` object `serve` already wraps — reuse, not a second implementation. |
| G2 | Downstream transport deadline model | **Per-call, not per-process** | `mcp_source._StdioTransport` fixes one deadline for a whole bounded discovery run; a gateway connection lives for a whole client session (could be hours), so `_DownstreamLink.call()` takes its own fresh timeout every call instead. |
| G3 | A well-formed JSON-RPC error from the downstream server vs. a transport fault | **Different outcomes** | A downstream error reply means the call *reached* the server and it made an authoritative decision — relayed verbatim, outcome `"executed"`. A transport fault (crash, timeout, truncated stream, unparseable bytes) means it did not — outcome `"error"`, and the gateway synthesizes its own refusal rather than inventing a fake server answer. |
| G4 | What forwards the argument mapping | **The exact object `authorize`/`redeem_grant` were called with, read once** | `_handle_tools_call` builds one `frozen_args` dict and never reads `params["arguments"]` again after that line — argument tampering between authorization and execution is impossible by construction, not by discipline. |
| G5 | A gateway-internal bug mid-dispatch | **Caught, answered, session continues** | `_handle_line` wraps dispatch in `try/except Exception` and still emits a JSON-RPC error for any request with an id; `run()` wraps the whole per-line handler so one bad message can never crash the stdio session. |

## 5. What did not change

`ToolConnectService`, `SqliteStore`, the Cedar `Broker`, and every existing HTTP route
in `server.py` are untouched — the gateway is a new, optional consumer of the exact
same public service surface `serve` and the client SDK already use. There is still no
`invoke()` method anywhere in this repository; `_DownstreamLink.call()` is wire
mechanics (send a frame, wait for the matching one back), not a tool implementation.
