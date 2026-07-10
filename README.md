# ToolConnect

**A tool-governance platform.** It connects agents and applications to tools, and it is the
authority on *which* tools exist, *what they do*, *who may call them*, *whether they are
healthy*, and *what happened when they were called*.

ToolConnect is **architecture and interfaces only**. There is no runtime, no server, and no
code in this repository yet. See [docs/STATUS.md](docs/STATUS.md) before proposing work.

---

## The one-sentence version

Every tool protocol in use today describes what a tool *is*. None of them decides whether a
given agent should be allowed to call it, tracks whether it still works, or leaves a record
that it was called. ToolConnect is that missing layer, and it is deliberately not a protocol.

## Why this exists

The Model Context Protocol is the de facto way agents reach tools, and it is explicit about
what it does not cover. Reading the current specification (revision `2025-11-25`):

* **No tool-level authorization.** MCP's authorization spec is transport-level OAuth 2.1. No
  protocol message answers "may this agent call this tool, with these arguments, right now."
  The spec's only guidance is that "there SHOULD always be a human in the loop."
* **No health.** There is a bare `ping` that returns `{}`. There is no readiness, no degraded
  state, no per-tool status.
* **No audit.** "Log tool usage for audit purposes" is a sentence of prose with no method,
  schema, or wire format attached.
* **No capability metadata.** A tool has a name, a description, JSON schemas, and four boolean
  hints. There is no risk tier, no cost, no data classification, no ownership.
* **No rate limiting.** "Servers MUST rate limit tool invocations" — with zero mechanism.
* **No federation.** Nothing in the core protocol lets one server discover or aggregate another.

And the load-bearing one, quoted from the specification itself:

> Clients **MUST** consider tool annotations to be untrusted unless they come from trusted servers.

A tool that says "I am read-only" is making a claim, not a promise. **A governance layer
therefore cannot derive authorization from what a tool says about itself.** ToolConnect's
registry — not the tool server — is the authority on what a tool is permitted to do. This single
constraint shapes most of the architecture.

## What ToolConnect owns

| | |
|---|---|
| **Tool registry** | The catalog. Tool identity, versioning, provenance, trust tier. |
| **Discovery** | Answering "what tools can *this* principal see?" — itself an authorization decision. |
| **Capability metadata** | Effect class, reversibility, idempotency, cost, latency, data classification. Asserted by the registry, never by the tool. |
| **Permissions** | The principal model: who is asking, on whose behalf, under what delegation. |
| **Policy** | The decision: allow, deny, or allow-with-constraints — with a machine-readable reason. |
| **Health** | Liveness, readiness, degradation, circuit state. Per tool, not just per server. |
| **Invocation brokerage** | Admission control and grant issuance. See the boundary note below. |
| **Audit** | A tamper-evident record of every decision, including the denials. |

## What ToolConnect does not own

| | Belongs to |
|---|---|
| Task management | AgentConnect |
| Memory | BrainConnect |
| Workflows and durable execution | AgentConnect (Temporal) |
| Model routing | AgentConnect / ComputeConnect |
| Secrets storage | The deployment's secret manager |

And three hard constraints on scope:

1. **No runtime implementation.** This repository is design work.
2. **No MCP replacement.** ToolConnect speaks MCP as a client and may expose an MCP server
   adapter. It does not compete with, fork, or extend the protocol.
3. **No tool execution engine.** ToolConnect never runs a tool.

### The brokerage boundary

"Owns invocation brokerage" and "is not a tool execution engine" only coexist under one reading,
and the architecture commits to it: **ToolConnect is a decision point, not a data path.**

It authorizes an invocation and records its outcome. It does not carry the request, does not
implement a transport, and does not sit between an agent and a tool server by default. A caller
asks for permission, receives a grant or a denial, performs the call itself using an ordinary
MCP or HTTP client, and reports back what happened.

In the vocabulary of XACML, ToolConnect is the **Policy Decision Point**, the **Policy
Administration Point**, and the **audit sink**. The **Policy Enforcement Point** lives in the
caller. This is what keeps "brokerage" from collapsing into "proxy."

## Where it sits

ToolConnect is a sibling of AgentConnect, BrainConnect, and ComputeConnect, and follows the same
discipline the AgentConnect specs established:

> **Define contracts, not engines.**

AgentConnect owns the ledger of work and does not own the memory engine or the inference engine.
ToolConnect owns the ledger of *tools* and does not own the tool servers, the policy language
runtime, or the transports. Each of them is replaceable behind an adapter.

## Documents

* **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** — the object model, the trust model, the
  interfaces, the reuse verdicts, and the open questions. Start here.
* **[docs/ROADMAP.md](docs/ROADMAP.md)** — phased plan, and what is deliberately deferred.
* **[docs/STATUS.md](docs/STATUS.md)** — what is actually true today. Read before trusting a spec.

## Honest positioning

Several actively maintained projects already occupy part of this space, and at least two are
good. If what you need is an in-path MCP proxy with a registry and plugin policy, use
[IBM ContextForge](https://github.com/IBM/mcp-context-forge) (Apache-2.0). If you need
tool-level RBAC and audit at the network edge, use
[agentgateway](https://github.com/agentgateway/agentgateway) (Apache-2.0, Linux Foundation).

ToolConnect is not a better version of those. It is a different shape: a protocol-neutral,
local-first governance *library and ledger* that its siblings call in-process, with no sidecar
and no network hop in the decision path — and which can delegate the in-path proxy role to
exactly those projects as a deployment adapter. The reasoning is in
[ARCHITECTURE.md](docs/ARCHITECTURE.md#why-not-just-use-contextforge-or-agentgateway), including
the conditions under which building this is the wrong call.
