# The Capability plane

**ToolConnect is the Capability plane of the [Connect ecosystem](https://github.com/Judgernaut777/Connect):
tool identity, trusted tool metadata, assertions, authorization, bounded discovery, grants,
capability policy, outcome evidence, and tool audit.**

This document confirms and consolidates the Capability plane's ecosystem responsibilities, and
draws the four distinctions that keep "governance" from collapsing into "proxy." Each point
below is already implemented or specified; citations are inline.

> **Status: shipped MVP service, with marketplace/verification parts marked design direction.**
> ToolConnect `0.1.0` ships the decision core, argument-bound grants, the SQLite audit chain,
> the loopback HTTP service, and the optional enforcement gateway. Marketplace tool
> verification and per-organization catalog scoping are design direction — see
> [ORGANIZATION_AWARE_SETUP.md](ORGANIZATION_AWARE_SETUP.md) and
> [Connect MARKETPLACE_ARCHITECTURE.md](https://github.com/Judgernaut777/Connect/blob/main/MARKETPLACE_ARCHITECTURE.md).

---

## The four distinctions

The single most important property of this plane is that four things a careless design would
merge are kept separate:

| Concept | What it is | Where it lives |
|---|---|---|
| **Policy decision** | *May* this principal call this tool, with these exact arguments? A structured `allow` / `deny` / `allow_with_constraints`, with reasons. A default `deny` is **not** a `forbid`. | The decision core (PDP) — never on the wire ([ARCHITECTURE.md](ARCHITECTURE.md)) |
| **Enforcement** | Actually stopping or permitting the call at the boundary. | A thin, optional, replaceable **PEP** — the caller's SDK `governed_invoke`, or the `toolconnect gateway` ([ADR 0003](adr/0003-mcp-enforcement-gateway.md)) |
| **Reported outcome** | What the caller *says* happened, self-attested after the fact via `record_outcome`. | The SDK/caller path ([SERVICE.md](SERVICE.md), [AGENTCONNECT_CONTRACT.md](AGENTCONNECT_CONTRACT.md)) |
| **Observed outcome** | What the enforcement gateway *directly observed* from the real downstream result (`executed` vs `error`). | The gateway path |

A decision is not enforcement; enforcement is not a claim that the call happened; a *reported*
outcome (self-attested) is weaker evidence than an *observed* one (seen by the gateway). An
operator can therefore find a call that was authorized but never actually happened, or happened
without being reported — because the plane never conflates the four.

## Final-argument authorization

Authorization binds the **exact final arguments** the caller is about to execute, not just the
tool name. `POST /authorize` may issue a one-use grant bound to a canonical-JSON `args_hash`;
`POST /grants/{id}/redeem` atomically consumes it, and a second redeem, an argument mismatch,
expiry, a principal mismatch, or the tool becoming non-invocable since issue all **deny**. This
moves authorization from worker-dispatch time to the final invocation boundary, where a
`write_file` path or a `shell` command actually matters ([ADR 0002](adr/0002-argument-bound-grants.md)).

## Short-lived, one-use grants

Grants are one-use and time-bounded (TTL clamped to `[1, 300]`s, default `60`). Grant status is
computed from timestamp latches, never a stored flag. A leaked `grant_id` is not a bearer
capability: it is bound to the principal and is not redeemable by a different one.

## Authenticated principals

A `Principal` carries kind, id, harness, model, privacy tier, sandbox, on-behalf-of, and task
reference. Delegation authority is the **intersection** of the chain, never the union — a
confused-deputy defense. Today the principal's trust tier is operator-assigned and the principal
is not yet cryptographically attested; signed-descriptor attestation is a named open item, not a
shipped guarantee ([ARCHITECTURE.md](ARCHITECTURE.md)).

## Bounded discovery and trusted tool metadata

A tool's self-description is a **claim, not a promise.** The registry — not the tool server — is
the authority. Capability metadata is treated as an **untrusted assertion**, which is exactly the
property that lets a non-MCP source plug in later (the "protocol-neutral" claim, still only
partially proven since ingested tools so far were MCP-shaped).

## Metadata-only events — no raw payloads centrally

The optional event publisher emits **metadata only**: principal id, source id, tool qualified
name, decision id, grant id, `args_hash` (**never the arguments it was hashed from**), reason,
and determining policies. Raw tool arguments, prompts, model output, and secrets never reach the
publisher, because the decision core has **no `invoke()`**, is never on the data path, and never
computes or stores them. The publisher is **off unless explicitly configured** with both a bus
URL and token. This satisfies the ecosystem prohibition on central transmission of raw tool
payloads by default ([Connect DATA_AND_COMPLIANCE_BOUNDARIES.md](https://github.com/Judgernaut777/Connect/blob/main/DATA_AND_COMPLIANCE_BOUNDARIES.md)).

## Zero-trust setup and organization scope

Authorization fails closed at any scale — an empty policy set denies everything, at one user or
ten thousand. Organizations express approved and prohibited tools and models as **policy bindings
scoped to org units** and may publish restricted marketplace catalogs; restriction is policy over
the registry and does not change the rule that capability metadata is an untrusted assertion. A
setup agent operates under the same fail-closed discipline — it may propose tool policy, but
approval is human and scoped ([ORGANIZATION_AWARE_SETUP.md](ORGANIZATION_AWARE_SETUP.md)).

## Marketplace tool verification and compliance metadata (design direction)

Marketplace tool verification — evaluating a tool's compatibility, security properties,
capability claims, and permissions — is an ecosystem concern that reuses this plane's
untrusted-assertion registry and trust tiers. Verification buys an evaluation, never a favorable
outcome or ranking; compliance-related tool metadata is exposed as searchable fields, not a vague
badge. The verification *process* and per-organization catalogs are design direction; see
[Connect MARKETPLACE_ARCHITECTURE.md](https://github.com/Judgernaut777/Connect/blob/main/MARKETPLACE_ARCHITECTURE.md).

## See also

- [ARCHITECTURE.md](ARCHITECTURE.md) — object model, trust tiers, principal model, PDP/PEP.
- [SERVICE.md](SERVICE.md) — the HTTP/CLI surface, grant lifecycle, canonical hashing.
- [AGENTCONNECT_CONTRACT.md](AGENTCONNECT_CONTRACT.md) — the adopted governor seam.
- [STATUS.md](STATUS.md) — what is actually true today.
- [Connect PRODUCT_THESIS.md](https://github.com/Judgernaut777/Connect/blob/main/PRODUCT_THESIS.md) — where the Capability plane sits.
