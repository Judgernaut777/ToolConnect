# Organization-aware setup — the Capability plane's part

**How ToolConnect participates when Connect is set up for an organization instead of a single
person.** The organizational model itself — onboarding profiles, import/attach/transfer/federate,
resource ownership — is a Connect management-plane concern, defined in
[Connect's `docs/ORGANIZATION_MODEL.md`](https://github.com/Judgernaut777/Connect/blob/main/docs/ORGANIZATION_MODEL.md).
This document says only what the **Capability plane** owns inside that model.

> **Status: design direction, not shipped.** ToolConnect `0.1.0` has the decision core this model
> needs — a policy engine, an untrusted-assertion registry, and fail-closed authorization — but it
> has **no organization object, no per-org catalog scoping, and no onboarding flow.** Read this as the
> direction the Capability plane converges on, not current runtime; [docs/STATUS.md](docs/STATUS.md)
> and [docs/SERVICE.md](docs/SERVICE.md) are the authority on what ships today.

## What the Capability plane configures during org-aware setup

An organization's *approved and prohibited tools and models* map directly onto surfaces ToolConnect
already has — policy and the registry — rather than a new mechanism:

- **Approved / prohibited tools and models** — expressed as policy, evaluated by the existing policy
  engine. An organization's baseline may forbid a class of tools; a department may narrow further; a
  team may hold an explicitly allowed override. This is the management-plane policy gradient (company →
  department → team → workspace) landing on the Capability plane as **policy bindings scoped to org
  units**.
- **Restricted marketplace catalogs** — an organization publishes a filtered catalog of what its
  principals may even see. Restriction is policy over the registry; it does not change the rule that
  capability metadata is an **untrusted assertion**, never a server's self-claim.
- **Internal and external tool registries** — a large organization may run several. Each registers
  tools the same way; org-aware setup decides which registry a given department draws from.

Two invariants hold at every organizational scale and constrain how the above behaves:

- **Authorization fails closed.** A larger org, more policies, or a missing binding never degrades to
  permissive. An empty policy set denies everything, at one user or ten thousand.
- **ToolConnect decides *whether*, and does not carry the call.** There is no `invoke()`. Org-aware
  setup governs which principal may call which tool; the caller still performs the call and closes the
  loop via the outcome route. Adding organizational structure never puts ToolConnect in the data path.

## Ownership and migration

A tool registry gains an **owner** (individual, team, department, organization, shared group) under
the org model. One management-plane rule is load-bearing here:

- **Tool assertions are preserved on import or federation.** When a department that already ran
  ToolConnect is imported or federated, the operator assertions that made its tools invocable — and
  its authorization/audit chain — carry over. The parent applies broader policy on top; it does not
  reset the registry, because doing so would silently make previously governed tools either unusable
  or, worse, ungoverned.
- **Post-migration drift still revokes invocability.** The property that a changed descriptor revokes
  invocability until re-asserted is not weakened by organizational scale; if a migration changes a
  tool's descriptor, it must be re-asserted under the new owner.

## Boundary

ToolConnect is a **policy and decision point, not a tool-execution proxy**, at organizational scale
too. Org-aware setup enriches *who may call what, under whose policy*; it never turns the Capability
plane into a gateway that calls tools on a principal's behalf. The audit chain stays verifiable and
the decision stays out of the data path.

## See also

- [Connect · `docs/ORGANIZATION_MODEL.md`](https://github.com/Judgernaut777/Connect/blob/main/docs/ORGANIZATION_MODEL.md)
  — the full onboarding model this plane plugs into.
- [docs/SERVICE.md](docs/SERVICE.md) · [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — the decision
  service, the registry, and the trust model org-scale policy builds on.
- [docs/STATUS.md](docs/STATUS.md) — what the Capability plane actually ships today.
