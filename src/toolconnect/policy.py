"""Policy decision point. Cedar behind an adapter, per "contracts, not engines".

Note what is absent from this module: `invoke`. The PDP authorizes and explains. The
caller enforces and executes.

Fail-closed is structural here, not a configuration flag. Every path that does not
produce an explicit `permit` produces a `Denial`, including engine errors and missing
descriptors. There is no code path that returns an allow on failure.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from .catalog import Catalog
from .descriptor import DataClass, Effect, ToolVersion


@dataclass(frozen=True)
class Principal:
    id: str
    privacy_tier: str = "local"
    kind: str = "agent"
    #: Delegation chain. Authority is the INTERSECTION of the chain, never the union.
    on_behalf_of: "Principal | None" = None

    def effective_tier(self) -> str:
        """The least-privileged tier in the delegation chain."""
        order = {"local": 0, "trusted-cloud": 1, "rented": 2}
        worst, node = self.privacy_tier, self.on_behalf_of
        while node is not None:
            if order.get(node.privacy_tier, 99) > order.get(worst, 99):
                worst = node.privacy_tier
            node = node.on_behalf_of
        return worst


@dataclass(frozen=True)
class Decision:
    """Allow or deny, always with a reason.

    `determining_policies` is empty on a *default* deny — no policy matched at all.
    That is a materially different event from an explicit `forbid`, and conflating the
    two makes a policy bug indistinguishable from a policy decision.
    """

    allowed: bool
    reason: str
    determining_policies: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()

    @property
    def is_default_deny(self) -> bool:
        return not self.allowed and not self.determining_policies and not self.errors


@runtime_checkable
class PolicyEngine(Protocol):
    def decide(self, principal: Principal, tool: ToolVersion, context: dict) -> Decision: ...


class CedarPolicyEngine:
    """Cedar via `cedarpy`. In-process, no network, no sidecar.

    Verified on aarch64 / CPython 3.11 with a prebuilt wheel (cedarpy 4.8.6).
    """

    def __init__(self, policies: str) -> None:
        import cedarpy  # imported lazily so the rest of the library needs no engine

        self._cedar = cedarpy
        # Parse once, reuse the handle. A policy set that does not parse must never
        # silently permit anything, so this raises rather than degrading to allow-all.
        #
        # Parse-checking is not type-checking. `validate_policies()` additionally
        # type-checks entity attributes against a Cedar schema and would catch, e.g.,
        # `resource.efect` misspelled. That needs a Cedar schema for the Agent/Tool
        # entity types, which Phase 2 should write. See PHASE1_VALIDATION.md.
        try:
            self._policies = cedarpy.PolicySet.from_str(policies)
        except Exception as exc:
            raise ValueError(f"invalid Cedar policy set: {exc}") from exc

    def _entities(self, principal: Principal, tool: ToolVersion) -> list[dict]:
        d = tool.asserted
        assert d is not None  # guarded by decide()
        return [
            {
                "uid": {"type": "Agent", "id": principal.id},
                "attrs": {
                    "privacy_tier": principal.effective_tier(),
                    "kind": principal.kind,
                    "delegated": principal.on_behalf_of is not None,
                },
                "parents": [],
            },
            {
                "uid": {"type": "Tool", "id": tool.ref.name},
                "attrs": {
                    "effect": d.effect.value,
                    "reversible": d.reversible,
                    "idempotent": d.idempotent,
                    "requires_approval": d.requires_approval,
                    "reads_sensitive": d.reads_sensitive,
                    "external_sink": d.is_external_sink,
                },
                "parents": [],
            },
        ]

    def decide(self, principal: Principal, tool: ToolVersion, context: dict) -> Decision:
        # Fail closed on an unasserted tool. A server's claim is not an authorization.
        if tool.asserted is None:
            return Decision(
                allowed=False,
                reason=f"{tool.ref.name} has no operator-asserted descriptor",
                determining_policies=("<unasserted>",),
            )

        request = {
            "principal": {"type": "Agent", "id": principal.id},
            "action": {"type": "Action", "id": "invoke"},
            "resource": {"type": "Tool", "id": tool.ref.name},
            "context": context,
        }
        try:
            res = self._cedar.is_authorized(request, self._policies, self._entities(principal, tool))
        except Exception as exc:  # engine failure is a denial, never an allow
            return Decision(False, f"policy engine error: {exc}", errors=(str(exc),))

        reasons = tuple(res.diagnostics.reasons or ())
        annots = res.diagnostics.id_annotations_by_reason or {}
        named = tuple(annots.get(r, r) for r in reasons)
        errors = tuple(str(e) for e in (res.diagnostics.errors or ()))

        if res.decision is self._cedar.Decision.Allow:
            return Decision(True, f"permitted by {', '.join(named)}", named, errors)
        if named:
            return Decision(False, f"forbidden by {', '.join(named)}", named, errors)
        if errors:
            return Decision(False, f"policy evaluation errored: {'; '.join(errors)}", (), errors)
        return Decision(False, "default deny: no policy matched", (), ())


@dataclass
class Broker:
    """Admission control. Note the absence of `invoke()` — by design.

    `authorize()` returns a decision. The caller performs the invocation itself and
    calls `record()` with the outcome. ToolConnect is never in the data path.
    """

    catalog: Catalog
    engine: PolicyEngine
    audit: list[dict]

    def authorize(self, principal: Principal, name: str, context: dict | None = None) -> Decision:
        tool = self.catalog.tools.get(name)
        if tool is None:
            d = Decision(False, f"unknown tool {name!r}", ("<unregistered>",))
        elif not self.catalog.invocable(name):
            tier = self.catalog.sources[tool.source_id].tier.value
            d = Decision(False, f"{name} not invocable (source tier={tier}, asserted={tool.is_asserted})",
                         ("<not-invocable>",))
        else:
            d = self.engine.decide(principal, tool, context or {})

        # A denial is a decision, not an error. Both are recorded identically.
        self.audit.append(
            {
                "principal": principal.id,
                "tool": name,
                "allowed": d.allowed,
                "reason": d.reason,
                "determining_policies": list(d.determining_policies),
                "default_deny": d.is_default_deny,
            }
        )
        return d
