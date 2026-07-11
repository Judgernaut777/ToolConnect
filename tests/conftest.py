"""Shared fixtures, strategies, and test doubles for the verification suite.

Determinism: the hypothesis profile is derandomized and given a fixed seed, so a
failing property reproduces identically on the next run. The whole suite runs
offline — nothing here opens a socket, and the one engine that uses a native
extension (Cedar) evaluates in-process.
"""

from __future__ import annotations

import pytest
from hypothesis import HealthCheck, settings

from toolconnect.catalog import Catalog
from toolconnect.descriptor import (
    AssertedDescriptor, ClaimedMetadata, DataClass, Effect, ToolRef, ToolVersion,
    TrustedSource, TrustTier,
)
from toolconnect.policy import Decision, Principal

settings.register_profile(
    "verification",
    derandomize=True,                       # deterministic: same inputs every run
    max_examples=200,
    deadline=None,                          # a shared box is not a latency oracle
    # The engines under conformance are immutable and stateless, so reusing a
    # function-scoped parametrized fixture across examples is correct, not a hazard.
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture],
)
settings.load_profile("verification")


# --------------------------------------------------------------------------- builders

def make_tool(
    name: str = "t",
    *,
    source: str = "s",
    effect: Effect = Effect.READ,
    reads=frozenset(),
    writes=frozenset(),
    asserted: bool = True,
    declassifies: bool = False,
    claimed: ClaimedMetadata | None = None,
) -> ToolVersion:
    desc = (
        AssertedDescriptor(
            effect=effect, reads=frozenset(reads), writes=frozenset(writes),
            declassifies=declassifies, asserted_by="op",
        )
        if asserted else None
    )
    return ToolVersion(ToolRef(name), source, claimed or ClaimedMetadata(), desc)


@pytest.fixture
def catalog() -> Catalog:
    c = Catalog()
    c.register_source(TrustedSource("s", TrustTier.KNOWN), declares={"a", "b"})
    return c


# --------------------------------------------------------------------- reference engine

class ReferencePolicyEngine:
    """A second, independent PolicyEngine implementation.

    Its only purpose is to be a second point in the conformance suite: the shared
    behavioral contract must hold for *every* engine, not just Cedar. If a future
    engine fails open on an unasserted tool, the conformance suite catches it here
    without needing Cedar.

    Contract implemented: deny unless the tool is asserted and its effect is READ.
    Deliberately minimal — correctness of the contract, not richness of policy.
    """

    def decide(self, principal: Principal, tool: ToolVersion, context: dict) -> Decision:
        if tool.asserted is None:
            return Decision(False, "unasserted tool", ("<unasserted>",))
        if tool.asserted.effect is Effect.READ:
            return Decision(True, "reference: read permitted", ("ref-allow-read",))
        return Decision(False, "reference: non-read denied", ())


BASIC_CEDAR = """
@id("allow-read")
permit(principal, action == Action::"invoke", resource)
when { resource.effect == "read" };
"""
