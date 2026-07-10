"""In-memory catalog and drift detection.

No database, no daemon, no HTTP, no invocation. The catalog answers three questions:
what is declared, what is actually there, and what has an operator vouched for.

Drift is the gap between those three sets. It is the cheapest useful thing this
platform does, and it is detectable without ever calling a tool.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .descriptor import (
    AssertedDescriptor,
    ClaimedMetadata,
    ToolRef,
    ToolVersion,
    TrustedSource,
    TrustTier,
)


@dataclass(frozen=True)
class DriftReport:
    """The result of comparing declaration, discovery, and assertion."""

    source_id: str
    #: Documented or manifest-declared, but absent from the running server.
    advertised_missing: tuple[str, ...] = ()
    #: Present at runtime, but never declared. Shadow surface.
    undeclared_present: tuple[str, ...] = ()
    #: Discovered but never operator-asserted. Not invocable — quarantined by default.
    unasserted: tuple[str, ...] = ()
    #: Asserted, but the server's self-description contradicts the assertion.
    claim_conflicts: tuple[tuple[str, str], ...] = ()
    #: The descriptor changed under a name that was already approved. Rug-pull.
    redefined_after_assertion: tuple[str, ...] = ()

    @property
    def clean(self) -> bool:
        return not (
            self.advertised_missing
            or self.undeclared_present
            or self.unasserted
            or self.claim_conflicts
            or self.redefined_after_assertion
        )

    def summary(self) -> str:
        if self.clean:
            return f"{self.source_id}: no drift"
        parts = []
        if self.advertised_missing:
            parts.append(f"{len(self.advertised_missing)} advertised-missing")
        if self.undeclared_present:
            parts.append(f"{len(self.undeclared_present)} undeclared-present")
        if self.unasserted:
            parts.append(f"{len(self.unasserted)} unasserted")
        if self.claim_conflicts:
            parts.append(f"{len(self.claim_conflicts)} claim-conflicts")
        if self.redefined_after_assertion:
            parts.append(f"{len(self.redefined_after_assertion)} redefined-after-assertion")
        return f"{self.source_id}: " + ", ".join(parts)


@dataclass
class Catalog:
    """An in-memory tool catalog. Single-writer, no persistence, no consensus."""

    sources: dict[str, TrustedSource] = field(default_factory=dict)
    tools: dict[str, ToolVersion] = field(default_factory=dict)
    #: What each source *says* it offers, independent of what it serves.
    declared: dict[str, set[str]] = field(default_factory=dict)
    #: Fingerprints captured at assertion time, to detect later redefinition.
    _assertion_fingerprints: dict[str, int] = field(default_factory=dict)

    # -- registration -----------------------------------------------------------

    def register_source(self, source: TrustedSource, declares: set[str] | None = None) -> None:
        self.sources[source.source_id] = source
        self.declared[source.source_id] = set(declares or ())

    def ingest_claimed(
        self, source_id: str, name: str, claimed: ClaimedMetadata, version: str = "1.0.0"
    ) -> ToolVersion:
        """Record what a server said. This never makes a tool invocable."""
        if source_id not in self.sources:
            raise KeyError(f"unknown source {source_id!r}")
        tv = ToolVersion(ref=ToolRef(name, version), source_id=source_id, claimed=claimed)
        self.tools[name] = tv
        return tv

    def assert_descriptor(self, name: str, desc: AssertedDescriptor) -> ToolVersion:
        """An operator vouches for what a tool actually does. Requires a human."""
        if not desc.asserted_by:
            raise ValueError("assert_descriptor requires asserted_by; promotion is human-only")
        tv = self.tools[name]
        new = ToolVersion(
            ref=tv.ref, source_id=tv.source_id, claimed=tv.claimed,
            asserted=desc, input_schema=tv.input_schema,
        )
        self.tools[name] = new
        self._assertion_fingerprints[name] = self._fingerprint(new)
        return new

    @staticmethod
    def _fingerprint(tv: ToolVersion) -> int:
        """What the server was claiming when we approved it."""
        c = tv.claimed
        return hash((tv.ref.version, c.description, c.read_only_hint,
                     c.destructive_hint, c.idempotent_hint, c.open_world_hint))

    # -- resolution -------------------------------------------------------------

    def invocable(self, name: str) -> bool:
        """A tool is invocable only if asserted AND its source's tier permits it."""
        tv = self.tools.get(name)
        if tv is None or not tv.is_asserted:
            return False
        return self.sources[tv.source_id].tier.invocable

    def toolset(self, names: set[str]) -> list[ToolVersion]:
        return [self.tools[n] for n in sorted(names) if n in self.tools]

    # -- drift ------------------------------------------------------------------

    def drift(self, source_id: str, discovered: set[str]) -> DriftReport:
        """Compare declaration, discovery, and assertion for one source.

        `discovered` is what a runtime `tools/list` returned. The catalog never
        calls the server itself; the caller supplies the observation.
        """
        declared = self.declared.get(source_id, set())
        mine = {n for n, tv in self.tools.items() if tv.source_id == source_id}

        asserted = {n for n in discovered if n in self.tools and self.tools[n].is_asserted}
        conflicts = tuple(
            (n, msg)
            for n in sorted(discovered & mine)
            for msg in self.tools[n].claim_conflicts()
        )
        redefined = tuple(
            n for n in sorted(discovered & mine)
            if n in self._assertion_fingerprints
            and self._fingerprint(self.tools[n]) != self._assertion_fingerprints[n]
        )
        return DriftReport(
            source_id=source_id,
            advertised_missing=tuple(sorted(declared - discovered)),
            undeclared_present=tuple(sorted(discovered - declared)),
            unasserted=tuple(sorted(discovered - asserted)),
            claim_conflicts=conflicts,
            redefined_after_assertion=redefined,
        )
