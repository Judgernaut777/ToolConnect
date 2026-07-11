"""In-memory catalog and drift detection.

No database, no daemon, no HTTP, no invocation. The catalog answers three questions:
what is declared, what is actually there, and what has an operator vouched for.

Two contracts are load-bearing here:

* **Namespaced identity.** A tool is identified by ``(source_id, name)``, never by
  bare name. Two sources may each expose a tool called ``search``; they are distinct
  and one can never overwrite or shadow the other. Bare-name lookup exists only as a
  convenience and refuses to guess when a name is ambiguous.

* **Assertion evidence survives re-ingestion.** An assertion records the *claim
  fingerprint* an operator vouched for. Re-ingesting a tool with an identical claim
  leaves the assertion standing; re-ingesting a *changed* claim drops invocability but
  retains the evidence that a previously-vouched tool changed — which drift reports
  distinctly from a tool that was never asserted at all.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Iterable

from .descriptor import (
    AssertedDescriptor,
    ClaimedMetadata,
    ToolRef,
    ToolVersion,
    TrustedSource,
)

#: Namespaced tool identity. Keyed by source so two sources cannot collide on name.
ToolId = tuple[str, str]


class AmbiguousToolName(KeyError):
    """Raised when a bare name resolves to more than one namespaced tool.

    Never silently pick one — that is exactly the shadowing hazard namespacing exists
    to prevent (Finding A). The caller must qualify with a source_id.
    """


class AssertionStatus(str, Enum):
    """The three assertion states that must not collapse into one another."""

    NEVER = "never_asserted"           # no operator ever vouched for this tool
    ASSERTED = "asserted"              # vouched, and the current claim still matches
    CHANGED = "asserted_then_changed"  # vouched before, but the claim has since changed


@dataclass(frozen=True)
class AssertionRecord:
    """Durable evidence that an operator vouched for a tool at a specific claim.

    Retained across re-ingestion so the catalog can tell "never asserted" apart from
    "asserted, then the server changed the tool underneath us."
    """

    descriptor: AssertedDescriptor
    fingerprint: int  # the claim fingerprint that was vouched for

    @property
    def asserted_by(self) -> str:
        return self.descriptor.asserted_by


@dataclass(frozen=True)
class DriftReport:
    """The result of comparing declaration, discovery, and assertion."""

    source_id: str
    #: Documented or manifest-declared, but absent from the running server.
    advertised_missing: tuple[str, ...] = ()
    #: Present at runtime, but never declared. Shadow surface.
    undeclared_present: tuple[str, ...] = ()
    #: Discovered but NEVER operator-asserted. Not invocable — quarantined by default.
    unasserted: tuple[str, ...] = ()
    #: Asserted, but the server's self-description contradicts the assertion.
    claim_conflicts: tuple[tuple[str, str], ...] = ()
    #: Previously asserted, but the claim has since changed. A vouched tool moved.
    #: Distinct from `unasserted`: the operator DID vouch, and must re-assert.
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
    #: Keyed by namespaced identity (source_id, name) — never by bare name.
    tools: dict[ToolId, ToolVersion] = field(default_factory=dict)
    #: What each source *says* it offers, independent of what it serves.
    declared: dict[str, set[str]] = field(default_factory=dict)
    #: Durable assertion evidence, keyed by ToolId. Survives re-ingestion; updated
    #: only by assert_descriptor. This is what distinguishes never-asserted from
    #: asserted-then-changed.
    _assertions: dict[ToolId, AssertionRecord] = field(default_factory=dict)

    # -- registration -----------------------------------------------------------

    def register_source(self, source: TrustedSource, declares: set[str] | None = None) -> None:
        self.sources[source.source_id] = source
        self.declared[source.source_id] = set(declares or ())

    def ingest_claimed(
        self, source_id: str, name: str, claimed: ClaimedMetadata, version: str = "1.0.0"
    ) -> ToolVersion:
        """Record what a server said. This never *grants* invocability on its own.

        If the tool was previously asserted and the new claim fingerprint matches what
        was vouched for, the assertion stands (identical re-announcement is a no-op).
        If the claim changed, the assertion is dropped — the tool becomes non-invocable
        until re-asserted — but the evidence that it was once vouched for is retained.
        """
        if source_id not in self.sources:
            raise KeyError(f"unknown source {source_id!r}")
        tid: ToolId = (source_id, name)
        tv = ToolVersion(ref=ToolRef(name, version), source_id=source_id, claimed=claimed)

        record = self._assertions.get(tid)
        if record is not None and self._fingerprint(tv) == record.fingerprint:
            # Same claim the operator vouched for: the assertion carries over.
            tv = replace(tv, asserted=record.descriptor)
        # else: never asserted, or the claim changed -> tv stays unasserted (fail closed).

        self.tools[tid] = tv
        return tv

    def assert_descriptor(
        self, source_id: str, name: str, desc: AssertedDescriptor
    ) -> ToolVersion:
        """An operator vouches for what a specific tool actually does. Requires a human.

        Assertion is source-qualified: you vouch for one namespaced tool, never for
        "whatever currently answers to this name."
        """
        if not desc.asserted_by:
            raise ValueError("assert_descriptor requires asserted_by; promotion is human-only")
        tid: ToolId = (source_id, name)
        tv = self.tools[tid]  # KeyError if this exact tool was never ingested
        new = replace(tv, asserted=desc)
        self.tools[tid] = new
        self._assertions[tid] = AssertionRecord(descriptor=desc, fingerprint=self._fingerprint(new))
        return new

    @staticmethod
    def _fingerprint(tv: ToolVersion) -> int:
        """The claim a source is making. Changes when the server redefines the tool."""
        c = tv.claimed
        return hash((tv.ref.version, c.description, c.read_only_hint,
                     c.destructive_hint, c.idempotent_hint, c.open_world_hint))

    # -- resolution -------------------------------------------------------------

    def get(self, source_id: str, name: str) -> ToolVersion | None:
        """Primary lookup, by namespaced identity."""
        return self.tools.get((source_id, name))

    def find_all(self, name: str) -> list[ToolId]:
        """Every namespaced id exposing this bare name, across all sources."""
        return [tid for tid in self.tools if tid[1] == name]

    def resolve(self, name: str) -> ToolId:
        """Bare-name convenience. Returns the single id for a globally-unambiguous name.

        Raises AmbiguousToolName if more than one source exposes the name, and KeyError
        if none does. It never silently selects one — that is the shadowing bug.
        """
        matches = self.find_all(name)
        if not matches:
            raise KeyError(f"no tool named {name!r}")
        if len(matches) > 1:
            raise AmbiguousToolName(
                f"{name!r} is exposed by {len(matches)} sources: "
                f"{sorted(s for s, _ in matches)}; qualify with a source_id"
            )
        return matches[0]

    def assertion_status(self, source_id: str, name: str) -> AssertionStatus:
        tid: ToolId = (source_id, name)
        if tid not in self._assertions:
            return AssertionStatus.NEVER
        tv = self.tools.get(tid)
        if tv is not None and tv.is_asserted:
            return AssertionStatus.ASSERTED
        return AssertionStatus.CHANGED

    def invocable(self, source_id: str, name: str) -> bool:
        """Invocable only if currently asserted AND the source's tier permits it.

        A changed-since-assertion tool is not currently asserted (its claim no longer
        matches the vouched fingerprint), so it is not invocable until re-asserted.
        """
        tv = self.get(source_id, name)
        if tv is None or not tv.is_asserted:
            return False
        return self.sources[tv.source_id].tier.invocable

    def toolset(self, ids: Iterable[ToolId]) -> list[ToolVersion]:
        """Resolve namespaced ids to tool versions, sorted, skipping unknown ids."""
        want = set(ids)
        return [self.tools[tid] for tid in sorted(want) if tid in self.tools]

    def select(self, names: Iterable[str]) -> list[ToolVersion]:
        """Bare-name convenience selection. Resolves each name unambiguously.

        Raises AmbiguousToolName if any name is shadowed across sources. Use `toolset`
        with explicit ids when names may collide.
        """
        return self.toolset(self.resolve(n) for n in names)

    # -- drift ------------------------------------------------------------------

    def drift(self, source_id: str, discovered: set[str]) -> DriftReport:
        """Compare declaration, discovery, and assertion for one source.

        `discovered` is what a runtime `tools/list` returned for this source (bare
        names, which are unique within a single source). The catalog never calls the
        server itself; the caller supplies the observation.
        """
        declared = self.declared.get(source_id, set())
        mine = {name for (sid, name) in self.tools if sid == source_id}

        def status(name: str) -> AssertionStatus:
            return self.assertion_status(source_id, name)

        # NEVER-asserted, discovered tools. Excludes tools that were vouched then changed.
        unasserted = tuple(sorted(
            n for n in discovered if status(n) is AssertionStatus.NEVER
        ))
        # Previously asserted, claim since changed. The operator DID vouch; re-assert.
        redefined = tuple(sorted(
            n for n in discovered & mine if status(n) is AssertionStatus.CHANGED
        ))
        conflicts = tuple(
            (n, msg)
            for n in sorted(discovered & mine)
            for msg in self.tools[(source_id, n)].claim_conflicts()
        )
        return DriftReport(
            source_id=source_id,
            advertised_missing=tuple(sorted(declared - discovered)),
            undeclared_present=tuple(sorted(discovered - declared)),
            unasserted=unasserted,
            claim_conflicts=conflicts,
            redefined_after_assertion=redefined,
        )
