"""Capability descriptors — the artifact that no standard provides.

The load-bearing distinction in this module is `claimed_*` versus `asserted_*`.

MCP requires clients to treat tool annotations as untrusted unless they come from a
trusted server. So what a tool server says about itself is *evidence*, recorded and
diffed, but never an authorization input. Only an operator-asserted descriptor is.

Nothing here invokes anything. There is no transport, no client, no `invoke()`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Mapping


class DataClass(str, Enum):
    """Classification of data a tool reads or writes.

    Ordered by sensitivity for reads; `EXTERNAL` is a *sink* class, meaningful only
    on the write side (it means "leaves the trust boundary").
    """

    PUBLIC = "public"
    INTERNAL = "internal"
    PII = "pii"
    SECRET = "secret"
    CREDENTIAL = "credential"
    EXTERNAL = "external"

    @property
    def is_sensitive(self) -> bool:
        return self in (DataClass.PII, DataClass.SECRET, DataClass.CREDENTIAL)


class Effect(str, Enum):
    """Primary policy axis. Crosswalks to MCP's annotation hints."""

    READ = "read"
    WRITE = "write"
    DESTRUCTIVE = "destructive"
    EXTERNAL = "external"


class TrustTier(str, Enum):
    VERIFIED = "verified"
    KNOWN = "known"
    UNTRUSTED = "untrusted"
    QUARANTINED = "quarantined"

    @property
    def invocable(self) -> bool:
        return self in (TrustTier.VERIFIED, TrustTier.KNOWN)


@dataclass(frozen=True)
class ToolRef:
    """A tool is identified by name *and version*. Approval binds to the version."""

    name: str
    version: str = "0.0.0"

    def __str__(self) -> str:  # pragma: no cover - trivial
        return f"{self.name}@{self.version}"


@dataclass(frozen=True)
class ClaimedMetadata:
    """What the tool server said about itself. Recorded. Diffed. Never trusted.

    Field names mirror MCP's `ToolAnnotations` so the crosswalk is legible.
    """

    description: str = ""
    read_only_hint: bool | None = None
    destructive_hint: bool | None = None
    idempotent_hint: bool | None = None
    open_world_hint: bool | None = None

    def implied_effect(self) -> Effect | None:
        """Translate MCP hints to an effect, using MCP's own defaults.

        `destructiveHint` defaults to true and `openWorldHint` defaults to true, but
        both are only meaningful when `readOnlyHint` is false. Returns None when the
        server said nothing at all.
        """
        if self.read_only_hint is None and self.destructive_hint is None and self.open_world_hint is None:
            return None
        if self.read_only_hint:
            return Effect.READ
        if self.destructive_hint is not False:
            return Effect.DESTRUCTIVE
        if self.open_world_hint is not False:
            return Effect.EXTERNAL
        return Effect.WRITE


@dataclass(frozen=True)
class AssertedDescriptor:
    """Operator-reviewed governance metadata. The ONLY authorization input."""

    effect: Effect
    reads: frozenset[DataClass] = frozenset()
    writes: frozenset[DataClass] = frozenset()
    scopes: frozenset[str] = frozenset()
    reversible: bool = True
    idempotent: bool = False
    requires_approval: bool = False
    # A declassifying tool is asserted to strip/redact sensitive data from what it
    # returns. It breaks a flow path. Asserting this is a security claim by a human.
    declassifies: bool = False
    asserted_by: str = ""

    @property
    def reads_sensitive(self) -> bool:
        return any(c.is_sensitive for c in self.reads) and not self.declassifies

    @property
    def is_external_sink(self) -> bool:
        return DataClass.EXTERNAL in self.writes


@dataclass(frozen=True)
class ToolVersion:
    """A registry entry. `asserted` is None until an operator reviews it."""

    ref: ToolRef
    source_id: str
    claimed: ClaimedMetadata
    asserted: AssertedDescriptor | None = None
    input_schema: Mapping[str, object] = field(default_factory=dict)

    @property
    def is_asserted(self) -> bool:
        return self.asserted is not None

    def claim_conflicts(self) -> list[str]:
        """Where the server's self-description contradicts the operator's assertion.

        A non-empty result is not necessarily an attack. It is always a question:
        either the tool is mislabeled, or it is hostile, or the operator is wrong.
        """
        if self.asserted is None:
            return []
        out: list[str] = []
        implied = self.claimed.implied_effect()
        if implied is not None and implied is not self.asserted.effect:
            out.append(f"claimed effect {implied.value!r} != asserted {self.asserted.effect.value!r}")
        if self.claimed.read_only_hint and self.asserted.effect is not Effect.READ:
            out.append("claims readOnlyHint=true but asserted effect is not read")
        if self.claimed.idempotent_hint is True and not self.asserted.idempotent:
            out.append("claims idempotentHint=true but asserted idempotent=false")
        if self.claimed.open_world_hint is False and self.asserted.is_external_sink:
            out.append("claims openWorldHint=false but asserted to write external")
        return out


@dataclass(frozen=True)
class TrustedSource:
    """The unit of trust. A tool inherits its source's ceiling and may be pinned lower."""

    source_id: str
    tier: TrustTier = TrustTier.UNTRUSTED
    transport: str = "mcp"
