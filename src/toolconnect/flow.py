"""Toolset-level flow analysis — ToolConnect's distinctive claim, under test.

The claim: a principal granted a tool that reads `secret` and a tool that writes
`external` has been granted an exfiltration path, whether or not either tool is
individually dangerous. No single-invocation authorization check can see this,
because the property belongs to the *set*.

The agent is the data path. Data flows out of a reader into the agent's context and
from there into any sink the agent can reach. There is no need for the two tools to
share a scope, a session, or an argument — which is exactly why this is hard to
suppress and easy to over-report.

Two reporting shapes are implemented so they can be compared empirically:

  * `pairwise_paths` — every (reader, sink) combination. The obvious formulation.
  * `findings`       — one per (source class -> sink class). The collapsed formulation.

See `experiments/flow_experiment.py` and `docs/PHASE1_VALIDATION.md` for which one
survived contact with a real catalog.
"""

from __future__ import annotations

from dataclasses import dataclass
from itertools import product

from .descriptor import DataClass, ToolVersion


@dataclass(frozen=True)
class FlowFinding:
    """One disclosed capability of a toolset, not one alert.

    `source_class` can reach `sink_class` because the toolset contains at least one
    reader of the former and at least one writer to the latter.
    """

    source_class: DataClass
    sink_class: DataClass
    readers: tuple[str, ...]
    sinks: tuple[str, ...]

    @property
    def path_count(self) -> int:
        """How many pairwise paths this single finding subsumes."""
        return len(self.readers) * len(self.sinks)

    def describe(self) -> str:
        return (
            f"{self.source_class.value} -> {self.sink_class.value}: "
            f"{len(self.readers)} reader(s) x {len(self.sinks)} sink(s) "
            f"= {self.path_count} path(s)"
        )


@dataclass(frozen=True)
class FlowReport:
    findings: tuple[FlowFinding, ...]
    pairwise_paths: tuple[tuple[str, str], ...]
    unlabeled: tuple[str, ...]

    @property
    def has_exfiltration_path(self) -> bool:
        return bool(self.findings)

    @property
    def collapse_ratio(self) -> float:
        """Pairwise paths per finding. The noise-reduction factor."""
        return len(self.pairwise_paths) / len(self.findings) if self.findings else 0.0


#: Which read-classes are worth tracking to which sink-classes.
#: `EXTERNAL` is the only sink class that leaves the trust boundary.
_TRACKED_SOURCES = (DataClass.SECRET, DataClass.CREDENTIAL, DataClass.PII)


def analyze_toolset(
    tools: list[ToolVersion],
    accepted: frozenset[tuple[DataClass, DataClass]] = frozenset(),
) -> FlowReport:
    """Compute the flow capabilities a toolset confers on its holder.

    `accepted` is the operator's allowlist of (source, sink) pairs that are known and
    intended — a "publish the report to GitHub" agent legitimately moves `internal`
    data to `external`. Suppressing at the class level rather than the tool-pair level
    is what keeps the configuration burden bounded.

    Unasserted tools are *not* skipped. They are reported in `unlabeled` and treated
    as unknown, because an unlabeled tool is exactly where an unnoticed sink hides.
    """
    labeled = [t for t in tools if t.asserted is not None]
    unlabeled = tuple(sorted(t.ref.name for t in tools if t.asserted is None))

    sinks = [t for t in labeled if t.asserted.is_external_sink]

    findings: list[FlowFinding] = []
    paths: list[tuple[str, str]] = []

    for source_class in _TRACKED_SOURCES:
        if (source_class, DataClass.EXTERNAL) in accepted:
            continue
        readers = [
            t for t in labeled
            if source_class in t.asserted.reads and not t.asserted.declassifies
        ]
        if not readers or not sinks:
            continue
        reader_names = tuple(sorted(t.ref.name for t in readers))
        sink_names = tuple(sorted(t.ref.name for t in sinks))
        findings.append(
            FlowFinding(
                source_class=source_class,
                sink_class=DataClass.EXTERNAL,
                readers=reader_names,
                sinks=sink_names,
            )
        )
        paths.extend(product(reader_names, sink_names))

    return FlowReport(
        findings=tuple(findings),
        pairwise_paths=tuple(paths),
        unlabeled=unlabeled,
    )
