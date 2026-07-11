"""Property-based tests for toolset flow analysis.

The claim under test: exfiltration is a property of a *set*. These properties must
hold for any random toolset — a reader alone is safe, a sink alone is safe, adding
tools never removes a capability, and every reported path is real.
"""

from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from toolconnect.descriptor import DataClass
from toolconnect.flow import analyze_toolset

from conftest import make_tool

CLASSES = list(DataClass)
TRACKED = (DataClass.SECRET, DataClass.CREDENTIAL, DataClass.PII)

# A tool is a (name, reads, writes, declassifies) tuple turned into a ToolVersion.
tool_strat = st.builds(
    lambda i, reads, writes, dc: make_tool(
        f"t{i}", reads=frozenset(reads), writes=frozenset(writes), declassifies=dc
    ),
    st.integers(0, 30),
    st.sets(st.sampled_from(CLASSES), max_size=3),
    st.sets(st.sampled_from(CLASSES), max_size=3),
    st.booleans(),
)
# Names are unique within a toolset: a real toolset comes from the catalog, which
# keys tools by name, so a set of tools never contains two entries of the same name.
# (Duplicate-name conflation across sources is Finding A, pinned in test_regression.)
toolsets = st.lists(tool_strat, max_size=12, unique_by=lambda t: t.ref.name)


class TestSoundness:
    @given(toolsets)
    def test_every_pairwise_path_connects_a_real_reader_and_sink(self, tools):
        r = analyze_toolset(tools)
        names = {t.ref.name for t in tools}
        for reader, sink in r.pairwise_paths:
            assert reader in names and sink in names

    @given(toolsets)
    def test_a_finding_requires_a_tracked_reader_and_an_external_sink(self, tools):
        r = analyze_toolset(tools)
        has_sink = any(
            t.asserted and DataClass.EXTERNAL in t.asserted.writes for t in tools
        )
        for f in r.findings:
            assert f.source_class in TRACKED
            assert has_sink
            assert f.readers and f.sinks

    @given(toolsets)
    def test_no_sink_means_no_finding(self, tools):
        no_sink = [
            t for t in tools
            if not (t.asserted and DataClass.EXTERNAL in t.asserted.writes)
        ]
        assert not analyze_toolset(no_sink).has_exfiltration_path


class TestAccounting:
    @given(toolsets)
    def test_pairwise_count_equals_sum_of_finding_path_counts(self, tools):
        r = analyze_toolset(tools)
        assert len(r.pairwise_paths) == sum(f.path_count for f in r.findings)

    @given(toolsets)
    def test_collapse_ratio_is_paths_over_findings(self, tools):
        r = analyze_toolset(tools)
        if r.findings:
            assert r.collapse_ratio == len(r.pairwise_paths) / len(r.findings)
        else:
            assert r.collapse_ratio == 0.0

    @given(toolsets)
    def test_labeled_and_unlabeled_partition_the_toolset(self, tools):
        # In this suite every tool is asserted, so unlabeled is always empty; the
        # invariant is that unlabeled names are a subset of the input names.
        r = analyze_toolset(tools)
        assert set(r.unlabeled) <= {t.ref.name for t in tools}


class TestMonotonicityAndSuppression:
    @given(base=toolsets, extra=tool_strat)
    def test_adding_a_tool_never_removes_a_source_class(self, base, extra):
        """Capability is monotonic: a larger grant cannot exfiltrate *less*."""
        before = {f.source_class for f in analyze_toolset(base).findings}
        after = {f.source_class for f in analyze_toolset(base + [extra]).findings}
        assert before <= after

    @given(toolsets)
    def test_declassifying_reader_is_never_a_source(self, tools):
        r = analyze_toolset(tools)
        declassifiers = {t.ref.name for t in tools if t.asserted and t.asserted.declassifies}
        for f in r.findings:
            assert not (set(f.readers) & declassifiers)

    @given(toolsets, st.sets(st.sampled_from(TRACKED), max_size=3))
    def test_accepting_a_class_pair_removes_exactly_that_source_class(self, tools, accept):
        accepted = frozenset((c, DataClass.EXTERNAL) for c in accept)
        full = {f.source_class for f in analyze_toolset(tools).findings}
        suppressed = {f.source_class for f in analyze_toolset(tools, accepted=accepted).findings}
        assert suppressed == full - accept
