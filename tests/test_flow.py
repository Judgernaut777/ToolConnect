"""Toolset flow analysis: the set-level property no single-call check can see."""

from __future__ import annotations

from toolconnect.descriptor import (
    AssertedDescriptor, ClaimedMetadata, DataClass, Effect, ToolRef, ToolVersion,
)
from toolconnect.flow import analyze_toolset

SEC, CRED, PII, INT, EXT = (
    DataClass.SECRET, DataClass.CREDENTIAL, DataClass.PII,
    DataClass.INTERNAL, DataClass.EXTERNAL,
)


def tool(name, reads=frozenset(), writes=frozenset(), declassifies=False, asserted=True):
    d = (
        AssertedDescriptor(
            effect=Effect.READ, reads=frozenset(reads), writes=frozenset(writes),
            declassifies=declassifies, asserted_by="op",
        )
        if asserted else None
    )
    return ToolVersion(ToolRef(name), "s", ClaimedMetadata(), d)


class TestExfiltrationPath:
    def test_reader_alone_is_safe(self):
        assert not analyze_toolset([tool("read", reads={SEC})]).has_exfiltration_path

    def test_sink_alone_is_safe(self):
        assert not analyze_toolset([tool("post", writes={EXT})]).has_exfiltration_path

    def test_the_pair_is_the_hazard(self):
        """Neither tool is individually dangerous. Together they exfiltrate."""
        r = analyze_toolset([tool("read", reads={SEC}), tool("post", writes={EXT})])
        assert r.has_exfiltration_path
        assert r.findings[0].source_class is SEC
        assert r.pairwise_paths == (("read", "post"),)

    def test_internal_reads_do_not_trip_it(self):
        r = analyze_toolset([tool("read", reads={INT}), tool("post", writes={EXT})])
        assert not r.has_exfiltration_path

    def test_all_three_sensitive_classes_are_tracked(self):
        r = analyze_toolset([
            tool("s", reads={SEC}), tool("c", reads={CRED}), tool("p", reads={PII}),
            tool("post", writes={EXT}),
        ])
        assert {f.source_class for f in r.findings} == {SEC, CRED, PII}

    def test_a_tool_can_be_both_reader_and_sink(self):
        """`fetch` reads the web and exfiltrates via the URL. One tool, whole path."""
        r = analyze_toolset([tool("read", reads={SEC}), tool("fetch", reads={EXT}, writes={EXT})])
        assert r.has_exfiltration_path


class TestSuppression:
    def test_declassification_breaks_the_path(self):
        r = analyze_toolset([
            tool("redact", reads={SEC}, declassifies=True), tool("post", writes={EXT}),
        ])
        assert not r.has_exfiltration_path

    def test_accepting_a_class_pair_suppresses_only_that_pair(self):
        tools = [tool("s", reads={SEC}), tool("c", reads={CRED}), tool("post", writes={EXT})]
        r = analyze_toolset(tools, accepted=frozenset({(SEC, EXT)}))
        assert {f.source_class for f in r.findings} == {CRED}


class TestReportingShape:
    def test_findings_collapse_the_pairwise_blowup(self):
        """3 readers x 4 sinks = 12 paths, but one decision for an operator to make."""
        tools = [tool(f"r{i}", reads={SEC}) for i in range(3)]
        tools += [tool(f"w{i}", writes={EXT}) for i in range(4)]
        r = analyze_toolset(tools)
        assert len(r.findings) == 1
        assert len(r.pairwise_paths) == 12
        assert r.findings[0].path_count == 12
        assert r.collapse_ratio == 12.0

    def test_no_findings_means_zero_collapse_ratio_not_a_crash(self):
        assert analyze_toolset([]).collapse_ratio == 0.0


class TestUnlabeled:
    def test_unasserted_tools_are_reported_not_silently_skipped(self):
        """An empty finding list on an unlabeled catalog is silence, not safety."""
        r = analyze_toolset([tool("mystery", asserted=False), tool("post", writes={EXT})])
        assert r.unlabeled == ("mystery",)
        assert not r.has_exfiltration_path  # and that is precisely the danger
