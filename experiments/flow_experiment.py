"""Measure whether toolset flow analysis is useful. Offline. No invocation.

Run:  .venv/bin/python experiments/flow_experiment.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path[:0] = [str(Path(__file__).resolve().parents[1] / p) for p in ("src", "fixtures")]

from real_catalog import (  # noqa: E402
    ARG_DEPENDENT, AMBIGUOUS, CODING_AGENT_TOOLSET, TOOLS, build_catalog,
)

from toolconnect.descriptor import AssertedDescriptor, DataClass  # noqa: E402
from toolconnect.flow import analyze_toolset  # noqa: E402


def rule(title: str) -> None:
    print(f"\n{title}\n{'-' * len(title)}")


def replace_reads(d: AssertedDescriptor, reads: frozenset, scope: str) -> AssertedDescriptor:
    """Re-assert a descriptor with a narrower read-class, under a narrower scope."""
    return AssertedDescriptor(
        effect=d.effect, reads=reads, writes=d.writes,
        scopes=frozenset({scope}), reversible=d.reversible, idempotent=d.idempotent,
        requires_approval=d.requires_approval, declassifies=d.declassifies,
        asserted_by="fixture-operator",
    )


def main() -> int:
    cat = build_catalog()
    print(f"catalog: {len(cat.tools)} tools across {len(cat.sources)} sources")

    # ---------------------------------------------------------------- full catalog
    rule("1. Full catalog (the worst case: an agent holding everything)")
    full = analyze_toolset(cat.toolset(set(cat.tools)))
    for f in full.findings:
        print(f"  {f.describe()}")
    print(f"  findings={len(full.findings)}  pairwise_paths={len(full.pairwise_paths)}")
    print(f"  collapse ratio: {full.collapse_ratio:.1f} pairwise paths per finding")

    # ------------------------------------------------------- realistic coding agent
    rule("2. Realistic grant (a coding agent on this box)")
    sub = analyze_toolset(cat.toolset(CODING_AGENT_TOOLSET))
    print(f"  toolset size: {len(CODING_AGENT_TOOLSET)}")
    for f in sub.findings:
        print(f"  {f.describe()}")
        print(f"      readers: {', '.join(f.readers)}")
        print(f"      sinks:   {', '.join(f.sinks)}")
    print(f"  findings={len(sub.findings)}  pairwise_paths={len(sub.pairwise_paths)}")
    print(f"  collapse ratio: {sub.collapse_ratio:.1f}")

    # -------------------------------------------------------------- suppression cost
    rule("3. Operator suppression is per CLASS-PAIR, not per tool-pair")
    # Suppose this deployment reviews artifacts before storage, so `secret` never
    # reaches them. The operator accepts secret->external as a known, intended flow.
    accepted = frozenset({(DataClass.SECRET, DataClass.EXTERNAL)})
    sup = analyze_toolset(cat.toolset(CODING_AGENT_TOOLSET), accepted=accepted)
    removed_f = len(sub.findings) - len(sup.findings)
    removed_p = len(sub.pairwise_paths) - len(sup.pairwise_paths)
    print(f"  accepting 1 class-pair removes {removed_f} finding ({removed_p} pairwise paths)")
    print(f"  remaining: {[f.source_class.value for f in sup.findings]}")
    print(f"  decisions an operator makes:  {len(sub.findings)} class-pairs")
    print(f"  decisions pairwise would ask: {len(sub.pairwise_paths)} tool-pairs")

    # ------------------------------------------- where the findings actually come from
    rule("3b. Are the findings trustworthy? Trace each to its label.")
    readers = sorted({r for f in sub.findings for r in f.readers})
    shaky = [r for r in readers if r in ARG_DEPENDENT or r in AMBIGUOUS]
    for r in readers:
        tags = []
        if r in ARG_DEPENDENT:
            tags.append("ARG_DEPENDENT")
        if r in AMBIGUOUS:
            tags.append("AMBIGUOUS")
        print(f"  {r:24} {'+'.join(tags) or 'solid'}")
    print(f"  -> {len(shaky)}/{len(readers)} sensitive readers rest on a worst-case guess.")
    print("  every finding above traces to a label a static descriptor cannot justify.")

    # ------------------------------------------------------- the minimal-cut question
    rule("4. What must be removed to break every path?")
    tools = cat.toolset(CODING_AGENT_TOOLSET)
    sinks = sorted({s for f in sub.findings for s in f.sinks})
    readers = sorted({r for f in sub.findings for r in f.readers})
    print(f"  drop all {len(sinks)} sinks, or all {len(readers)} sensitive readers")
    print(f"  sinks:   {', '.join(sinks)}")
    print(f"  readers: {', '.join(readers)}")
    without_sinks = analyze_toolset([t for t in tools if t.ref.name not in set(sinks)])
    print(f"  toolset minus sinks -> findings={len(without_sinks.findings)} "
          f"(agent can no longer push code, create PRs, or fetch)")

    # ----------------------------------------------------------- labeling burden
    rule("5. Labeling burden and expressiveness")
    n = len(TOOLS)
    print(f"  tools requiring a human assertion:  {n}/{n} (100%)")
    print(f"  labels a judgment call (AMBIGUOUS): {len(AMBIGUOUS)}/{n} = {100*len(AMBIGUOUS)/n:.0f}%")
    print(f"  class depends on ARGUMENTS not tool: {len(ARG_DEPENDENT)}/{n} = {100*len(ARG_DEPENDENT)/n:.0f}%")
    print(f"    -> {sorted(ARG_DEPENDENT)}")
    print("  a static descriptor CANNOT express the arg-dependent set.")

    # --------------------------------------------- does scoping fix arg-dependence?
    rule("6. Scope-narrowing: classify (tool, scope), not tool")
    # The same `read_file` is CREDENTIAL-reading when the filesystem server is rooted
    # at `/`, and merely INTERNAL when it is rooted at a project directory with no
    # secrets in it. The tool did not change. Its scope did.
    scoped = build_catalog()
    for name, reads in (
        ("read_file", {DataClass.INTERNAL}),          # server rooted at ~/project
        ("read_artifact_chunk", {DataClass.INTERNAL}),  # artifacts reviewed pre-storage
        ("get_task_context_pack", {DataClass.INTERNAL}),
    ):
        old = scoped.tools[name].asserted
        scoped.assert_descriptor(
            name,
            replace_reads(old, frozenset(reads), scope="project-root"),
        )
    after = analyze_toolset(scoped.toolset(CODING_AGENT_TOOLSET))
    print(f"  before scoping: {len(sub.findings)} findings, {len(sub.pairwise_paths)} paths")
    print(f"  after scoping:  {len(after.findings)} findings, {len(after.pairwise_paths)} paths")
    print("  the arg-dependence collapses once the SOURCE is scoped. The descriptor")
    print("  should bind to (tool, scope), which is a registry fact, not a guess.")

    # ------------------------------------------------------------- unlabeled = unknown
    rule("7. Unlabeled tools are not skipped")
    raw = build_catalog(assert_all=False)
    unl = analyze_toolset(raw.toolset(CODING_AGENT_TOOLSET))
    print(f"  with 0 assertions: findings={len(unl.findings)}, unlabeled={len(unl.unlabeled)}")
    print("  an unasserted catalog reports NO findings -- silence, not safety.")
    print("  this is why unasserted tools are quarantined rather than analyzed.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
