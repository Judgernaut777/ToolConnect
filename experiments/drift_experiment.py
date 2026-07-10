"""Catalog drift, measured against a real, unmodified repository.

AgentConnect's `BACKPLANE_SPEC.md` §17 names the manager-coordination primitives and
says managers read results "through MCP". Its MCP adapter registers 17 tools. Three of
the named primitives are not among them: they exist as `AgentConnectService` methods
but were never exposed through the adapter.

A manager that reads the spec and calls `claim_review` over MCP gets tool-not-found.
No tool was invoked to discover this. The catalog compared two lists.

Verified 2026-07-10 against /home/mini/mcp-agentconnect @ origin/main. Nothing in that
repository was modified.

Run:  .venv/bin/python experiments/drift_experiment.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path[:0] = [str(Path(__file__).resolve().parents[1] / p) for p in ("src", "fixtures")]

from toolconnect.catalog import Catalog  # noqa: E402
from toolconnect.descriptor import (  # noqa: E402
    AssertedDescriptor, ClaimedMetadata, DataClass, Effect, TrustedSource, TrustTier,
)

#: BACKPLANE_SPEC.md §17 "Manager coordination model" — the declared primitives.
DECLARED_BY_SPEC = {
    "claim_task", "release_task", "request_review", "claim_review", "complete_review",
    "record_decision", "record_attempt", "get_manager_inbox", "get_handoff_summary",
}

#: The tools `packages/agentconnect-mcp/src/agentconnect/mcp/server.py` actually
#: registers with `@mcp.tool()`. Seventeen of them.
DISCOVERED_AT_RUNTIME = {
    "create_task", "open_task", "get_handoff_summary", "claim_task", "release_task",
    "record_decision", "record_attempt", "request_review", "submit_subtask",
    "get_status", "list_artifacts", "read_artifact_chunk", "explain_route",
    "recall_memory", "capture_memory_candidate", "record_memory_feedback",
    "get_task_context_pack",
}


def main() -> int:
    cat = Catalog()
    cat.register_source(
        TrustedSource("agentconnect", TrustTier.VERIFIED, transport="mcp"),
        declares=DECLARED_BY_SPEC,
    )

    # Ingest only what the running server actually offers.
    for name in sorted(DISCOVERED_AT_RUNTIME):
        cat.ingest_claimed("agentconnect", name, ClaimedMetadata(read_only_hint=True))

    # The operator has reviewed most of them, but not the two newest.
    unreviewed = {"get_task_context_pack", "record_memory_feedback"}
    for name in sorted(DISCOVERED_AT_RUNTIME - unreviewed):
        cat.assert_descriptor(
            name,
            AssertedDescriptor(
                effect=Effect.READ, reads=frozenset({DataClass.INTERNAL}),
                asserted_by="operator",
            ),
        )

    report = cat.drift("agentconnect", DISCOVERED_AT_RUNTIME)

    print("Drift: AgentConnect MCP adapter vs BACKPLANE_SPEC.md §17\n")
    print(f"  declared by spec:      {len(DECLARED_BY_SPEC)}")
    print(f"  discovered at runtime: {len(DISCOVERED_AT_RUNTIME)}")
    print(f"\n  {report.summary()}\n")

    print("  ADVERTISED, MISSING AT RUNTIME (a manager calling these gets tool-not-found):")
    for n in report.advertised_missing:
        print(f"    - {n}")
    print("\n  PRESENT BUT UNDECLARED (11) -- MOSTLY A FALSE POSITIVE:")
    print("    §17 lists coordination primitives, not the adapter's full surface.")
    print("    Prose is not a manifest. Drift detection needs a declared artifact")
    print("    (server.json, an OpenAPI doc) to diff against, or it invents findings.")
    for n in report.undeclared_present:
        print(f"    - {n}")
    print("\n  DISCOVERED BUT UNASSERTED (quarantined; not invocable):")
    for n in report.unasserted:
        print(f"    - {n}")

    print("\n  Consequence: BACKPLANE_SPEC §17 describes a review loop")
    print("  (request_review -> inbox -> claim_review -> complete_review) that")
    print("  cannot be completed over MCP. `request_review` exists; the three")
    print("  tools needed to finish the loop do not. The capability is present in")
    print("  AgentConnectService and absent from the adapter.")
    print("\n  Detected by comparing two lists. No tool was invoked.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
