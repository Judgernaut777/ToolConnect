"""A representative tool catalog, assembled from real tool surfaces.

Provenance, so the flow-analysis numbers can be trusted or disputed:

* `agentconnect` — the 17 tools actually registered by `@mcp.tool()` in
  `packages/agentconnect-mcp/src/agentconnect/mcp/server.py` (read 2026-07-10).
* `brainconnect`  — the 9 `brain_*` tools in `cli/wiki/mcp_server.py` (WikiBrain).
* `filesystem`, `github`, `slack`, `fetch`, `postgres`, `shell` — the tool names of the
  widely-deployed reference MCP servers. Representative rather than transcribed.

Labels are the author's assertions, made as an operator would make them. Two sets are
called out because they are the honest weak points of the exercise:

* `AMBIGUOUS`    — labeling required a judgment call a real operator might make differently.
* `ARG_DEPENDENT` — the data class is a property of the *arguments*, not the tool. A static
                    descriptor cannot express these, and that is a finding, not an oversight.
"""

from __future__ import annotations

from toolconnect.catalog import Catalog
from toolconnect.descriptor import (
    AssertedDescriptor,
    ClaimedMetadata,
    DataClass,
    Effect,
    TrustedSource,
    TrustTier,
)

PUB, INT, PII, SEC, CRED, EXT = (
    DataClass.PUBLIC, DataClass.INTERNAL, DataClass.PII,
    DataClass.SECRET, DataClass.CREDENTIAL, DataClass.EXTERNAL,
)
R, W, D, X = Effect.READ, Effect.WRITE, Effect.DESTRUCTIVE, Effect.EXTERNAL

#: (source_id, tool, effect, reads, writes)
TOOLS: list[tuple[str, str, Effect, set[DataClass], set[DataClass]]] = [
    # -- AgentConnect: the 17 tools its MCP adapter actually registers ------------
    ("agentconnect", "create_task", W, {INT}, {INT}),
    ("agentconnect", "open_task", R, {INT}, set()),
    ("agentconnect", "get_handoff_summary", R, {INT}, set()),
    ("agentconnect", "claim_task", W, {INT}, {INT}),
    ("agentconnect", "release_task", W, {INT}, {INT}),
    ("agentconnect", "record_decision", W, {INT}, {INT}),
    ("agentconnect", "record_attempt", W, {INT}, {INT}),
    ("agentconnect", "request_review", W, {INT}, {INT}),
    ("agentconnect", "submit_subtask", W, {INT}, {INT}),
    ("agentconnect", "get_status", R, {INT}, set()),
    ("agentconnect", "list_artifacts", R, {INT}, set()),
    # Artifacts are "untrusted until reviewed" and may contain anything a worker wrote.
    ("agentconnect", "read_artifact_chunk", R, {INT, SEC}, set()),
    ("agentconnect", "explain_route", R, {INT}, set()),
    ("agentconnect", "recall_memory", R, {INT}, set()),
    ("agentconnect", "capture_memory_candidate", W, {INT}, {INT}),
    ("agentconnect", "record_memory_feedback", W, {INT}, {INT}),
    ("agentconnect", "get_task_context_pack", R, {INT, SEC}, set()),

    # -- BrainConnect (WikiBrain): the 9 real brain_* tools -----------------------
    ("brainconnect", "brain_recall", R, {INT}, set()),
    ("brainconnect", "brain_search", R, {INT}, set()),
    ("brainconnect", "brain_hybrid", R, {INT}, set()),
    ("brainconnect", "brain_graph", R, {INT}, set()),
    ("brainconnect", "brain_pending", R, {INT}, set()),
    ("brainconnect", "brain_capture", W, {INT}, {INT}),
    ("brainconnect", "brain_feedback", W, {INT}, {INT}),
    ("brainconnect", "brain_promote", W, {INT}, {INT}),
    ("brainconnect", "brain_reject", W, {INT}, {INT}),

    # -- filesystem ---------------------------------------------------------------
    # read_file can read ~/.ssh/id_ed25519 and .env. Its class is its worst case.
    ("filesystem", "read_file", R, {INT, SEC, CRED}, set()),
    ("filesystem", "read_multiple_files", R, {INT, SEC, CRED}, set()),
    ("filesystem", "write_file", W, set(), {INT}),
    ("filesystem", "edit_file", W, {INT}, {INT}),
    ("filesystem", "create_directory", W, set(), {INT}),
    ("filesystem", "list_directory", R, {INT}, set()),
    ("filesystem", "directory_tree", R, {INT}, set()),
    ("filesystem", "move_file", D, {INT}, {INT}),
    ("filesystem", "search_files", R, {INT}, set()),
    ("filesystem", "get_file_info", R, {INT}, set()),
    ("filesystem", "list_allowed_directories", R, {PUB}, set()),

    # -- github: every write is a sink outside the trust boundary ------------------
    ("github", "get_file_contents", R, {EXT, PUB}, set()),
    ("github", "search_repositories", R, {EXT, PUB}, set()),
    ("github", "create_or_update_file", X, set(), {EXT}),
    ("github", "push_files", X, set(), {EXT}),
    ("github", "create_repository", X, set(), {EXT}),
    ("github", "create_issue", X, set(), {EXT}),
    ("github", "create_pull_request", X, set(), {EXT}),
    ("github", "fork_repository", X, set(), {EXT}),
    ("github", "create_branch", X, set(), {EXT}),

    # -- slack ---------------------------------------------------------------------
    ("slack", "slack_list_channels", R, {EXT}, set()),
    ("slack", "slack_get_channel_history", R, {EXT, PII}, set()),
    ("slack", "slack_post_message", X, set(), {EXT}),
    ("slack", "slack_reply_to_thread", X, set(), {EXT}),

    # -- fetch: a reader that is ALSO a sink. Data leaves in the URL. ---------------
    ("fetch", "fetch", X, {EXT, PUB}, {EXT}),

    # -- postgres -------------------------------------------------------------------
    ("postgres", "query", R, {INT, PII}, set()),

    # -- shell: unbounded. Reads anything, writes anywhere. --------------------------
    ("shell", "run_command", D, {INT, SEC, CRED}, {INT, EXT}),
]

#: Tools whose label required a judgment call another operator might make differently.
AMBIGUOUS = {
    "read_artifact_chunk",     # secret only if a worker wrote one into the artifact
    "get_task_context_pack",   # inherits artifact sensitivity transitively
    "recall_memory",           # trusted-only by default, but pending items are requestable
    "fetch",                   # sink-ness depends on whether the URL carries a payload
    "move_file",               # destructive, or just a rename?
    "brain_recall",            # same as recall_memory
}

#: Tools whose data class is a property of the ARGUMENTS, not the tool identity.
#: A static descriptor cannot express these. This is an expressiveness limit.
ARG_DEPENDENT = {
    "read_file",           # reads(path) -> class depends entirely on path
    "read_multiple_files",
    "run_command",         # reads/writes anything the shell can reach
    "query",               # SELECT on a pii column vs a public one
    "fetch",               # GET a public page vs POST a secret to an attacker
    "read_artifact_chunk",
    "write_file",
}

#: Sources an operator would plausibly trust at these tiers.
SOURCES = {
    "agentconnect": TrustTier.VERIFIED,
    "brainconnect": TrustTier.VERIFIED,
    "filesystem": TrustTier.KNOWN,
    "github": TrustTier.KNOWN,
    "slack": TrustTier.KNOWN,
    "fetch": TrustTier.UNTRUSTED,
    "postgres": TrustTier.KNOWN,
    "shell": TrustTier.KNOWN,
}


def build_catalog(assert_all: bool = True) -> Catalog:
    """Construct the fixture catalog. Purely in memory."""
    cat = Catalog()
    for sid, tier in SOURCES.items():
        names = {t[1] for t in TOOLS if t[0] == sid}
        cat.register_source(TrustedSource(sid, tier), declares=names)

    for sid, name, effect, reads, writes in TOOLS:
        # Every server claims to be harmless. That is the point of the exercise.
        cat.ingest_claimed(
            sid, name,
            ClaimedMetadata(
                description=f"{name} (server-supplied)",
                read_only_hint=(effect is Effect.READ),
                destructive_hint=(effect is Effect.DESTRUCTIVE),
                open_world_hint=(effect is Effect.EXTERNAL),
            ),
        )
        if assert_all:
            cat.assert_descriptor(
                sid, name,
                AssertedDescriptor(
                    effect=effect,
                    reads=frozenset(reads),
                    writes=frozenset(writes),
                    scopes=frozenset({sid}),
                    reversible=effect is not Effect.DESTRUCTIVE,
                    requires_approval=name in ("brain_promote", "run_command"),
                    asserted_by="fixture-operator",
                ),
            )
    return cat


#: A realistic grant: what a coding agent on this box would actually hold.
CODING_AGENT_TOOLSET = {
    "read_file", "write_file", "edit_file", "list_directory", "search_files",
    "create_task", "record_decision", "read_artifact_chunk", "get_task_context_pack",
    "brain_recall", "brain_capture",
    "create_or_update_file", "push_files", "create_pull_request", "create_issue",
    "fetch",
}
