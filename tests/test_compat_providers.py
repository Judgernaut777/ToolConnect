"""Compatibility fixtures for provider types, and the one cross-provider behavior
that is actually implemented today.

No provider adapter exists in code yet (see ARCHITECTURE §5 — `ToolSourceAdapter` is
a documented Protocol, not an implementation). So there is nothing to run an
"identical behavioral suite" against for MCP / A2A / OpenAPI / HTTP.

What is real is the *ingest contract*: whatever a provider reports becomes
`ClaimedMetadata`, and the claimed->effect crosswalk must behave identically no matter
which provider shape produced it. This file:

  * builds fixture representations of an MCP tool and an OpenAPI operation,
  * adapts each into `ClaimedMetadata` the way a real adapter will have to,
  * asserts the crosswalk is provider-independent,
  * and marks A2A / HTTP / future types as explicitly pending, with reasons, rather
    than pretending to cover them.

When real adapters land, `adapt_*` moves into the package and these fixtures become
the seed of the shared conformance suite the handoff asks for.
"""

from __future__ import annotations

import pytest

from toolconnect.descriptor import ClaimedMetadata, Effect

# --------------------------------------------------------------- provider fixtures

MCP_TOOL = {  # shape of one entry in an MCP tools/list result (spec 2025-11-25)
    "name": "delete_record",
    "title": "Delete Record",
    "description": "Remove a record by id.",
    "inputSchema": {"type": "object", "properties": {"id": {"type": "string"}}},
    "annotations": {"readOnlyHint": False, "destructiveHint": True, "openWorldHint": False},
}

MCP_READONLY_TOOL = {
    "name": "get_record",
    "annotations": {"readOnlyHint": True},
    "inputSchema": {"type": "object"},
}

OPENAPI_OP = {  # an OpenAPI 3.x operation; HTTP method carries effect semantics
    "operationId": "deleteRecord",
    "method": "delete",
    "path": "/records/{id}",
    "x-toolconnect": {"effect": "destructive"},
}

OPENAPI_GET = {"operationId": "getRecord", "method": "get", "path": "/records/{id}"}


# --------------------------------------------------------------- reference adapters
# These live in the test until a real ToolSourceAdapter exists. They encode the
# minimum an adapter must do: translate provider self-description into ClaimedMetadata
# WITHOUT deciding anything (claims stay claims).

def adapt_mcp(tool: dict) -> ClaimedMetadata:
    a = tool.get("annotations", {})
    return ClaimedMetadata(
        description=tool.get("description", ""),
        read_only_hint=a.get("readOnlyHint"),
        destructive_hint=a.get("destructiveHint"),
        idempotent_hint=a.get("idempotentHint"),
        open_world_hint=a.get("openWorldHint"),
    )


_HTTP_EFFECT = {"get": True, "head": True, "options": True}  # read-only methods


def adapt_openapi(op: dict) -> ClaimedMetadata:
    read_only = _HTTP_EFFECT.get(op.get("method", "").lower(), False)
    return ClaimedMetadata(
        description=op.get("operationId", ""),
        read_only_hint=read_only,
        destructive_hint=(op.get("method", "").lower() == "delete") or None,
    )


class TestProviderIngestCrosswalk:
    def test_mcp_destructive_tool_maps_to_destructive_effect(self):
        assert adapt_mcp(MCP_TOOL).implied_effect() is Effect.DESTRUCTIVE

    def test_mcp_readonly_tool_maps_to_read(self):
        assert adapt_mcp(MCP_READONLY_TOOL).implied_effect() is Effect.READ

    def test_openapi_delete_maps_to_destructive(self):
        assert adapt_openapi(OPENAPI_OP).implied_effect() is Effect.DESTRUCTIVE

    def test_openapi_get_maps_to_read(self):
        assert adapt_openapi(OPENAPI_GET).implied_effect() is Effect.READ

    def test_crosswalk_is_provider_independent(self):
        """A destructive tool is destructive whether MCP or OpenAPI described it."""
        assert adapt_mcp(MCP_TOOL).implied_effect() is adapt_openapi(OPENAPI_OP).implied_effect()

    def test_adapters_never_produce_an_assertion(self):
        # An adapter emits claims only. It cannot vouch for a tool.
        for cm in (adapt_mcp(MCP_TOOL), adapt_openapi(OPENAPI_OP)):
            assert isinstance(cm, ClaimedMetadata)


@pytest.mark.skip(reason="No A2A adapter or agreed provider shape exists yet (unbuilt).")
def test_a2a_provider_conformance():
    ...


@pytest.mark.skip(reason="No generic HTTP adapter or agreed provider shape exists yet (unbuilt).")
def test_http_provider_conformance():
    ...
