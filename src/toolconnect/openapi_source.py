"""OpenAPI 3.x source adapter — document ingest only, no network, no execution.

This is the Phase-2 protocol-neutral proof: an OpenAPI document is normalized into the
SAME structures the MCP stdio adapter produces (:class:`~toolconnect.mcp_source.DiscoveredTool`,
:class:`~toolconnect.mcp_source.DiscoveryResult`, and
:class:`~toolconnect.descriptor.ClaimedMetadata`), so every downstream guarantee —
namespaced identity, assertion-evidence, fail-closed authorization, drift, audit —
applies to a non-MCP tool with no special-casing anywhere in the decision path.

The gate this answers (docs/ROADMAP.md, Phase 1 → Phase 2 gate 2): ingest a real
OpenAPI document into the same catalog beside the MCP tools WITHOUT an MCP-shaped
intermediate representation. Nothing here shells out to FastMCP, builds a synthetic
MCP server, or speaks JSON-RPC; the document is parsed directly into ToolConnect's
own claim model.

Note what is absent, exactly as in ``mcp_source``: there is no request execution, no
HTTP client, no ``invoke()``. Ingesting ``GET /pets/{id}`` records what the spec
*claims* about that operation; it never calls it. ``servers:`` URLs are read for
nothing except documentation — this adapter deliberately never fetches one (the
offline gate must stay offline).

Every failure mode fails closed as a typed :class:`OpenAPISpecError` carrying a
machine-readable ``kind``, mirroring ``McpDiscoveryError``. A spec that cannot be
parsed whole is discarded whole — never partially ingested, for the same reason a
partial MCP discovery is discarded: the missing half is exactly where a shadowing
capability hides.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Mapping

from .descriptor import ClaimedMetadata
from .mcp_source import DiscoveredTool, DiscoveryResult

#: Fault taxonomy. Every ingest failure is one of these, and each is auditable.
FAULT_KINDS = (
    "unreadable",          # the spec file could not be read at all
    "malformed_document",  # bytes that parse as neither JSON nor YAML
    "not_openapi",         # parses, but is not an OpenAPI 3.x document
    "no_operations",       # a valid document declaring zero operations
    "duplicate_operation", # two operations resolve to the same capability name
    "invalid_parameter",   # a parameter/operation violates the OpenAPI shape
)


class OpenAPISpecError(Exception):
    """A failed OpenAPI ingest. `kind` is one of FAULT_KINDS; always fail closed."""

    def __init__(self, kind: str, message: str) -> None:
        assert kind in FAULT_KINDS, kind
        super().__init__(message)
        self.kind = kind


#: The HTTP methods that define operations under a path item (OpenAPI 3.x §4.7.2).
_METHODS = frozenset(
    {"get", "put", "post", "delete", "options", "head", "patch", "trace"})

#: Methods an operator would read as side-effect-free. This is the OpenAPI
#: crosswalk's analogue of MCP's `readOnlyHint` — and like every `claimed_*` field,
#: it is a claim recorded and diffed, never an authorization input.
_READ_ONLY_METHODS = frozenset({"get", "head", "options"})

_SAFE_NAME = re.compile(r"[^A-Za-z0-9_.-]+")


def _claimed_for(method: str, summary: str, description: str) -> ClaimedMetadata:
    """Map one operation's HTTP semantics onto the claimed-metadata crosswalk.

    Deliberately conservative and documented, mirroring ``ClaimedMetadata.implied_effect``:

    * GET/HEAD/OPTIONS claim ``read_only_hint=True``; destructive/open-world hints are
      left unset (meaningless for a read-only method, per MCP's own rule).
    * DELETE claims ``read_only_hint=False, destructive_hint=True``.
    * Every other write method claims ``read_only_hint=False, destructive_hint=False,
      open_world_hint=True`` — an OpenAPI operation talks to a server across a network
      boundary, which is exactly what open-world means in the MCP crosswalk.
    """
    if method in _READ_ONLY_METHODS:
        return ClaimedMetadata(
            description=summary or description, read_only_hint=True)
    if method == "delete":
        return ClaimedMetadata(
            description=summary or description,
            read_only_hint=False, destructive_hint=True, open_world_hint=True)
    return ClaimedMetadata(
        description=summary or description,
        read_only_hint=False, destructive_hint=False, open_world_hint=True)


def _fallback_name(method: str, path: str) -> str:
    """Capability name for an operation with no operationId: ``{method}_{path}``.

    Path templating and separators are normalized to underscores so the name is a
    single registry token: ``get /pets/{petId}`` -> ``get_pets_petId``.
    """
    cleaned = _SAFE_NAME.sub("_", path.strip("/")).strip("_")
    return f"{method}_{cleaned}" if cleaned else method


def _merge_schema_parameters(operation: Mapping[str, Any],
                             path_item: Mapping[str, Any]) -> dict:
    """Build the capability's input schema from parameters + requestBody.

    Parameters (path-item level first, operation level overriding by ``(name, in)``)
    and a JSON ``requestBody`` object schema are merged into one JSON Schema object,
    because ToolConnect's ``input_schema`` is a single contract for "the arguments of
    one call". Non-object body schemas (arrays, scalars) are recorded as an opaque
    ``body`` property rather than dropped.
    """
    properties: dict[str, Any] = {}
    required: list[str] = []

    params: dict[tuple[str, str], Mapping[str, Any]] = {}
    for source in (path_item.get("parameters"), operation.get("parameters")):
        if source is None:
            continue
        if not isinstance(source, list):
            raise OpenAPISpecError(
                "invalid_parameter", "'parameters' must be an array")
        for p in source:
            if not isinstance(p, Mapping) or not isinstance(p.get("name"), str):
                raise OpenAPISpecError(
                    "invalid_parameter", f"parameter without a usable name: {p!r}")
            params[(p["name"], str(p.get("in", "query")))] = p
    for p in params.values():
        properties[p["name"]] = dict(p.get("schema") or {})
        if p.get("required") is True:
            required.append(p["name"])

    body = operation.get("requestBody")
    if isinstance(body, Mapping):
        content = body.get("content") or {}
        if isinstance(content, Mapping):
            # Prefer an exact application/json entry; otherwise accept any
            # structured-*+json media type (application/problem+json, ...).
            entry = content.get("application/json")
            if not isinstance(entry, Mapping):
                entry = next(
                    (v for k, v in content.items()
                     if isinstance(k, str) and k.endswith("+json")
                     and isinstance(v, Mapping)),
                    None)
            schema = entry.get("schema") if isinstance(entry, Mapping) else None
            if isinstance(schema, Mapping):
                if schema.get("type") == "object" or "properties" in schema:
                    for k, v in (schema.get("properties") or {}).items():
                        properties[k] = v
                    for r in schema.get("required") or ():
                        if isinstance(r, str) and r not in required:
                            required.append(r)
                else:
                    # A non-object body (array, scalar) is recorded as an opaque
                    # `body` property rather than dropped silently.
                    properties["body"] = dict(schema)
    out: dict[str, Any] = {"type": "object", "properties": properties}
    if required:
        out["required"] = sorted(set(required))
    return out


def parse_openapi(document: Mapping[str, Any]) -> DiscoveryResult:
    """Normalize a parsed OpenAPI 3.x document into a DiscoveryResult.

    One capability per ``(path, method)`` operation, named by ``operationId`` when
    present and by ``{method}_{path}`` otherwise. Raises :class:`OpenAPISpecError`
    (never returns a partial result) on any shape violation.
    """
    if not isinstance(document, Mapping):
        raise OpenAPISpecError("not_openapi", "document is not a JSON/YAML object")
    version = document.get("openapi")
    if not isinstance(version, str) or not version.startswith("3."):
        raise OpenAPISpecError(
            "not_openapi",
            f"document declares openapi={version!r}; only OpenAPI 3.x is supported "
            f"(a 'swagger: \"2.0\"' document must be upgraded first)")
    info = document.get("info") or {}
    if not isinstance(info, Mapping):
        raise OpenAPISpecError("not_openapi", "'info' is not an object")
    paths = document.get("paths")
    if not isinstance(paths, Mapping):
        raise OpenAPISpecError(
            "no_operations", "document has no 'paths' object — nothing to ingest")

    api_version = str(info.get("version") or "0.0.0")
    tools: list[DiscoveredTool] = []
    seen: set[str] = set()
    for path, path_item in paths.items():
        if not isinstance(path, str) or not path.startswith("/"):
            raise OpenAPISpecError(
                "invalid_parameter", f"path key {path!r} must start with '/'")
        if not isinstance(path_item, Mapping):
            raise OpenAPISpecError(
                "invalid_parameter", f"path item {path!r} is not an object")
        for method, operation in path_item.items():
            if method not in _METHODS:
                continue  # 'parameters', 'summary', '$ref', x-* extensions
            if not isinstance(operation, Mapping):
                raise OpenAPISpecError(
                    "invalid_parameter",
                    f"operation {method.upper()} {path} is not an object")
            op_id = operation.get("operationId")
            if op_id is not None and not isinstance(op_id, str):
                raise OpenAPISpecError(
                    "invalid_parameter",
                    f"operationId of {method.upper()} {path} is not a string")
            name = op_id or _fallback_name(method, path)
            if name in seen:
                # One source, one namespace — the same rule the MCP adapter enforces.
                # A duplicated operationId is a spec bug or a shadowing attempt.
                raise OpenAPISpecError(
                    "duplicate_operation",
                    f"capability name {name!r} is declared more than once "
                    f"(second occurrence: {method.upper()} {path})")
            seen.add(name)
            tools.append(DiscoveredTool(
                name=name,
                claimed=_claimed_for(
                    method,
                    str(operation.get("summary") or ""),
                    str(operation.get("description") or "")),
                input_schema=_merge_schema_parameters(operation, path_item),
                version=api_version,
            ))
    if not tools:
        raise OpenAPISpecError(
            "no_operations", "document declares paths but zero operations")
    return DiscoveryResult(
        server_name=str(info.get("title") or "unknown"),
        server_version=api_version,
        protocol_version=f"openapi-{version}",
        tools=tuple(tools),
    )


def discovery_to_payload(result: DiscoveryResult) -> list[dict]:
    """Convert a parsed DiscoveryResult into the ``tools`` list shape
    :meth:`~toolconnect.service.ToolConnectService.ingest_payload` accepts.

    This is the single conversion used by both the CLI (``ingest-openapi``) and the
    tests, so the wire shape is defined exactly once. The payload carries claims and
    schemas only — nothing executable, nothing fetched.
    """
    return [
        {
            "name": t.name,
            "version": t.version,
            "claimed": {
                "description": t.claimed.description,
                "read_only_hint": t.claimed.read_only_hint,
                "destructive_hint": t.claimed.destructive_hint,
                "idempotent_hint": t.claimed.idempotent_hint,
                "open_world_hint": t.claimed.open_world_hint,
            },
            "input_schema": dict(t.input_schema),
        }
        for t in result.tools
    ]


def load_openapi(path: str | Path) -> DiscoveryResult:
    """Load and parse a local OpenAPI spec file (JSON, or YAML when PyYAML is
    installed). No network fetch — this is deliberately file-only so the offline
    gate stays offline. Fails closed with a typed :class:`OpenAPISpecError`.
    """
    p = Path(path)
    try:
        raw = p.read_bytes()
    except OSError as exc:
        raise OpenAPISpecError("unreadable", f"could not read {p}: {exc}")
    document: Any = None
    try:
        document = json.loads(raw)
    except json.JSONDecodeError:
        try:
            import yaml  # optional; JSON ingest never depends on it
        except ImportError:
            raise OpenAPISpecError(
                "malformed_document",
                f"{p} is not valid JSON, and PyYAML is not installed to try YAML")
        try:
            document = yaml.safe_load(raw)
        except yaml.YAMLError as exc:
            raise OpenAPISpecError(
                "malformed_document", f"{p} parses as neither JSON nor YAML: {exc}")
    return parse_openapi(document)
