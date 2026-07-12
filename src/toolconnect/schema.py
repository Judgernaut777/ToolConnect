"""Grant-time structural validation of a tool's declared ``input_schema``.

Deliverable 11 asks for an explicit boundary between what ToolConnect validates and
what the caller validates. That boundary is:

* **ToolConnect validates the *shape of the declared schema* at grant time** — when an
  operator asserts (vouches for) a tool. A tool whose own input contract is malformed
  is not a tool an operator can meaningfully vouch for, so the assertion is refused.
  This is cheap, static, and safe: it inspects a small JSON object, never runtime data.

* **The caller validates *arguments* against that schema at invocation time.**
  ToolConnect is never in the data path (there is no ``invoke``), so it never sees a
  call's arguments and cannot validate them. Arg-vs-schema validation is the invoking
  runtime's job, exactly as ARCHITECTURE §5/§8 require.

The check here is intentionally conservative — it accepts anything that is a plausible
JSON Schema object and rejects only things that are structurally incoherent (a
non-object schema, a ``properties`` that is not an object, a ``required`` that is not a
list of names that appear in ``properties``, an unknown top-level ``type``). It is not a
full JSON Schema meta-validator, and it deliberately does not fetch ``$ref`` or evaluate
``$schema``. An empty schema (``{}``) is valid: it means "no declared constraints".
"""

from __future__ import annotations

from typing import Any, Mapping

__all__ = ["SchemaValidationError", "validate_input_schema"]

# The primitive types a top-level JSON Schema ``type`` may name. A tool's input is by
# convention an object, but we accept any valid JSON Schema type rather than over-fit.
_JSON_SCHEMA_TYPES = frozenset(
    {"object", "array", "string", "number", "integer", "boolean", "null"})


class SchemaValidationError(ValueError):
    """The declared ``input_schema`` is not a structurally coherent JSON Schema."""


def validate_input_schema(schema: Any) -> None:
    """Raise :class:`SchemaValidationError` if ``schema`` is not a coherent JSON Schema.

    Returns ``None`` on success (including for an empty ``{}`` schema).
    """
    if not isinstance(schema, Mapping):
        raise SchemaValidationError(
            f"input_schema must be a JSON object, got {type(schema).__name__}")

    if not schema:
        return  # {} — no declared constraints, trivially valid.

    stype = schema.get("type")
    if stype is not None:
        types = stype if isinstance(stype, list) else [stype]
        for t in types:
            if not isinstance(t, str) or t not in _JSON_SCHEMA_TYPES:
                raise SchemaValidationError(
                    f"input_schema 'type' {t!r} is not a JSON Schema type "
                    f"(one of {sorted(_JSON_SCHEMA_TYPES)})")

    props = schema.get("properties")
    if props is not None and not isinstance(props, Mapping):
        raise SchemaValidationError(
            "input_schema 'properties' must be an object mapping names to subschemas")
    if isinstance(props, Mapping):
        for name, subschema in props.items():
            if not isinstance(subschema, Mapping):
                raise SchemaValidationError(
                    f"input_schema property {name!r} must map to an object subschema")

    required = schema.get("required")
    if required is not None:
        if not isinstance(required, list) or not all(
                isinstance(r, str) for r in required):
            raise SchemaValidationError(
                "input_schema 'required' must be a list of property-name strings")
        declared = set(props.keys()) if isinstance(props, Mapping) else set()
        # Only enforce the cross-reference when properties were declared at all; a
        # schema that lists required names without a properties block is unusual but
        # not incoherent (some servers declare required separately).
        if declared:
            missing = [r for r in required if r not in declared]
            if missing:
                raise SchemaValidationError(
                    f"input_schema 'required' names not in 'properties': {missing}")
