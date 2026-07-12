"""Grant-time input_schema validation and the validate-vs-caller boundary.

Deliverable 11. ToolConnect validates the *shape of a tool's declared schema* when an
operator asserts it; the caller validates *arguments* against that schema at invocation
time (ToolConnect is never in the data path). These tests pin both the unit behavior of
``validate_input_schema`` and its integration at assert time.
"""

from __future__ import annotations

import pytest

from toolconnect.policy import CedarPolicyEngine
from toolconnect.schema import SchemaValidationError, validate_input_schema
from toolconnect.service import ServiceError, ToolConnectService
from toolconnect.store import SqliteStore


class TestValidateInputSchema:
    @pytest.mark.parametrize("schema", [
        {},
        {"type": "object"},
        {"type": "object", "properties": {"path": {"type": "string"}},
         "required": ["path"]},
        {"type": "object", "properties": {}},
        {"type": ["object", "null"]},
        {"required": ["x"]},  # required without properties is unusual but not incoherent
    ])
    def test_valid_schemas_pass(self, schema):
        validate_input_schema(schema)  # must not raise

    @pytest.mark.parametrize("schema,needle", [
        ("not a dict", "must be a JSON object"),
        ({"type": "objct"}, "not a JSON Schema type"),
        ({"type": 7}, "not a JSON Schema type"),
        ({"properties": ["a", "b"]}, "'properties' must be an object"),
        ({"properties": {"p": "notaschema"}}, "must map to an object subschema"),
        ({"required": "path"}, "'required' must be a list"),
        ({"required": [1, 2]}, "'required' must be a list"),
        ({"properties": {"a": {"type": "string"}}, "required": ["b"]},
         "not in 'properties'"),
    ])
    def test_incoherent_schemas_fail(self, schema, needle):
        with pytest.raises(SchemaValidationError) as exc:
            validate_input_schema(schema)
        assert needle in str(exc.value)


class TestGrantTimeValidation:
    @pytest.fixture()
    def service(self, tmp_path):
        store = SqliteStore(tmp_path / "tc.db")
        svc = ToolConnectService(store, CedarPolicyEngine(""))
        svc.register_source("s", tier="known")
        yield svc
        store.close()

    def test_assert_refuses_a_tool_with_an_incoherent_schema(self, service):
        service.ingest_payload("s", [{
            "name": "bad", "claimed": {},
            "input_schema": {"type": "object", "properties": {"a": {"type": "string"}},
                             "required": ["missing"]},
        }])
        with pytest.raises(ServiceError) as exc:
            service.assert_tool("s", "bad", {"effect": "read", "asserted_by": "op"})
        assert exc.value.status == 422
        assert "input_schema is invalid" in str(exc.value)
        # Fail closed: the refusal leaves the tool unasserted, not invocable.
        assert service.catalog.invocable("s", "bad") is False

    def test_assert_accepts_a_tool_with_a_valid_schema(self, service):
        service.ingest_payload("s", [{
            "name": "good", "claimed": {"read_only_hint": True},
            "input_schema": {"type": "object",
                             "properties": {"path": {"type": "string"}},
                             "required": ["path"]},
        }])
        result = service.assert_tool("s", "good",
                                     {"effect": "read", "asserted_by": "op"})
        assert result["invocable"] is True

    def test_empty_schema_is_acceptable(self, service):
        service.ingest_payload("s", [{"name": "noschema", "claimed": {}}])
        result = service.assert_tool("s", "noschema",
                                     {"effect": "read", "asserted_by": "op"})
        assert result["invocable"] is True
