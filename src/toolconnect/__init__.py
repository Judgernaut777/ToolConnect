"""ToolConnect — a tool governance decision point.

The in-memory decision core (catalog, descriptors, policy, flow) is the semantic
authority; `store` persists and hydrates it, `service`/`server` expose it over HTTP,
and `mcp_source` discovers real MCP servers over stdio — ingest only. There is
deliberately no `invoke()` anywhere in this package.

ToolConnect authorizes and records. The caller enforces and executes.
"""

__version__ = "0.1.0"

from .catalog import (
    AmbiguousToolName,
    AssertionRecord,
    AssertionStatus,
    Catalog,
    DriftReport,
    ToolId,
)
from .descriptor import (
    AssertedDescriptor,
    ClaimedMetadata,
    DataClass,
    Effect,
    ToolRef,
    ToolVersion,
    TrustedSource,
    TrustTier,
)
from .client import (
    ClientDecision,
    ToolConnectClient,
    ToolConnectDenied,
    ToolConnectError,
    ToolConnectUnavailable,
)
from .flow import FlowFinding, FlowReport, analyze_toolset
from .mcp_source import DiscoveredTool, DiscoveryResult, McpDiscoveryError, discover
from .openapi_source import OpenAPISpecError, load_openapi, parse_openapi
from .policy import Broker, CedarPolicyEngine, Decision, PolicyEngine, Principal
from .schema import SchemaValidationError, validate_input_schema
from .service import DECISION_CONTRACT_VERSION, ServiceError, ToolConnectService
from .store import SqliteStore

__all__ = [
    "AmbiguousToolName", "AssertedDescriptor", "AssertionRecord", "AssertionStatus",
    "Broker", "Catalog", "CedarPolicyEngine", "ClaimedMetadata", "ClientDecision",
    "DECISION_CONTRACT_VERSION", "DataClass", "Decision", "DiscoveredTool",
    "DiscoveryResult", "DriftReport", "Effect", "FlowFinding", "FlowReport",
    "McpDiscoveryError", "OpenAPISpecError", "PolicyEngine", "Principal", "SchemaValidationError",
    "ServiceError", "SqliteStore", "ToolConnectClient", "ToolConnectDenied",
    "ToolConnectError", "ToolConnectService", "ToolConnectUnavailable", "ToolId",
    "ToolRef", "ToolVersion", "TrustTier", "TrustedSource", "analyze_toolset",
    "discover", "load_openapi", "parse_openapi", "validate_input_schema",
]
