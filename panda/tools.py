from __future__ import annotations

from typing import Any

from panda.mock_api import MockAPIEnvironment
from panda.models import ToolResult


class MockToolRegistry:
    """A safe mock registry that grounds each tool in a simple simulated API environment."""

    def __init__(self) -> None:
        self.api = MockAPIEnvironment()

    def discover_endpoints(self, state: dict[str, Any]) -> ToolResult:
        endpoints = self.api.list_endpoints()
        return ToolResult(
            tool="discover_endpoints",
            success=True,
            summary="Discovered the application surface and the key user/admin routes in the simulated API.",
            observations=[
                f"Endpoint {item['path']} exposes methods {', '.join(item['methods'])} and auth requirement {item['auth_required']}."
                for item in endpoints
            ],
            metrics={"endpoint_count": len(endpoints)},
            evidence=[],
        )

    def inspect_request(self, state: dict[str, Any], path: str | None = None) -> ToolResult:
        path = path or "/users/{id}"
        request_shape = self.api.inspect_request(path)
        return ToolResult(
            tool="inspect_request",
            success=True,
            summary=f"Request inspection for {path} shows a user-scoped identifier and optional profile expansion input.",
            observations=[
                "The route accepts a user identifier and optional profile expansion field.",
                "The mock API binds the request to a user identity without object ownership checks.",
            ],
            metrics=request_shape,
            evidence=[],
        )

    def inspect_response(self, state: dict[str, Any], path: str | None = None) -> ToolResult:
        path = path or "/users/{id}"
        response_shape = self.api.inspect_response(path)
        return ToolResult(
            tool="inspect_response",
            success=True,
            summary=f"Observed response content for {path} contains identity and profile metadata beyond the minimal user payload.",
            observations=[
                "The response includes role metadata and a profile payload.",
                "A standard user may access fields that appear broader than the route contract suggests.",
            ],
            metrics=response_shape,
            evidence=[],
        )

    def inspect_traffic(self, state: dict[str, Any]) -> ToolResult:
        metrics = self.api.traffic_metrics()
        return ToolResult(
            tool="inspect_traffic",
            success=True,
            summary="Traffic metrics show a moderate request rate and elevated latency on protected administrative resources.",
            observations=[
                "Admin endpoints show higher latency and more error churn than the user route.",
                "The request pattern is consistent with a mixed user/admin control surface.",
            ],
            metrics=metrics,
            evidence=[],
        )

    def compare_responses(self, state: dict[str, Any], endpoint_a: str = "/users/{id}", endpoint_b: str = "/admin/reports") -> ToolResult:
        delta = self.api.compare_responses(endpoint_a, endpoint_b)
        return ToolResult(
            tool="compare_responses",
            success=True,
            summary="Comparing user and admin route responses shows a policy mismatch in access control and data exposure.",
            observations=[
                "The user route returns sensitive identity metadata without strong object ownership checks.",
                "The admin route shows a stricter response boundary and higher latency under similar load.",
            ],
            metrics=delta,
            evidence=[],
        )

    def analyze_authentication(self, state: dict[str, Any]) -> ToolResult:
        auth = self.api.authentication_context()
        return ToolResult(
            tool="analyze_authentication",
            success=True,
            summary="Authentication is present, but the mock API exposes a role and object boundary problem rather than a missing login flow.",
            observations=[
                "A user token is required for the application surface.",
                "Different roles influence route exposure, but object-level checks are weak.",
            ],
            metrics=auth,
            evidence=[],
        )

    def analyze_authorization(self, state: dict[str, Any]) -> ToolResult:
        authz = self.api.authorization_context()
        return ToolResult(
            tool="analyze_authorization",
            success=True,
            summary="Authorization analysis indicates a plausible broken object-level authorization condition in the user identifier flow.",
            observations=[
                "A user-scoped object can be retrieved with a token that should be constrained to the caller's own record.",
                "The admin route remains protected more strictly than the user route.",
            ],
            metrics=authz,
            evidence=[],
        )

    def analyze_input_behavior(self, state: dict[str, Any]) -> ToolResult:
        behavior = self.api.input_behavior()
        return ToolResult(
            tool="analyze_input_behavior",
            success=True,
            summary="Input handling is bounded, but parameterized object access is the more relevant issue in this scenario.",
            observations=[
                "The API accepts an identifier and profile expansion flag.",
                "The higher-risk behavior is object access rather than injection or malformed input.",
            ],
            metrics=behavior,
            evidence=[],
        )

    def inspect_sensitive_data(self, state: dict[str, Any]) -> ToolResult:
        data = self.api.inspect_sensitive_data()
        return ToolResult(
            tool="inspect_sensitive_data",
            success=True,
            summary="Sensitive metadata such as role, profile, and identity information appears in a normal user response.",
            observations=[
                "The mock API includes profile metadata beyond the minimal user record.",
                "This is consistent with a BOLA-style exposure hypothesis rather than an outright vulnerability assertion.",
            ],
            metrics=data,
            evidence=[],
        )

    def analyze_endpoint_relationships(self, state: dict[str, Any]) -> ToolResult:
        relations = self.api.endpoint_relationships()
        return ToolResult(
            tool="analyze_endpoint_relationships",
            success=True,
            summary="The user and admin routes share similar request patterns, suggesting a related authorization policy boundary.",
            observations=[
                "The endpoints are structurally related by object access patterns.",
                "A permission mismatch between neighboring resources is consistent with the observed behavior.",
            ],
            metrics=relations,
            evidence=[],
        )

    def validate_hypothesis(self, state: dict[str, Any], hypothesis: str | None = None) -> ToolResult:
        text = hypothesis or "broken object-level authorization"
        return ToolResult(
            tool="validate_hypothesis",
            success=True,
            summary=f"Validation of the '{text}' hypothesis is inconclusive but strongly suggests a policy gap in object access control.",
            observations=[
                "Evidence is suggestive but not conclusive enough to classify as a confirmed vulnerability without stricter checks.",
                "The mock environment deliberately leaves the final classification as a hypothesis for the prototype.",
            ],
            metrics={"support_score": 0.76, "status": "NEEDS_MORE_EVIDENCE"},
            evidence=[],
        )


def safe_tool_registry() -> MockToolRegistry:
    return MockToolRegistry()
