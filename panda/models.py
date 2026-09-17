from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


# ---------------------------------------------------------------------------
# Legacy action types (retained for graph.py backward compatibility)
# ---------------------------------------------------------------------------

ActionType = Literal[
    "discover_endpoints",
    "inspect_request",
    "inspect_response",
    "inspect_traffic",
    "compare_responses",
    "analyze_authentication",
    "analyze_authorization",
    "analyze_input_behavior",
    "inspect_sensitive_data",
    "analyze_endpoint_relationships",
    "validate_hypothesis",
    "stop",
]


# ---------------------------------------------------------------------------
# Core models (shared)
# ---------------------------------------------------------------------------

class TargetScope(BaseModel):
    name: str
    base_url: str
    authorized_targets: list[str] = Field(default_factory=list)
    allowed_domains: list[str] = Field(default_factory=list)
    allowed_endpoints: list[str] = Field(default_factory=list)
    allowed_tools: list[str] = Field(default_factory=list)
    maximum_iterations: int = 10
    maximum_requests: int = 50
    rate_limit_per_minute: int = 30
    non_destructive_action_policy: str = "read-only and bounded"


class EndpointObservation(BaseModel):
    path: str
    methods: list[str] = Field(default_factory=list)
    auth_required: bool = False
    parameters: list[str] = Field(default_factory=list)
    status_codes: list[int] = Field(default_factory=list)
    response_structure: dict[str, Any] = Field(default_factory=dict)
    avg_latency_ms: float = 0.0
    request_rate: float = 0.0
    error_rate: float = 0.0


class AuthState(BaseModel):
    authentication_required: bool = True
    roles: list[str] = Field(default_factory=list)
    active_token: str | None = None
    auth_observations: list[str] = Field(default_factory=list)


class TrafficMetrics(BaseModel):
    request_rate: float = 0.0
    error_rate: float = 0.0
    latency_ms: float = 0.0


class Hypothesis(BaseModel):
    description: str
    supporting_observations: list[str] = Field(default_factory=list)
    confidence: float = 0.0
    suggested_next_actions: list[str] = Field(default_factory=list)
    status: Literal["OPEN", "PARTIAL", "REJECTED", "CONFIRMED", "INCONCLUSIVE"] = "OPEN"


class EvidenceRecord(BaseModel):
    source: str
    observation: str
    confidence: float = 0.0


class ToolResult(BaseModel):
    tool: str
    success: bool
    summary: str
    observations: list[str] = Field(default_factory=list)
    metrics: dict[str, Any] = Field(default_factory=dict)
    evidence: list[EvidenceRecord] = Field(default_factory=list)


class CandidateAction(BaseModel):
    action: ActionType
    rationale: str
    expected_information_gain: float = 0.0
    cost: float = 0.0
    confidence: float = 0.0


class InvestigationReport(BaseModel):
    target: str
    summary: str
    status: Literal["CONFIRMED", "REJECTED", "INCONCLUSIVE", "NEEDS_MORE_EVIDENCE"]
    findings: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    recommended_next_steps: list[str] = Field(default_factory=list)
    confidence: float = 0.0


class AgentState(BaseModel):
    model_config = ConfigDict(extra="allow")

    target: TargetScope
    discovered_endpoints: list[EndpointObservation] = Field(default_factory=list)
    api_schemas: list[dict[str, Any]] = Field(default_factory=list)
    auth_state: AuthState = Field(default_factory=AuthState)
    observed_requests: list[dict[str, Any]] = Field(default_factory=list)
    observed_responses: list[dict[str, Any]] = Field(default_factory=list)
    traffic_metrics: TrafficMetrics = Field(default_factory=TrafficMetrics)
    security_observations: list[str] = Field(default_factory=list)
    hypotheses: list[Hypothesis] = Field(default_factory=list)
    candidate_actions: list[CandidateAction] = Field(default_factory=list)
    selected_action: ActionType | None = None
    evidence: list[str] = Field(default_factory=list)
    findings: list[str] = Field(default_factory=list)
    confidence: float = 0.0
    investigation_history: list[str] = Field(default_factory=list)
    iteration_count: int = 0
    remaining_investigation_budget: int = 5
    status: Literal["initialized", "CONTINUE", "TERMINATED", "BLOCKED"] = "initialized"
    validation: Literal["NOT_RUN", "CONFIRMED", "REJECTED", "INCONCLUSIVE", "NEEDS_MORE_EVIDENCE"] = "NOT_RUN"
    next_decision: str = "start"
    last_tool_result: ToolResult | None = None
    last_observation: str = ""
    report: InvestigationReport | None = None


class ObservationLog(BaseModel):
    timestamp: str
    agent: str
    observation: str
    hypothesis: str
    candidate_actions: list[str] = Field(default_factory=list)
    selected_action: str | None = None
    reason: str
    tool_result: str
    confidence: float = 0.0
    next_decision: str


# ---------------------------------------------------------------------------
# New models for the LLM-driven pipeline
# ---------------------------------------------------------------------------

SeverityLevel = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

OWASPCategory = Literal[
    "API1:2023-BOLA",
    "API2:2023-Broken-Authentication",
    "API3:2023-Broken-Object-Property-Level-Authorization",
    "API4:2023-Unrestricted-Resource-Consumption",
    "API5:2023-Broken-Function-Level-Authorization",
    "API6:2023-Unrestricted-Access-to-Sensitive-Business-Flows",
    "API7:2023-Server-Side-Request-Forgery",
    "API8:2023-Security-Misconfiguration",
    "API9:2023-Improper-Inventory-Management",
    "API10:2023-Unsafe-Consumption-of-APIs",
    "OTHER",
]


class DataModel(BaseModel):
    """A data entity inferred from the API contract and responses."""
    name: str
    fields: list[str] = Field(default_factory=list)
    sensitive_fields: list[str] = Field(default_factory=list)
    relationships: list[str] = Field(default_factory=list)


class AuthPattern(BaseModel):
    """Authentication / authorization pattern observed in the API."""
    mechanism: str = ""
    roles_observed: list[str] = Field(default_factory=list)
    observations: list[str] = Field(default_factory=list)


class APIUnderstanding(BaseModel):
    """LLM's inferred understanding of the API's purpose and structure."""
    reasoning: str = Field(
        description="Chain-of-thought reasoning about the API's purpose, users, and security-relevant patterns."
    )
    business_context: str = Field(
        description="One-paragraph summary of what this API does and who its users are."
    )
    api_type: str = Field(
        description="Category of API, e.g. 'User management', 'E-commerce', 'Healthcare', 'IoT', etc."
    )
    data_models: list[DataModel] = Field(default_factory=list)
    auth_patterns: list[AuthPattern] = Field(default_factory=list)
    security_relevant_observations: list[str] = Field(
        default_factory=list,
        description="Key observations that are relevant to security testing.",
    )


class ThreatHypothesis(BaseModel):
    """A specific threat hypothesis generated by the LLM."""
    id: str = Field(description="Short identifier, e.g. 'H1', 'H2'.")
    owasp_category: OWASPCategory
    title: str = Field(description="Short descriptive title for the hypothesis.")
    reasoning: str = Field(
        description="Chain-of-thought reasoning for why this threat is relevant to this specific API."
    )
    relevance_score: float = Field(
        ge=0.0, le=1.0,
        description="How relevant this threat is to this API (0.0 = not relevant, 1.0 = highly relevant).",
    )
    affected_endpoints: list[str] = Field(default_factory=list)
    suggested_probes: list[str] = Field(
        default_factory=list,
        description="High-level descriptions of what to test.",
    )
    confidence: float = Field(
        default=0.0,
        description="Confidence level after testing (0.0 to 1.0)",
    )
    status: Literal["OPEN", "PARTIAL", "REJECTED", "CONFIRMED", "INCONCLUSIVE"] = Field(
        default="OPEN",
        description="Status of the hypothesis after testing.",
    )


class TestCase(BaseModel):
    """A specific test probe designed by the LLM."""
    id: str = Field(description="Short identifier, e.g. 'T1', 'T2'.")
    hypothesis_id: str = Field(description="Which hypothesis this test targets.")
    method: str = Field(description="HTTP method: GET or HEAD.")
    path: str = Field(description="The endpoint path, using concrete values for path parameters.")
    query_params: dict[str, str] = Field(default_factory=dict)
    auth_profile: str = Field(default="anonymous", description="Auth profile name to use.")
    reasoning: str = Field(
        description="Why this specific probe was chosen and what it will reveal."
    )
    expected_if_vulnerable: str = Field(
        description="What the response should look like if the vulnerability exists."
    )
    expected_if_safe: str = Field(
        description="What the response should look like if the API is properly secured."
    )


class ProbeResult(BaseModel):
    """Result of executing a single test probe against the real API."""
    test_id: str
    method: str
    url: str
    path: str
    auth_profile: str
    status_code: int
    response_headers: dict[str, str] = Field(default_factory=dict)
    response_body_summary: str = Field(
        default="",
        description="Truncated response body for analysis (max ~2000 chars).",
    )
    response_time_ms: float = 0.0
    error: str | None = None


class HypothesisUpdate(BaseModel):
    """LLM's updated assessment of a hypothesis after seeing test results."""
    hypothesis_id: str
    new_confidence: float = Field(ge=0.0, le=1.0)
    status: Literal["CONFIRMED", "LIKELY", "INCONCLUSIVE", "UNLIKELY", "REJECTED"]
    reasoning: str = Field(description="Why the confidence/status changed based on the evidence.")


class TestAnalysis(BaseModel):
    """LLM's analysis of a batch of test results."""
    reasoning: str = Field(
        description="Chain-of-thought analysis of the test results."
    )
    hypothesis_updates: list[HypothesisUpdate] = Field(default_factory=list)
    new_observations: list[str] = Field(default_factory=list)
    should_continue: bool = Field(
        default=False,
        description="Whether more testing is needed to reach conclusions.",
    )
    continuation_rationale: str = Field(
        default="",
        description="If should_continue is True, explain what additional testing would help and why.",
    )


class Finding(BaseModel):
    """A confirmed or suspected security finding."""
    id: str = Field(description="Short identifier, e.g. 'F1', 'F2'.")
    title: str
    severity: SeverityLevel
    owasp_category: OWASPCategory
    description: str = Field(description="Detailed description of the vulnerability.")
    evidence: list[str] = Field(
        default_factory=list,
        description="Specific evidence supporting this finding (HTTP requests/responses).",
    )
    impact: str = Field(description="What an attacker could achieve by exploiting this.")
    remediation: str = Field(description="Specific, actionable remediation guidance.")
    confidence: float = Field(
        ge=0.0, le=1.0,
        description="Confidence that this is a real vulnerability.",
    )


class SecurityReport(BaseModel):
    """The full structured security assessment report generated by the LLM."""
    reasoning: str = Field(
        description="Chain-of-thought reasoning about the overall security posture."
    )
    executive_summary: str = Field(
        description="2-3 paragraph executive summary of the assessment."
    )
    api_overview: str = Field(
        description="Description of the assessed API and its purpose."
    )
    findings: list[Finding] = Field(default_factory=list)
    positive_observations: list[str] = Field(
        default_factory=list,
        description="Security controls that are working correctly.",
    )
    methodology_notes: str = Field(
        default="",
        description="Brief description of the testing methodology used.",
    )
    limitations: list[str] = Field(
        default_factory=list,
        description="Limitations of this assessment (read-only, no auth bypass attempts, etc.).",
    )
