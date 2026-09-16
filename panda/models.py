from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


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
