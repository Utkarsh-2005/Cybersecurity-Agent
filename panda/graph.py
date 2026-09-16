from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal

from langgraph.graph import END, StateGraph

from panda.models import AgentState, CandidateAction, Hypothesis, TargetScope
from panda.tools import safe_tool_registry


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_target(raw_target: dict[str, Any] | None) -> TargetScope:
    if raw_target is None:
        raw_target = {}
    return TargetScope(
        name=raw_target.get("name", "simulated-target"),
        base_url=raw_target.get("base_url", "https://api.example.com"),
        authorized_targets=raw_target.get("authorized_targets", ["https://api.example.com"]),
        allowed_domains=raw_target.get("allowed_domains", ["api.example.com"]),
        allowed_endpoints=raw_target.get("allowed_endpoints", ["/users", "/users/{id}", "/admin/reports"]),
        allowed_tools=raw_target.get("allowed_tools", [
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
        ]),
        maximum_iterations=raw_target.get("maximum_iterations", 8),
        maximum_requests=raw_target.get("maximum_requests", 25),
        rate_limit_per_minute=raw_target.get("rate_limit_per_minute", 30),
        non_destructive_action_policy=raw_target.get("non_destructive_action_policy", "read-only, no destructive or credential-bearing actions"),
    )


def _to_agent_state(raw: dict[str, Any]) -> AgentState:
    target = _safe_target(raw.get("target"))
    return AgentState(
        target=target,
        discovered_endpoints=raw.get("discovered_endpoints", []),
        api_schemas=raw.get("api_schemas", []),
        auth_state=raw.get("auth_state", {}),
        observed_requests=raw.get("observed_requests", []),
        observed_responses=raw.get("observed_responses", []),
        traffic_metrics=raw.get("traffic_metrics", {}),
        security_observations=raw.get("security_observations", []),
        hypotheses=raw.get("hypotheses", []),
        candidate_actions=raw.get("candidate_actions", []),
        selected_action=raw.get("selected_action"),
        evidence=raw.get("evidence", []),
        findings=raw.get("findings", []),
        confidence=raw.get("confidence", 0.0),
        investigation_history=raw.get("investigation_history", []),
        iteration_count=raw.get("iteration_count", 0),
        remaining_investigation_budget=raw.get("remaining_investigation_budget", 5),
        status=raw.get("status", "initialized"),
        validation=raw.get("validation", "NOT_RUN"),
        next_decision=raw.get("next_decision", "start"),
        last_tool_result=raw.get("last_tool_result"),
        last_observation=raw.get("last_observation", ""),
    )


def _tool_by_name(registry: Any, tool_name: str):
    candidates = {
        "discover_endpoints": registry.discover_endpoints,
        "inspect_request": registry.inspect_request,
        "inspect_response": registry.inspect_response,
        "inspect_traffic": registry.inspect_traffic,
        "compare_responses": registry.compare_responses,
        "analyze_authentication": registry.analyze_authentication,
        "analyze_authorization": registry.analyze_authorization,
        "analyze_input_behavior": registry.analyze_input_behavior,
        "inspect_sensitive_data": registry.inspect_sensitive_data,
        "analyze_endpoint_relationships": registry.analyze_endpoint_relationships,
        "validate_hypothesis": registry.validate_hypothesis,
    }
    if tool_name not in candidates:
        raise ValueError(f"Tool '{tool_name}' is not available in the mock registry")
    return candidates[tool_name]


def recon_agent(state: AgentState) -> AgentState:
    registry = safe_tool_registry()
    result = registry.discover_endpoints(state.model_dump())
    state.last_tool_result = result
    state.last_observation = result.summary
    state.evidence.append(result.summary)
    state.security_observations.extend(result.observations)
    state.status = "CONTINUE"
    state.next_decision = "hypothesis"
    state.investigation_history.append(f"{_timestamp()}|recon_agent|discover_endpoints")
    return state


def hypothesis_agent(state: AgentState) -> AgentState:
    observations = state.security_observations
    if not observations:
        state.hypotheses = [Hypothesis(description="No observable evidence yet; continue reconnaissance.", confidence=0.1, suggested_next_actions=["discover_endpoints"])]
    else:
        h1 = Hypothesis(
            description="There may be an authorization inconsistency between user-scoped and admin-scoped resources.",
            supporting_observations=[obs for obs in observations if "authorization" in obs.lower() or "role" in obs.lower() or "admin" in obs.lower() or "user" in obs.lower()],
            confidence=0.72,
            suggested_next_actions=["analyze_authorization", "compare_responses", "validate_hypothesis"],
        )
        h2 = Hypothesis(
            description="Sensitive metadata may be exposed on normal user responses beyond the expected contract.",
            supporting_observations=[obs for obs in observations if "profile" in obs.lower() or "role" in obs.lower() or "sensitive" in obs.lower()],
            confidence=0.68,
            suggested_next_actions=["inspect_sensitive_data", "inspect_response", "validate_hypothesis"],
        )
        state.hypotheses = [h1, h2]

    state.confidence = max((h.confidence for h in state.hypotheses), default=0.0)
    state.next_decision = "plan"
    state.investigation_history.append(f"{_timestamp()}|hypothesis_agent|formed_hypotheses")
    return state


def planning_agent(state: AgentState) -> AgentState:
    hypotheses = state.hypotheses or [Hypothesis(description="Awaiting data.", confidence=0.0, suggested_next_actions=["discover_endpoints"])]
    if state.validation in {"CONFIRMED", "REJECTED"}:
        state.selected_action = "stop"
        state.next_decision = "terminate"
        state.status = "TERMINATED"
        return state

    top_hypothesis = max(hypotheses, key=lambda h: h.confidence)
    candidate_actions = [
        CandidateAction(action="analyze_authorization", rationale="Check whether different roles see divergent permission boundaries.", expected_information_gain=0.9, cost=0.4, confidence=top_hypothesis.confidence),
        CandidateAction(action="compare_responses", rationale="Compare user and admin responses for unexpected privilege divergence.", expected_information_gain=0.8, cost=0.3, confidence=top_hypothesis.confidence),
        CandidateAction(action="inspect_sensitive_data", rationale="Identify whether normal responses expose broader data than expected.", expected_information_gain=0.7, cost=0.3, confidence=top_hypothesis.confidence),
        CandidateAction(action="validate_hypothesis", rationale="Assess whether current evidence supports the current hypothesis.", expected_information_gain=0.6, cost=0.2, confidence=0.7),
    ]

    if state.remaining_investigation_budget <= 1:
        state.selected_action = "stop"
        state.next_decision = "terminate"
        state.status = "TERMINATED"
        return state

    if state.last_tool_result and "authorization" in state.last_tool_result.summary.lower():
        selected = "analyze_authorization"
    elif state.iteration_count >= 2 and state.evidence and any("response" in item.lower() for item in state.evidence):
        selected = "compare_responses"
    else:
        selected = "inspect_sensitive_data"

    state.candidate_actions = candidate_actions
    state.selected_action = selected
    state.next_decision = "tool"
    state.investigation_history.append(f"{_timestamp()}|planning_agent|selected={selected}")
    return state


def tool_execution_agent(state: AgentState) -> AgentState:
    if state.selected_action is None:
        state.selected_action = "validate_hypothesis"

    registry = safe_tool_registry()
    tool = _tool_by_name(registry, state.selected_action)
    if state.selected_action == "validate_hypothesis":
        result = tool(state.model_dump(), hypothesis=(state.hypotheses[0].description if state.hypotheses else "authorization inconsistency"))
    else:
        result = tool(state.model_dump())

    state.last_tool_result = result
    state.last_observation = result.summary
    state.evidence.extend(result.observations)
    state.confidence = max(state.confidence, sum(item.confidence for item in state.hypotheses) / max(len(state.hypotheses), 1) if state.hypotheses else 0.5)
    state.status = "CONTINUE"
    state.next_decision = "validate"
    state.investigation_history.append(f"{_timestamp()}|tool_execution_agent|{state.selected_action}")
    return state


def validation_agent(state: AgentState) -> AgentState:
    evidence_text = " ".join(state.evidence).lower()
    if "inconclusive" in evidence_text or "needs more evidence" in evidence_text:
        state.validation = "NEEDS_MORE_EVIDENCE"
        state.next_decision = "replan"
    elif "authorization" in evidence_text and "inconsistent" in evidence_text:
        state.validation = "CONFIRMED"
        state.next_decision = "terminate"
        state.status = "TERMINATED"
    elif "sensitive" in evidence_text or "profile" in evidence_text:
        state.validation = "INCONCLUSIVE"
        state.next_decision = "replan"
    else:
        state.validation = "REJECTED"
        state.next_decision = "replan"

    if state.remaining_investigation_budget > 0:
        state.remaining_investigation_budget -= 1
    state.iteration_count += 1
    state.investigation_history.append(f"{_timestamp()}|validation_agent|validation={state.validation}")
    return state


def replan_agent(state: AgentState) -> AgentState:
    if state.validation == "CONFIRMED":
        state.status = "TERMINATED"
        state.next_decision = "stop"
        return state

    if state.remaining_investigation_budget <= 0:
        state.status = "TERMINATED"
        state.next_decision = "budget_exhausted"
        return state

    if state.validation in {"INCONCLUSIVE", "NEEDS_MORE_EVIDENCE"}:
        state.selected_action = "compare_responses" if state.selected_action != "compare_responses" else "validate_hypothesis"
        state.next_decision = "tool"
    else:
        state.selected_action = "analyze_authentication"
        state.next_decision = "tool"

    state.status = "CONTINUE"
    state.investigation_history.append(f"{_timestamp()}|replan_agent|seek_new_evidence")
    return state


def should_continue(state: AgentState) -> Literal["recon", "hypothesis", "plan", "tool", "validate", "replan", "stop"]:
    if state.status == "TERMINATED":
        return "stop"
    if state.next_decision == "start":
        return "recon"
    if state.next_decision == "hypothesis":
        return "hypothesis"
    if state.next_decision == "plan":
        return "plan"
    if state.next_decision == "tool":
        return "tool"
    if state.next_decision == "validate":
        return "validate"
    if state.next_decision == "replan":
        return "replan"
    if state.next_decision == "terminate":
        return "stop"
    return "stop"


def build_graph():
    workflow = StateGraph(AgentState)
    workflow.add_node("recon", recon_agent)
    workflow.add_node("hypothesis", hypothesis_agent)
    workflow.add_node("plan", planning_agent)
    workflow.add_node("tool", tool_execution_agent)
    workflow.add_node("validate", validation_agent)
    workflow.add_node("replan", replan_agent)

    workflow.set_entry_point("recon")
    workflow.add_conditional_edges(
        "recon",
        should_continue,
        {
            "recon": "recon",
            "hypothesis": "hypothesis",
            "plan": "plan",
            "tool": "tool",
            "validate": "validate",
            "replan": "replan",
            "stop": END,
        },
    )
    workflow.add_conditional_edges(
        "hypothesis",
        should_continue,
        {
            "recon": "recon",
            "hypothesis": "hypothesis",
            "plan": "plan",
            "tool": "tool",
            "validate": "validate",
            "replan": "replan",
            "stop": END,
        },
    )
    workflow.add_conditional_edges(
        "plan",
        should_continue,
        {
            "recon": "recon",
            "hypothesis": "hypothesis",
            "plan": "plan",
            "tool": "tool",
            "validate": "validate",
            "replan": "replan",
            "stop": END,
        },
    )
    workflow.add_conditional_edges(
        "tool",
        should_continue,
        {
            "recon": "recon",
            "hypothesis": "hypothesis",
            "plan": "plan",
            "tool": "tool",
            "validate": "validate",
            "replan": "replan",
            "stop": END,
        },
    )
    workflow.add_conditional_edges(
        "validate",
        should_continue,
        {
            "recon": "recon",
            "hypothesis": "hypothesis",
            "plan": "plan",
            "tool": "tool",
            "validate": "validate",
            "replan": "replan",
            "stop": END,
        },
    )
    workflow.add_conditional_edges(
        "replan",
        should_continue,
        {
            "recon": "recon",
            "hypothesis": "hypothesis",
            "plan": "plan",
            "tool": "tool",
            "validate": "validate",
            "replan": "replan",
            "stop": END,
        },
    )
    return workflow.compile()
