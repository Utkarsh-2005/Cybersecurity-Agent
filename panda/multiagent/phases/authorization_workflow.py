"""LLM-directed, bounded authorization workflow selection and execution."""

from __future__ import annotations

import json
import re
from typing import Any

from langchain_openai import ChatOpenAI

from panda.models import (
    AuthorizationWorkflowPlan,
    ProbeResult,
    TestCase,
    ThreatHypothesis,
)
from panda.tools import LiveHTTPExecutor

from ..utils import _emit_event, _extract_json_from_response, _llm_call


def _run_authorization_workflow(
    discovery: dict[str, Any],
    hypotheses: list[ThreatHypothesis],
    executor: LiveHTTPExecutor,
    llm: ChatOpenAI,
    events: list[dict[str, Any]],
    allow_write: bool = False,
) -> list[ProbeResult]:
    """Let the agent decide whether a bounded authorization workflow is needed."""
    plan = _plan_workflow(discovery, hypotheses, llm, events, allow_write)
    if not plan.should_run:
        _emit_event(events, "authorization_workflow", "skipped", detail=plan.stop_reason or "not selected")
        return []

    tests = _validate_steps(plan, discovery, allow_write, events)
    results: list[ProbeResult] = []
    for test in tests:
        result = executor.execute(test)
        result.validation_checks.append("AGENT_SELECTED_AUTHORIZATION_WORKFLOW")
        results.append(result)
        _emit_event(
            events,
            "authorization_workflow",
            "called tool",
            "http_request",
            f"{test.method} {test.path} ({test.auth_profile}) -> {result.status_code}",
        )
    return results


def _plan_workflow(
    discovery: dict[str, Any],
    hypotheses: list[ThreatHypothesis],
    llm: ChatOpenAI,
    events: list[dict[str, Any]],
    allow_write: bool,
) -> AuthorizationWorkflowPlan:
    prompt = f"""You are PANDA's authorization workflow controller.
Decide whether the current evidence justifies a bounded, identity-aware workflow.
Do not declare a vulnerability. Select a workflow only to resolve ownership or
role uncertainty. Prefer OWNER_COMPARISON when at least two non-anonymous profiles
have configured principal metadata. Prefer AUTHORIZATION_MATRIX for role comparisons.

Rules:
- Use only routes in the documented route inventory.
- Use only available auth profiles.
- Use GET, HEAD, or OPTIONS unless explicit lab mode is enabled: {allow_write}.
- Never invent credentials, tokens, object ownership, or route paths.
- Maximum 8 steps.

## Route inventory
{json.dumps(discovery.get('documented_paths', {}), indent=2)}
## Auth profiles and identity metadata
{json.dumps(discovery.get('auth_profile_metadata', {}), indent=2)}
## Threat hypotheses
{json.dumps([h.model_dump() for h in hypotheses], indent=2)}

Return ONLY JSON with should_run, workflow_type, reasoning, stop_reason, and steps.
"""
    content, _ = _llm_call(
        llm, prompt, events, "authorization_workflow", "deciding whether identity-aware authorization testing is needed"
    )
    try:
        return AuthorizationWorkflowPlan(**json.loads(_extract_json_from_response(content)))
    except Exception as exc:
        print(f"[authorization_workflow] Warning: could not parse workflow plan: {exc}")
        return AuthorizationWorkflowPlan(stop_reason="unparseable workflow plan")


def _validate_steps(
    plan: AuthorizationWorkflowPlan,
    discovery: dict[str, Any],
    allow_write: bool,
    events: list[dict[str, Any]],
) -> list[TestCase]:
    known_paths = set(discovery.get("documented_paths", {}))
    profiles = set(discovery.get("auth_profiles_available", []))
    allowed = {"GET", "HEAD", "OPTIONS"} | ({"POST", "PUT", "PATCH", "DELETE"} if allow_write else set())
    tests: list[TestCase] = []
    for step in plan.steps[:8]:
        method = step.method.upper()
        path = step.path.rstrip("/") or "/"
        template_path = re.sub(r"/[^/]+(?=$|/)", "/{id}", path)
        route_ok = path in known_paths or template_path in known_paths or any(
            "{" in route and re.fullmatch(re.sub(r"\{[^}]+\}", r"[^/]+", route), path)
            for route in known_paths
        )
        if method not in allowed or step.auth_profile not in profiles or not route_ok:
            _emit_event(events, "authorization_workflow", "rejected step", "policy", f"{step.id}: route, profile, or method not permitted")
            continue
        tests.append(TestCase(
            id=f"AUTHWF-{step.id}",
            hypothesis_id="H-AUTHZ-WORKFLOW",
            method=method,
            path=path,
            auth_profile=step.auth_profile,
            request_body=step.request_body,
            reasoning=step.purpose,
            expected_if_vulnerable="The same protected object or function is available to an unauthorized principal.",
            expected_if_safe=step.expected_secure_behavior,
        ))
    return tests