"""Bounded LLM-guided reconnaissance.

The LLM may identify knowledge gaps and select probes, but it cannot expand the
route or method policy. Recon observations are fed back into discovery and are
not findings by themselves.
"""

from __future__ import annotations

import json
import re
from typing import Any

from langchain_openai import ChatOpenAI

from panda.models import ReconPlan, ProbeResult
from panda.tools import LiveHTTPExecutor

from ..utils import _emit_event, _extract_json_from_response, _llm_call


_MAX_RECON_ITERATIONS = 3
_MAX_PROBES_PER_ITERATION = 8


def _run_recon_loop(
    discovery: dict[str, Any],
    executor: LiveHTTPExecutor,
    llm: ChatOpenAI,
    events: list[dict[str, Any]],
) -> list[ProbeResult]:
    """Resolve reconnaissance gaps with bounded, contract-backed probes."""
    all_results: list[ProbeResult] = []
    previous_results: list[ProbeResult] = []

    for iteration in range(1, _MAX_RECON_ITERATIONS + 1):
        plan = _plan_recon(discovery, previous_results, llm, events, iteration)
        probes = _validate_recon_probes(plan, discovery, events)
        if not probes:
            _emit_event(events, "recon_loop", "completed", detail=plan.stop_reason or "no validated probes")
            break

        results: list[ProbeResult] = []
        for probe in probes:
            result = executor.execute(probe)
            result.route_classification = "DOCUMENTED_API_ROUTE"
            result.validation_checks.append("RECONTRACT_PROBE")
            results.append(result)
            discovery.setdefault("baseline_results", []).append({
                "path": result.path,
                "auth_profile": result.auth_profile,
                "status_code": result.status_code,
                "response_body": result.response_body_summary,
                "response_fields": result.response_fields,
                "request_id": result.request_id,
                "route_classification": result.route_classification,
                "validation_checks": result.validation_checks,
            })
            _emit_event(
                events,
                "recon_loop",
                "called tool",
                "http_request",
                f"{probe.method} {probe.path} ({probe.auth_profile}) -> {result.status_code}",
            )

        all_results.extend(results)
        previous_results = results
        if not plan.should_continue:
            _emit_event(events, "recon_loop", "completed", detail=plan.stop_reason or "knowledge gaps resolved")
            break

    return all_results


def _plan_recon(
    discovery: dict[str, Any],
    previous_results: list[ProbeResult],
    llm: ChatOpenAI,
    events: list[dict[str, Any]],
    iteration: int,
) -> ReconPlan:
    previous = json.dumps([result.model_dump() for result in previous_results], indent=2, default=str)
    prompt = f"""You are PANDA's reconnaissance analyst. Identify the most valuable remaining
knowledge gaps about this API and propose bounded read-only probes to resolve them.

Recon is for discovering facts, not declaring vulnerabilities. Do not label anything
BOLA, BFLA, BOPLA, or a vulnerability in this phase. Every probe must use an exact
documented route and an available auth profile. Prefer comparing anonymous, user, and
admin profiles on the same route. Do not invent routes, IDs, request bodies, or methods.

## Route inventory
{json.dumps(discovery.get('documented_paths', {}), indent=2)}

## Available profiles
{json.dumps(discovery.get('auth_profiles_available', []))}

## Profile metadata
{json.dumps(discovery.get('auth_profile_metadata', {}))}

## Target identity
{json.dumps(discovery.get('target_identity', {}))}

## Prior recon observations
{json.dumps(discovery.get('baseline_results', [])[-40:], indent=2, default=str)}

## Results from the previous recon iteration
{previous}

Return ONLY JSON:
{{
  "reasoning": "What is still unknown and why it matters",
  "probes": [
    {{
      "id": "R{iteration}-1",
      "path": "/users/v1",
      "method": "GET",
      "auth_profile": "anonymous",
      "knowledge_gap": "Whether the collection is exposed without authentication",
      "purpose": "Compare access behavior across available profiles",
      "expected_observation": "A route-specific JSON response and its fields",
      "disconfirming_observation": "401 or 403, or no route-specific response"
    }}
  ],
  "should_continue": false,
  "stop_reason": "No unresolved high-value knowledge gap"
}}
"""
    content, _ = _llm_call(
        llm, prompt, events, "recon_loop", f"planning bounded recon probes (iteration {iteration})"
    )
    try:
        return ReconPlan(**json.loads(_extract_json_from_response(content)))
    except Exception as exc:
        print(f"[recon_loop] Warning: could not parse recon plan: {exc}")
        return ReconPlan(reasoning=content[:1500], stop_reason="unparseable recon plan")


def _validate_recon_probes(
    plan: ReconPlan,
    discovery: dict[str, Any],
    events: list[dict[str, Any]],
) -> list[Any]:
    known_paths = set(discovery.get("documented_paths", {}))
    profiles = set(discovery.get("auth_profiles_available", []))
    existing = {
        (item.get("path"), item.get("auth_profile"))
        for item in discovery.get("baseline_results", [])
    }
    accepted = []
    for probe in plan.probes[:_MAX_PROBES_PER_ITERATION]:
        normalized = probe.path.rstrip("/") or "/"
        base_path = re.sub(r"/\d+", "/{id}", normalized)
        if probe.method not in {"GET", "HEAD"}:
            _emit_event(events, "recon_loop", "rejected probe", "policy", f"{probe.id}: method not read-only")
            continue
        if probe.auth_profile not in profiles:
            _emit_event(events, "recon_loop", "rejected probe", "policy", f"{probe.id}: unknown auth profile")
            continue
        if not (normalized in known_paths or base_path in known_paths):
            _emit_event(events, "recon_loop", "rejected probe", "policy", f"{probe.id}: route not in inventory")
            continue
        if (normalized, probe.auth_profile) in existing:
            _emit_event(events, "recon_loop", "rejected probe", "policy", f"{probe.id}: duplicate baseline probe")
            continue
        probe.path = normalized
        accepted.append(probe)
    return accepted