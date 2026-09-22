"""Phase 5 — Execution + Analysis (deterministic exec, LLM analysis).

Execute test probes and ask the LLM to analyze the results.
"""

from __future__ import annotations

import json
from collections import defaultdict
from typing import Any

from langchain_openai import ChatOpenAI

from panda.models import (
    APIUnderstanding,
    ProbeResult,
    TestAnalysis,
    TestCase,
    ThreatHypothesis,
)
from panda.tools import LiveHTTPExecutor

from ..utils import _emit_event, _extract_json_from_response, _llm_call


def _execute_and_analyze(
    discovery: dict[str, Any],
    understanding: APIUnderstanding,
    hypotheses: list[ThreatHypothesis],
    tests: list[TestCase],
    executor: LiveHTTPExecutor,
    llm: ChatOpenAI,
    events: list[dict[str, Any]],
    iteration: int = 1,
) -> tuple[list[ProbeResult], TestAnalysis]:
    """Execute test probes and ask the LLM to analyze the results."""

    # Execute all tests
    print(f"\n[executor] === Running {len(tests)} probes (iteration {iteration}) ===")
    results: list[ProbeResult] = []
    for test in tests:
        result = executor.execute(test)
        result.route_classification = _route_classification(result.path, discovery)
        results.append(result)
        status = result.status_code if result.status_code else f"ERROR: {result.error}"
        _emit_event(events, "executor", "called tool", "http_request",
                    f"{result.method} {result.path} ({result.auth_profile}) -> {status}")
        print(f"[executor] {result.method} {result.url} ({result.auth_profile}) -> {status} ({result.response_time_ms:.0f}ms)")

    # Ask LLM to analyze results
    _apply_validation_checks(results)

    results_json = json.dumps(
        [r.model_dump() for r in results],
        indent=2, default=str,
    )
    hypotheses_json = json.dumps([h.model_dump() for h in hypotheses], indent=2)

    prompt = f"""You are PANDA, an expert API security analyst reviewing test results.

Analyze the probe results below against the threat hypotheses. For each hypothesis,
update your confidence based on the evidence. Think carefully about what each
response reveals — status codes, response bodies, differences between auth profiles.

## API Context
{understanding.business_context}

## Threat Hypotheses
{hypotheses_json}

## Test Results
{results_json}

## Deterministic Validation Rules
Treat route classifications and validation checks as authoritative evidence. A
frontend shell, unverified route, or status code alone cannot confirm a vulnerability.

## Instructions
1. Analyze each result and what it reveals about security
2. Update confidence for each hypothesis based on evidence
3. Identify any new observations
4. Decide whether more testing is needed (max {3 - iteration} more iterations available)

## Response Format
Return ONLY a JSON object:
{{
  "reasoning": "Detailed chain-of-thought analysis of the results...",
  "hypothesis_updates": [
    {{
      "hypothesis_id": "H1",
      "new_confidence": 0.85,
      "status": "CONFIRMED|LIKELY|INCONCLUSIVE|UNLIKELY|REJECTED",
      "reasoning": "Why confidence changed based on evidence..."
    }}
  ],
  "new_observations": ["Any new security observations from the results"],
  "should_continue": false,
  "continuation_rationale": "If true, explain what additional testing would help"
}}"""

    content, _ = _llm_call(llm, prompt, events, "analyst", f"analyzing test results (iteration {iteration})")

    try:
        data = json.loads(_extract_json_from_response(content))
        analysis = TestAnalysis(**data)
    except (json.JSONDecodeError, Exception) as exc:
        print(f"[analyst] Warning: could not parse analysis: {exc}")
        analysis = TestAnalysis(
            reasoning=content[:2000],
            should_continue=False,
        )

    # Print analysis
    print(f"\n[analyst] === Analysis (iteration {iteration}) ===")
    print(f"[analyst] Reasoning: {analysis.reasoning[:300]}...")
    for update in analysis.hypothesis_updates:
        print(f"[analyst]   {update.hypothesis_id}: {update.status} (confidence: {update.new_confidence:.2f})")
        print(f"[analyst]     -> {update.reasoning[:150]}...")
    if analysis.new_observations:
        for obs in analysis.new_observations:
            print(f"[analyst]   [!] New observation: {obs}")
    if analysis.should_continue:
        print(f"[analyst]   -> Wants to continue: {analysis.continuation_rationale}")
    print()

    return results, analysis


def _route_classification(path: str, discovery: dict[str, Any]) -> str:
    """Classify an executed test against the validated discovery inventory."""
    if path in discovery.get("documented_paths", {}):
        return "DOCUMENTED_API_ROUTE"
    for finding in discovery.get("undocumented_findings", []):
        if finding.get("path") == path:
            return finding.get("route_classification", "UNVERIFIED")
    for documented_path in discovery.get("documented_paths", {}):
        prefix = documented_path.split("{", 1)[0].rstrip("/")
        if prefix and path.startswith(prefix):
            return "DOCUMENTED_API_ROUTE"
    return "UNVERIFIED"


def _apply_validation_checks(results: list[ProbeResult]) -> None:
    """Add conservative, deterministic comparison signals for the LLM."""
    by_path: dict[str, list[ProbeResult]] = defaultdict(list)
    for result in results:
        if result.route_classification in {"DOCUMENTED_API_ROUTE", "DISCOVERED_API_ROUTE"}:
            result.validation_checks.append("API_ROUTE_VALIDATED")
        else:
            result.validation_checks.append("ROUTE_NOT_VALIDATED")
        by_path[result.path].append(result)

    for path_results in by_path.values():
        if len(path_results) < 2:
            continue
        statuses = {result.status_code for result in path_results}
        profiles = {result.auth_profile for result in path_results}
        if len(statuses) > 1 and len(profiles) > 1:
            for result in path_results:
                result.validation_checks.append("AUTH_PROFILE_STATUS_DIFFERENTIAL")
        hashes = {result.response_body_sha256 for result in path_results if result.response_body_sha256}
        if len(hashes) == 1 and len(profiles) > 1:
            for result in path_results:
                result.validation_checks.append("AUTH_PROFILE_BODY_EQUIVALENT")
