"""Phase 4 — Test Planning (LLM-driven).

Design specific test cases for the top threat hypotheses.
"""

from __future__ import annotations

import json
import re
from typing import Any

from langchain_openai import ChatOpenAI

from panda.models import APIUnderstanding, ProbeResult, TestCase, ThreatHypothesis

from ..utils import _emit_event, _extract_json_from_response, _llm_call


def _plan_investigation(
    discovery: dict[str, Any],
    understanding: APIUnderstanding,
    hypotheses: list[ThreatHypothesis],
    llm: ChatOpenAI,
    events: list[dict[str, Any]],
    previous_results: list[ProbeResult] | None = None,
    iteration: int = 1,
) -> list[TestCase]:
    """Ask the LLM to design specific test cases for the top hypotheses."""

    previous_context = ""
    if previous_results:
        results_summary = json.dumps(
            [r.model_dump(exclude={"response_headers"}) for r in previous_results],
            indent=2, default=str,
        )
        previous_context = f"""
## Previous Test Results (iteration {iteration - 1})
The following probes have already been executed. Design NEW probes that
build on these results — don't repeat tests that have already been run.

{results_summary}
"""

    hypotheses_json = json.dumps([h.model_dump() for h in hypotheses], indent=2)

    prompt = f"""You are PANDA, an expert API security tester designing targeted probes.

Design specific, safe test cases to investigate the threat hypotheses below.
Each test should have a clear purpose: what it tests, what you expect to see
if the vulnerability exists, and what a secure response looks like.

## Rules
- You may use GET, HEAD, POST, PUT, PATCH, or DELETE methods as appropriate
- You may test any endpoint path — documented or discovered during recon
- Use ONLY the available auth profiles
- Use concrete path parameter values (e.g., 1, 2, 99) for parameterized paths
- For POST/PUT/PATCH, include a request_body field with the JSON body to send
- When testing for Server-Side Request Forgery (SSRF) on webhook/URL endpoints, use internal URLs like `http://127.0.0.1:8000/health` or `http://localhost:8000/admin/reports`
- Design 4-10 test cases, prioritizing the highest-relevance hypotheses
- Each test should be independently meaningful

## API Understanding
{understanding.business_context}

## Available Auth Profiles
{json.dumps(discovery.get('auth_profiles_available', []))}

## Documented Endpoints  
{json.dumps(discovery.get('documented_paths', {}), indent=2)}

## Threat Hypotheses to Investigate
{hypotheses_json}
{previous_context}
## Response Format
Return ONLY a JSON array of test cases:
[
  {{
    "id": "T1",
    "hypothesis_id": "H1",
    "method": "GET",
    "path": "/users/2",
    "query_params": {{}},
    "auth_profile": "user-token",
    "request_body": {{}},
    "reasoning": "Why this specific probe and what it will reveal...",
    "expected_if_vulnerable": "What response means the vulnerability exists...",
    "expected_if_safe": "What response means the API is properly secured..."
  }}
]"""

    label = f"designing test cases (iteration {iteration})"
    content, _ = _llm_call(llm, prompt, events, "test_planner", label)

    try:
        data = json.loads(_extract_json_from_response(content))
        if not isinstance(data, list):
            data = [data]
        tests = [TestCase(**item) for item in data]
    except (json.JSONDecodeError, Exception) as exc:
        print(f"[test_planner] Warning: could not parse test plan: {exc}")
        tests = []

    # Safety validation — flexible method allowance, lenient path matching
    allowed_methods = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"}
    safe_tests = []
    known_paths = set(discovery.get("documented_paths", {}).keys())
    # Also include paths discovered during undocumented probing
    for uf in discovery.get("undocumented_findings", []):
        known_paths.add(uf.get("path", ""))
    # Add paths observed in baseline results
    for br in discovery.get("baseline_results", []):
        known_paths.add(br.get("path", ""))
        if "concrete_path" in br:
            known_paths.add(br["concrete_path"])

    for test in tests:
        method = test.method.upper()
        if method not in allowed_methods:
            _emit_event(events, "safety", "rejected test", "policy",
                        f"{test.id}: method {method} not recognized")
            continue
        # Lenient path matching: accept if any known path is a prefix or
        # if the test path (with IDs replaced) matches a known template
        base_path = re.sub(r"/\d+", "/{id}", test.path)
        # Also try common parameter patterns
        base_path_alt = re.sub(r"/\d+", "/{user_id}", test.path)
        path_ok = (
            test.path in known_paths
            or base_path in known_paths
            or base_path_alt in known_paths
            or any(test.path.startswith(dp.split("{")[0].rstrip("/")) for dp in known_paths if dp)
        )
        if not path_ok:
            _emit_event(events, "safety", "warning", "policy",
                        f"{test.id}: path {test.path} not in known endpoints (allowing anyway)")
        safe_tests.append(test)

    print(f"\n[test_planner] === Test Plan ({len(safe_tests)} tests, iteration {iteration}) ===")
    for t in safe_tests:
        print(f"[test_planner]   {t.id}: {t.method} {t.path} as {t.auth_profile} -> {t.reasoning[:100]}...")
    print()

    return safe_tests
