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

    # Include write-method probe results if available
    write_method_context = ""
    write_results = discovery.get("write_method_results", [])
    if write_results:
        write_method_context = f"""
## Write-Method Recon Results (POST/PUT/PATCH/DELETE probes from recon)
These are responses from probing write endpoints with empty bodies during recon.
Study the error messages, status codes, and field names — they reveal expected
request schemas, authorization behavior, and potential attack surfaces.

{json.dumps(write_results, indent=2, default=str)}
"""

    prompt = f"""You are PANDA, an expert API security tester designing targeted probes.

Design specific, safe test cases to investigate the threat hypotheses below.
Each test should have a clear purpose: what it tests, what you expect to see
if the vulnerability exists, and what a secure response looks like.

## Rules
- You MUST use GET, POST, PUT, PATCH, and DELETE methods as appropriate — do NOT limit yourself to GET
- You may test any endpoint path — documented or discovered during recon
- Use ONLY the available auth profiles
- Use concrete path parameter values (e.g., 1, 2, 99) for parameterized paths
- For POST/PUT/PATCH, include a request_body field with the JSON body to send
- Design 6-15 test cases, prioritizing the highest-relevance hypotheses
- Each test should be independently meaningful
- IMPORTANT: You must include tests for write-method endpoints (POST, PUT, PATCH), not just GET

## Attack Pattern Reference
Use these concrete attack patterns when designing probes:

### BOLA (API1) — Broken Object Level Authorization
- Access another user's resource: GET /users/2 with user-token (if user-token belongs to user 1)
- Access settings/profile of another user: GET /users/2/settings with user-token

### Broken Authentication (API2)
- Test differential errors: POST /auth/login with valid username + wrong password, then invalid username + any password — compare error messages
- Look for "User not found" vs "Invalid password" differences that leak username existence

### Mass Assignment (API3) — Broken Object Property Level Authorization
- Send privileged fields in creation: POST /users with {{"role": "admin"}} in the body
- Check if response contains the elevated role

### Unrestricted Resource Consumption (API4)
- Send extreme values: POST /reports/export with {{"row_limit": 999999999}}
- Look for acceptance without validation

### BFLA (API5) — Broken Function Level Authorization
- Access admin endpoints with user credentials: GET /admin/users/export with user-token
- If it returns data instead of 403, it's broken

### SSRF (API7) — Server-Side Request Forgery
- On webhook/URL-accepting endpoints: POST /webhooks/test with {{"target_url": "http://127.0.0.1:8000/health"}} or "http://localhost:8000/admin/reports"
- If the server fetches internal resources and returns them, it's vulnerable

### IDOR via Write Methods
- Update another user's data: PUT /users/2 with user-token (belonging to user 1) and a modified body
- If it succeeds (200), there's no ownership check

## API Understanding
{understanding.business_context}

## Available Auth Profiles
{json.dumps(discovery.get('auth_profiles_available', []))}

## Documented Endpoints  
{json.dumps(discovery.get('documented_paths', {}), indent=2)}
{write_method_context}
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
