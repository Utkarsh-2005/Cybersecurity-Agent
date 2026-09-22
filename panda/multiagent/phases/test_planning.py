"""Phase 4 — Test Planning (LLM-driven).

Design specific test cases for the top threat hypotheses.
"""

from __future__ import annotations

import json
import re
import uuid
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
    allow_write: bool = False,
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
- Use GET, HEAD, or OPTIONS by default. This run's explicit write capability is: {allow_write}.
- If write capability is false, do not propose POST, PUT, PATCH, or DELETE.
- If write capability is true, use documented request schemas and prefer isolated test
    identities or harmless updates. Treat DELETE, database reset, bulk actions, and
    destructive state changes as requiring explicit lab authorization; never infer that
    allow_write makes every destructive action safe.
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

## Auth Profile Metadata
{json.dumps(discovery.get('auth_profile_metadata', {}))}

## Documented Endpoints  
{json.dumps(discovery.get('documented_paths', {}), indent=2)}

## Configured Target Route
{json.dumps(discovery.get('target_route', {}), indent=2)}

Use the configured target route as the first probe when it is present. Do not
rename it or replace it with a guessed synonym.

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

    if allow_write:
        tests.extend(_deterministic_lab_write_tests(discovery, hypotheses))

    target_route = discovery.get("target_route") or {}
    target_path = target_route.get("path")
    if target_path:
        existing_target_tests = {test.path.rstrip("/") for test in tests}
        hypothesis_id = hypotheses[0].id if hypotheses else "H1"
        target_tests = [
            TestCase(
                id=f"TARGET-{index}",
                hypothesis_id=hypothesis_id,
                method="GET",
                path=target_path,
                auth_profile=profile_name,
                reasoning="Baseline probe of the user-configured target route.",
                expected_if_vulnerable="A route-specific security-relevant response requiring further analysis.",
                expected_if_safe="A valid route response without unauthorized data exposure.",
            )
            for index, profile_name in enumerate(
                discovery.get("auth_profiles_available", []), start=1
            )
            if profile_name in discovery.get("auth_profiles_available", [])
            and target_path.rstrip("/") not in existing_target_tests
        ]
        tests = target_tests + tests

    # Force paired read probes for object-like documented routes. These probes
    # establish a comparison matrix; the analyst still needs ownership evidence
    # before classifying a result as BOLA.
    existing_probes = {
        (test.method.upper(), test.path, test.auth_profile)
        for test in tests
    }
    existing_results = {
        (result.method.upper(), result.path, result.auth_profile, tuple(sorted(result.query_params.items())))
        for result in previous_results or []
    }
    profile_names = discovery.get("auth_profiles_available", [])
    object_profiles = [name for name in profile_names if name != "anonymous"] or profile_names
    bola_hypothesis = next(
        (hypothesis for hypothesis in hypotheses if hypothesis.owasp_category == "API1:2023-BOLA"),
        None,
    )
    if bola_hypothesis and len(object_profiles) >= 2:
        for template in discovery.get("documented_paths", {}):
            if "{" not in template:
                continue
            concrete = re.sub(
                r"\{([^}]+)\}",
                lambda match: "name1" if "user" in match.group(1).lower() or "name" in match.group(1).lower() else "1",
                template,
            )
            for profile_name in object_profiles[:3]:
                key = ("GET", concrete, profile_name)
                if key in existing_probes:
                    continue
                tests.append(TestCase(
                    id=f"BOLA-{len(tests) + 1}",
                    hypothesis_id=bola_hypothesis.id,
                    method="GET",
                    path=concrete,
                    auth_profile=profile_name,
                    reasoning="Compare the same object identifier across principals as a prerequisite for BOLA analysis.",
                    expected_if_vulnerable="A principal receives another principal's object without authorization.",
                    expected_if_safe="Access is denied or limited to an object owned by the requesting principal.",
                ))
                existing_probes.add(key)

    # Only probe routes that are documented or positively classified as API routes.
    allowed_methods = {"GET", "HEAD", "OPTIONS"}
    if allow_write:
        allowed_methods |= {"POST", "PUT", "PATCH", "DELETE"}
    safe_tests = []
    known_paths = set(discovery.get("documented_paths", {}).keys())
    route_classes = {
        uf.get("path"): uf.get("route_classification")
        for uf in discovery.get("undocumented_findings", [])
    }
    for uf in discovery.get("undocumented_findings", []):
        if uf.get("route_classification") == "DISCOVERED_API_ROUTE":
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
        if test.auth_profile not in discovery.get("auth_profiles_available", []):
            _emit_event(events, "safety", "rejected test", "policy",
                        f"{test.id}: auth profile {test.auth_profile} is unavailable")
            continue
        base_path = re.sub(r"/\d+", "/{id}", test.path)
        base_path_alt = re.sub(r"/\d+", "/{user_id}", test.path)
        path_ok = (
            test.path in known_paths
            or base_path in known_paths
            or base_path_alt in known_paths
            or any(
                re.fullmatch(re.sub(r"\{[^}]+\}", r"[^/]+", template), test.path)
                for template in known_paths if "{" in template
            )
        )
        if not path_ok:
            classification = route_classes.get(test.path, "UNVERIFIED")
            _emit_event(events, "safety", "rejected test", "policy",
                        f"{test.id}: path {test.path} is {classification}, not a validated API route")
            continue
        probe_key = (
            method,
            test.path,
            test.auth_profile,
            tuple(sorted(test.query_params.items())),
        )
        if probe_key in existing_results:
            _emit_event(events, "safety", "rejected test", "policy",
                        f"{test.id}: duplicate probe from a previous iteration")
            continue
        safe_tests.append(test)

    print(f"\n[test_planner] === Test Plan ({len(safe_tests)} tests, iteration {iteration}) ===")
    for t in safe_tests:
        print(f"[test_planner]   {t.id}: {t.method} {t.path} as {t.auth_profile} -> {t.reasoning[:100]}...")
    print()

    return safe_tests


def _deterministic_lab_write_tests(
    discovery: dict[str, Any],
    hypotheses: list[ThreatHypothesis],
) -> list[TestCase]:
    """Guarantee bounded POST/PUT coverage when explicit lab mode is enabled."""
    documented = discovery.get("documented_paths", {})
    profile_names = discovery.get("auth_profiles_available", [])
    auth_profile = next((name for name in profile_names if name != "anonymous"), None)
    if not auth_profile:
        return []
    hypothesis_id = hypotheses[0].id if hypotheses else "H1"
    suffix = uuid.uuid4().hex[:8]
    candidates: list[TestCase] = []

    if "/users" in documented and "post" in documented["/users"]:
        candidates.append(TestCase(
            id="LAB-POST-USERS",
            hypothesis_id=hypothesis_id,
            method="POST",
            path="/users",
            auth_profile=auth_profile,
            request_body={
                "username": f"panda_lab_{suffix}",
                "email": f"panda_lab_{suffix}@example.invalid",
                "full_name": "PANDA Lab User",
                "role": "user",
            },
            reasoning="Bounded lab registration probe for mass-assignment and input handling.",
            expected_if_vulnerable="The server accepts unauthorized role or unexpected fields.",
            expected_if_safe="The server creates only a least-privileged user or rejects the request.",
        ))

    if "/auth/login" in documented and "post" in documented["/auth/login"]:
        candidates.append(TestCase(
            id="LAB-POST-LOGIN",
            hypothesis_id=hypothesis_id,
            method="POST",
            path="/auth/login",
            auth_profile="anonymous",
            request_body={"username": "panda_lab_unknown", "password": "invalid"},
            reasoning="Bounded login error-behavior probe for authentication enumeration.",
            expected_if_vulnerable="The response reveals whether the username exists.",
            expected_if_safe="The response uses a generic authentication failure.",
        ))

    if "/reports/export" in documented and "post" in documented["/reports/export"]:
        candidates.append(TestCase(
            id="LAB-POST-EXPORT",
            hypothesis_id=hypothesis_id,
            method="POST",
            path="/reports/export",
            auth_profile=auth_profile,
            request_body={"report_type": "users", "row_limit": 1},
            reasoning="Bounded low-volume export probe for request validation.",
            expected_if_vulnerable="The endpoint accepts an unsafe export request without limits.",
            expected_if_safe="The request is bounded and validated.",
        ))

    if "/users/{user_id}" in documented and "put" in documented["/users/{user_id}"]:
        candidates.append(TestCase(
            id="LAB-PUT-USER",
            hypothesis_id=hypothesis_id,
            method="PUT",
            path="/users/2",
            auth_profile=auth_profile,
            request_body={"full_name": "PANDA Lab Update"},
            reasoning="Bounded update probe for object-level authorization.",
            expected_if_vulnerable="A user can update an object they do not own.",
            expected_if_safe="The server denies or limits updates to owned objects.",
        ))

    return candidates
