"""PANDA — LLM-driven API security assessment agent.

This module implements the core intelligence pipeline:

  Recon → API Understanding → Threat Modeling → Test Planning
    → Execution + Analysis (loop) → Report Generation

Every key decision is made by the LLM with chain-of-thought reasoning.
Safety guardrails (method allow-lists, rate limiting) are enforced by
deterministic code in ``tools.py``.
"""

from __future__ import annotations

import json
import os
import re
import argparse
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

import requests
from dotenv import load_dotenv
import httpx
from langchain_openai import ChatOpenAI

from panda.models import (
    APIUnderstanding,
    Finding,
    HypothesisUpdate,
    ProbeResult,
    SecurityReport,
    TestAnalysis,
    TestCase,
    ThreatHypothesis,
)
from panda.tools import LiveHTTPExecutor


# ---------------------------------------------------------------------------
# Environment & LLM setup
# ---------------------------------------------------------------------------

def _load_environment() -> None:
    env_candidates = [
        Path(__file__).resolve().parent / ".env",
        Path(__file__).resolve().parents[1] / ".env",
        Path.cwd() / ".env",
    ]
    for env_path in env_candidates:
        if env_path.exists():
            load_dotenv(env_path, override=False)


def _build_llm(*, max_tokens: int = 2048) -> ChatOpenAI:
    _load_environment()

    api_key = os.getenv("OPENROUTER_API_KEY", "").strip()
    if not api_key or api_key.lower() in {"your_openrouter_api_key_here", "placeholder"}:
        raise RuntimeError(
            "OpenRouter is not configured. Replace the placeholder OPENROUTER_API_KEY "
            "in the root .env file with a real key."
        )
    return ChatOpenAI(
        model=os.getenv("OPENROUTER_MODEL", "openai/gpt-4o-mini"),
        temperature=0.2,
        max_tokens=max_tokens,
        api_key=api_key,
        base_url=os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1"),
        default_headers={
            "HTTP-Referer": "https://github.com/panda-security-agent",
            "X-Title": "PANDA API Security Agent",
        },
        http_client=httpx.Client(verify=False),
    )


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def _base_url(target_url: str) -> str:
    parsed = urlparse(target_url)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError("Target must be an absolute URL such as http://127.0.0.1:8000")
    return f"{parsed.scheme}://{parsed.netloc}/"


def _extract_usage(response: Any) -> dict[str, Any]:
    usage = getattr(response, "usage_metadata", None) or {}
    return {
        "input_tokens": usage.get("input_tokens", usage.get("prompt_token_count")),
        "output_tokens": usage.get("output_tokens", usage.get("candidates_token_count")),
        "total_tokens": usage.get("total_tokens", usage.get("total_token_count")),
    }


def _short_error(exc: Exception, limit: int = 300) -> str:
    detail = str(exc)
    if "<html" in detail.lower() or "<!doctype" in detail.lower():
        return "provider returned HTML instead of JSON; check proxy/Zscaler routing or OPENROUTER_BASE_URL"
    return detail[:limit]


def _emit_event(
    events: list[dict[str, Any]],
    agent: str,
    action: str,
    tool: str | None = None,
    detail: str = "",
    usage: dict[str, Any] | None = None,
) -> None:
    event = {"agent": agent, "action": action, "tool": tool, "detail": detail}
    if usage is not None:
        event["usage"] = usage
    events.append(event)
    tool_text = f" tool={tool}" if tool else ""
    usage_text = f" usage={json.dumps(usage)}" if usage else ""
    print(f"[agent={agent}] {action}{tool_text}: {detail}{usage_text}")


def _auth_profiles() -> dict[str, dict[str, str]]:
    _load_environment()
    raw_profiles = os.getenv("PANDA_AUTH_PROFILES_JSON", "")
    if not raw_profiles:
        return {"anonymous": {}}
    try:
        profiles = json.loads(raw_profiles)
    except json.JSONDecodeError as exc:
        raise ValueError("PANDA_AUTH_PROFILES_JSON must contain a JSON object") from exc
    if not isinstance(profiles, dict) or not all(isinstance(v, dict) for v in profiles.values()):
        raise ValueError("PANDA_AUTH_PROFILES_JSON must map profile names to HTTP header objects")
    return {"anonymous": {}, **profiles}


# ---------------------------------------------------------------------------
# LLM call helper with structured output parsing
# ---------------------------------------------------------------------------

def _extract_json_from_response(content: str) -> str:
    """Extract JSON from LLM response, handling markdown code blocks."""
    content = content.strip()
    # Try to find JSON in code blocks first
    code_block_match = re.search(r"```(?:json)?\s*\n?(.*?)\n?```", content, re.DOTALL)
    if code_block_match:
        return code_block_match.group(1).strip()
    # If the content starts with { or [, treat it as raw JSON
    if content.startswith("{") or content.startswith("["):
        return content
    # Last resort: find the first { and last }
    first_brace = content.find("{")
    last_brace = content.rfind("}")
    if first_brace >= 0 and last_brace > first_brace:
        return content[first_brace : last_brace + 1]
    return content


def _llm_call(
    llm: ChatOpenAI,
    system_prompt: str,
    events: list[dict[str, Any]],
    agent_name: str,
    purpose: str,
) -> tuple[str, dict[str, Any]]:
    """Invoke the LLM and return (content, usage_dict).

    Centralises event logging, error handling, and JSON extraction.
    """
    _emit_event(events, agent_name, "started", "openrouter", purpose)
    try:
        response = llm.invoke([("system", system_prompt)])
        usage = _extract_usage(response)
        content = response.content.strip()
        _emit_event(events, agent_name, "completed", "openrouter", purpose, usage)
        return content, usage
    except Exception as exc:
        detail = _short_error(exc, 500)
        _emit_event(events, agent_name, "failed", "openrouter", detail)
        raise RuntimeError(f"LLM call failed ({agent_name}): {detail}") from exc


# ---------------------------------------------------------------------------
# Phase 1 — Reconnaissance (deterministic)
# ---------------------------------------------------------------------------

def _discover_api(
    target_url: str,
    events: list[dict[str, Any]],
) -> dict[str, Any]:
    """Discover the target through its documentation and baseline probes."""
    base_url = _base_url(target_url)
    session = requests.Session()
    session.headers.update({"User-Agent": "PANDA-discovery/1.0"})

    # --- Fetch OpenAPI schema ---
    _emit_event(events, "recon", "started", "openapi_discovery", "learning the API contract")

    docs_url = urljoin(base_url, "docs")
    docs_response = session.get(docs_url, timeout=5)
    _emit_event(events, "recon", "called tool", "http_get", f"/docs -> {docs_response.status_code}")
    print(f"[recon] GET {docs_url} -> {docs_response.status_code}")

    schema_url = urljoin(base_url, "openapi.json")
    schema_response = session.get(schema_url, timeout=5)
    _emit_event(events, "recon", "called tool", "http_get", f"/openapi.json -> {schema_response.status_code}")
    print(f"[recon] GET {schema_url} -> {schema_response.status_code}")

    schema: dict[str, Any] = {}
    if schema_response.ok:
        try:
            schema = schema_response.json()
        except ValueError:
            print("[recon] OpenAPI response was not valid JSON.")

    # Parse documented paths
    paths = schema.get("paths", {})
    print(f"[recon] discovered {len(paths)} documented paths")
    documented_paths: dict[str, Any] = {}
    for path, operations in paths.items():
        methods = ", ".join(
            m.upper() for m in operations if m in {"get", "post", "put", "patch", "delete"}
        )
        print(f"[recon]   {methods or 'UNKNOWN'} {path}")
        documented_paths[path] = {
            method: {
                "summary": op.get("summary", ""),
                "parameters": [
                    {"name": p.get("name"), "in": p.get("in"), "required": p.get("required", False)}
                    for p in op.get("parameters", [])
                ],
                "responses": sorted(op.get("responses", {}).keys()),
                "request_body": bool(op.get("requestBody")),
            }
            for method, op in operations.items()
            if method in {"get", "post", "put", "patch", "delete"} and isinstance(op, dict)
        }

    # --- Baseline probes: hit every GET endpoint with every auth profile ---
    profiles = _auth_profiles()
    baseline_results: list[dict[str, Any]] = []

    for path, operations in documented_paths.items():
        if "get" not in operations:
            continue
        # Skip paths with path parameters for baseline (we'll test those in the investigation)
        if "{" in path:
            continue
        for profile_name, headers in profiles.items():
            url = urljoin(base_url, path.lstrip("/"))
            try:
                resp = session.get(url, headers=headers, timeout=5)
                result: dict[str, Any] = {
                    "path": path,
                    "auth_profile": profile_name,
                    "status_code": resp.status_code,
                }
                try:
                    body = resp.json()
                    result["response_body"] = json.dumps(body, indent=2, default=str)[:1500]
                    result["response_fields"] = sorted(body.keys()) if isinstance(body, dict) else []
                except ValueError:
                    result["response_body"] = resp.text[:500]
                baseline_results.append(result)
                _emit_event(events, "recon", "called tool", "http_get",
                            f"{path} ({profile_name}) -> {resp.status_code}")
                print(f"[recon] GET {url} ({profile_name}) -> {resp.status_code}")
            except requests.RequestException as exc:
                baseline_results.append({
                    "path": path, "auth_profile": profile_name,
                    "status_code": 0, "error": str(exc)[:200],
                })

    # Also test a couple of parameterized paths with simple IDs
    for path, operations in documented_paths.items():
        if "get" not in operations or "{" not in path:
            continue
        for test_id in ["1", "2"]:
            concrete = re.sub(r"\{[^}]+\}", test_id, path)
            for profile_name, headers in profiles.items():
                url = urljoin(base_url, concrete.lstrip("/"))
                try:
                    resp = session.get(url, headers=headers, timeout=5)
                    result = {
                        "path": path,
                        "concrete_path": concrete,
                        "path_value": test_id,
                        "auth_profile": profile_name,
                        "status_code": resp.status_code,
                    }
                    try:
                        body = resp.json()
                        result["response_body"] = json.dumps(body, indent=2, default=str)[:1500]
                    except ValueError:
                        result["response_body"] = resp.text[:500]
                    baseline_results.append(result)
                    _emit_event(events, "recon", "called tool", "http_get",
                                f"{concrete} ({profile_name}) -> {resp.status_code}")
                    print(f"[recon] GET {url} ({profile_name}) -> {resp.status_code}")
                except requests.RequestException:
                    pass

    _emit_event(events, "recon", "completed", detail=f"discovered {len(paths)} paths, ran {len(baseline_results)} baseline probes")

    return {
        "target_url": target_url,
        "base_url": base_url,
        "openapi_schema": schema,
        "api_title": schema.get("info", {}).get("title", ""),
        "api_version": schema.get("info", {}).get("version", ""),
        "documented_paths": documented_paths,
        "baseline_results": baseline_results,
        "auth_profiles_available": list(profiles.keys()),
    }


# ---------------------------------------------------------------------------
# Phase 2 — API Understanding (LLM-driven)
# ---------------------------------------------------------------------------

def _understand_api(
    discovery: dict[str, Any],
    llm: ChatOpenAI,
    events: list[dict[str, Any]],
) -> APIUnderstanding:
    """Ask the LLM to reason about what this API does and identify
    security-relevant patterns."""

    prompt = f"""You are PANDA, an expert API security analyst. You have just completed
reconnaissance on a target API. Analyze the data below to understand what this API
does, who its users are, and what security-relevant patterns you observe.

Think step-by-step. First reason about the business context, then identify data models
and relationships, then note security-relevant observations.

## API Information
- Title: {discovery.get('api_title', 'Unknown')}
- Version: {discovery.get('api_version', 'Unknown')}
- Auth profiles available: {json.dumps(discovery.get('auth_profiles_available', []))}

## Documented Endpoints
{json.dumps(discovery.get('documented_paths', {}), indent=2)}

## Baseline Probe Results
{json.dumps(discovery.get('baseline_results', []), indent=2, default=str)}

## Response Format
Return ONLY a JSON object with this exact structure:
{{
  "reasoning": "Your detailed chain-of-thought analysis...",
  "business_context": "One-paragraph summary of what this API does...",
  "api_type": "Category of API...",
  "data_models": [
    {{
      "name": "Model name",
      "fields": ["field1", "field2"],
      "sensitive_fields": ["field_that_contains_PII_or_secrets"],
      "relationships": ["Related to X via Y"]
    }}
  ],
  "auth_patterns": [
    {{
      "mechanism": "How auth works",
      "roles_observed": ["role1", "role2"],
      "observations": ["observation about auth behavior"]
    }}
  ],
  "security_relevant_observations": ["observation1", "observation2"]
}}"""

    content, _ = _llm_call(llm, prompt, events, "understanding", "analyzing API structure and business context")

    try:
        data = json.loads(_extract_json_from_response(content))
        understanding = APIUnderstanding(**data)
    except (json.JSONDecodeError, Exception) as exc:
        print(f"[understanding] Warning: could not parse structured output, using raw reasoning: {exc}")
        understanding = APIUnderstanding(
            reasoning=content[:2000],
            business_context="Could not parse structured understanding; raw analysis available in reasoning field.",
            api_type="Unknown",
        )

    # Print the reasoning for visibility
    print(f"\n[understanding] === LLM Reasoning ===")
    print(f"[understanding] Business context: {understanding.business_context}")
    print(f"[understanding] API type: {understanding.api_type}")
    for obs in understanding.security_relevant_observations:
        print(f"[understanding]   [!] {obs}")
    print()

    return understanding


# ---------------------------------------------------------------------------
# Phase 3 — Threat Modeling (LLM-driven)
# ---------------------------------------------------------------------------

def _model_threats(
    discovery: dict[str, Any],
    understanding: APIUnderstanding,
    llm: ChatOpenAI,
    events: list[dict[str, Any]],
) -> list[ThreatHypothesis]:
    """Ask the LLM to generate ranked threat hypotheses based on the API
    understanding and OWASP API Security Top 10."""

    prompt = f"""You are PANDA, an expert API security analyst performing threat modeling.
Based on your understanding of this API, generate ranked threat hypotheses.

Think like a real penetration tester: consider the OWASP API Security Top 10 (2023),
but ONLY include threats that are actually relevant to THIS specific API based on the
evidence you've seen. Don't include every OWASP category — only the ones that make
sense given the API's structure and behavior.

## Your API Understanding
{understanding.model_dump_json(indent=2)}

## Available Auth Profiles
{json.dumps(discovery.get('auth_profiles_available', []))}

## Documented Endpoints
{json.dumps(discovery.get('documented_paths', {}), indent=2)}

## Baseline Results Summary
{json.dumps(discovery.get('baseline_results', []), indent=2, default=str)}

## OWASP API Security Top 10 (2023) Reference
- API1:2023-BOLA — Broken Object Level Authorization
- API2:2023-Broken-Authentication — Broken Authentication  
- API3:2023-Broken-Object-Property-Level-Authorization — Excessive data exposure, mass assignment
- API4:2023-Unrestricted-Resource-Consumption — Rate limiting, resource exhaustion
- API5:2023-Broken-Function-Level-Authorization — Admin/user function separation
- API6:2023-Unrestricted-Access-to-Sensitive-Business-Flows — Business logic abuse
- API7:2023-Server-Side-Request-Forgery — SSRF
- API8:2023-Security-Misconfiguration — Headers, CORS, verbose errors, debug endpoints
- API9:2023-Improper-Inventory-Management — Undocumented endpoints, version differences
- API10:2023-Unsafe-Consumption-of-APIs — Third-party API trust issues

## Response Format
Return ONLY a JSON array of threat hypotheses, ranked by relevance_score (highest first):
[
  {{
    "id": "H1",
    "owasp_category": "API1:2023-BOLA",
    "title": "Short descriptive title",
    "reasoning": "Detailed chain-of-thought explaining WHY this is relevant to THIS API...",
    "relevance_score": 0.9,
    "affected_endpoints": ["/path1", "/path2"],
    "suggested_probes": ["Description of what to test"]
  }}
]

Generate 3-7 hypotheses. Be specific — don't generate generic threats."""

    content, _ = _llm_call(llm, prompt, events, "threat_modeling", "generating ranked threat hypotheses")

    try:
        data = json.loads(_extract_json_from_response(content))
        if not isinstance(data, list):
            data = [data]
        hypotheses = [ThreatHypothesis(**item) for item in data]
    except (json.JSONDecodeError, Exception) as exc:
        print(f"[threat_modeling] Warning: could not parse hypotheses: {exc}")
        hypotheses = [ThreatHypothesis(
            id="H1", owasp_category="OTHER", title="Unparsed threat analysis",
            reasoning=content[:1500], relevance_score=0.5,
        )]

    # Sort by relevance
    hypotheses.sort(key=lambda h: h.relevance_score, reverse=True)

    print(f"\n[threat_modeling] === Threat Hypotheses ({len(hypotheses)}) ===")
    for h in hypotheses:
        print(f"[threat_modeling]   {h.id}: [{h.owasp_category}] {h.title} (relevance: {h.relevance_score:.1f})")
        print(f"[threat_modeling]     -> {h.reasoning[:150]}...")
    print()

    return hypotheses


# ---------------------------------------------------------------------------
# Phase 4 — Test Planning (LLM-driven)
# ---------------------------------------------------------------------------

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
- ONLY use GET or HEAD methods (safety policy)
- Use ONLY the documented endpoint paths from the API
- Use ONLY the available auth profiles
- Use concrete path parameter values (e.g., 1, 2, 99) for parameterized paths
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

    # Safety validation — reject any non-GET/HEAD tests
    safe_tests = []
    known_paths = set(discovery.get("documented_paths", {}).keys())
    for test in tests:
        method = test.method.upper()
        if method not in {"GET", "HEAD"}:
            _emit_event(events, "safety", "rejected test", "policy",
                        f"{test.id}: method {method} not allowed")
            continue
        # Check that the base path (without parameter substitutions) exists
        base_path = re.sub(r"/\d+", "/{id}", test.path)
        # Be lenient: accept the test if any documented path is a prefix match
        path_ok = any(
            test.path.startswith(dp.split("{")[0]) for dp in known_paths
        ) or test.path in known_paths or base_path in known_paths
        if not path_ok:
            _emit_event(events, "safety", "rejected test", "policy",
                        f"{test.id}: path {test.path} not in documented endpoints")
            continue
        safe_tests.append(test)

    print(f"\n[test_planner] === Test Plan ({len(safe_tests)} tests, iteration {iteration}) ===")
    for t in safe_tests:
        print(f"[test_planner]   {t.id}: {t.method} {t.path} as {t.auth_profile} -> {t.reasoning[:100]}...")
    print()

    return safe_tests


# ---------------------------------------------------------------------------
# Phase 5 — Execution + Analysis (deterministic exec, LLM analysis)
# ---------------------------------------------------------------------------

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
        results.append(result)
        status = result.status_code if result.status_code else f"ERROR: {result.error}"
        _emit_event(events, "executor", "called tool", "http_request",
                    f"{result.method} {result.path} ({result.auth_profile}) -> {status}")
        print(f"[executor] {result.method} {result.url} ({result.auth_profile}) -> {status} ({result.response_time_ms:.0f}ms)")

    # Ask LLM to analyze results
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


# ---------------------------------------------------------------------------
# Phase 6 — Report Generation (LLM-driven)
# ---------------------------------------------------------------------------

def _generate_report(
    discovery: dict[str, Any],
    understanding: APIUnderstanding,
    hypotheses: list[ThreatHypothesis],
    all_results: list[ProbeResult],
    all_analyses: list[TestAnalysis],
    llm: ChatOpenAI,
    events: list[dict[str, Any]],
) -> SecurityReport:
    """Ask the LLM to synthesize all evidence into a structured security report."""

    # Compile evidence summary
    results_summary = json.dumps(
        [r.model_dump(exclude={"response_headers"}) for r in all_results],
        indent=2, default=str,
    )
    analyses_summary = json.dumps(
        [a.model_dump() for a in all_analyses],
        indent=2, default=str,
    )
    hypotheses_json = json.dumps([h.model_dump() for h in hypotheses], indent=2)

    prompt = f"""You are PANDA, an expert API security consultant writing a professional
security assessment report. Synthesize all the evidence from your investigation into
a comprehensive, actionable report.

Write like a senior penetration tester delivering findings to a development team.
Be specific: cite exact HTTP requests and responses as evidence. Rate severity
accurately — don't inflate or deflate. Provide actionable, specific remediation
guidance (not generic advice).

## API Understanding
{understanding.model_dump_json(indent=2)}

## Threat Hypotheses Investigated
{hypotheses_json}

## All Test Results
{results_summary}

## Analysis Notes
{analyses_summary}

## OWASP Categories for Reference
- API1:2023-BOLA, API2:2023-Broken-Authentication,
  API3:2023-Broken-Object-Property-Level-Authorization,
  API4:2023-Unrestricted-Resource-Consumption,
  API5:2023-Broken-Function-Level-Authorization,
  API6:2023-Unrestricted-Access-to-Sensitive-Business-Flows,
  API7:2023-Server-Side-Request-Forgery,
  API8:2023-Security-Misconfiguration,
  API9:2023-Improper-Inventory-Management,
  API10:2023-Unsafe-Consumption-of-APIs, OTHER

## Response Format
Return ONLY a JSON object:
{{
  "reasoning": "Your chain-of-thought about the overall security posture...",
  "executive_summary": "2-3 paragraph executive summary...",
  "api_overview": "Description of the assessed API...",
  "findings": [
    {{
      "id": "F1",
      "title": "Finding title",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
      "owasp_category": "API1:2023-BOLA",
      "description": "Detailed description of the vulnerability...",
      "evidence": ["Specific HTTP request/response evidence..."],
      "impact": "What an attacker could achieve...",
      "remediation": "Specific, actionable fix...",
      "confidence": 0.9
    }}
  ],
  "positive_observations": ["Security controls that are working correctly..."],
  "methodology_notes": "Brief description of testing methodology...",
  "limitations": ["Read-only testing only", "No authentication bypass attempts", "..."]
}}"""

    content, _ = _llm_call(llm, prompt, events, "report_generator", "synthesizing final security report")

    try:
        data = json.loads(_extract_json_from_response(content))
        report = SecurityReport(**data)
    except (json.JSONDecodeError, Exception) as exc:
        print(f"[report] Warning: could not parse structured report: {exc}")
        report = SecurityReport(
            reasoning=content[:2000],
            executive_summary="Report generation encountered a parsing error. Raw analysis is available in the reasoning field.",
            api_overview=understanding.business_context,
        )

    return report


# ---------------------------------------------------------------------------
# Report rendering (Markdown)
# ---------------------------------------------------------------------------

def _render_markdown_report(
    target_url: str,
    understanding: APIUnderstanding,
    hypotheses: list[ThreatHypothesis],
    report: SecurityReport,
    all_results: list[ProbeResult],
    events: list[dict[str, Any]],
) -> str:
    """Render the SecurityReport into a human-readable Markdown document."""

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    sorted_findings = sorted(report.findings, key=lambda f: severity_order.get(f.severity, 5))

    severity_emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"}

    lines = [
        "# PANDA Security Assessment Report",
        "",
        f"- **Target:** `{target_url}`",
        f"- **Generated:** `{timestamp}`",
        f"- **API:** {understanding.api_type} — {understanding.business_context[:100]}",
        f"- **Findings:** {len(report.findings)} ({sum(1 for f in report.findings if f.severity in {'CRITICAL', 'HIGH'})} high/critical)",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
        report.executive_summary,
        "",
        "---",
        "",
        "## API Overview",
        "",
        report.api_overview,
        "",
    ]

    # Findings
    if sorted_findings:
        lines.extend(["---", "", "## Security Findings", ""])
        for finding in sorted_findings:
            emoji = severity_emoji.get(finding.severity, "⚪")
            lines.extend([
                f"### {emoji} {finding.id}: {finding.title}",
                "",
                f"| Property | Value |",
                f"|----------|-------|",
                f"| **Severity** | {finding.severity} |",
                f"| **OWASP Category** | {finding.owasp_category} |",
                f"| **Confidence** | {finding.confidence:.0%} |",
                "",
                f"**Description:** {finding.description}",
                "",
                f"**Impact:** {finding.impact}",
                "",
            ])
            if finding.evidence:
                lines.append("**Evidence:**")
                for ev in finding.evidence:
                    lines.append(f"- {ev}")
                lines.append("")
            lines.extend([
                f"**Remediation:** {finding.remediation}",
                "",
            ])
    else:
        lines.extend([
            "---", "",
            "## Security Findings", "",
            "No significant security findings were identified during this assessment.",
            "",
        ])

    # Positive observations
    if report.positive_observations:
        lines.extend(["---", "", "## Positive Observations", ""])
        for obs in report.positive_observations:
            lines.append(f"- ✅ {obs}")
        lines.append("")

    # Threat model
    lines.extend(["---", "", "## Threat Model", ""])
    for h in hypotheses:
        status_emoji = {"CONFIRMED": "🔴", "LIKELY": "🟠", "INCONCLUSIVE": "🟡", "UNLIKELY": "🔵", "REJECTED": "⚪"}
        lines.append(f"- **{h.id}** [{h.owasp_category}] {h.title} — relevance: {h.relevance_score:.1f}")
    lines.append("")

    # Test summary
    lines.extend(["---", "", "## Test Execution Summary", ""])
    lines.append(f"| # | Method | Path | Auth | Status | Time |")
    lines.append(f"|---|--------|------|------|--------|------|")
    for i, r in enumerate(all_results, 1):
        status = str(r.status_code) if r.status_code else f"ERR"
        lines.append(f"| {i} | `{r.method}` | `{r.path}` | `{r.auth_profile}` | **{status}** | {r.response_time_ms:.0f}ms |")
    lines.append("")

    # Methodology & limitations
    if report.methodology_notes:
        lines.extend(["---", "", "## Methodology", "", report.methodology_notes, ""])
    if report.limitations:
        lines.extend(["---", "", "## Limitations", ""])
        for lim in report.limitations:
            lines.append(f"- {lim}")
        lines.append("")

    # Agent decision log
    lines.extend(["---", "", "## Agent Decision Log", ""])
    for i, event in enumerate(events, 1):
        tool = f" via `{event['tool']}`" if event.get("tool") else ""
        detail = event.get("detail", "").replace("\n", " ")[:150]
        usage = event.get("usage")
        usage_text = f" tokens=`{json.dumps(usage, separators=(',', ':'))}`" if usage else ""
        lines.append(f"{i}. **{event['agent']}** `{event['action']}`{tool}. {detail}.{usage_text}")
    lines.append("")

    return "\n".join(lines)


def _write_markdown_report(
    target_url: str,
    markdown: str,
    discovery: dict[str, Any],
) -> Path:
    reports_dir = Path.cwd() / "reports"
    reports_dir.mkdir(exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    report_path = reports_dir / f"panda_report_{timestamp}.md"
    report_path.write_text(markdown, encoding="utf-8")
    return report_path


# ---------------------------------------------------------------------------
# Main pipeline orchestrator
# ---------------------------------------------------------------------------

_MAX_INVESTIGATION_ITERATIONS = 3


def run_panda_assessment(target_url: str) -> str:
    """Run the full LLM-driven PANDA security assessment pipeline."""

    print("\n" + "=" * 60)
    print("  PANDA — LLM-Driven API Security Assessment")
    print("=" * 60)
    print(f"  Target: {target_url}")
    print("=" * 60 + "\n")

    events: list[dict[str, Any]] = []

    # --- Phase 1: Reconnaissance ---
    print("\n" + "-" * 40)
    print("  Phase 1: Reconnaissance")
    print("-" * 40)
    try:
        discovery = _discover_api(target_url, events)
    except (requests.RequestException, ValueError) as exc:
        msg = f"\nPANDA could not reach the target API: {exc}\n"
        print(msg)
        return msg

    # --- Build LLM and executor ---
    try:
        llm = _build_llm(max_tokens=2048)
    except RuntimeError as exc:
        msg = f"\nPANDA requires an LLM: {exc}\n"
        print(msg)
        return msg

    profiles = _auth_profiles()
    executor = LiveHTTPExecutor(
        base_url=discovery["base_url"],
        auth_profiles=profiles,
        rate_limit=30,
    )

    # --- Phase 2: API Understanding ---
    print("\n" + "-" * 40)
    print("  Phase 2: API Understanding (LLM)")
    print("-" * 40)
    understanding = _understand_api(discovery, llm, events)

    # --- Phase 3: Threat Modeling ---
    print("\n" + "-" * 40)
    print("  Phase 3: Threat Modeling (LLM)")
    print("-" * 40)
    hypotheses = _model_threats(discovery, understanding, llm, events)

    # --- Phase 4+5: Investigation Loop ---
    all_results: list[ProbeResult] = []
    all_analyses: list[TestAnalysis] = []

    for iteration in range(1, _MAX_INVESTIGATION_ITERATIONS + 1):
        print("\n" + "-" * 40)
        print(f"  Phase 4: Test Planning (iteration {iteration})")
        print("-" * 40)

        tests = _plan_investigation(
            discovery, understanding, hypotheses, llm, events,
            previous_results=all_results if all_results else None,
            iteration=iteration,
        )
        if not tests:
            print("[pipeline] No tests generated, ending investigation.")
            _emit_event(events, "pipeline", "investigation ended", detail="no tests generated")
            break

        print("\n" + "-" * 40)
        print(f"  Phase 5: Execution + Analysis (iteration {iteration})")
        print("-" * 40)

        results, analysis = _execute_and_analyze(
            discovery, understanding, hypotheses, tests,
            executor, llm, events, iteration,
        )
        all_results.extend(results)
        all_analyses.append(analysis)

        # Update hypotheses with new confidence levels
        for update in analysis.hypothesis_updates:
            for h in hypotheses:
                if h.id == update.hypothesis_id:
                    h.confidence = update.new_confidence
                    # Map analysis status to hypothesis status
                    status_map = {
                        "CONFIRMED": "CONFIRMED",
                        "LIKELY": "PARTIAL",
                        "INCONCLUSIVE": "INCONCLUSIVE",
                        "UNLIKELY": "OPEN",
                        "REJECTED": "REJECTED",
                    }
                    h.status = status_map.get(update.status, "OPEN")

        if not analysis.should_continue:
            _emit_event(events, "pipeline", "investigation complete",
                        detail=f"analyst decided to stop after {iteration} iteration(s)")
            break
        if iteration < _MAX_INVESTIGATION_ITERATIONS:
            _emit_event(events, "pipeline", "continuing investigation",
                        detail=analysis.continuation_rationale[:200])

    # --- Phase 6: Report Generation ---
    print("\n" + "-" * 40)
    print("  Phase 6: Report Generation (LLM)")
    print("-" * 40)

    report = _generate_report(
        discovery, understanding, hypotheses,
        all_results, all_analyses, llm, events,
    )

    # Render and save
    markdown = _render_markdown_report(
        target_url, understanding, hypotheses,
        report, all_results, events,
    )

    report_path = _write_markdown_report(target_url, markdown, discovery)

    print("\n" + "=" * 60)
    print("  Assessment Complete")
    print("=" * 60)
    print(f"\n[report] Markdown report written to {report_path}")
    print(f"[report] Findings: {len(report.findings)}")
    for f in report.findings:
        emoji = {"CRITICAL": "[CRITICAL]", "HIGH": "[HIGH]", "MEDIUM": "[MEDIUM]", "LOW": "[LOW]", "INFO": "[INFO]"}.get(f.severity, "[INFO]")
        print(f"[report]   {emoji} {f.id}: {f.title} ({f.severity}, confidence: {f.confidence:.0%})")
    print()

    return markdown


# ---------------------------------------------------------------------------
# Backward-compatible entry points
# ---------------------------------------------------------------------------

def build_multiagent_system() -> dict[str, Any]:
    """Legacy shim — kept for backward compatibility."""
    llm = _build_llm()
    return {
        "planner_agent": llm,
        "executor_agent": "policy-validated read-only HTTP tool agent",
        "report_agent": "LLM-driven evidence synthesis agent",
    }


def run_panda_demo(
    target_url: str,
    discovery: dict[str, Any],
    events: list[dict[str, Any]],
) -> str:
    """Legacy shim — redirects to the new pipeline."""
    return run_panda_assessment(target_url)


def run_terminal_demo(target_url: str, question: str | None = None) -> str:
    """Run an autonomous URL-only assessment."""
    del question
    return run_panda_assessment(target_url)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run PANDA autonomously against a user-provided API URL."
    )
    parser.add_argument(
        "target_url",
        help="Absolute API URL, for example http://127.0.0.1:8000",
    )
    args = parser.parse_args()
    run_panda_assessment(args.target_url)


if __name__ == "__main__":
    main()
