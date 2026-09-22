"""Phase 3 — Threat Modeling (LLM-driven).

Generate ranked threat hypotheses based on the API understanding and
OWASP API Security Top 10.
"""

from __future__ import annotations

import json
from typing import Any

from langchain_openai import ChatOpenAI

from panda.models import APIUnderstanding, ThreatHypothesis

from ..utils import _extract_json_from_response, _llm_call


def _model_threats(
    discovery: dict[str, Any],
    understanding: APIUnderstanding,
    llm: ChatOpenAI,
    events: list[dict[str, Any]],
) -> list[ThreatHypothesis]:
    """Ask the LLM to generate ranked threat hypotheses based on the API
    understanding and OWASP API Security Top 10."""

    # Include write-method probe results if available
    write_method_context = ""
    write_results = discovery.get("write_method_results", [])
    if write_results:
        write_method_context = f"""
## Write-Method Probe Results (POST/PUT/PATCH/DELETE from recon)
These show how write endpoints respond with different auth profiles and empty bodies.
Analyze error messages, status codes, and schema hints to identify attack surfaces.

{json.dumps(write_results, indent=2, default=str)}
"""

    prompt = f"""You are PANDA, an expert API security analyst performing threat modeling.
Based on your understanding of this API, generate ranked threat hypotheses.

Think like a real penetration tester: consider the OWASP API Security Top 10 (2023),
but ONLY include threats that are actually relevant to THIS specific API based on the
evidence you've seen. Don't include every OWASP category — only the ones that make
sense given the API's structure and behavior.

Pay special attention to:
- Endpoints that accept user IDs or object IDs in the path — potential BOLA/IDOR
- POST/PUT endpoints that accept role, permission, or privilege fields — mass assignment
- Admin endpoints accessible without admin role verification — BFLA
- Login/auth endpoints with different error messages for different failure modes — info leakage
- Endpoints that accept URLs or file paths — SSRF
- Endpoints that accept numeric limits without validation — resource consumption
- Deprecated or versioned endpoints (e.g. /api/v1/) that lack auth — improper inventory management
- Excessive PII in list responses — data exposure

## Your API Understanding
{understanding.model_dump_json(indent=2)}

## Available Auth Profiles
{json.dumps(discovery.get('auth_profiles_available', []))}

## Documented Endpoints
{json.dumps(discovery.get('documented_paths', {}), indent=2)}

## Baseline Results Summary
{json.dumps(discovery.get('baseline_results', []), indent=2, default=str)}

## Undocumented Endpoint Findings
{json.dumps(discovery.get('undocumented_findings', []), indent=2, default=str)}
{write_method_context}
## OWASP API Security Top 10 (2023) — With Concrete Examples
- API1:2023-BOLA — Broken Object Level Authorization
  Example: GET /users/2 with user-1's token returns user-2's data (no ownership check)
- API2:2023-Broken-Authentication — Broken Authentication  
  Example: POST /auth/login returns "User not found" vs "Invalid password" (username enumeration)
  Example: No rate limiting on login endpoint
- API3:2023-Broken-Object-Property-Level-Authorization — Excessive data exposure, mass assignment
  Example: GET /users returns salary, SSN, address (excessive PII in list view)
  Example: POST /users accepts "role":"admin" in body (mass assignment)
- API4:2023-Unrestricted-Resource-Consumption — Rate limiting, resource exhaustion
  Example: POST /reports/export accepts row_limit=999999999 with no cap
- API5:2023-Broken-Function-Level-Authorization — Admin/user function separation
  Example: GET /admin/export with user-token returns 200 instead of 403
- API6:2023-Unrestricted-Access-to-Sensitive-Business-Flows — Business logic abuse
- API7:2023-Server-Side-Request-Forgery — SSRF
  Example: POST /webhooks/test with target_url=http://127.0.0.1/admin fetches internal resources
- API8:2023-Security-Misconfiguration — Headers, CORS, verbose errors, debug endpoints
  Example: 500 responses include stack traces, CORS allows *, Server header leaks version
- API9:2023-Improper-Inventory-Management — Undocumented endpoints, version differences
  Example: /api/v1/users still active but hidden from schema, returns PII without auth
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

Generate 5-10 hypotheses. Be specific — don't generate generic threats."""

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
