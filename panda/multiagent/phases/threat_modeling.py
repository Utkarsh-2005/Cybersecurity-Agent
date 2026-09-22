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
- API1:2023-BOLA — Broken Object Level Authorization. Require an object identifier
    and cross-principal access evidence; collection exposure alone is not BOLA.
- API2:2023-Broken-Authentication — Broken Authentication  
- API3:2023-Broken-Object-Property-Level-Authorization — Unauthorized property
    access or mass assignment. Do not use it solely because a response contains
    sensitive data unless property-level authorization is demonstrated.
- API4:2023-Unrestricted-Resource-Consumption — Rate limiting, resource exhaustion
- API5:2023-Broken-Function-Level-Authorization — Admin/user function separation
- API6:2023-Unrestricted-Access-to-Sensitive-Business-Flows — Excessive automated
    use of a sensitive business flow, not a generic data disclosure endpoint.
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

Generate 3-7 hypotheses. Be specific — don't generate generic threats. For each
hypothesis, explain which observed behavior supports the category and name the
missing evidence that would be needed to upgrade a tentative classification."""

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
