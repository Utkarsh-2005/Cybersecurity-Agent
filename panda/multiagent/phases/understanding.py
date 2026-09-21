"""Phase 2 — API Understanding (LLM-driven).

Ask the LLM to reason about what the API does and identify
security-relevant patterns.
"""

from __future__ import annotations

import json
from typing import Any

from langchain_openai import ChatOpenAI

from panda.models import APIUnderstanding

from ..utils import _extract_json_from_response, _llm_call


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

## Response Header Fingerprints
{json.dumps(discovery.get('header_fingerprints', {}), indent=2)}

## Undocumented Paths That Responded
{json.dumps(discovery.get('undocumented_findings', []), indent=2)}

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
