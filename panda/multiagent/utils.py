"""Environment setup, LLM builder, and common utilities for the multiagent pipeline."""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx
from dotenv import load_dotenv
from langchain_openai import ChatOpenAI


# ---------------------------------------------------------------------------
# Environment & LLM setup
# ---------------------------------------------------------------------------

def _load_environment() -> None:
    env_candidates = [
        Path(__file__).resolve().parent / ".env",
        Path(__file__).resolve().parents[1] / ".env",
        Path(__file__).resolve().parents[2] / ".env",
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

@dataclass(frozen=True)
class TargetURL:
    """Normalized target identity while retaining the user-supplied path."""
    original: str
    origin: str
    path: str


def _target_url(target_url: str) -> TargetURL:
    parsed = urlparse(target_url)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError("Target must be an absolute URL such as http://127.0.0.1:8000")
    path = parsed.path or "/"
    if not path.endswith("/"):
        path += "/"
    return TargetURL(
        original=target_url,
        origin=f"{parsed.scheme}://{parsed.netloc}/",
        path=path,
    )


def _base_url(target_url: str) -> str:
    """Return the origin for absolute API route resolution."""
    return _target_url(target_url).origin


def _resolve_target_url(target_url: str, route: str) -> str:
    """Resolve a route without silently dropping the configured target path."""
    target = _target_url(target_url)
    if route.startswith("/"):
        return urljoin(target.origin, route.lstrip("/"))
    return urljoin(urljoin(target.origin, target.path.lstrip("/")), route)


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


def _profile_headers(profile: dict[str, Any]) -> dict[str, str]:
    """Extract request headers from either legacy or metadata-rich profiles."""
    headers = profile.get("headers", profile)
    return dict(headers) if isinstance(headers, dict) else {}


def _profile_metadata(profile: dict[str, Any]) -> dict[str, str | None]:
    """Return non-secret identity metadata for prompts and evidence."""
    return {
        "principal_id": profile.get("principal_id"),
        "role": profile.get("role"),
    }


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
