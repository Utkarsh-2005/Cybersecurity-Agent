from __future__ import annotations

import json
import os
import argparse
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

import requests
from dotenv import load_dotenv
from langchain_openai import ChatOpenAI


def _load_environment() -> None:
    env_candidates = [
        Path(__file__).resolve().parent / ".env",
        Path(__file__).resolve().parents[1] / ".env",
        Path.cwd() / ".env",
    ]
    for env_path in env_candidates:
        if env_path.exists():
            load_dotenv(env_path, override=False)


def _build_llm() -> ChatOpenAI:
    _load_environment()

    api_key = os.getenv("OPENROUTER_API_KEY")
    if not api_key:
        raise RuntimeError(
            "OpenRouter is not configured. Set OPENROUTER_API_KEY in the root .env file."
        )
    return ChatOpenAI(
        model=os.getenv("OPENROUTER_MODEL", "openai/gpt-4o-mini"),
        temperature=0.1,
        max_tokens=500,
        api_key=api_key,
        base_url=os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1"),
        default_headers={
            "HTTP-Referer": "https://github.com/panda-security-agent",
            "X-Title": "PANDA API Security Agent",
        },
    )


def _base_url(target_url: str) -> str:
    parsed = urlparse(target_url)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError("Target must be an absolute URL such as http://127.0.0.1:8000")
    return f"{parsed.scheme}://{parsed.netloc}/"


def _discover_api(
    target_url: str,
    events: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Discover the target through its documentation before touching application routes."""
    base_url = _base_url(target_url)
    events = events if events is not None else []
    session = requests.Session()
    session.headers.update({"User-Agent": "PANDA-read-only-discovery/0.1"})

    docs_url = urljoin(base_url, "docs")
    docs_response = session.get(docs_url, timeout=5)
    _emit_event(events, "recon_agent", "called tool", "http_get", f"/docs -> {docs_response.status_code}")
    print(f"[recon] GET {docs_url} -> {docs_response.status_code}")
    if docs_response.status_code >= 400:
        print("[recon] API docs are unavailable; continuing with the OpenAPI candidate.")

    schema_url = urljoin(base_url, "openapi.json")
    schema_response = session.get(schema_url, timeout=5)
    _emit_event(events, "recon_agent", "called tool", "http_get", f"/openapi.json -> {schema_response.status_code}")
    print(f"[recon] GET {schema_url} -> {schema_response.status_code}")
    schema: dict[str, Any] = {}
    if schema_response.ok:
        try:
            schema = schema_response.json()
        except ValueError:
            print("[recon] OpenAPI response was not valid JSON.")

    paths = schema.get("paths", {})
    print(f"[recon] discovered {len(paths)} documented paths")
    documented_paths: dict[str, Any] = {}
    for path, operations in paths.items():
        methods = ", ".join(
            method.upper()
            for method in operations
            if method in {"get", "post", "put", "patch", "delete"}
        )
        print(f"[recon]   {methods or 'UNKNOWN'} {path}")
        documented_paths[path] = {
            method: {
                "summary": operation.get("summary", ""),
                "parameters": [
                    {"name": parameter.get("name"), "in": parameter.get("in"), "required": parameter.get("required", False)}
                    for parameter in operation.get("parameters", [])
                ],
                "responses": sorted(operation.get("responses", {}).keys()),
            }
            for method, operation in operations.items()
            if method in {"get", "post", "put", "patch", "delete"} and isinstance(operation, dict)
        }

    return {
        "target_url": target_url,
        "base_url": base_url,
        "docs_url": docs_url,
        "docs_status": docs_response.status_code,
        "openapi_url": schema_url,
        "openapi_status": schema_response.status_code,
        "api_title": schema.get("info", {}).get("title", ""),
        "api_version": schema.get("info", {}).get("version", ""),
        "documented_paths": documented_paths,
    }


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
        return "provider returned HTML instead of an OpenRouter JSON response; check proxy/Zscaler routing or OPENROUTER_BASE_URL"
    return detail[:limit]


def _emit_event(
    events: list[dict[str, Any]],
    agent: str,
    action: str,
    tool: str | None = None,
    detail: str = "",
    usage: dict[str, Any] | None = None,
) -> None:
    event = {
        "agent": agent,
        "action": action,
        "tool": tool,
        "detail": detail,
    }
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
    if not isinstance(profiles, dict) or not all(isinstance(value, dict) for value in profiles.values()):
        raise ValueError("PANDA_AUTH_PROFILES_JSON must map profile names to HTTP header objects")
    return {"anonymous": {}, **profiles}


def _baseline_test_plan(discovery: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {"method": "GET", "path": path, "profile": "anonymous", "purpose": "baseline accessibility"}
        for path, operations in discovery.get("documented_paths", {}).items()
        if "get" in operations
    ][:8]


def _object_values(discovery: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for result in discovery.get("baseline_tests", []):
        values.extend(str(value) for value in result.get("returned_user_ids", []) if value is not None)
        if result.get("returned_object_id") is not None:
            values.append(str(result["returned_object_id"]))
    values.extend(["1", "2"])
    return list(dict.fromkeys(values))[:3]


def _ensure_authorization_coverage(
    plan: list[dict[str, Any]],
    discovery: dict[str, Any],
) -> list[dict[str, Any]]:
    """Add safe object-access comparisons the model might omit."""
    covered = {(item.get("path"), item.get("profile"), str(item.get("path_value", ""))) for item in plan}
    profiles = _auth_profiles()
    for path, operations in discovery.get("documented_paths", {}).items():
        if "get" not in operations or "{" not in path:
            continue
        for profile in profiles:
            if profile == "anonymous":
                continue
            for value in _object_values(discovery):
                key = (path, profile, str(value))
                if key in covered:
                    continue
                plan.append({
                    "method": "GET",
                    "path": path,
                    "profile": profile,
                    "query": {},
                    "path_value": value,
                    "purpose": "authorization boundary comparison",
                })
                covered.add(key)
                if len(plan) >= 16:
                    return plan
    return plan


def _plan_tests(
    discovery: dict[str, Any],
    llm: ChatOpenAI,
    events: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Ask OpenRouter to select safe probes from the discovered contract."""
    operations = []
    for path, methods in discovery.get("documented_paths", {}).items():
        for method, operation in methods.items():
            operations.append({"method": method.upper(), "path": path, **operation})
    profiles = list(_auth_profiles())
    prompt = (
        "You are PANDA's API test planner. Select up to 8 safe, read-only probes from this OpenAPI inventory. "
        "Prioritize access-control boundaries, object identifiers, required query parameters, admin/user separation, "
        "and endpoints whose responses reveal sensitive data. Only GET or HEAD is allowed. Do not invent routes. "
        "Use only these auth profile names. Return JSON only as an array of objects with method, path, profile, "
        "query (object), and purpose. Use path placeholders with concrete values only when the path clearly names an "
        "identifier; otherwise use the documented path as-is.\n\n"
        f"Auth profiles: {json.dumps(profiles)}\n"
        f"Baseline observations: {json.dumps(discovery.get('baseline_tests', []), separators=(',', ':'))}\n"
        f"OpenAPI inventory: {json.dumps(operations, separators=(',', ':'))}"
    )
    _emit_event(events, "planner_agent", "started", "openrouter", "selecting endpoint-specific probes")
    try:
        response = llm.invoke([("system", prompt)])
        usage = _extract_usage(response)
        _emit_event(events, "planner_agent", "completed model planning", "openrouter", "received bounded test plan", usage)
        content = response.content.strip()
        if content.startswith("```"):
            content = content.strip("`").removeprefix("json").strip()
        planned = json.loads(content)
        if not isinstance(planned, list):
            raise ValueError("planner response was not an array")
        return planned[:8]
    except Exception as exc:
        detail = _short_error(exc)
        _emit_event(events, "planner_agent", "failed", "openrouter", detail)
        raise RuntimeError(f"OpenRouter planning failed: {detail}") from exc


def _expand_path(path: str, path_value: Any = None) -> str:
    if path_value is not None:
        start = path.find("{")
        end = path.find("}", start)
        if start >= 0 and end > start:
            path = path[:start] + str(path_value) + path[end + 1:]
    replacements = {
        "user_id": "1",
        "id": "1",
        "report_id": "r1",
        "item_id": "1",
    }
    for name, value in replacements.items():
        path = path.replace("{" + name + "}", value)
    return path


def _execute_test_plan(
    discovery: dict[str, Any],
    plan: list[dict[str, Any]],
    events: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    session = requests.Session()
    session.headers.update({"User-Agent": "PANDA-adaptive-read-only-test/0.2"})
    profiles = _auth_profiles()
    known_paths = discovery.get("documented_paths", {})
    results: list[dict[str, Any]] = []
    for candidate in plan:
        method = str(candidate.get("method", "")).upper()
        path = str(candidate.get("path", ""))
        profile = str(candidate.get("profile", "anonymous"))
        if method not in {"GET", "HEAD"} or path not in known_paths or profile not in profiles:
            _emit_event(events, "policy_agent", "rejected probe", "local_policy", f"method/path/profile not allowed: {method} {path} {profile}")
            continue
        concrete_path = _expand_path(path, candidate.get("path_value"))
        query = candidate.get("query") if isinstance(candidate.get("query"), dict) else {}
        request_url = urljoin(discovery["base_url"], concrete_path.lstrip("/"))
        try:
            response = session.request(method, request_url, params=query, headers=profiles[profile], timeout=5)
            result = _response_evidence(method, concrete_path, response, profile)
            result["purpose"] = str(candidate.get("purpose", "planned probe"))[:160]
            results.append(result)
            _emit_event(events, "executor_agent", "called tool", "safe_http_request", f"{method} {concrete_path} ({profile}) -> {response.status_code}")
            print(f"[test] {method} {response.url} ({profile}) -> {response.status_code}")
        except requests.RequestException as exc:
            result = {"method": method, "path": concrete_path, "auth_context": profile, "error": str(exc)}
            results.append(result)
            _emit_event(events, "executor_agent", "tool error", "safe_http_request", f"{method} {concrete_path}: {exc}")
    return results


def _response_evidence(
    method: str,
    path: str,
    response: requests.Response,
    auth_context: str,
) -> dict[str, Any]:
    evidence: dict[str, Any] = {
        "method": method,
        "path": path,
        "status": response.status_code,
        "auth_context": auth_context,
    }
    path_value = path.rstrip("/").rsplit("/", 1)[-1]
    if path_value and path_value not in {"users", "reports", "health"}:
        evidence["requested_object_id"] = path_value
    try:
        payload = response.json()
    except ValueError:
        return evidence

    if isinstance(payload, dict):
        evidence["response_fields"] = sorted(payload.keys())
        if isinstance(payload.get("id"), int | str):
            evidence["returned_object_id"] = payload["id"]
        users = payload.get("users")
        if isinstance(users, list):
            evidence["returned_user_ids"] = [item.get("id") for item in users if isinstance(item, dict)]
        reports = payload.get("reports")
        if isinstance(reports, list):
            evidence["returned_report_ids"] = [item.get("id") for item in reports if isinstance(item, dict)]
    return evidence


def build_multiagent_system() -> dict[str, Any]:
    """Build the bounded OpenRouter planner and deterministic execution agents."""
    llm = _build_llm()
    return {
        "planner_agent": llm,
        "executor_agent": "policy-validated read-only HTTP tool agent",
        "report_agent": "deterministic evidence synthesis agent",
    }


def run_panda_demo(
    target_url: str,
    discovery: dict[str, Any],
    events: list[dict[str, Any]],
) -> str:
    """Plan endpoint-specific probes once, execute them locally, and synthesize locally."""
    baseline_plan = _baseline_test_plan(discovery)
    discovery["baseline_tests"] = _execute_test_plan(discovery, baseline_plan, events)
    try:
        system = build_multiagent_system()
    except Exception as exc:
        detail = _short_error(exc, 500)
        _emit_event(events, "planner_agent", "failed", "openrouter", detail)
        raise RuntimeError(f"OpenRouter is required: {detail}") from exc

    plan = _ensure_authorization_coverage(_plan_tests(discovery, system["planner_agent"], events), discovery)
    discovery["test_plan"] = plan
    baseline_keys = {(item["path"], item["profile"]) for item in baseline_plan}
    adaptive_plan = [
        item for item in plan
        if (item.get("path"), item.get("profile")) not in baseline_keys
    ]
    discovery["safe_get_tests"] = discovery["baseline_tests"] + _execute_test_plan(discovery, adaptive_plan, events)
    _emit_event(events, "report_agent", "completed local synthesis", "markdown_writer", "derived findings from observed responses")
    return _build_local_report(target_url, discovery, events, "The planner selected bounded probes from the API contract; findings below are based on their observed responses.")


def _build_local_report(
    target_url: str,
    discovery: dict[str, Any],
    events: list[dict[str, Any]],
    specialist_assessment: str,
) -> str:
    results = discovery.get("safe_get_tests", [])
    profile_objects: dict[str, set[str]] = {}
    for item in results:
        if item.get("status") == 200 and item.get("returned_object_id") is not None:
            profile_objects.setdefault(str(item.get("auth_context")), set()).add(str(item["returned_object_id"]))
    bola_profile = next((profile for profile, objects in profile_objects.items() if len(objects) > 1 and profile != "admin-token"), None)
    lines = [
        "## PANDA Security Assessment",
        "",
        f"**Target:** `{target_url}`",
        "",
        "### Executive Summary",
        "",
    ]
    if bola_profile:
        object_ids = sorted(profile_objects[bola_profile])
        lines.extend([
            "**Potential BOLA:** one non-admin authentication profile retrieved multiple object IDs.",
            "",
            f"- Authentication profile: `{bola_profile}`",
            f"- Returned object IDs: `{', '.join(object_ids)}`",
            "- Interpretation: this is direct evidence of missing object-level isolation if the profile represents one user.",
        ])
    else:
        lines.append("No direct BOLA evidence was observed in the bounded checks.")
    lines.extend(["", "### Discovered Endpoints", ""])
    for path, operations in discovery.get("documented_paths", {}).items():
        methods = ", ".join(method.upper() for method in operations)
        lines.append(f"- `{methods} {path}`")
    lines.extend(["", "### Test Results", ""])
    for result in results:
        status = result.get("status", "ERROR")
        context = result.get("auth_context", "anonymous")
        details = []
        if "returned_object_id" in result:
            details.append(f"object {result['returned_object_id']}")
        if "returned_user_ids" in result:
            details.append(f"user IDs {result['returned_user_ids']}")
        suffix = f" ({', '.join(details)})" if details else ""
        lines.append(f"- `{result.get('method', 'GET')} {result.get('path')}` -> **{status}**; `{context}`{suffix}")
    lines.extend([
        "",
        "### Assessment Basis",
        "",
        specialist_assessment.strip(),
        "",
        "### Selected Test Plan",
        "",
    ])
    for index, planned in enumerate(discovery.get("test_plan", []), start=1):
        query = planned.get("query") if isinstance(planned.get("query"), dict) else {}
        query_text = f"?{json.dumps(query, separators=(',', ':'))}" if query else ""
        lines.append(
            f"{index}. `{str(planned.get('method', 'GET')).upper()} {planned.get('path')}{query_text}` "
            f"as `{planned.get('profile', 'anonymous')}`: {planned.get('purpose', 'planned probe')}"
        )
    lines.extend([
        "",
        "### Remediation",
        "",
        "- Enforce object ownership or admin privilege before returning `/users/{user_id}`.",
        "- Keep security and endpoint metadata behind an intentional access-control policy.",
        "- Add authorization tests for own-object, different-object, admin, anonymous, and invalid-token cases.",
        "",
        "### Agent Decision Log",
        "",
    ])
    for index, event in enumerate(events, start=1):
        tool = f" via `{event['tool']}`" if event.get("tool") else ""
        detail = event.get("detail", "").replace("\n", " ")
        usage = event.get("usage")
        usage_text = f" Token usage: `{json.dumps(usage, separators=(',', ':'))}`." if usage else ""
        lines.append(f"{index}. **{event['agent']}** `{event['action']}`{tool}. {detail}.{usage_text}")
    return "\n".join(lines)


def run_terminal_demo(target_url: str, question: str | None = None) -> str:
    """Run an autonomous URL-only demo; question is retained for API compatibility."""
    del question

    print("\n=== PANDA terminal demo ===")
    print(f"Target: {target_url}\n")
    events: list[dict[str, Any]] = []

    try:
        _emit_event(events, "recon_agent", "started", "openapi_discovery", "learning the API contract")
        discovery = _discover_api(target_url, events)
        _emit_event(events, "recon_agent", "completed", detail=f"discovered {len(discovery['documented_paths'])} paths")
        result = run_panda_demo(target_url, discovery, events)
    except (RuntimeError, requests.RequestException, ValueError) as exc:
        message = f"\nPANDA stopped before producing a report: {exc}\n"
        print(message)
        return message
    except Exception as exc:
        message = (
            "\nPANDA could not complete the assessment. "
            "Check the OpenRouter key/model or target availability.\n"
            f"Details: {exc}\n"
        )
        print(message)
        return message

    print("\n=== Final PANDA Report ===")
    print(result)
    report_path = _write_markdown_report(target_url, result, discovery, events)
    print(f"\n[report] Markdown report written to {report_path}")
    return result


def _write_markdown_report(
    target_url: str,
    report: str,
    discovery: dict[str, Any],
    events: list[dict[str, Any]] | None = None,
) -> Path:
    reports_dir = Path.cwd() / "reports"
    reports_dir.mkdir(exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    report_path = reports_dir / f"panda_report_{timestamp}.md"
    report_path.write_text(
        "# PANDA Security Assessment Report\n\n"
        f"- Target: `{target_url}`\n"
        f"- Generated: `{timestamp}`\n"
        f"- Documented paths: `{len(discovery.get('documented_paths', {}))}`\n\n"
        "---\n\n"
        f"{report}\n",
        encoding="utf-8",
    )
    return report_path


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run PANDA autonomously against a user-provided API URL."
    )
    parser.add_argument(
        "target_url",
        help="Absolute API URL, for example http://127.0.0.1:8000",
    )
    args = parser.parse_args()
    run_terminal_demo(args.target_url)


if __name__ == "__main__":
    main()
