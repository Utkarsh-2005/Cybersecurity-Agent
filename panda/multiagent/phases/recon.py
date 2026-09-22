"""Phase 1 — Reconnaissance (deterministic).

API discovery, baseline probes, undocumented-path probing, and header
fingerprinting.
"""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import urljoin

import requests

from ..utils import _auth_profiles, _base_url, _emit_event


# Common paths that may exist but not be documented in OpenAPI specs
_UNDOCUMENTED_PROBE_PATHS = [
    "/debug", "/internal", "/graphql", "/swagger", "/api-docs",
    "/actuator", "/actuator/health", "/metrics", "/.env", "/config",
    "/admin", "/status", "/info", "/version", "/api/v1", "/api/v2",
    "/console", "/trace", "/dump", "/env", "/heapdump",
    "/api/v1/users", "/v1/users",
]

# Security-relevant response headers to fingerprint
_SECURITY_HEADERS = {
    "server", "x-powered-by", "x-frame-options", "x-content-type-options",
    "strict-transport-security", "content-security-policy",
    "access-control-allow-origin", "access-control-allow-methods",
    "access-control-allow-credentials", "x-xss-protection",
    "referrer-policy", "permissions-policy", "set-cookie",
    "www-authenticate", "x-ratelimit-limit", "x-ratelimit-remaining",
}


def _fingerprint_headers(resp: requests.Response) -> dict[str, str]:
    """Extract security-relevant headers from a response."""
    return {
        key: value
        for key, value in resp.headers.items()
        if key.lower() in _SECURITY_HEADERS
    }


def _discover_api(
    target_url: str,
    events: list[dict[str, Any]],
) -> dict[str, Any]:
    """Discover the target through its documentation, baseline probes,
    undocumented-path probing, and header fingerprinting."""
    base_url = _base_url(target_url)
    session = requests.Session()
    session.headers.update({"User-Agent": "PANDA-discovery/1.0"})

    # --- Fetch OpenAPI schema (try multiple common locations) ---
    _emit_event(events, "recon", "started", "openapi_discovery", "learning the API contract")

    schema: dict[str, Any] = {}
    openapi_candidates = [
        "openapi.json", "swagger.json", "api-docs",
        "docs", "v1/openapi.json", "api/openapi.json",
    ]
    for spec_path in openapi_candidates:
        spec_url = urljoin(base_url, spec_path)
        try:
            resp = session.get(spec_url, timeout=5)
            _emit_event(events, "recon", "called tool", "http_get",
                        f"/{spec_path} -> {resp.status_code}")
            print(f"[recon] GET {spec_url} -> {resp.status_code}")
            if resp.ok and not schema:
                try:
                    candidate = resp.json()
                    # Validate it looks like an OpenAPI spec
                    if isinstance(candidate, dict) and ("paths" in candidate or "openapi" in candidate or "swagger" in candidate):
                        schema = candidate
                        print(f"[recon]   -> found valid OpenAPI spec at /{spec_path}")
                except ValueError:
                    pass
        except requests.RequestException:
            pass

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
    header_fingerprints: dict[str, dict[str, str]] = {}  # path -> headers

    for path, operations in documented_paths.items():
        if "get" not in operations:
            continue
        # Skip paths with path parameters for baseline (tested separately below)
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
                # Fingerprint headers on first response per path
                if path not in header_fingerprints:
                    header_fingerprints[path] = _fingerprint_headers(resp)
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

    # --- Parameterized path probes: expanded ID range + edge cases ---
    test_ids = ["1", "2", "99", "9999", "0", "-1"]
    for path, operations in documented_paths.items():
        if "get" not in operations or "{" not in path:
            continue
        for test_id in test_ids:
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
                    if path not in header_fingerprints:
                        header_fingerprints[path] = _fingerprint_headers(resp)
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

    # --- Undocumented path probing (with all auth profiles) ---
    _emit_event(events, "recon", "started", "undocumented_probing",
                f"probing {len(_UNDOCUMENTED_PROBE_PATHS)} common undocumented paths")
    print(f"\n[recon] Probing {len(_UNDOCUMENTED_PROBE_PATHS)} common undocumented paths (with all auth profiles)...")
    undocumented_findings: list[dict[str, Any]] = []
    documented_path_set = set(documented_paths.keys())
    for probe_path in _UNDOCUMENTED_PROBE_PATHS:
        if probe_path in documented_path_set:
            continue
        url = urljoin(base_url, probe_path.lstrip("/"))
        for profile_name, profile_headers in profiles.items():
            try:
                resp = session.get(url, headers=profile_headers, timeout=3)
                finding = {
                    "path": probe_path,
                    "auth_profile": profile_name,
                    "status_code": resp.status_code,
                    "content_type": resp.headers.get("content-type", ""),
                }
                if resp.status_code not in {404, 405}:
                    # Non-404 means something responded at this undocumented path
                    try:
                        body = resp.json()
                        finding["response_body"] = json.dumps(body, indent=2, default=str)[:500]
                        finding["response_fields"] = sorted(body.keys()) if isinstance(body, dict) else []
                    except ValueError:
                        finding["response_body"] = resp.text[:500]
                    undocumented_findings.append(finding)
                    if probe_path not in header_fingerprints:
                        header_fingerprints[probe_path] = _fingerprint_headers(resp)
                    print(f"[recon]   {probe_path} ({profile_name}) -> {resp.status_code} [INTERESTING]")
                else:
                    print(f"[recon]   {probe_path} ({profile_name}) -> {resp.status_code}")
            except requests.RequestException:
                pass

    # --- Write-method endpoint discovery ---
    # Probe documented POST/PUT/PATCH/DELETE endpoints with empty bodies
    # to capture error responses, schema hints, and differential errors
    write_method_results: list[dict[str, Any]] = []
    write_methods_found = set()
    for path, operations in documented_paths.items():
        for method in ["post", "put", "patch", "delete"]:
            if method not in operations:
                continue
            write_methods_found.add(f"{method.upper()} {path}")
            concrete = re.sub(r"\{[^}]+\}", "1", path)  # use ID 1 for params
            url = urljoin(base_url, concrete.lstrip("/"))
            for profile_name, profile_headers in profiles.items():
                try:
                    resp = session.request(
                        method.upper(), url,
                        headers={**profile_headers, "Content-Type": "application/json"},
                        json={},
                        timeout=5,
                    )
                    result = {
                        "path": path,
                        "concrete_path": concrete,
                        "method": method.upper(),
                        "auth_profile": profile_name,
                        "status_code": resp.status_code,
                    }
                    try:
                        body = resp.json()
                        result["response_body"] = json.dumps(body, indent=2, default=str)[:1000]
                        result["response_fields"] = sorted(body.keys()) if isinstance(body, dict) else []
                    except ValueError:
                        result["response_body"] = resp.text[:500]
                    write_method_results.append(result)
                    _emit_event(events, "recon", "called tool", "http_request",
                                f"{method.upper()} {concrete} ({profile_name}) -> {resp.status_code}")
                    print(f"[recon] {method.upper()} {url} ({profile_name}) -> {resp.status_code}")
                except requests.RequestException:
                    pass

    if write_methods_found:
        print(f"[recon] Probed {len(write_methods_found)} write-method endpoints: {write_methods_found}")
    if write_method_results:
        print(f"[recon] Collected {len(write_method_results)} write-method probe results")

    # --- Consolidate header fingerprint report ---
    header_summary: dict[str, Any] = {}
    present_headers: set[str] = set()
    for path_headers in header_fingerprints.values():
        for k in path_headers:
            present_headers.add(k.lower())
    missing_security_headers = [
        h for h in ["x-content-type-options", "x-frame-options",
                    "strict-transport-security", "content-security-policy"]
        if h not in present_headers
    ]
    info_leak_headers = {
        k: v for path_headers in header_fingerprints.values()
        for k, v in path_headers.items()
        if k.lower() in {"server", "x-powered-by"}
    }
    cors_headers = {
        k: v for path_headers in header_fingerprints.values()
        for k, v in path_headers.items()
        if k.lower().startswith("access-control")
    }
    header_summary = {
        "present_security_headers": sorted(present_headers & _SECURITY_HEADERS),
        "missing_security_headers": missing_security_headers,
        "info_leak_headers": info_leak_headers,
        "cors_headers": cors_headers,
    }
    if missing_security_headers:
        print(f"[recon] Missing security headers: {', '.join(missing_security_headers)}")
    if info_leak_headers:
        print(f"[recon] Info-leak headers: {info_leak_headers}")
    if cors_headers:
        print(f"[recon] CORS headers: {cors_headers}")

    _emit_event(events, "recon", "completed",
                detail=f"discovered {len(paths)} documented paths, "
                       f"{len(undocumented_findings)} undocumented paths responded, "
                       f"ran {len(baseline_results)} baseline probes")

    return {
        "target_url": target_url,
        "base_url": base_url,
        "openapi_schema": schema,
        "api_title": schema.get("info", {}).get("title", ""),
        "api_version": schema.get("info", {}).get("version", ""),
        "documented_paths": documented_paths,
        "baseline_results": baseline_results,
        "undocumented_findings": undocumented_findings,
        "write_method_results": write_method_results,
        "header_fingerprints": header_summary,
        "auth_profiles_available": list(profiles.keys()),
    }
