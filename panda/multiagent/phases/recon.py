"""Phase 1 — Reconnaissance (deterministic).

API discovery, baseline probes, undocumented-path probing, and header
fingerprinting.
"""

from __future__ import annotations

import json
import hashlib
import re
from typing import Any
from urllib.parse import urljoin

import requests

from ..utils import _auth_profiles, _base_url, _emit_event, _profile_headers, _profile_metadata, _target_url


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


def _classify_response(
    response: requests.Response,
    root_signature: tuple[str, str, int, str] | None,
) -> tuple[str, bool, str]:
    content_type = response.headers.get("content-type", "").lower()
    body = response.content
    body_hash = hashlib.sha256(body).hexdigest()
    signature = (content_type.split(";", 1)[0], body_hash, len(body), response.text[:120])
    is_html = "text/html" in content_type
    same_as_root = root_signature is not None and signature[:3] == root_signature[:3]
    if "json" in content_type:
        return "DISCOVERED_API_ROUTE", False, body_hash
    if is_html and (same_as_root or "<html" in response.text[:500].lower()):
        return "FRONTEND_CATCH_ALL", True, body_hash
    return "UNVERIFIED", False, body_hash


def _discover_api(
    target_url: str,
    events: list[dict[str, Any]],
) -> dict[str, Any]:
    """Discover the target through its documentation, baseline probes,
    undocumented-path probing, and header fingerprinting."""
    base_url = _base_url(target_url)
    target = _target_url(target_url)
    session = requests.Session()
    session.headers.update({"User-Agent": "PANDA-discovery/1.0"})

    target_identity: dict[str, Any] = {
        "requested_url": target_url,
        "path": target.path,
    }
    target_route: dict[str, Any] | None = None
    try:
        identity_response = session.get(target_url, timeout=5)
        identity_content_type = identity_response.headers.get("content-type", "")
        target_identity.update({
            "status_code": identity_response.status_code,
            "content_type": identity_content_type,
            "title": re.search(r"<title[^>]*>(.*?)</title>", identity_response.text, re.I | re.S).group(1).strip()
            if re.search(r"<title[^>]*>(.*?)</title>", identity_response.text, re.I | re.S)
            else "",
        })
        if identity_response.ok and "json" in identity_content_type.lower():
            target_route = {
                "path": target.path.rstrip("/") or "/",
                "get": {
                    "summary": "Configured target route",
                    "parameters": [],
                    "responses": [str(identity_response.status_code)],
                    "request_body": False,
                },
            }
    except requests.RequestException as exc:
        target_identity["error"] = str(exc)[:200]

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
    if target_route and target_route["path"] not in documented_paths:
        documented_paths[target_route["path"]] = {
            "get": target_route["get"],
        }
        print(f"[recon] added configured target route {target_route['path']}")

    # --- Baseline probes: hit every GET endpoint with every auth profile ---
    profiles = _auth_profiles()
    baseline_results: list[dict[str, Any]] = []
    header_fingerprints: dict[str, dict[str, str]] = {}  # path -> headers

    root_signature: tuple[str, str, int, str] | None = None
    try:
        root_response = session.get(base_url, timeout=5)
        root_content_type = root_response.headers.get("content-type", "").lower()
        root_signature = (
            root_content_type.split(";", 1)[0],
            hashlib.sha256(root_response.content).hexdigest(),
            len(root_response.content),
            root_response.text[:120],
        )
        header_fingerprints["/"] = _fingerprint_headers(root_response)
    except requests.RequestException:
        pass

    for path, operations in documented_paths.items():
        if "get" not in operations:
            continue
        # Skip paths with path parameters for baseline (tested separately below)
        if "{" in path:
            continue
        for profile_name, headers in profiles.items():
            url = urljoin(base_url, path.lstrip("/"))
            try:
                resp = session.get(url, headers=_profile_headers(headers), timeout=5)
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
                    resp = session.get(url, headers=_profile_headers(headers), timeout=5)
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

    # --- Undocumented path probing ---
    _emit_event(events, "recon", "started", "undocumented_probing",
                f"probing {len(_UNDOCUMENTED_PROBE_PATHS)} common undocumented paths")
    print(f"\n[recon] Probing {len(_UNDOCUMENTED_PROBE_PATHS)} common undocumented paths...")
    undocumented_findings: list[dict[str, Any]] = []
    documented_path_set = set(documented_paths.keys())
    for probe_path in _UNDOCUMENTED_PROBE_PATHS:
        if probe_path in documented_path_set:
            continue
        url = urljoin(base_url, probe_path.lstrip("/"))
        try:
            resp = session.get(url, timeout=3)
            finding = {
                "path": probe_path,
                "status_code": resp.status_code,
                "content_type": resp.headers.get("content-type", ""),
                "response_headers": _fingerprint_headers(resp),
            }
            if resp.status_code not in {404, 405}:
                classification, is_html_shell, body_hash = _classify_response(resp, root_signature)
                finding["route_classification"] = classification
                finding["is_html_shell"] = is_html_shell
                finding["response_body_sha256"] = body_hash
                try:
                    body = resp.json()
                    finding["response_body"] = json.dumps(body, indent=2, default=str)[:500]
                    finding["response_fields"] = sorted(body.keys()) if isinstance(body, dict) else []
                except ValueError:
                    finding["response_body"] = resp.text[:500]
                finding["response_fields"] = []
                undocumented_findings.append(finding)
                print(f"[recon]   {probe_path} -> {resp.status_code} [{classification}]")
            else:
                print(f"[recon]   {probe_path} -> {resp.status_code}")
        except requests.RequestException:
            pass

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
        "target_path": target.path,
        "target_identity": target_identity,
        "target_route": target_route,
        "openapi_schema": schema,
        "api_title": schema.get("info", {}).get("title", ""),
        "api_version": schema.get("info", {}).get("version", ""),
        "documented_paths": documented_paths,
        "baseline_results": baseline_results,
        "undocumented_findings": undocumented_findings,
        "header_fingerprints": header_summary,
        "auth_profiles_available": list(profiles.keys()),
        "auth_profile_metadata": {
            name: _profile_metadata(profile)
            for name, profile in profiles.items()
            if isinstance(profile, dict)
        },
    }
