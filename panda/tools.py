"""Execution layer for PANDA — live HTTP probes with safety guardrails.

This module replaces the old MockToolRegistry with a LiveHTTPExecutor that
actually sends requests to the target API.  Policy enforcement (method
allow-list, rate limiting, body restrictions) is deterministic code —
never delegated to the LLM.
"""

from __future__ import annotations

import json
import time
from typing import Any
from urllib.parse import urljoin

import requests

from panda.models import ProbeResult, TestCase


# ---------------------------------------------------------------------------
# Legacy shim — keeps `from panda.tools import safe_tool_registry` working
# for graph.py without modification.
# ---------------------------------------------------------------------------

def safe_tool_registry():
    """Backward-compatible shim.  Imports the mock registry lazily so that
    the main agent path (LiveHTTPExecutor) never touches mock data."""
    from panda.mock_api import MockAPIEnvironment
    from panda.models import ToolResult

    class _LegacyMockRegistry:
        def __init__(self) -> None:
            self.api = MockAPIEnvironment()

        def discover_endpoints(self, state: dict[str, Any]) -> ToolResult:
            endpoints = self.api.list_endpoints()
            return ToolResult(
                tool="discover_endpoints", success=True,
                summary="Discovered the simulated API surface.",
                observations=[
                    f"Endpoint {ep['path']} exposes methods {', '.join(ep['methods'])} "
                    f"and auth requirement {ep['auth_required']}."
                    for ep in endpoints
                ],
                metrics={"endpoint_count": len(endpoints)},
            )

        def inspect_request(self, state: dict[str, Any], path: str | None = None) -> ToolResult:
            path = path or "/users/{id}"
            return ToolResult(tool="inspect_request", success=True,
                              summary=f"Request inspection for {path}.",
                              observations=["Mock: accepts user identifier."])

        def inspect_response(self, state: dict[str, Any], path: str | None = None) -> ToolResult:
            return ToolResult(tool="inspect_response", success=True,
                              summary="Mock response inspection.",
                              observations=["Mock: returns identity and profile metadata."])

        def inspect_traffic(self, state: dict[str, Any]) -> ToolResult:
            return ToolResult(tool="inspect_traffic", success=True,
                              summary="Mock traffic metrics.", observations=[])

        def compare_responses(self, state: dict[str, Any], endpoint_a: str = "/users/{id}", endpoint_b: str = "/admin/reports") -> ToolResult:
            return ToolResult(tool="compare_responses", success=True,
                              summary="Mock comparison.", observations=[])

        def analyze_authentication(self, state: dict[str, Any]) -> ToolResult:
            return ToolResult(tool="analyze_authentication", success=True,
                              summary="Mock auth analysis.", observations=[])

        def analyze_authorization(self, state: dict[str, Any]) -> ToolResult:
            return ToolResult(tool="analyze_authorization", success=True,
                              summary="Mock authz analysis.", observations=[])

        def analyze_input_behavior(self, state: dict[str, Any]) -> ToolResult:
            return ToolResult(tool="analyze_input_behavior", success=True,
                              summary="Mock input behavior analysis.", observations=[])

        def inspect_sensitive_data(self, state: dict[str, Any]) -> ToolResult:
            return ToolResult(tool="inspect_sensitive_data", success=True,
                              summary="Mock sensitive data inspection.", observations=[])

        def analyze_endpoint_relationships(self, state: dict[str, Any]) -> ToolResult:
            return ToolResult(tool="analyze_endpoint_relationships", success=True,
                              summary="Mock endpoint relationships.", observations=[])

        def validate_hypothesis(self, state: dict[str, Any], hypothesis: str | None = None) -> ToolResult:
            return ToolResult(tool="validate_hypothesis", success=True,
                              summary="Mock hypothesis validation.", observations=[],
                              metrics={"support_score": 0.76, "status": "NEEDS_MORE_EVIDENCE"})

    return _LegacyMockRegistry()


# ---------------------------------------------------------------------------
# Live HTTP executor — the real execution layer
# ---------------------------------------------------------------------------

_ALLOWED_METHODS = {"GET", "HEAD"}
_MAX_BODY_CAPTURE = 2000
_DEFAULT_TIMEOUT = 8


class LiveHTTPExecutor:
    """Execute test probes against a real API with deterministic safety
    guardrails.

    Safety invariants (enforced in code, never by the LLM):
    - Only GET/HEAD by default; other methods require ``allow_write=True``.
    - Request bodies are never sent (even if allow_write is True in v1).
    - Rate limiting: at most ``rate_limit`` requests per minute.
    - Response bodies are truncated before being stored / passed to the LLM.
    """

    def __init__(
        self,
        base_url: str,
        auth_profiles: dict[str, dict[str, str]],
        *,
        rate_limit: int = 30,
        allow_write: bool = False,
        timeout: int = _DEFAULT_TIMEOUT,
    ) -> None:
        self.base_url = base_url.rstrip("/") + "/"
        self.auth_profiles = auth_profiles
        self.rate_limit = rate_limit
        self.allow_write = allow_write
        self.timeout = timeout

        self._session = requests.Session()
        self._session.headers.update({"User-Agent": "PANDA-security-agent/1.0"})

        # Simple sliding-window rate limiter
        self._request_timestamps: list[float] = []

    # ----- public API -----

    def execute(self, test: TestCase) -> ProbeResult:
        """Run a single test case and return structured evidence."""
        method = test.method.upper()
        if not self._method_allowed(method):
            return ProbeResult(
                test_id=test.id,
                method=method,
                url="",
                path=test.path,
                auth_profile=test.auth_profile,
                status_code=0,
                error=f"Method {method} blocked by safety policy (allowed: {', '.join(self._effective_methods())})",
            )

        self._enforce_rate_limit()

        url = urljoin(self.base_url, test.path.lstrip("/"))
        headers = dict(self.auth_profiles.get(test.auth_profile, {}))

        start = time.perf_counter()
        try:
            response = self._session.request(
                method,
                url,
                params=test.query_params or None,
                headers=headers,
                timeout=self.timeout,
                allow_redirects=False,
            )
            elapsed_ms = (time.perf_counter() - start) * 1000

            # Capture response body (truncated for LLM context)
            body_summary = self._truncate_body(response)

            # Capture interesting headers
            interesting_headers = self._extract_headers(response)

            return ProbeResult(
                test_id=test.id,
                method=method,
                url=str(response.url),
                path=test.path,
                auth_profile=test.auth_profile,
                status_code=response.status_code,
                response_headers=interesting_headers,
                response_body_summary=body_summary,
                response_time_ms=round(elapsed_ms, 1),
            )

        except requests.RequestException as exc:
            elapsed_ms = (time.perf_counter() - start) * 1000
            return ProbeResult(
                test_id=test.id,
                method=method,
                url=url,
                path=test.path,
                auth_profile=test.auth_profile,
                status_code=0,
                response_time_ms=round(elapsed_ms, 1),
                error=str(exc)[:500],
            )

    def execute_batch(self, tests: list[TestCase]) -> list[ProbeResult]:
        """Run a list of test cases sequentially."""
        return [self.execute(test) for test in tests]

    # ----- internal helpers -----

    def _method_allowed(self, method: str) -> bool:
        if method in _ALLOWED_METHODS:
            return True
        if self.allow_write and method in {"POST", "PUT", "PATCH", "DELETE"}:
            return True
        return False

    def _effective_methods(self) -> set[str]:
        methods = set(_ALLOWED_METHODS)
        if self.allow_write:
            methods |= {"POST", "PUT", "PATCH", "DELETE"}
        return methods

    def _enforce_rate_limit(self) -> None:
        now = time.time()
        # Remove timestamps older than 60s
        self._request_timestamps = [
            ts for ts in self._request_timestamps if now - ts < 60
        ]
        if len(self._request_timestamps) >= self.rate_limit:
            sleep_time = 60 - (now - self._request_timestamps[0])
            if sleep_time > 0:
                print(f"[rate-limit] Sleeping {sleep_time:.1f}s to respect {self.rate_limit} req/min limit")
                time.sleep(sleep_time)
        self._request_timestamps.append(time.time())

    @staticmethod
    def _truncate_body(response: requests.Response) -> str:
        try:
            data = response.json()
            text = json.dumps(data, indent=2, default=str)
        except (ValueError, TypeError):
            text = response.text or ""

        if len(text) > _MAX_BODY_CAPTURE:
            return text[:_MAX_BODY_CAPTURE] + f"\n... [truncated, {len(text)} total chars]"
        return text

    @staticmethod
    def _extract_headers(response: requests.Response) -> dict[str, str]:
        """Extract security-relevant response headers."""
        interesting = {
            "content-type", "www-authenticate", "x-ratelimit-limit",
            "x-ratelimit-remaining", "x-ratelimit-reset",
            "access-control-allow-origin", "access-control-allow-methods",
            "strict-transport-security", "x-content-type-options",
            "x-frame-options", "content-security-policy",
            "set-cookie", "server", "x-powered-by",
        }
        return {
            key: value
            for key, value in response.headers.items()
            if key.lower() in interesting
        }
