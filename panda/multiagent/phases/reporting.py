"""Phase 6 — Report Generation (LLM-driven).

Synthesize all evidence into a structured security report, render it as
Markdown, and write it to disk.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from langchain_openai import ChatOpenAI

from panda.models import (
    APIUnderstanding,
    ProbeResult,
    SecurityReport,
    TestAnalysis,
    ThreatHypothesis,
)

from ..utils import _extract_json_from_response, _llm_call
from .execution import build_authorization_matrix


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
        [r.model_dump() for r in all_results],
        indent=2, default=str,
    )
    analyses_summary = json.dumps(
        [a.model_dump() for a in all_analyses],
        indent=2, default=str,
    )
    hypotheses_json = json.dumps([h.model_dump() for h in hypotheses], indent=2)
    authorization_matrix = build_authorization_matrix(all_results)

    prompt = f"""You are PANDA, an expert API security consultant writing a professional
security assessment report. Synthesize all the evidence from your investigation into
a comprehensive, actionable report.

Write like a senior penetration tester delivering findings to a development team.
Be specific: cite exact HTTP requests and responses as evidence. Rate severity
accurately — don't inflate or deflate. Provide actionable, specific remediation
guidance (not generic advice). Treat OWASP classification as a separate adjudication
step from deciding whether an observation is security-relevant.

## OWASP Classification Rules
Use the narrowest category supported by the executed evidence. A successful response
alone is not proof of a vulnerability category.
- API1 BOLA requires an object identifier controlled by the client and evidence that
    one principal can access another principal's object. A collection endpoint such as
    GET /users/v1 is not BOLA by itself.
- API3 BOPLA requires an unauthorized property to be returned or accepted, or clear
    mass-assignment evidence. A debug endpoint exposing passwords is sensitive-data
    exposure, but do not call it BOPLA unless the evidence demonstrates a property-level
    authorization failure.
- API5 requires a restricted function being usable by an unauthorized role.
- API6 requires abuse of a sensitive business flow through excessive automated use;
    a debug or data-disclosure endpoint is not API6.
- API8 is appropriate for exposed debug functionality, unsafe defaults, verbose errors,
    or other configuration failures when that is what the evidence demonstrates.
- Use OTHER when the behavior is real but does not fit an OWASP API Top 10 category.

For every finding, separately score observation_confidence and classification_confidence.
Set overall confidence no higher than the weaker of those two scores. Do not convert
HTTP 200 into 100% vulnerability or classification confidence.

## API Understanding
{understanding.model_dump_json(indent=2)}

## Threat Hypotheses Investigated
{hypotheses_json}

## All Test Results
{results_summary}

## Analysis Notes
{analyses_summary}

## Authorization Matrix Evidence
{json.dumps(authorization_matrix, indent=2, default=str)}

Treat this matrix as observed access behavior, not proof of object ownership. A
cross-profile comparison is necessary for BOLA analysis but is not sufficient unless
the object identifier and ownership relationship are also established.

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
        "state": "OBSERVED|SUSPECTED|CONFIRMED|NOT_TESTED",
        "confidence": 0.8,
        "observation_confidence": 0.95,
        "classification_confidence": 0.85,
        "classification_rationale": "Explain why this category fits the evidence and why the closest alternatives do not.",
    "evidence_test_ids": ["T1"],
    "evidence_request_ids": ["request-id"],
    "validation_checks": ["API_ROUTE_VALIDATED"],
    "route_classification": "DOCUMENTED_API_ROUTE"
    }}
  ],
  "positive_observations": ["Security controls that are working correctly..."],
  "methodology_notes": "Brief description of testing methodology...",
    "limitations": ["Read-only testing only", "No authentication bypass attempts", "..."],
    "coverage": [
        {{"category": "BOLA", "status": "NOT_CONCLUSIVELY_TESTED", "basis": "No cross-principal object test was executed."}},
        {{"category": "BOPLA", "status": "PARTIAL", "basis": "..."}},
        {{"category": "BFLA", "status": "NOT_TESTED", "basis": "..."}},
        {{"category": "Injection", "status": "NOT_TESTED", "basis": "..."}},
        {{"category": "Rate limiting", "status": "NOT_TESTED", "basis": "..."}}
        ],
    "authorization_matrix": [
        {{"endpoint": "/users/{{username}}", "profiles": [{{"auth_profile": "anonymous", "status_code": 401}}], "comparison_status": "SINGLE_PROFILE"}}
    ]
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
            limitations=["LLM report synthesis failed; deterministic evidence fallback was applied."],
        )

    report.findings = _evidence_gate(report.findings, all_results)
    report.findings = _merge_deterministic_findings(
        report.findings,
        _deterministic_findings(discovery, all_results),
    )
    _normalize_finding_confidence(report.findings)
    report.authorization_matrix = authorization_matrix
    report.coverage = _build_coverage(discovery, all_results, report.coverage)
    if report.findings and "parsing error" in report.executive_summary.lower():
        report.executive_summary = (
            "The assessment confirmed security-relevant behavior from executed HTTP evidence. "
            "The narrative LLM synthesis failed, so deterministic evidence-backed findings are shown below."
        )
    if not all_results:
        report.findings = []
        report.executive_summary = (
            "No security findings were confirmed because no validated API probes were executed. "
            "The target contract or route inventory was insufficient for safe testing."
        )
        report.api_overview = (
            f"{understanding.api_type}. Reconnaissance identified no validated route that could "
            "be tested safely during this run."
        )
        report.methodology_notes = (
            "Reconnaissance and hypothesis generation completed, but test execution did not start "
            "because the planner produced no validated probes."
        )
        report.limitations = list(dict.fromkeys([
            *report.limitations,
            "No validated API probes were executed.",
            "This is not evidence that the target is secure.",
        ]))
    return report


def _deterministic_findings(
    discovery: dict[str, Any],
    results: list[ProbeResult],
) -> list[Any]:
    """Convert directly observed baseline and executed behavior into findings."""
    from panda.models import Finding

    findings: list[Finding] = []
    baseline = discovery.get("baseline_results", [])

    def observed(path_fragment: str, profile: str | None = None) -> list[dict[str, Any]]:
        return [
            item for item in baseline
            if path_fragment in item.get("path", "")
            and (profile is None or item.get("auth_profile") == profile)
            and item.get("status_code") == 200
        ]

    export_results = observed("/admin/users/export", "user-token")
    if export_results:
        findings.append(Finding(
            id="DF-BFLA",
            title="Authenticated User Can Access Admin User Export",
            severity="HIGH",
            owasp_category="API5:2023-Broken-Function-Level-Authorization",
            state="CONFIRMED",
            description="The user-token profile received a successful response from the documented admin user export endpoint.",
            evidence=["GET /admin/users/export (user-token) -> 200 from reconnaissance baseline."],
            impact="A non-admin authenticated user may retrieve an administrative export containing other users' data.",
            remediation="Require an administrator role before allowing access to the user export function.",
            confidence=0.9,
            observation_confidence=0.99,
            classification_confidence=0.9,
            classification_rationale="The evidence directly demonstrates a lower-privileged profile reaching a route documented as an admin function.",
            validation_checks=["BASELINE_RESPONSE", "AUTH_PROFILE_STATUS_DIFFERENTIAL"],
            route_classification="DOCUMENTED_API_ROUTE",
        ))

    settings_results = [
        item for item in baseline
        if item.get("path", "").endswith("/settings")
        and item.get("auth_profile") == "user-token"
        and item.get("status_code") == 200
    ]
    bola_results = [
        result for result in results
        if "BOLA_NON_OWNER_SUCCESS" in result.validation_checks
        and result.status_code in {200, 201, 202}
    ]
    if bola_results:
        findings.append(Finding(
            id="DF-BOLA-CONFIRMED",
            title="Authenticated Principal Can Access Another User's Object",
            severity="HIGH",
            owasp_category="API1:2023-BOLA",
            state="CONFIRMED",
            description="A principal with known identity successfully accessed a different numeric user object ID.",
            evidence=[
                f"{result.method} {result.path} ({result.username or result.auth_profile}, principal {result.principal_id}) -> {result.status_code}"
                for result in bola_results[:6]
            ],
            impact="A user may read or modify another user's profile or settings, including sensitive properties.",
            remediation="Enforce ownership or role authorization against the requested user ID before returning or modifying the object.",
            confidence=0.95,
            observation_confidence=0.99,
            classification_confidence=0.95,
            classification_rationale="The principal identity and requested numeric object ID are both known, and the non-owner request succeeded.",
            evidence_test_ids=[result.test_id for result in bola_results],
            evidence_request_ids=[result.request_id for result in bola_results if result.request_id],
            validation_checks=["BOLA_NON_OWNER_SUCCESS", "KNOWN_PRINCIPAL_ID"],
            route_classification=bola_results[0].route_classification,
        ))
    if settings_results:
        findings.append(Finding(
            id="DF-BOLA-SETTINGS",
            title="User Token Can Read Other User Settings",
            severity="HIGH",
            owasp_category="API1:2023-BOLA",
            state="SUSPECTED",
            description="The user-token profile received successful responses for multiple user settings object IDs. Ownership of the token was not established in this run, so this remains a suspected BOLA finding.",
            evidence=[
                f"GET {item.get('path')} (user-token) -> {item.get('status_code')}"
                for item in settings_results[:6]
            ],
            impact="If the token belongs to a different user, private settings such as API keys and webhook URLs may be exposed.",
            remediation="Enforce requester ownership or an explicitly authorized role before returning another user's settings.",
            confidence=0.65,
            observation_confidence=0.99,
            classification_confidence=0.65,
            classification_rationale="Successful object-specific reads are observed, but BOLA requires verified token ownership and a cross-owner comparison.",
            validation_checks=["BASELINE_RESPONSE", "OBJECT_ID_COMPARISON_REQUIRED"],
            route_classification="DOCUMENTED_API_ROUTE",
        ))

    user_list_results = observed("/users", "user-token")
    if user_list_results:
        findings.append(Finding(
            id="DF-DATA-EXPOSURE",
            title="Authenticated User Receives Excessive User Data",
            severity="MEDIUM",
            owasp_category="API3:2023-Broken-Object-Property-Level-Authorization",
            state="OBSERVED",
            description="The authenticated users collection returned a broad user listing. The response should be reviewed for unnecessary PII and sensitive properties.",
            evidence=["GET /users (user-token) -> 200 from reconnaissance baseline."],
            impact="Unnecessary user attributes can support account enumeration, profiling, and follow-on attacks.",
            remediation="Return only fields required by the client and enforce field-level authorization for sensitive properties.",
            confidence=0.7,
            observation_confidence=0.95,
            classification_confidence=0.7,
            classification_rationale="The collection is accessible to an authenticated user and is designed to expose broad user records; property-level impact requires response-field review.",
            validation_checks=["BASELINE_RESPONSE", "SENSITIVE_FIELD_REVIEW_REQUIRED"],
            route_classification="DOCUMENTED_API_ROUTE",
        ))

    hidden_results = [
        item for item in discovery.get("undocumented_findings", [])
        if item.get("route_classification") == "DISCOVERED_API_ROUTE"
        and item.get("status_code") == 200
    ]
    if hidden_results:
        findings.append(Finding(
            id="DF-INVENTORY",
            title="Undocumented API Route Exposes User Data",
            severity="MEDIUM",
            owasp_category="API9:2023-Improper-Inventory-Management",
            state="CONFIRMED",
            description="Reconnaissance discovered an active JSON route that was not present in the OpenAPI inventory.",
            evidence=[f"GET {item.get('path')} -> {item.get('status_code')} ({item.get('content_type', '')})" for item in hidden_results],
            impact="Untracked API versions can expose data and bypass the controls applied to documented routes.",
            remediation="Remove deprecated routes or document, authenticate, authorize, and monitor them consistently.",
            confidence=0.85,
            observation_confidence=0.99,
            classification_confidence=0.85,
            classification_rationale="The route was positively identified as JSON/API behavior but was absent from the documented route inventory.",
            validation_checks=["UNDOCUMENTED_JSON_ROUTE"],
            route_classification="DISCOVERED_API_ROUTE",
        ))

    write_results = [
        result for result in results
        if result.method.upper() in {"POST", "PUT", "PATCH", "DELETE"}
        and result.status_code not in {0, 404, 405}
        and result.route_classification in {"DOCUMENTED_API_ROUTE", "DISCOVERED_API_ROUTE"}
    ]
    update_results = [
        result for result in write_results
        if result.method.upper() == "PUT" and "/users/" in result.path
        and result.status_code in {200, 201, 202}
    ]
    if update_results:
        findings.append(Finding(
            id="DF-IDOR-UPDATE",
            title="Authenticated User Can Update a User Object",
            severity="HIGH",
            owasp_category="API1:2023-BOLA",
            state="SUSPECTED",
            description="A non-anonymous profile successfully updated a user object through a parameterized endpoint. The profile's ownership of the target object was not established, so this is a suspected IDOR/BOLA issue.",
            evidence=[
                f"{result.method} {result.path} ({result.auth_profile}) -> {result.status_code}"
                for result in update_results
            ],
            impact="A user may be able to modify another user's profile data if the target ID is not owned by the requester.",
            remediation="Require an ownership or role check before applying updates to the requested user ID.",
            confidence=0.65,
            observation_confidence=0.99,
            classification_confidence=0.65,
            classification_rationale="The update succeeded, but the evidence does not yet establish that the authenticated principal differs from the target owner.",
            evidence_test_ids=[result.test_id for result in update_results],
            evidence_request_ids=[result.request_id for result in update_results if result.request_id],
            validation_checks=["WRITE_RESPONSE", "OWNER_COMPARISON_REQUIRED"],
            route_classification=update_results[0].route_classification,
        ))

    mass_assignment_results = [
        result for result in write_results
        if result.method.upper() == "POST"
        and result.path == "/users"
        and "role" in result.request_body
        and result.status_code in {200, 201}
    ]
    if mass_assignment_results:
        findings.append(Finding(
            id="DF-MASS-ASSIGNMENT-SURFACE",
            title="User Creation Accepts a Client-Supplied Role Field",
            severity="MEDIUM",
            owasp_category="API3:2023-Broken-Object-Property-Level-Authorization",
            state="OBSERVED",
            description="The user-creation request accepted a client-supplied role property. This demonstrates a mass-assignment surface; privilege escalation is not confirmed unless an elevated role is accepted or effective.",
            evidence=[
                f"POST {result.path} ({result.auth_profile}) -> {result.status_code}; submitted fields: {', '.join(result.request_body)}"
                for result in mass_assignment_results
            ],
            impact="If privileged role values are accepted, a regular user may create an elevated account.",
            remediation="Ignore client-supplied privilege fields and assign roles server-side according to policy.",
            confidence=0.7,
            observation_confidence=0.99,
            classification_confidence=0.75,
            classification_rationale="The request and successful response prove the property is accepted by the endpoint, but the submitted role was not elevated in this probe.",
            evidence_test_ids=[result.test_id for result in mass_assignment_results],
            evidence_request_ids=[result.request_id for result in mass_assignment_results if result.request_id],
            validation_checks=["WRITE_RESPONSE", "ROLE_ESCALATION_NOT_CONFIRMED"],
            route_classification=mass_assignment_results[0].route_classification,
        ))

    debug_results = [
        result for result in results
        if "_debug" in result.path.lower()
        and result.status_code == 200
        and result.route_classification in {"DOCUMENTED_API_ROUTE", "DISCOVERED_API_ROUTE"}
        and _contains_sensitive_field(result)
    ]
    if not debug_results:
        return findings
    evidence_ids = [result.test_id for result in debug_results]
    findings.append(Finding(
        id="DF1",
        title="Exposed Debug Endpoint Returns Sensitive User Data",
        severity="HIGH",
        owasp_category="API8:2023-Security-Misconfiguration",
        description="A debug endpoint returned sensitive user properties, including credential-related data, to an unauthenticated request.",
        evidence=[
            f"{result.method} {result.path} ({result.auth_profile}) returned {result.status_code} with fields: {', '.join(result.response_fields)}"
            for result in debug_results[:3]
        ],
        impact="An unauthenticated attacker may retrieve sensitive account data and use it for account compromise or further attacks.",
        remediation="Remove the debug route from deployed environments or require strong authorization and redact passwords, tokens, and other secrets from responses.",
        confidence=0.9,
        state="CONFIRMED",
        observation_confidence=0.99,
        classification_confidence=0.85,
        classification_rationale="The executed evidence proves an exposed debug function and sensitive response properties. It does not prove BOLA, BOPLA, or API6, so this is classified conservatively as API8 security misconfiguration.",
        evidence_test_ids=evidence_ids,
        evidence_request_ids=[result.request_id for result in debug_results if result.request_id],
        validation_checks=sorted({check for result in debug_results for check in result.validation_checks}),
        route_classification=debug_results[0].route_classification,
    ))
    return findings


def _contains_sensitive_field(result: ProbeResult) -> bool:
    sensitive_names = {"password", "passwd", "secret", "token", "ssn", "credit_card"}
    return any(
        any(name in field.lower() for name in sensitive_names)
        for field in result.response_fields
    ) or any(
        name in result.response_body_summary.lower()
        for name in sensitive_names
    )


def _merge_deterministic_findings(findings: list[Any], fallback: list[Any]) -> list[Any]:
    existing_routes = {
        (finding.owasp_category, tuple(finding.evidence_test_ids))
        for finding in findings
    }
    for finding in fallback:
        key = (finding.owasp_category, tuple(finding.evidence_test_ids))
        if key not in existing_routes:
            findings.append(finding)
    return findings


def _build_coverage(
    discovery: dict[str, Any],
    results: list[ProbeResult],
    existing: list[dict[str, str]],
) -> list[dict[str, str]]:
    """Fill coverage gaps without allowing the LLM to imply untested coverage."""
    if existing:
        return existing
    methods = {result.method.upper() for result in results}
    paths = {result.path.lower() for result in results}
    debug_observed = any("_debug" in path for path in paths)
    return [
        {"category": "BOLA", "status": "NOT_CONCLUSIVELY_TESTED", "basis": "No verified owner/non-owner object comparison was executed."},
        {"category": "BOPLA", "status": "PARTIAL", "basis": "Sensitive properties were observed, but property authorization was not isolated."},
        {"category": "BFLA", "status": "NOT_CONCLUSIVELY_TESTED", "basis": "No controlled lower-role versus admin-function comparison was completed."},
        {"category": "Debug/data exposure", "status": "CONFIRMED" if debug_observed else "NOT_TESTED", "basis": "A debug route was observed in executed responses." if debug_observed else "No debug route was tested."},
        {"category": "Injection", "status": "NOT_TESTED", "basis": "No injection payloads were executed."},
        {"category": "Authentication/JWT", "status": "PARTIAL" if any(result.status_code == 401 for result in results) else "NOT_TESTED", "basis": "Authentication responses were observed, but token issuance and validation were not fully tested."},
        {"category": "Rate limiting", "status": "NOT_TESTED", "basis": "No sustained request-rate test was executed."},
        {"category": "Write operations", "status": "TESTED" if methods & {"POST", "PUT", "PATCH", "DELETE"} else "NOT_TESTED", "basis": f"Executed methods: {', '.join(sorted(methods & {'POST', 'PUT', 'PATCH', 'DELETE'})) or 'none'}; destructive coverage remains bounded."},
        {"category": "Security headers", "status": "OBSERVED" if discovery.get("header_fingerprints") else "NOT_TESTED", "basis": "Headers were fingerprinted during reconnaissance."},
    ]


def _evidence_gate(findings: list[Any], results: list[ProbeResult]) -> list[Any]:
    """Keep only findings linked to executed, validated API evidence."""
    result_by_id = {result.test_id: result for result in results}
    gated = []
    for finding in findings:
        linked = [
            result_by_id[test_id]
            for test_id in finding.evidence_test_ids
            if test_id in result_by_id
        ]
        if not linked:
            continue
        if any(
            result.route_classification not in {"DOCUMENTED_API_ROUTE", "DISCOVERED_API_ROUTE"}
            for result in linked
        ):
            continue
        finding.evidence_request_ids = [
            result.request_id for result in linked if result.request_id
        ]
        finding.route_classification = linked[0].route_classification
        finding.validation_checks = sorted({
            check for result in linked for check in result.validation_checks
        })
        if finding.state == "CONFIRMED" and not finding.validation_checks:
            finding.state = "SUSPECTED"
        gated.append(finding)
    return gated


def _normalize_finding_confidence(findings: list[Any]) -> None:
    """Keep confidence dimensions consistent even when the model omits fields."""
    for finding in findings:
        if finding.observation_confidence == 0.0:
            finding.observation_confidence = finding.confidence
        if finding.classification_confidence == 0.0:
            finding.classification_confidence = finding.confidence
        finding.confidence = min(
            finding.confidence,
            finding.observation_confidence,
            finding.classification_confidence,
        )


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
                f"| **State** | {finding.state} |",
                f"| **OWASP Category** | {finding.owasp_category} |",
                f"| **Confidence** | {finding.confidence:.0%} |",
                f"| **Observation Confidence** | {finding.observation_confidence:.0%} |",
                f"| **Classification Confidence** | {finding.classification_confidence:.0%} |",
                "",
                f"**Description:** {finding.description}",
                "",
                f"**Impact:** {finding.impact}",
                "",
            ])
            if finding.classification_rationale:
                lines.extend([
                    f"**Classification Rationale:** {finding.classification_rationale}",
                    "",
                ])
            if finding.evidence:
                lines.append("**Evidence:**")
                for ev in finding.evidence:
                    lines.append(f"- {ev}")
                lines.append("")
            if finding.evidence_test_ids:
                lines.append(f"**Evidence Tests:** `{', '.join(finding.evidence_test_ids)}`")
                lines.append(f"**Request IDs:** `{', '.join(finding.evidence_request_ids)}`")
                lines.append(f"**Validation:** `{', '.join(finding.validation_checks)}`")
                lines.append(f"**Route Classification:** `{finding.route_classification}`")
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

    # Explicitly distinguish tested coverage from untested attack surface.
    if report.coverage:
        lines.extend(["---", "", "## Coverage Summary", ""])
        lines.extend([
            "| Category | Status | Basis |",
            "|----------|--------|-------|",
        ])
        for item in report.coverage:
            lines.append(
                f"| {item.get('category', 'Unspecified')} | "
                f"{item.get('status', 'UNSPECIFIED')} | "
                f"{item.get('basis', '')} |"
            )
        lines.append("")

    if report.authorization_matrix:
        lines.extend(["---", "", "## Authorization Matrix", ""])
        lines.extend([
            "Observed responses by endpoint and auth profile. This does not establish object ownership.",
            "",
            "| Endpoint | Profile | Role | Status | Fields | Comparison |",
            "|----------|---------|------|--------|--------|------------|",
        ])
        for route in report.authorization_matrix:
            for profile in route.get("profiles", []):
                lines.append(
                    f"| `{route.get('endpoint', '')}` | `{profile.get('auth_profile', '')}` | "
                    f"{profile.get('role') or '-'} | {profile.get('status_code', '')} | "
                    f"{', '.join(profile.get('response_fields', [])) or '-'} | "
                    f"{route.get('comparison_status', '')} |"
                )
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
