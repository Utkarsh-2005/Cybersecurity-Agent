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
        )

    report.findings = _evidence_gate(report.findings, all_results)
    _normalize_finding_confidence(report.findings)
    report.authorization_matrix = authorization_matrix
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
