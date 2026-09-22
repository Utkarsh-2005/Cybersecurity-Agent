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

    prompt = f"""You are PANDA, an expert API security consultant writing a professional
security assessment report. Synthesize all the evidence from your investigation into
a comprehensive, actionable report.

Write like a senior penetration tester delivering findings to a development team.
Be specific: cite exact HTTP requests and responses as evidence. Rate severity
accurately — don't inflate or deflate. Provide actionable, specific remediation
guidance (not generic advice).

## API Understanding
{understanding.model_dump_json(indent=2)}

## Threat Hypotheses Investigated
{hypotheses_json}

## All Test Results
{results_summary}

## Analysis Notes
{analyses_summary}

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
    "confidence": 0.9,
    "evidence_test_ids": ["T1"],
    "evidence_request_ids": ["request-id"],
    "validation_checks": ["API_ROUTE_VALIDATED"],
    "route_classification": "DOCUMENTED_API_ROUTE"
    }}
  ],
  "positive_observations": ["Security controls that are working correctly..."],
  "methodology_notes": "Brief description of testing methodology...",
  "limitations": ["Read-only testing only", "No authentication bypass attempts", "..."]
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
                "",
                f"**Description:** {finding.description}",
                "",
                f"**Impact:** {finding.impact}",
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
