"""Main pipeline orchestrator — assembles all phases into run_panda_assessment."""

from __future__ import annotations

from typing import Any

import requests

from panda.models import ProbeResult, TestAnalysis
from panda.tools import LiveHTTPExecutor

from .phases.execution import _execute_and_analyze
from .phases.recon import _discover_api
from .phases.recon_loop import _run_recon_loop
from .phases.reporting import (
    _generate_report,
    _render_markdown_report,
    _write_markdown_report,
)
from .phases.test_planning import _plan_investigation
from .phases.threat_modeling import _model_threats
from .phases.understanding import _understand_api
from .utils import _auth_profiles, _build_llm, _emit_event


_MAX_INVESTIGATION_ITERATIONS = 3


def run_panda_assessment(target_url: str, *, allow_write: bool = False) -> str:
    """Run the full LLM-driven PANDA security assessment pipeline."""

    print("\n" + "=" * 60)
    print("  PANDA — LLM-Driven API Security Assessment")
    print("=" * 60)
    print(f"  Target: {target_url}")
    print("=" * 60 + "\n")

    events: list[dict[str, Any]] = []

    # --- Phase 1: Reconnaissance ---
    print("\n" + "-" * 40)
    print("  Phase 1: Reconnaissance")
    print("-" * 40)
    try:
        discovery = _discover_api(target_url, events)
    except (requests.RequestException, ValueError) as exc:
        msg = f"\nPANDA could not reach the target API: {exc}\n"
        print(msg)
        return msg

    # --- Build LLM and executor ---
    try:
        llm = _build_llm(max_tokens=2048)
    except RuntimeError as exc:
        msg = f"\nPANDA requires an LLM: {exc}\n"
        print(msg)
        return msg

    profiles = _auth_profiles()
    executor = LiveHTTPExecutor(
        base_url=discovery["base_url"],
        auth_profiles=profiles,
        rate_limit=30,
        allow_write=allow_write,
    )

    # --- Phase 1b: bounded LLM-guided reconnaissance ---
    print("\n" + "-" * 40)
    print("  Phase 1b: LLM Reconnaissance Loop")
    print("-" * 40)
    recon_results = _run_recon_loop(discovery, executor, llm, events)

    # --- Phase 2: API Understanding ---
    print("\n" + "-" * 40)
    print("  Phase 2: API Understanding (LLM)")
    print("-" * 40)
    understanding = _understand_api(discovery, llm, events)

    # --- Phase 3: Threat Modeling ---
    print("\n" + "-" * 40)
    print("  Phase 3: Threat Modeling (LLM)")
    print("-" * 40)
    hypotheses = _model_threats(discovery, understanding, llm, events)

    # --- Phase 4+5: Investigation Loop ---
    all_results: list[ProbeResult] = list(recon_results)
    all_analyses: list[TestAnalysis] = []

    for iteration in range(1, _MAX_INVESTIGATION_ITERATIONS + 1):
        print("\n" + "-" * 40)
        print(f"  Phase 4: Test Planning (iteration {iteration})")
        print("-" * 40)

        tests = _plan_investigation(
            discovery, understanding, hypotheses, llm, events,
            previous_results=all_results if all_results else None,
            iteration=iteration,
            allow_write=allow_write,
        )
        if not tests:
            print("[pipeline] No tests generated, ending investigation.")
            _emit_event(events, "pipeline", "investigation ended", detail="no tests generated")
            break

        print("\n" + "-" * 40)
        print(f"  Phase 5: Execution + Analysis (iteration {iteration})")
        print("-" * 40)

        results, analysis = _execute_and_analyze(
            discovery, understanding, hypotheses, tests,
            executor, llm, events, iteration,
        )
        all_results.extend(results)
        all_analyses.append(analysis)

        # Update hypotheses with new confidence levels
        for update in analysis.hypothesis_updates:
            for h in hypotheses:
                if h.id == update.hypothesis_id:
                    h.confidence = update.new_confidence
                    # Map analysis status to hypothesis status
                    status_map = {
                        "CONFIRMED": "CONFIRMED",
                        "LIKELY": "PARTIAL",
                        "INCONCLUSIVE": "INCONCLUSIVE",
                        "UNLIKELY": "OPEN",
                        "REJECTED": "REJECTED",
                    }
                    h.status = status_map.get(update.status, "OPEN")

        if not analysis.should_continue:
            _emit_event(events, "pipeline", "investigation complete",
                        detail=f"analyst decided to stop after {iteration} iteration(s)")
            break
        if iteration < _MAX_INVESTIGATION_ITERATIONS:
            _emit_event(events, "pipeline", "continuing investigation",
                        detail=analysis.continuation_rationale[:200])

    # --- Phase 6: Report Generation ---
    print("\n" + "-" * 40)
    print("  Phase 6: Report Generation (LLM)")
    print("-" * 40)

    report = _generate_report(
        discovery, understanding, hypotheses,
        all_results, all_analyses, llm, events,
    )

    # Render and save
    markdown = _render_markdown_report(
        target_url, understanding, hypotheses,
        report, all_results, events,
    )

    report_path = _write_markdown_report(target_url, markdown, discovery)

    print("\n" + "=" * 60)
    print("  Assessment Complete")
    print("=" * 60)
    print(f"\n[report] Markdown report written to {report_path}")
    print(f"[report] Findings: {len(report.findings)}")
    for f in report.findings:
        emoji = {"CRITICAL": "[CRITICAL]", "HIGH": "[HIGH]", "MEDIUM": "[MEDIUM]", "LOW": "[LOW]", "INFO": "[INFO]"}.get(f.severity, "[INFO]")
        print(f"[report]   {emoji} {f.id}: {f.title} ({f.severity}, confidence: {f.confidence:.0%})")
    print()

    return markdown
