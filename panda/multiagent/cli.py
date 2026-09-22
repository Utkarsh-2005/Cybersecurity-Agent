"""CLI argument parsing and backward-compatible helper functions."""

from __future__ import annotations

import argparse
from typing import Any

from .pipeline import run_panda_assessment
from .utils import _build_llm


# ---------------------------------------------------------------------------
# Backward-compatible entry points
# ---------------------------------------------------------------------------

def build_multiagent_system() -> dict[str, Any]:
    """Legacy shim — kept for backward compatibility."""
    llm = _build_llm()
    return {
        "planner_agent": llm,
        "executor_agent": "policy-validated read-only HTTP tool agent",
        "report_agent": "LLM-driven evidence synthesis agent",
    }


def run_panda_demo(
    target_url: str,
    discovery: dict[str, Any],
    events: list[dict[str, Any]],
) -> str:
    """Legacy shim — redirects to the new pipeline."""
    return run_panda_assessment(target_url)


def run_terminal_demo(target_url: str, question: str | None = None) -> str:
    """Run an autonomous URL-only assessment."""
    del question
    return run_panda_assessment(target_url)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run PANDA autonomously against a user-provided API URL."
    )
    parser.add_argument(
        "target_url",
        help="Absolute API URL, for example http://127.0.0.1:8000",
    )
    parser.add_argument(
        "--allow-write",
        action="store_true",
        help="Enable POST/PUT/PATCH/DELETE probes for an explicitly authorized lab target.",
    )
    args = parser.parse_args()
    run_panda_assessment(args.target_url, allow_write=args.allow_write)


if __name__ == "__main__":
    main()
