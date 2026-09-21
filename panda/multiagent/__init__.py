"""PANDA — LLM-driven API security assessment agent.

This package implements the core intelligence pipeline:

  Recon → API Understanding → Threat Modeling → Test Planning
    → Execution + Analysis (loop) → Report Generation

Every key decision is made by the LLM with chain-of-thought reasoning.
Safety guardrails (method allow-lists, rate limiting) are enforced by
deterministic code in ``tools.py``.
"""

from .cli import (
    build_multiagent_system,
    main,
    run_panda_demo,
    run_terminal_demo,
)
from .pipeline import run_panda_assessment

__all__ = [
    "build_multiagent_system",
    "run_panda_assessment",
    "run_panda_demo",
    "run_terminal_demo",
    "main",
]
