"""Realistic mock API for PANDA security testing.

This package simulates a user-management backend that a small SaaS company
might ship.  It looks and behaves like a normal API — no endpoint or
response explicitly names or hints at any vulnerability.  The security
issues are *implicit*, exactly the way they appear in the real world.
"""

# Import routes so that FastAPI registers the endpoints on import
from . import routes  # noqa: F401

from .app import app
from .server import main, run_mock_api

__all__ = ["app", "run_mock_api", "main"]
