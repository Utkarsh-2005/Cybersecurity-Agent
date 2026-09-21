# Refactor mock_api.py and multiagent.py into Modular File Structures

The goal is to segment `mock_api.py` and `multiagent.py` into a logical, simple, and readable file structure while keeping all code and functionality strictly identical. We will convert these two monolithic files into packages (directories) and organize their contents into modules.

## Proposed Changes

### `mock_api.py` Refactoring

We will replace the `mock_api.py` file with a directory named `mock_api` and split its contents into smaller, focused modules. The `__init__.py` will expose necessary components to maintain backwards compatibility.

#### [DELETE] `panda/mock_api.py`
#### [NEW] `panda/mock_api/__init__.py`
Will import the application and main entry point to maintain compatibility.
#### [NEW] `panda/mock_api/models.py`
Will contain all Pydantic models (e.g., `UserProfile`, `UserRecord`, `CreateUserRequest`, etc.).
#### [NEW] `panda/mock_api/data_store.py`
Will house the in-memory data dictionaries (`_USERS`, `_SETTINGS`, `_REPORTS`, `_CREDENTIALS`, etc.).
#### [NEW] `panda/mock_api/app.py`
Will initialize the FastAPI app, define middlewares, and configure the exception handler.
#### [NEW] `panda/mock_api/routes.py`
Will group all endpoints (health, users, settings, auth, admin, webhooks) and the `_resolve_auth` helper.
#### [NEW] `panda/mock_api/server.py`
Will contain the `run_mock_api` and `main` entry point functions.

---

### `multiagent.py` Refactoring

Similarly, we will replace the `multiagent.py` file with a directory named `multiagent` and organize its phases into distinct modules.

#### [DELETE] `panda/multiagent.py`
#### [NEW] `panda/multiagent/__init__.py`
Will export the main orchestrator functions and backward-compatible entry points (`build_multiagent_system`, `run_panda_demo`, `run_terminal_demo`, `run_panda_assessment`).
#### [NEW] `panda/multiagent/utils.py`
Will contain environment setup, LLM builder, and common utilities (`_emit_event`, `_llm_call`, etc.).
#### [NEW] `panda/multiagent/phases/recon.py`
Will handle API discovery and baseline probes (`_discover_api`).
#### [NEW] `panda/multiagent/phases/understanding.py`
Will contain the API understanding LLM prompt (`_understand_api`).
#### [NEW] `panda/multiagent/phases/threat_modeling.py`
Will contain the threat modeling phase (`_model_threats`).
#### [NEW] `panda/multiagent/phases/test_planning.py`
Will contain test probe generation logic (`_plan_investigation`).
#### [NEW] `panda/multiagent/phases/execution.py`
Will execute the tests and analyze the results (`_execute_and_analyze`).
#### [NEW] `panda/multiagent/phases/reporting.py`
Will house report generation, markdown rendering, and file writing logic.
#### [NEW] `panda/multiagent/pipeline.py`
Will assemble the phases into the main orchestrator (`run_panda_assessment`).
#### [NEW] `panda/multiagent/cli.py`
Will provide the CLI argument parsing and backward-compatible helper functions.

## Verification Plan

### Automated Tests
I will attempt to run the modules directly to verify there are no syntax errors or import issues, e.g., `python -m panda.mock_api.server` and `python -m panda.multiagent.cli -h`.

### Manual Verification
Review the git status to confirm that everything has been moved properly without breaking the overall package structure, and that both the Mock API and Multi-Agent pipeline can run successfully just as they did when they were monoliths.
