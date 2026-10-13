# Cybersecurity Agent

A Python-based API security assessment tool that discovers an API, reasons about its business context and likely vulnerabilities, plans targeted probes, executes them safely, and produces a human-readable security report.

This project is built around a concept called PANDA: an LLM-driven API security agent that uses structured reasoning to analyze a target API and identify issues like broken object-level authorization, excessive data exposure, authentication weaknesses, SSRF, and misconfiguration.

## Project overview

The repository contains:

- `panda/` — the main assessment engine and supporting modules
- `reports/` — generated markdown assessment reports
- `implementation_plan.md` — design notes and architecture plan for the project
- `requirements.txt` — Python dependencies
- `panda/mock_api.py` — a realistic mock API intentionally seeded with common security issues for testing the agent

## What the project does

The agent performs a workflow like this:

1. Reconnaissance
   - Attempts to discover OpenAPI or Swagger metadata
   - Probes endpoints and common undocumented paths
   - Captures response headers and security-related metadata

2. API understanding
   - Uses an LLM to infer what the API is for, which data models it uses, and which auth patterns it observes

3. Threat modeling
   - Builds a ranked list of plausible API security issues based on OWASP API Top 10 concepts

4. Investigation planning
   - Generates test cases for the highest-value hypotheses

5. Execution and analysis
   - Runs safe HTTP probes against the target API
   - Uses the LLM to analyze evidence and decide whether more testing is needed

6. Reporting
   - Produces a markdown report with findings, severity, evidence, and remediation guidance

## Repository structure

```text
Cybersecurity-Agent/
├── implementation_plan.md
├── requirements.txt
├── reports/
│   └── *.md
├── panda/
│   ├── __init__.py
│   ├── graph.py
│   ├── mock_api.py
│   ├── models.py
│   ├── multiagent.py
│   └── tools.py
└── README.md
```

## Main components

### `panda/multiagent.py`

This is the core orchestration layer. It drives the assessment pipeline:

- environment setup
- LLM initialization
- API discovery
- API understanding
- threat modeling
- test planning
- execution analysis
- report generation

### `panda/tools.py`

Contains the execution and safety layer. It validates requests and enforces policy around HTTP execution so tests remain controlled and safe.

### `panda/models.py`

Defines the structured data models used for API understanding, threat hypotheses, test cases, analysis results, findings, and final report generation.

### `panda/mock_api.py`

A FastAPI-based mock API that represents a realistic internal SaaS application with intentionally vulnerable endpoints. It is used to validate the security agent and demonstrate finding-generation behavior.

### `panda/graph.py`

Includes a graph-oriented workflow and is part of the earlier or alternative pipeline design. The project's current emphasis is on the multi-agent / LLM-driven workflow in `multiagent.py`.

## Mock API behavior

The mock API represents an internal user-management system and intentionally contains issues such as:

- broken object-level authorization
- broken function-level authorization
- excessive data exposure
- insecure mass assignment
- differential login errors
- SSRF via webhook testing
- rate-limit weakness and security misconfiguration

This makes it useful as a benchmark or demonstration target for API security testing.

## Setup

1. Clone the repository

```bash
git clone https://github.com/Utkarsh-2005/Cybersecurity-Agent.git
cd Cybersecurity-Agent
```

2. Create a virtual environment

```bash
python -m venv .venv
source .venv/bin/activate
```

3. Install dependencies

```bash
pip install -r requirements.txt
```

4. Configure your LLM provider

The project expects an OpenRouter-compatible API key.

Create a `.env` file in the project root with something like:

```env
OPENROUTER_API_KEY=your_api_key_here
OPENROUTER_MODEL=openai/gpt-4o-mini
OPENROUTER_BASE_URL=https://openrouter.ai/api/v1
```

You may also provide authentication profiles if you want to simulate different user roles when testing a target API:

```env
PANDA_AUTH_PROFILES_JSON='{"user-token":{"Authorization":"Bearer user-token"},"admin-token":{"Authorization":"Bearer admin-token"}}'
```

## Running the mock API

Start the included mock API locally:

```bash
python panda/mock_api.py --host 127.0.0.1 --port 8000
```

The API will be available at:

```text
http://127.0.0.1:8000
```

## Running the agent

Run the security assessment against the mock API:

```bash
python -m panda.multiagent http://127.0.0.1:8000
```

This will:

- discover the API structure
- reason about the application and likely vulnerabilities
- plan targeted tests
- execute them
- generate a markdown report in the `reports/` directory

## Example report output

Reports are saved under `reports/` in filenames like:

```text
reports/panda_report_20260917T111405Z.md
```

These reports include:

- executive summary
- API overview
- findings with severity ratings
- evidence from HTTP responses
- remediation guidance
- methodology notes and limitations

## Dependencies

The project depends on:

- FastAPI
- Uvicorn
- Requests
- Pydantic
- LangGraph
- LangChain
- LangChain OpenAI
- python-dotenv

See `requirements.txt` for the full pinned list.

## Use cases

This project is useful for:

- learning how LLM-based security testing workflows can be built
- evaluating API security testing patterns
- exploring OWASP API Top 10 categories in a controlled mock environment
- prototyping intelligent security analysis pipelines

## Notes and limitations

- This project is designed as a security research and experimentation tool.
- LLM output quality depends on the model and the input context.
- The mock API is intentionally vulnerable for demonstration purposes.
- Real-world API testing should follow strict authorization, rate-limit, and safety controls.

## License

This repository does not currently declare a license in the project metadata. Check the repository settings if you need explicit licensing information before commercial or public redistribution.

## Summary

Cybersecurity-Agent is a Python prototype for an LLM-driven API security assessment workflow. It combines reconnaissance, business context analysis, threat modeling, targeted testing, and professional-grade reporting to create a practical security agent aimed at API vulnerabilities.

For more detail on the intended architecture and planned redesign, see `implementation_plan.md`.
