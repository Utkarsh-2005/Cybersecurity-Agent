from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Header, HTTPException, Query
from pydantic import BaseModel, Field


class UserRecord(BaseModel):
    id: int
    name: str
    email: str | None = None
    role: str = "user"
    profile: dict[str, Any] = Field(default_factory=dict)


class ReportRecord(BaseModel):
    id: str
    title: str
    owner: str
    summary: str


class MockAPIEnvironment:
    """A simulated API with intentionally bounded and read-only behavior."""

    def __init__(self) -> None:
        self._users = {
            1: UserRecord(
                id=1,
                name="alice",
                email="alice@example.com",
                role="user",
                profile={"department": "engineering", "manager": "carol", "api_key_hint": "dev-user-key"},
            ),
            2: UserRecord(
                id=2,
                name="bob",
                email="bob@example.com",
                role="user",
                profile={"department": "sales", "manager": "dave", "api_key_hint": "sales-user-key"},
            ),
            99: UserRecord(
                id=99,
                name="admin",
                email="admin@example.com",
                role="admin",
                profile={"department": "security", "manager": "security-team", "api_key_hint": "admin-key"},
            ),
        }
        self._reports = {
            "r1": ReportRecord(id="r1", title="Quarterly Status", owner="admin", summary="Internal summary for leadership."),
            "r2": ReportRecord(id="r2", title="Engineer Notes", owner="alice", summary="Project notes for engineering."),
        }

    def list_endpoints(self) -> list[dict[str, Any]]:
        return [
            {
                "path": "/users",
                "methods": ["GET"],
                "auth_required": True,
                "parameters": ["limit"],
                "status_codes": [200, 401],
                "response_structure": {"users": [{"id": 1, "name": "alice"}]},
                "avg_latency_ms": 110.0,
                "request_rate": 5.0,
                "error_rate": 0.02,
            },
            {
                "path": "/users/{id}",
                "methods": ["GET", "PATCH"],
                "auth_required": True,
                "parameters": ["id", "include_profile"],
                "status_codes": [200, 403, 404],
                "response_structure": {"user": {"id": 1, "role": "user", "profile": {"email": "alice@example.com"}}},
                "avg_latency_ms": 170.0,
                "request_rate": 4.0,
                "error_rate": 0.03,
            },
            {
                "path": "/admin/reports",
                "methods": ["GET"],
                "auth_required": True,
                "parameters": ["from", "to"],
                "status_codes": [200, 403, 500],
                "response_structure": {"reports": [{"id": "r1"}]},
                "avg_latency_ms": 410.0,
                "request_rate": 2.0,
                "error_rate": 0.08,
            },
        ]

    def inspect_request(self, path: str) -> dict[str, Any]:
        return {
            "method": "GET",
            "path": path,
            "parameters": ["id", "include_profile"],
            "auth": "user-token",
            "object_scope": "user-scoped",
        }

    def inspect_response(self, path: str) -> dict[str, Any]:
        return {
            "path": path,
            "status_codes": [200, 403],
            "fields": ["id", "role", "profile"],
            "exposure_level": "broader_than_expected",
        }

    def traffic_metrics(self) -> dict[str, Any]:
        return {
            "request_rate": 5.5,
            "error_rate": 0.09,
            "latency_ms": 210.0,
        }

    def compare_responses(self, endpoint_a: str, endpoint_b: str) -> dict[str, Any]:
        return {
            "endpoint_a": endpoint_a,
            "endpoint_b": endpoint_b,
            "delta_latency_ms": 240.0,
            "delta_error_rate": 0.05,
            "authorization_boundary_gap": "user-route exposes broader object data than admin route",
        }

    def authentication_context(self) -> dict[str, Any]:
        return {
            "authentication_required": True,
            "roles": ["user", "admin"],
            "active_token": "user-token",
        }

    def authorization_context(self) -> dict[str, Any]:
        return {
            "access_pattern": "user-scoped object access",
            "boundary": "authorization boundary mismatch",
            "risk": "possible broken object-level authorization",
        }

    def input_behavior(self) -> dict[str, Any]:
        return {
            "accepted_parameters": ["id", "include_profile"],
            "validation_confidence": 0.52,
            "risk": "parameterized object access is the key path",
        }

    def inspect_sensitive_data(self) -> dict[str, Any]:
        return {
            "fields": ["role", "profile", "identity"],
            "sensitive": True,
            "exposure": "present in user-facing normal responses",
        }

    def endpoint_relationships(self) -> dict[str, Any]:
        return {
            "user_admin_relation": "shared route pattern and different authorization expectations",
            "relationship_score": 0.8,
        }


API_ENV = MockAPIEnvironment()
app = FastAPI(title="PANDA Mock API", version="0.1.0")


def _auth_context(authorization: str | None) -> str:
    if not authorization:
        return "anonymous"
    return authorization.replace("Bearer ", "").strip()


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "panda-mock-api"}


@app.get("/api/endpoints")
def list_api_endpoints() -> list[dict[str, Any]]:
    return API_ENV.list_endpoints()


@app.get("/users")
def list_users(limit: int = Query(default=10, ge=1, le=50), authorization: str | None = Header(default=None, alias="Authorization")) -> dict[str, Any]:
    _auth_context(authorization)
    users = list(API_ENV._users.values())[:limit]
    return {"users": [user.model_dump(exclude={"profile"}) for user in users]}


@app.get("/users/{user_id}")
def get_user(user_id: int, include_profile: bool = Query(default=False), authorization: str | None = Header(default=None, alias="Authorization")) -> dict[str, Any]:
    token = _auth_context(authorization)
    user = API_ENV._users.get(user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="user not found")

    if token in {"user-token", "admin-token"}:
        payload = user.model_dump()
        if not include_profile:
            payload.pop("profile", None)
        return payload

    raise HTTPException(status_code=401, detail="authentication required")


@app.get("/admin/reports")
def get_reports(from_date: str | None = Query(default=None), to_date: str | None = Query(default=None), authorization: str | None = Header(default=None, alias="Authorization")) -> dict[str, Any]:
    token = _auth_context(authorization)
    if token != "admin-token":
        raise HTTPException(status_code=403, detail="admin access required")
    return {"reports": [report.model_dump() for report in API_ENV._reports.values()]}


@app.get("/security-context")
def get_security_context() -> dict[str, Any]:
    return {
        "authentication": API_ENV.authentication_context(),
        "authorization": API_ENV.authorization_context(),
        "relationships": API_ENV.endpoint_relationships(),
    }


def run_mock_api(host: str = "127.0.0.1", port: int = 8000) -> None:
    import uvicorn

    uvicorn.run(app, host=host, port=port)


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Run the PANDA mock FastAPI server.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    run_mock_api(host=args.host, port=args.port)


if __name__ == "__main__":
    main()
