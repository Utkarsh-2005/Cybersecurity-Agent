"""Realistic mock API for PANDA security testing.

This API simulates a user-management backend that a small SaaS company
might ship.  It looks and behaves like a normal API — no endpoint or
response explicitly names or hints at any vulnerability.  The security
issues are *implicit*, exactly the way they appear in the real world.

Intentional vulnerabilities (for agent discovery, NOT labeled anywhere):
- BOLA on /users/{id} and /users/{id}/settings
- BFLA on /admin/users/export (user-token can access admin function)
- Mass assignment on POST /users (accepts "role" in body)
- IDOR on PUT /users/{id} (any authed user can update anyone)
- Differential errors on POST /auth/login
- Excessive data exposure on /users and /users/{id}
- Security misconfiguration (verbose errors, CORS *, info leak headers)
- No rate limiting on /auth/login
"""

from __future__ import annotations

import time
import traceback
import uuid
import requests
from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

class UserProfile(BaseModel):
    department: str = ""
    phone: str = ""
    address: str = ""
    ssn_last4: str = ""
    salary: float = 0.0
    emergency_contact: str = ""


class UserRecord(BaseModel):
    id: int
    username: str
    email: str
    full_name: str
    role: str = "user"
    is_active: bool = True
    created_at: str = ""
    profile: UserProfile = Field(default_factory=UserProfile)


class UserSettings(BaseModel):
    user_id: int
    theme: str = "light"
    notifications_enabled: bool = True
    two_factor_enabled: bool = False
    api_key: str = ""
    webhook_url: str = ""
    timezone: str = "UTC"


class ReportRecord(BaseModel):
    id: str
    title: str
    created_by: str
    created_at: str
    status: str
    row_count: int
    summary: str


class CreateUserRequest(BaseModel):
    username: str
    email: str
    full_name: str
    role: str = "user"  # mass-assignment: accepted from client
    department: str = ""
    phone: str = ""


class UpdateUserRequest(BaseModel):
    full_name: str | None = None
    email: str | None = None
    phone: str | None = None
    department: str | None = None


class LoginRequest(BaseModel):
    username: str
    password: str


class WebhookTestRequest(BaseModel):
    target_url: str


class ExportReportsRequest(BaseModel):
    report_type: str = "users"
    row_limit: int = 100


# ---------------------------------------------------------------------------
# In-memory data store
# ---------------------------------------------------------------------------

_USERS: dict[int, UserRecord] = {
    1: UserRecord(
        id=1, username="alice", email="alice.chen@acmecorp.io",
        full_name="Alice Chen", role="user", created_at="2025-11-02T09:14:00Z",
        profile=UserProfile(
            department="Engineering", phone="+1-555-0101",
            address="742 Evergreen Terrace, Springfield, IL 62704",
            ssn_last4="4829", salary=125000.00,
            emergency_contact="Bob Chen (+1-555-0182)",
        ),
    ),
    2: UserRecord(
        id=2, username="bob", email="bob.martinez@acmecorp.io",
        full_name="Bob Martinez", role="user", created_at="2025-11-15T14:30:00Z",
        profile=UserProfile(
            department="Sales", phone="+1-555-0102",
            address="123 Oak Street, Portland, OR 97201",
            ssn_last4="7713", salary=95000.00,
            emergency_contact="Maria Martinez (+1-555-0199)",
        ),
    ),
    3: UserRecord(
        id=3, username="carol", email="carol.nguyen@acmecorp.io",
        full_name="Carol Nguyen", role="moderator", created_at="2025-12-01T10:00:00Z",
        profile=UserProfile(
            department="Support", phone="+1-555-0103",
            address="456 Pine Ave, Austin, TX 73301",
            ssn_last4="3351", salary=105000.00,
            emergency_contact="David Nguyen (+1-555-0177)",
        ),
    ),
    4: UserRecord(
        id=4, username="dave", email="dave.oconnor@acmecorp.io",
        full_name="Dave O'Connor", role="user", created_at="2026-01-10T08:45:00Z",
        profile=UserProfile(
            department="Engineering", phone="+1-555-0104",
            address="789 Maple Dr, Seattle, WA 98101",
            ssn_last4="6642", salary=130000.00,
            emergency_contact="Ellen O'Connor (+1-555-0188)",
        ),
    ),
    5: UserRecord(
        id=5, username="eve", email="eve.wright@acmecorp.io",
        full_name="Eve Wright", role="user", is_active=False,
        created_at="2026-02-20T16:00:00Z",
        profile=UserProfile(
            department="Marketing", phone="+1-555-0105",
            address="321 Elm Blvd, Denver, CO 80201",
            ssn_last4="1198", salary=88000.00,
            emergency_contact="Frank Wright (+1-555-0155)",
        ),
    ),
    99: UserRecord(
        id=99, username="sysadmin", email="admin@acmecorp.io",
        full_name="System Administrator", role="admin",
        created_at="2025-10-01T00:00:00Z",
        profile=UserProfile(
            department="IT Security", phone="+1-555-0100",
            address="100 Corporate Blvd, San Jose, CA 95110",
            ssn_last4="0001", salary=175000.00,
            emergency_contact="IT Help Desk (+1-555-0000)",
        ),
    ),
}

_SETTINGS: dict[int, UserSettings] = {
    1: UserSettings(
        user_id=1, theme="dark", notifications_enabled=True,
        two_factor_enabled=True, api_key="ak_prod_a1b2c3d4e5f6",
        webhook_url="https://hooks.acmecorp.io/alice", timezone="America/Chicago",
    ),
    2: UserSettings(
        user_id=2, theme="light", notifications_enabled=True,
        two_factor_enabled=False, api_key="ak_prod_g7h8i9j0k1l2",
        webhook_url="", timezone="America/Los_Angeles",
    ),
    3: UserSettings(
        user_id=3, theme="dark", notifications_enabled=False,
        two_factor_enabled=True, api_key="ak_prod_m3n4o5p6q7r8",
        webhook_url="https://hooks.acmecorp.io/carol", timezone="America/Chicago",
    ),
    4: UserSettings(
        user_id=4, theme="auto", notifications_enabled=True,
        two_factor_enabled=False, api_key="ak_prod_s9t0u1v2w3x4",
        webhook_url="", timezone="America/Los_Angeles",
    ),
    5: UserSettings(
        user_id=5, theme="light", notifications_enabled=False,
        two_factor_enabled=False, api_key="ak_prod_y5z6a7b8c9d0",
        webhook_url="", timezone="America/Denver",
    ),
    99: UserSettings(
        user_id=99, theme="dark", notifications_enabled=True,
        two_factor_enabled=True, api_key="ak_admin_MASTER_e1f2g3h4",
        webhook_url="https://hooks.acmecorp.io/admin-alerts", timezone="America/New_York",
    ),
}

_REPORTS: dict[str, ReportRecord] = {
    "rpt-001": ReportRecord(
        id="rpt-001", title="Q3 Revenue Summary",
        created_by="sysadmin", created_at="2026-07-01T09:00:00Z",
        status="final", row_count=1247,
        summary="Quarterly revenue across all product lines, including per-region breakdown.",
    ),
    "rpt-002": ReportRecord(
        id="rpt-002", title="User Growth Metrics",
        created_by="sysadmin", created_at="2026-08-15T14:30:00Z",
        status="draft", row_count=834,
        summary="Month-over-month user signups, churn, and retention cohort analysis.",
    ),
    "rpt-003": ReportRecord(
        id="rpt-003", title="Infrastructure Cost Audit",
        created_by="sysadmin", created_at="2026-09-01T11:00:00Z",
        status="final", row_count=562,
        summary="Cloud spend by service, with cost-optimization recommendations.",
    ),
}

# Token → user-id mapping (simulates JWT-extracted identity)
_TOKEN_IDENTITY: dict[str, int] = {
    "user-token": 1,      # alice
    "admin-token": 99,    # sysadmin
}

_CREDENTIALS: dict[str, str] = {
    "alice": "password123",
    "bob": "bobsecure!",
    "carol": "carol2026",
    "dave": "d4v3p@ss",
    "eve": "evelyn99",
    "sysadmin": "Adm1n$ecure!",
}

_NEXT_USER_ID = 100


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

app = FastAPI(
    title="AcmeCorp User Management API",
    version="2.1.0",
    description="Internal API for managing AcmeCorp employee accounts and reports.",
)

# Security misconfiguration: wildcard CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Middleware — adds info-leak headers to every response
# ---------------------------------------------------------------------------

@app.middleware("http")
async def add_server_headers(request: Request, call_next):
    response = await call_next(request)
    # Security misconfiguration: leaking server and framework info
    response.headers["Server"] = "uvicorn/0.30.0"
    response.headers["X-Powered-By"] = "FastAPI/0.115.0"
    # Missing recommended security headers (agent should notice absence)
    # No X-Content-Type-Options
    # No X-Frame-Options
    # No Strict-Transport-Security
    return response


# ---------------------------------------------------------------------------
# Global exception handler — verbose errors (info leak)
# ---------------------------------------------------------------------------

@app.exception_handler(Exception)
async def verbose_error_handler(request: Request, exc: Exception):
    """Return detailed error info — a common real-world misconfiguration."""
    tb = traceback.format_exception(type(exc), exc, exc.__traceback__)
    return JSONResponse(
        status_code=500,
        content={
            "error": "internal_server_error",
            "message": str(exc),
            "path": str(request.url.path),
            "traceback": tb[-3:],  # last 3 frames of stack trace
        },
    )


# ---------------------------------------------------------------------------
# Auth helper
# ---------------------------------------------------------------------------

def _resolve_auth(authorization: str | None) -> tuple[str, int | None]:
    """Return (token_string, user_id_or_None)."""
    if not authorization:
        return "anonymous", None
    token = authorization.replace("Bearer ", "").strip()
    return token, _TOKEN_IDENTITY.get(token)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/health")
def health():
    return {"status": "ok", "version": "2.1.0"}


# ---- Users ----

@app.get("/api/v1/users", include_in_schema=False)
def list_users_v1(limit: int = Query(default=20, ge=1, le=100)):
    """Old version of the users API. 
    Vulnerability: Improper Inventory Management (API9). 
    This endpoint does not require authentication and returns PII.
    It is hidden from the OpenAPI schema but remains active.
    """
    users = list(_USERS.values())[:limit]
    return {
        "users": [
            {
                "id": u.id,
                "username": u.username,
                "email": u.email,
                "full_name": u.full_name,
                "role": u.role,
                "department": u.profile.department,
                "phone": u.profile.phone,
                "is_active": u.is_active,
                "created_at": u.created_at,
            }
            for u in users
        ],
        "total": len(users),
        "warning": "This is a v1 deprecated API.",
    }


@app.get("/users")
def list_users(
    limit: int = Query(default=20, ge=1, le=100),
    include_inactive: bool = Query(default=False),
    authorization: str | None = Header(default=None, alias="Authorization"),
):
    """List users. Requires authentication.
    Vulnerability: returns excessive PII (email, phone, role) to any authed user.
    """
    token, user_id = _resolve_auth(authorization)
    if user_id is None:
        raise HTTPException(status_code=401, detail="Authentication required.")

    users = list(_USERS.values())
    if not include_inactive:
        users = [u for u in users if u.is_active]
    users = users[:limit]

    # Excessive data exposure: returns more fields than a list view should
    return {
        "users": [
            {
                "id": u.id,
                "username": u.username,
                "email": u.email,
                "full_name": u.full_name,
                "role": u.role,
                "department": u.profile.department,
                "phone": u.profile.phone,
                "is_active": u.is_active,
                "created_at": u.created_at,
            }
            for u in users
        ],
        "total": len(users),
    }


@app.get("/users/{user_id}")
def get_user(
    user_id: int,
    authorization: str | None = Header(default=None, alias="Authorization"),
):
    """Get user details.
    Vulnerability: BOLA — any authenticated user can read any user's full profile,
    including PII (salary, SSN last 4, address). No ownership check.
    """
    token, requester_id = _resolve_auth(authorization)
    if requester_id is None:
        raise HTTPException(status_code=401, detail="Authentication required.")

    user = _USERS.get(user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found.")

    # No ownership check — any authed user gets full details including profile
    return user.model_dump()


@app.post("/users")
def create_user(
    body: CreateUserRequest,
    authorization: str | None = Header(default=None, alias="Authorization"),
):
    """Create a new user.
    Vulnerability: Mass assignment — the "role" field from the request body is
    accepted directly. A regular user could create an account with role="admin".
    """
    global _NEXT_USER_ID
    token, requester_id = _resolve_auth(authorization)
    if requester_id is None:
        raise HTTPException(status_code=401, detail="Authentication required.")

    # Check for duplicate username
    if any(u.username == body.username for u in _USERS.values()):
        raise HTTPException(status_code=409, detail="Username already exists.")

    new_id = _NEXT_USER_ID
    _NEXT_USER_ID += 1

    new_user = UserRecord(
        id=new_id,
        username=body.username,
        email=body.email,
        full_name=body.full_name,
        role=body.role,  # mass assignment: role accepted from client
        created_at=datetime.now(timezone.utc).isoformat(),
        profile=UserProfile(department=body.department, phone=body.phone),
    )
    _USERS[new_id] = new_user

    # Also create default settings
    _SETTINGS[new_id] = UserSettings(
        user_id=new_id,
        api_key=f"ak_prod_{uuid.uuid4().hex[:12]}",
    )

    return {"id": new_id, "username": new_user.username, "role": new_user.role}


@app.put("/users/{user_id}")
def update_user(
    user_id: int,
    body: UpdateUserRequest,
    authorization: str | None = Header(default=None, alias="Authorization"),
):
    """Update user profile.
    Vulnerability: IDOR — any authenticated user can update any other user's
    profile. No check that requester_id == user_id.
    """
    token, requester_id = _resolve_auth(authorization)
    if requester_id is None:
        raise HTTPException(status_code=401, detail="Authentication required.")

    user = _USERS.get(user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found.")

    # No ownership check — any authed user can modify any user
    if body.full_name is not None:
        user.full_name = body.full_name
    if body.email is not None:
        user.email = body.email
    if body.phone is not None:
        user.profile.phone = body.phone
    if body.department is not None:
        user.profile.department = body.department

    return {"message": "User updated successfully.", "id": user_id}


@app.delete("/users/{user_id}")
def delete_user(
    user_id: int,
    authorization: str | None = Header(default=None, alias="Authorization"),
):
    """Delete a user. Admin only — properly gated (positive control)."""
    token, requester_id = _resolve_auth(authorization)
    if requester_id is None:
        raise HTTPException(status_code=401, detail="Authentication required.")

    requester = _USERS.get(requester_id)
    if requester is None or requester.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required.")

    if user_id not in _USERS:
        raise HTTPException(status_code=404, detail="User not found.")

    del _USERS[user_id]
    _SETTINGS.pop(user_id, None)
    return {"message": "User deleted.", "id": user_id}


# ---- User settings ----

@app.get("/users/{user_id}/settings")
def get_user_settings(
    user_id: int,
    authorization: str | None = Header(default=None, alias="Authorization"),
):
    """Get user settings including API key.
    Vulnerability: BOLA — any authed user can read any user's settings,
    which include the API key and webhook URL.
    """
    token, requester_id = _resolve_auth(authorization)
    if requester_id is None:
        raise HTTPException(status_code=401, detail="Authentication required.")

    settings = _SETTINGS.get(user_id)
    if settings is None:
        raise HTTPException(status_code=404, detail="Settings not found.")

    # No ownership check
    return settings.model_dump()


# ---- Auth ----

@app.post("/auth/login")
def login(body: LoginRequest):
    """Authenticate and receive a token.
    Vulnerabilities:
    - Differential error messages: "User not found" vs "Invalid password"
    - No rate limiting
    - No account lockout
    """
    if body.username not in _CREDENTIALS:
        # Differential error: reveals whether username exists
        raise HTTPException(status_code=401, detail="User not found.")

    if _CREDENTIALS[body.username] != body.password:
        # Different message for wrong password
        raise HTTPException(status_code=401, detail="Invalid password.")

    # Find user ID
    uid = next((u.id for u in _USERS.values() if u.username == body.username), None)
    token = f"tok_{body.username}_{uuid.uuid4().hex[:8]}"

    return {
        "access_token": token,
        "token_type": "bearer",
        "user_id": uid,
        "role": next((u.role for u in _USERS.values() if u.username == body.username), "user"),
    }


# ---- Admin ----

@app.get("/admin/reports")
def get_reports(
    authorization: str | None = Header(default=None, alias="Authorization"),
):
    """List admin reports. Properly gated — admin only (positive control)."""
    token, requester_id = _resolve_auth(authorization)
    if requester_id is None:
        raise HTTPException(status_code=401, detail="Authentication required.")

    requester = _USERS.get(requester_id)
    if requester is None or requester.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required.")

    return {"reports": [r.model_dump() for r in _REPORTS.values()]}


@app.get("/admin/users/export")
def export_users(
    format: str = Query(default="json"),
    authorization: str | None = Header(default=None, alias="Authorization"),
):
    """Export all users with full profiles.
    Vulnerability: BFLA — This is supposed to be admin-only, but the
    authorization check only verifies that the user is authenticated,
    not that they are an admin.
    """
    token, requester_id = _resolve_auth(authorization)
    if requester_id is None:
        raise HTTPException(status_code=401, detail="Authentication required.")

    # BUG: Missing role check — any authenticated user can export all data
    # Should check: if requester.role != "admin": raise 403

    all_users = [u.model_dump() for u in _USERS.values()]
    return {
        "format": format,
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "count": len(all_users),
        "users": all_users,
    }


@app.post("/reports/export")
def generate_export(
    body: ExportReportsRequest,
    authorization: str | None = Header(default=None, alias="Authorization"),
):
    """Generate a large export report.
    Vulnerability: Unrestricted Resource Consumption (API4).
    The row_limit has no maximum validation. If a huge number is provided,
    it accepts it and pretends to process a massive job.
    """
    token, requester_id = _resolve_auth(authorization)
    if requester_id is None:
        raise HTTPException(status_code=401, detail="Authentication required.")

    # No upper bound validation on row_limit
    estimated_seconds = body.row_limit * 0.05
    if body.row_limit > 10000:
        return {
            "status": "processing",
            "job_id": f"job_{uuid.uuid4().hex[:8]}",
            "rows_requested": body.row_limit,
            "estimated_completion_time_seconds": estimated_seconds,
            "message": "Large job accepted. This will consume significant server resources."
        }
    return {
        "status": "completed",
        "rows_processed": body.row_limit,
    }


# ---- Webhooks ----

@app.post("/webhooks/test")
def test_webhook(
    body: WebhookTestRequest,
    authorization: str | None = Header(default=None, alias="Authorization"),
):
    """Test a webhook URL.
    Vulnerability: Server-Side Request Forgery (SSRF) (API7).
    The endpoint fetches the user-provided URL without any validation
    or restrictions against internal endpoints (like localhost).
    """
    token, requester_id = _resolve_auth(authorization)
    if requester_id is None:
        raise HTTPException(status_code=401, detail="Authentication required.")

    try:
        # Dangerous: blindly fetching the user-provided URL
        # We use a short timeout to prevent the mock server from hanging
        resp = requests.get(body.target_url, timeout=2.0)
        return {
            "message": "Webhook test completed.",
            "target_url": body.target_url,
            "status_code": resp.status_code,
            "response_body": resp.text[:1000],  # Return up to 1KB of the response
        }
    except Exception as e:
        return {
            "message": "Webhook test failed.",
            "error": str(e),
        }


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run_mock_api(host: str = "127.0.0.1", port: int = 8000) -> None:
    import uvicorn
    uvicorn.run(app, host=host, port=port)


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Run the AcmeCorp mock API server.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    run_mock_api(host=args.host, port=args.port)


if __name__ == "__main__":
    main()
