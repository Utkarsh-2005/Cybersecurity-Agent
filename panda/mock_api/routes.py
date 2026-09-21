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

import uuid
import requests
from datetime import datetime, timezone

from fastapi import Header, HTTPException, Query

from .app import app
from .data_store import (
    _CREDENTIALS,
    _NEXT_USER_ID,
    _REPORTS,
    _SETTINGS,
    _TOKEN_IDENTITY,
    _USERS,
)
from .models import (
    CreateUserRequest,
    ExportReportsRequest,
    LoginRequest,
    UpdateUserRequest,
    UserProfile,
    UserRecord,
    UserSettings,
    WebhookTestRequest,
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
    # Use the module-level variable via data_store
    import panda.mock_api.data_store as _ds

    token, requester_id = _resolve_auth(authorization)
    if requester_id is None:
        raise HTTPException(status_code=401, detail="Authentication required.")

    # Check for duplicate username
    if any(u.username == body.username for u in _USERS.values()):
        raise HTTPException(status_code=409, detail="Username already exists.")

    new_id = _ds._NEXT_USER_ID
    _ds._NEXT_USER_ID += 1

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
