"""Pydantic data models for the AcmeCorp mock API."""

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
