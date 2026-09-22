"""In-memory data store for the AcmeCorp mock API."""

from .models import (
    ReportRecord,
    UserProfile,
    UserRecord,
    UserSettings,
)


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
    "user-token": 1,      # alice (user 1)
    "user-2-token": 2,    # bob (user 2)
    "user-3-token": 3,    # carol (user 3, moderator)
    "admin-token": 99,    # sysadmin (admin)
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
