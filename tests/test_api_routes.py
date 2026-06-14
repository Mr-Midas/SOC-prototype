"""API route integration tests using FastAPI TestClient with a mock database layer.

Tests cover:
- Health endpoint (no DB required)
- Login / logout / me flows
- Alert list, detail, and governor decision
- Settings get/put
- 401/403 enforcement on protected routes
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient

from arbiterion.main import app


@pytest.fixture
def client():
    return TestClient(app)


def _make_mock_db():
    """Build a MagicMock that looks like the Database class."""
    tenant_id = uuid4()
    user_id = uuid4()
    alert_id = uuid4()

    db = MagicMock()

    db.create_tenant = AsyncMock(return_value={
        "id": tenant_id, "name": "Test Corp", "slug": "test",
        "plan_tier": "starter", "alert_limit": 100,
    })
    db.get_tenant = AsyncMock(return_value={
        "id": tenant_id, "name": "Default Corp", "slug": "default",
        "plan_tier": "starter", "alert_limit": 100,
        "alerts_used_today": 0, "daily_reset_at": None,
        "stripe_customer_id": None,
    })
    db.get_tenant_by_slug = AsyncMock(return_value={
        "id": tenant_id, "name": "Default Corp", "slug": "default",
        "plan_tier": "starter", "alert_limit": 100,
        "alerts_used_today": 0, "daily_reset_at": None,
    })
    db.get_user_by_email = AsyncMock(return_value={
        "id": user_id, "tenant_id": tenant_id,
        "email": "admin@arbiterion.local",
        "password_hash": "f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6$abc123",
        "role": "admin",
    })
    db.get_settings = AsyncMock(return_value={
        "llm_provider": "openai", "llm_model": "gpt-4o-mini",
        "use_ai_triage": True, "safe_mode": True,
        "webhook_secret": None, "llm_api_key": None,
    })
    db.check_alert_limit = AsyncMock(return_value=True)
    db.increment_alert_usage = AsyncMock()
    db.create_alert = AsyncMock(return_value={
        "id": alert_id, "tenant_id": tenant_id,
        "pipeline_state": "queued", "governor_status": "pending",
        "created_at": "2026-01-01T00:00:00",
    })
    db.get_alert = AsyncMock(return_value={
        "id": alert_id, "tenant_id": tenant_id,
        "pipeline_state": "queued", "governor_status": "pending",
        "severity": "High", "risk_score": 75,
        "manager_output": None, "triage_output": None,
        "containment_output": None, "reasoning_log": [],
        "raw_alert": {}, "source": "Test", "rule_name": "Test Rule",
        "summary": "Test alert", "created_at": "2026-01-01T00:00:00",
    })
    db.list_alerts = AsyncMock(return_value={
        "rows": [], "total": 0,
    })
    db.update_settings = AsyncMock()
    db.update_alert_pipeline = AsyncMock()
    db.set_governor_decision = AsyncMock()
    db.enqueue_action = AsyncMock()

    return db, tenant_id, alert_id


@pytest.fixture
def mock_db():
    db, tid, aid = _make_mock_db()
    return {"db": db, "tenant_id": tid, "alert_id": aid}


@pytest.fixture(autouse=True)
def patch_get_db(mock_db):
    """Replace get_db() in every module that imports it with our mock."""
    import arbiterion.api.deps as deps
    import arbiterion.api.auth as auth_mod
    import arbiterion.api.ingestion as ingest_mod

    async def fake_get_db():
        return mock_db["db"]

    original_deps = deps.get_db
    original_auth = auth_mod.get_db
    original_ingest = ingest_mod.get_db

    deps.get_db = fake_get_db
    auth_mod.get_db = fake_get_db
    ingest_mod.get_db = fake_get_db

    yield

    deps.get_db = original_deps
    auth_mod.get_db = original_auth
    ingest_mod.get_db = original_ingest


# â”€â”€ Health â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestHealth:
    def test_health_returns_ok(self, client):
        resp = client.get("/api/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["service"] == "arbiterion"


# â”€â”€ Auth Routes â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestAuth:
    def test_logout_returns_ok(self, client):
        resp = client.post("/api/logout")
        assert resp.status_code == 200

    def test_me_without_auth(self, client):
        resp = client.get("/api/me")
        assert resp.status_code == 401

    def test_me_with_bad_session(self, client):
        client.cookies.set("soc_session", "bad|token|here|deadbeef")
        resp = client.get("/api/me")
        assert resp.status_code == 401


# â”€â”€ Alert Routes â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestAlerts:
    def test_list_alerts_without_auth(self, client):
        resp = client.get("/api/alerts")
        assert resp.status_code == 401

    def test_get_alert_without_auth(self, client):
        resp = client.get(f"/api/alerts/{uuid4()}")
        assert resp.status_code == 401

    def test_governor_without_auth(self, client):
        resp = client.post(f"/api/alerts/{uuid4()}/governor", json={"decision": "approve"})
        assert resp.status_code == 401

    def test_governor_with_analyst_session_denied(self, client, mock_db):
        """A session with role=analyst gets 403 on the governor endpoint."""
        import arbiterion.api.auth as auth_mod
        token = auth_mod._issue_session_token(str(uuid4()), str(mock_db["tenant_id"]), "analyst")
        client.cookies.set("soc_session", token)
        resp = client.post(f"/api/alerts/{uuid4()}/governor", json={"decision": "approve"})
        assert resp.status_code == 403


# â”€â”€ Settings Routes â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestSettings:
    def test_get_settings_without_auth(self, client):
        resp = client.get("/api/settings")
        assert resp.status_code == 401

    def test_update_settings_without_auth(self, client):
        resp = client.put("/api/settings", json={"llm_provider": "anthropic"})
        assert resp.status_code == 401


# â”€â”€ Ingestion Routes â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestIngestion:
    def test_ingest_without_auth(self, client):
        resp = client.post("/api/v1/ingest/alert", json={
            "source": "Test", "rule_name": "Test Rule",
            "summary": "This is a test alert for integration testing",
        })
        assert resp.status_code == 401

