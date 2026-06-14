"""Tenant settings CRUD â€” LLM provider, model, webhook secret, feature toggles.

Sensitive values (llm_api_key, webhook_secret) are masked in GET responses.
The PUT endpoint accepts partial updates via TenantSettingsUpdate model.
"""

from __future__ import annotations

import platform
from uuid import UUID

from fastapi import APIRouter, HTTPException, Request

from arbiterion.api.auth import require_auth
from arbiterion.api.deps import get_db
from arbiterion.models import TenantSettingsUpdate

router = APIRouter(tags=["settings"])

_collector_start_cb = None
_collector_stop_cb = None
_collector_is_running_cb = None


def register_collector_callbacks(start_cb, stop_cb, is_running_cb):
    """Called once at startup by main.py to wire the collector lifecycle."""
    global _collector_start_cb, _collector_stop_cb, _collector_is_running_cb
    _collector_start_cb = start_cb
    _collector_stop_cb = stop_cb
    _collector_is_running_cb = is_running_cb


@router.get("/api/settings")
async def get_settings(request: Request):
    user_identity = require_auth(request)
    db = await get_db()
    tenant_id = UUID(user_identity["tenant_id"])

    settings = await db.get_settings(tenant_id)
    sensitive_keys = {"llm_api_key", "webhook_secret"}
    clean = {k: v for k, v in settings.items() if k not in sensitive_keys}
    for k in sensitive_keys:
        if settings.get(k):
            clean[k] = "********"
        else:
            clean[k] = None

    clean["sampleGenerationEnabled"] = clean.get("sample_events_enabled", True)

    collector_running = False
    if _collector_is_running_cb:
        collector_running = _collector_is_running_cb()

    return {
        "settings": clean,
        "is_windows": platform.system() == "Windows",
        "collector_status": {"running": collector_running} if collector_running else None,
    }


@router.put("/api/settings")
async def update_settings(request: Request):
    user_identity = require_auth(request)
    db = await get_db()
    tenant_id = UUID(user_identity["tenant_id"])

    body = await request.json()
    changes = {}
    for key in ("use_ai_triage", "safe_mode", "threat_intel_enabled", "sample_events_enabled", "monitor_windows_events"):
        if key in body:
            changes[key] = bool(body[key])

    if changes:
        await db.update_settings(tenant_id, changes)

    if "monitor_windows_events" in changes:
        if changes["monitor_windows_events"] and _collector_start_cb:
            _collector_start_cb()
        elif not changes["monitor_windows_events"] and _collector_stop_cb:
            _collector_stop_cb()

    settings = await db.get_settings(tenant_id)
    sensitive_keys = {"llm_api_key", "webhook_secret"}
    clean = {k: v for k, v in settings.items() if k not in sensitive_keys}
    for k in sensitive_keys:
        clean[k] = "********" if settings.get(k) else None

    clean["sampleGenerationEnabled"] = clean.get("sample_events_enabled", True)

    collector_running = False
    if _collector_is_running_cb:
        collector_running = _collector_is_running_cb()

    return {
        "settings": clean,
        "is_windows": platform.system() == "Windows",
        "collector_status": {"running": collector_running} if collector_running else None,
    }

