"""Tenant settings CRUD — LLM provider, model, webhook secret, feature toggles.

Sensitive values (llm_api_key, webhook_secret) are masked in GET responses.
The PUT endpoint accepts partial updates via TenantSettingsUpdate model.
"""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, HTTPException, Request

from copilot_soc.api.auth import require_auth
from copilot_soc.api.deps import get_db
from copilot_soc.models import TenantSettingsUpdate

router = APIRouter(tags=["settings"])


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
    import platform
    return {"settings": clean, "is_windows": platform.system() == "Windows", "collector_status": None}


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

    settings = await db.get_settings(tenant_id)
    sensitive_keys = {"llm_api_key", "webhook_secret"}
    clean = {k: v for k, v in settings.items() if k not in sensitive_keys}
    for k in sensitive_keys:
        clean[k] = "********" if settings.get(k) else None

    clean["sampleGenerationEnabled"] = clean.get("sample_events_enabled", True)
    import platform
    return {"settings": clean, "is_windows": platform.system() == "Windows", "collector_status": None}
