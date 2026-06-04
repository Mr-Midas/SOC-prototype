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

    return {"settings": clean}


@router.put("/api/settings")
async def update_settings(request: Request):
    user_identity = require_auth(request)
    db = await get_db()
    tenant_id = UUID(user_identity["tenant_id"])

    body = await request.json()
    try:
        update = TenantSettingsUpdate(**body)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid settings: {exc}")

    changes = update.model_dump(exclude_none=True)
    if not changes:
        return {"status": "no changes"}

    await db.update_settings(tenant_id, changes)
    return {"status": "updated"}
