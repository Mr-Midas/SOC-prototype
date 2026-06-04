from __future__ import annotations

from typing import Optional
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query, Request

from copilot_soc.api.auth import require_auth, require_governor
from copilot_soc.api.deps import get_db
from copilot_soc.models import DecisionRequest

router = APIRouter(tags=["alerts"])


@router.get("/api/alerts")
async def list_alerts(
    request: Request,
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=25, ge=5, le=100),
    pipeline_state: Optional[str] = Query(default=None),
    governor_status: Optional[str] = Query(default=None),
    severity: Optional[str] = Query(default=None),
):
    user_identity = require_auth(request)
    db = await get_db()
    tenant_id = UUID(user_identity["tenant_id"])

    result = await db.list_alerts(
        tenant_id=tenant_id,
        page=page,
        per_page=per_page,
        pipeline_state=pipeline_state,
        governor_status=governor_status,
        severity=severity,
    )

    return {
        "alerts": result["rows"],
        "total": result["total"],
        "page": page,
        "per_page": per_page,
        "pages": (result["total"] + per_page - 1) // per_page,
    }


@router.get("/api/alerts/{alert_id}")
async def get_alert(alert_id: str, request: Request):
    user_identity = require_auth(request)
    db = await get_db()
    tenant_id = UUID(user_identity["tenant_id"])

    alert = await db.get_alert(UUID(alert_id), tenant_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found.")

    return {"alert": alert}


@router.post("/api/alerts/{alert_id}/governor")
async def governor_decision(alert_id: str, request: Request):
    user_identity = require_governor(request)
    db = await get_db()
    tenant_id = UUID(user_identity["tenant_id"])

    body = await request.json()
    try:
        decision = DecisionRequest(**body)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid decision: {exc}")

    alert = await db.get_alert(UUID(alert_id), tenant_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found.")

    governor_status = "approved" if decision.decision == "approve" else "rejected"

    await db.update_alert_pipeline(
        UUID(alert_id), tenant_id,
        governor_status=governor_status,
        governor_decision={
            "status": governor_status,
            "operator_note": decision.operator_note,
            "decided_at": None,
            "decided_by": user_identity["user_id"],
        },
    )

    if governor_status == "approved" and alert.get("containment_output"):
        await db.enqueue_action(
            tenant_id=tenant_id,
            alert_id=UUID(alert_id),
            action_type=alert["containment_output"].get("action_type", "unknown"),
            payload=alert["containment_output"],
        )

    return {"status": governor_status, "alert_id": alert_id}
