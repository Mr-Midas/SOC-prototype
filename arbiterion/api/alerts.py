"""Alert routes â€” list, detail, and governor decision endpoints.

The governor endpoint is the human-in-the-loop approval mechanism.
Only users with role=governor or role=admin may approve/reject containment plans.
"""

from __future__ import annotations

from typing import Optional
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query, Request

from arbiterion.api.auth import require_auth, require_governor
from arbiterion.api.deps import get_db
from arbiterion.models import DecisionRequest

router = APIRouter(tags=["alerts"])


def _parse_jsonb(value):
    """Parse a JSONB value that may come back as a string or dict/list from asyncpg."""
    if isinstance(value, str):
        import json
        try:
            return json.loads(value)
        except Exception:
            return {}
    return value if value else {}


def _transform_alert(row: dict) -> dict:
    """Transform flat DB row into the nested structure the frontend JS expects."""
    raw = _parse_jsonb(row.get("raw_alert"))
    manager = _parse_jsonb(row.get("manager_output"))
    triage = _parse_jsonb(row.get("triage_output"))
    containment = _parse_jsonb(row.get("containment_output"))
    governor_decision = _parse_jsonb(row.get("governor_decision"))
    reasoning = _parse_jsonb(row.get("reasoning_log"))
    if not isinstance(reasoning, list):
        reasoning = []

    if not governor_decision.get("status"):
        governor_decision = {"status": row.get("governor_status", "pending"), "operator_note": None}

    return {
        "id": row["id"],
        "rule_name": row.get("rule_name", ""),
        "summary": row.get("summary", ""),
        "source": row.get("source", ""),
        "severity": row.get("severity"),
        "created_at": row.get("created_at"),
        "manager": {
            "severity": manager.get("severity", row.get("severity", "Medium")),
            "risk_score": manager.get("risk_score", 50),
        },
        "triage": {
            "confidence_score": triage.get("confidence_score", 0),
        },
        "containment": {
            "proposed_action": containment.get("proposed_action", "No action proposed"),
        },
        "governor": {
            "status": governor_decision.get("status", row.get("governor_status", "Pending Approval")).replace("_", " ").title(),
            "operator_note": governor_decision.get("operator_note"),
        },
        "reasoning_log": reasoning if isinstance(reasoning, list) else [],
        "telemetry": raw.get("telemetry", []),
        "indicators": raw.get("indicators", []),
    }


@router.get("/api/alerts")
async def list_alerts(
    request: Request,
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=25, ge=5, le=100),
    pipeline_state: Optional[str] = Query(default=None),
    governor_status: Optional[str] = Query(default=None),
    severity: Optional[str] = Query(default=None),
):
    """Paginated alert list for the dashboard. Supports optional filters."""
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
        "alerts": [_transform_alert(r) for r in result["rows"]],
        "total": result["total"],
        "page": page,
        "per_page": per_page,
        "pages": (result["total"] + per_page - 1) // per_page,
    }


@router.get("/api/alerts/{alert_id}")
async def get_alert(alert_id: str, request: Request):
    """Detail view for a single alert â€” includes pipeline output, reasoning log, governor decision."""
    user_identity = require_auth(request)
    db = await get_db()
    tenant_id = UUID(user_identity["tenant_id"])

    alert = await db.get_alert(UUID(alert_id), tenant_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found.")

    return _transform_alert(alert)


@router.post("/api/alerts/{alert_id}/decision")
@router.post("/api/alerts/{alert_id}/governor")
async def governor_decision(alert_id: str, request: Request):
    """Submit an approve/reject decision. Only governors and admins may call this.

    On approval, the containment action is enqueued for execution by the Celery worker.
    """
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

    await db.set_governor_decision(
        alert_id=UUID(alert_id),
        tenant_id=tenant_id,
        decision=governor_status,
        governor_decision={
            "status": governor_status,
            "operator_note": decision.operator_note,
            "decided_at": None,
            "decided_by": user_identity["user_id"],
        },
        user_id=UUID(user_identity["user_id"]),
        note=decision.operator_note,
    )

    updated_alert = await db.get_alert(UUID(alert_id), tenant_id)
    return _transform_alert(updated_alert) if updated_alert else {"status": governor_status, "alert_id": alert_id}

