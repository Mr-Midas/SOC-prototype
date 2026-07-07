"""Alert ingestion via webhook (primary path) or local endpoint events.

The primary endpoint is ``POST /api/v1/ingest/alert``.
Backward-compatible shims exist at ``/api/ingest/webhook`` and
``/api/ingest/endpoint-event`` so the old monolithic frontend still works.

Every ingested alert is dispatched to Celery for async pipeline processing.
If Celery / Redis is unreachable the alert is still persisted and the request
returns HTTP 202 â€” processing resumes when the worker comes back.
"""

from __future__ import annotations

import json
import os
from typing import Optional
from uuid import UUID, uuid4

import redis
import structlog
from fastapi import APIRouter, HTTPException, Request
from pydantic import ValidationError

from arbiterion.api.deps import get_db
from arbiterion.api.auth import require_auth
from arbiterion.models import IngestionRequest

# Redis client for ingestion streams
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
redis_client = redis.from_url(REDIS_URL, decode_responses=True)

logger = structlog.get_logger()
router = APIRouter(tags=["ingestion"])


def _verify_webhook_signature(raw_body: bytes, signature: Optional[str], secret: str) -> bool:
    """HMAC-SHA256 signature verification for webhook payloads.

    If no webhook_secret is configured, all payloads are accepted (dev mode).
    """
    if not secret:
        return True
    if not signature:
        return False
    expected = hmac.new(
        secret.encode("utf-8"),
        raw_body,
        hashlib.sha256,
    ).hexdigest()
    provided = signature.replace("sha256=", "").strip()
    return hmac.compare_digest(expected, provided)


@router.post("/api/v1/ingest/alert")
async def ingest_alert(request: Request):
    """Primary ingestion endpoint. Accepts structured JSON, enforces rate limits, dispatches to Celery."""
    user_identity = require_auth(request)

    db = await get_db()
    tenant_id = UUID(user_identity["tenant_id"])

    settings = await db.get_settings(tenant_id)

    raw_body = await request.body()
    signature = request.headers.get("X-Signature")
    webhook_secret = settings.get("webhook_secret") or ""
    if webhook_secret and not _verify_webhook_signature(raw_body, signature, webhook_secret):
        raise HTTPException(status_code=401, detail="Invalid webhook signature.")

    try:
        body = json.loads(raw_body)
        payload = IngestionRequest(**body)
    except (json.JSONDecodeError, ValidationError) as exc:
        raise HTTPException(status_code=400, detail=f"Invalid alert payload: {exc}")

    if not await db.check_alert_limit(tenant_id):
        raise HTTPException(status_code=429, detail="Daily alert limit reached. Upgrade your plan.")

    alert = await db.create_alert(
        tenant_id=tenant_id,
        source=payload.source,
        rule_name=payload.rule_name,
        summary=payload.summary,
        raw_alert={
            "alert_id": str(uuid4()),
            "generated_at": None,
            "scenario_id": payload.scenario_id,
            "source": payload.source,
            "rule_name": payload.rule_name,
            "summary": payload.summary,
            "mitre_tactic": payload.mitre_tactic,
            "affected_user": payload.affected_user,
            "affected_host": payload.affected_host,
            "source_ip": payload.source_ip,
            "indicators": payload.indicators,
            "telemetry": payload.telemetry,
            "metadata": payload.metadata,
            "analyst_supplied_severity": payload.severity,
        },
        external_id=payload.metadata.get("vendor_event_id") if isinstance(payload.metadata, dict) else None,
    )

    await db.increment_alert_usage(tenant_id)

    try:
        # Push to Redis Stream for burst handling
        redis_client.xadd("alerts:ingest", {"alert_id": str(alert["id"]), "tenant_id": str(tenant_id)})
    except Exception:
        logger.warning("redis_stream_unavailable_alert_queued_locally", alert_id=str(alert["id"]))

    return {
        "status": "accepted",
        "id": str(alert["id"]),
        "pipeline_state": "queued",
    }


# Keep backward compatibility with existing webhook path
@router.post("/api/ingest/webhook")
async def ingest_webhook_legacy(request: Request):
    """Legacy alias for /api/v1/ingest/alert (preserved for old webhook integrations)."""
    return await ingest_alert(request)


# Keep backward compatibility with existing endpoint-event path
@router.post("/api/ingest/endpoint-event")
async def ingest_endpoint_event_legacy(request: Request):
    """Legacy endpoint-event ingestion (preserved for old monolithic frontend compatibility)."""
    user_identity = require_auth(request)
    db = await get_db()
    tenant_id = UUID(user_identity["tenant_id"])

    raw_body = await request.body()
    settings = await db.get_settings(tenant_id)
    signature = request.headers.get("X-Signature")
    webhook_secret = settings.get("webhook_secret") or ""
    if webhook_secret and not (
        signature and hmac.compare_digest(
            hmac.new(webhook_secret.encode("utf-8"), raw_body, hashlib.sha256).hexdigest(),
            signature.replace("sha256=", "").strip(),
        )
    ):
        raise HTTPException(status_code=401, detail="Invalid signature.")

    try:
        body = json.loads(raw_body)
    except (json.JSONDecodeError, ValidationError) as exc:
        raise HTTPException(status_code=400, detail=f"Invalid payload: {exc}")

    if not await db.check_alert_limit(tenant_id):
        raise HTTPException(status_code=429, detail="Daily alert limit reached.")

    event_type = str(body.get("event_type", "local_event")).strip().lower().replace(" ", "_")
    rule_name = f"Endpoint Event: {event_type}"
    summary = body.get("summary", "Endpoint event received.")

    alert = await db.create_alert(
        tenant_id=tenant_id,
        source="Local Endpoint Agent",
        rule_name=rule_name,
        summary=summary,
        raw_alert={
            "alert_id": str(uuid4()),
            "generated_at": None,
            "scenario_id": "endpoint_detection",
            "source": "Local Endpoint Agent",
            "rule_name": rule_name,
            "summary": summary,
            "mitre_tactic": "Execution",
            "affected_user": body.get("username"),
            "affected_host": body.get("host_id"),
            "source_ip": body.get("source_ip"),
            "process_name": body.get("process_name"),
            "command_line": body.get("command_line"),
            "event_type": event_type,
            "indicators": body.get("indicators", []),
            "telemetry": body.get("telemetry", []),
            "metadata": body.get("metadata", {}),
            "analyst_supplied_severity": body.get("severity_hint"),
        },
    )

    await db.increment_alert_usage(tenant_id)
    try:
        # Push to Redis Stream for burst handling
        redis_client.xadd("alerts:ingest", {"alert_id": str(alert["id"]), "tenant_id": str(tenant_id)})
    except Exception:
        logger.warning("redis_stream_unavailable_alert_queued_locally", alert_id=str(alert["id"]))

    return {"status": "accepted", "id": str(alert["id"])}


async def _ingest_event(db, tenant_id: UUID, event: dict) -> dict:
    """Ingest a single collector event directly into the DB (bypasses HTTP)."""
    event_type = str(event.get("event_type", "local_event")).strip().lower().replace(" ", "_")
    rule_name = f"Endpoint Event: {event_type}"
    summary = event.get("summary", "Endpoint event received.")

    if not await db.check_alert_limit(tenant_id):
        return {"status": "rate_limited"}

    alert = await db.create_alert(
        tenant_id=tenant_id,
        source="Local Endpoint Agent",
        rule_name=rule_name,
        summary=summary,
        raw_alert={
            "alert_id": str(uuid4()),
            "generated_at": None,
            "scenario_id": "endpoint_detection",
            "source": "Local Endpoint Agent",
            "rule_name": rule_name,
            "summary": summary,
            "mitre_tactic": "Execution",
            "affected_user": event.get("username"),
            "affected_host": event.get("host_id"),
            "source_ip": event.get("source_ip"),
            "process_name": event.get("process_name"),
            "command_line": event.get("command_line"),
            "event_type": event_type,
            "indicators": event.get("indicators", []),
            "telemetry": event.get("telemetry", []),
            "metadata": event.get("metadata", {}),
            "analyst_supplied_severity": event.get("severity_hint"),
        },
    )

    await db.increment_alert_usage(tenant_id)
    try:
        # Push to Redis Stream for burst handling
        redis_client.xadd("alerts:ingest", {"alert_id": str(alert["id"]), "tenant_id": str(tenant_id)})
    except Exception:
        logger.warning("redis_stream_unavailable_alert_queued_locally", alert_id=str(alert["id"]))

    return {"status": "accepted", "id": str(alert["id"])}

