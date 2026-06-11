"""Celery tasks for the alert pipeline and action queue consumer.

``run_alert_pipeline`` — called by ingestion endpoints via `.delay()`.
Runs the full 3-agent pipeline inside an async event loop (Celery is sync,
so we create a new loop per task invocation).

``process_action_queue`` — periodic task (or manually triggered) that picks
the next pending action and either executes it via a webhook or logs it as a
dry run (controlled by the CONNECTOR_MODE env var).
"""

from __future__ import annotations

import json
import os
from uuid import UUID

import httpx
import structlog

from copilot_soc.db.postgres import Database
from copilot_soc.pipeline.orchestrator import process_alert
from copilot_soc.worker.celery_app import celery_app

logger = structlog.get_logger()

# Module-level singleton Database instance (separate from the HTTP app pool)
db: Database | None = None


async def get_db() -> Database:
    """Lazy-initialised Database singleton for the Celery worker."""
    global db
    if db is None:
        db = Database()
        await db.connect()
    return db


@celery_app.task(bind=True, max_retries=3, default_retry_delay=10)
def run_alert_pipeline(
    self,
    alert_id_str: str,
    tenant_id_str: str,
) -> dict:
    """Celery task: runs the full pipeline (Manager→Triage→Containment) asynchronously.

    Called via ``run_alert_pipeline.delay(alert_id, tenant_id)`` from ingestion endpoints.
    Retries up to 3 times with exponential backoff if the pipeline fails.
    """
    import asyncio

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(
            _run_pipeline_async(alert_id_str, tenant_id_str)
        )
    finally:
        loop.close()


async def _run_pipeline_async(alert_id_str: str, tenant_id_str: str) -> dict:
    """Async inner function that actually runs the pipeline."""
    d = await get_db()
    alert_id = UUID(alert_id_str)
    tenant_id = UUID(tenant_id_str)

    settings = await d.get_settings(tenant_id)
    result = await process_alert(d, alert_id, tenant_id, settings)
    return result


@celery_app.task
def process_action_queue() -> None:
    """Celery task: pick the next pending action and execute or dry-run it."""
    import asyncio

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(_process_next_action())
    finally:
        loop.close()


async def _process_next_action() -> None:
    """Dequeue one pending action, execute or dry-run, record the result."""
    d = await get_db()
    row = await d.next_pending_action()
    if not row:
        return
    try:
        payload = row["payload"]
        if isinstance(payload, str):
            payload = json.loads(payload)

        connector_mode = os.getenv("CONNECTOR_MODE", "dry_run").lower()
        if connector_mode == "webhook":
            webhook_url = os.getenv("CONTAINMENT_WEBHOOK_URL", "")
            if webhook_url:
                async with httpx.AsyncClient(timeout=20.0) as client:
                    resp = await client.post(webhook_url, json=payload)
                    resp.raise_for_status()
                result = {"mode": "webhook", "status_code": resp.status_code}
                status = "executed"
            else:
                result = {"mode": "webhook", "error": "CONTAINMENT_WEBHOOK_URL not set"}
                status = "failed"
        else:
            result = {"mode": "dry_run", "message": "Action recorded but not sent.", "payload": payload}
            status = "executed"

        await d.complete_action(row["id"], status, result)
        logger.info("action_completed", action_id=str(row["id"]), status=status)
    except Exception as exc:
        await d.complete_action(row["id"], "failed", {"error": str(exc)})
        logger.error("action_failed", action_id=str(row["id"]), error=str(exc))
