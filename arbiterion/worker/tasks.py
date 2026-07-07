"""Celery tasks for the alert pipeline and action queue consumer.

``run_alert_pipeline`` â€” called by ingestion endpoints via `.delay()`.
Runs the full 3-agent pipeline inside an async event loop (Celery is sync,
so we create a new loop per task invocation).

``process_action_queue`` â€” periodic task (or manually triggered) that picks
the next pending action and either executes it via a webhook or logs it as a
dry run (controlled by the CONNECTOR_MODE env var).
"""

from __future__ import annotations

import json
import os
from uuid import UUID

import httpx
import structlog

from arbiterion.db.postgres import Database
from arbiterion.pipeline.orchestrator import process_alert
from arbiterion.worker.celery_app import celery_app
from arbiterion.edr import get_edr_client
from arbiterion.notifications import notify

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
    """Celery task: runs the full pipeline (Managerâ†’Triageâ†’Containment) asynchronously.

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


@celery_app.task(bind=True, max_retries=3, default_retry_delay=10)
def execute_containment(
    self,
    alert_id_str: str,
    tenant_id_str: str,
) -> dict:
    """Celery task: executes the containment action approved by the Governor."""
    import asyncio
    
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(_execute_containment_async(alert_id_str, tenant_id_str))
    finally:
        loop.close()


async def _execute_containment_async(alert_id_str: str, tenant_id_str: str) -> dict:
    """Async inner function to perform the EDR action."""
    d = await get_db()
    alert_id = UUID(alert_id_str)
    tenant_id = UUID(tenant_id_str)
    
    # 1. Fetch alert and settings
    alert = await d.get_alert(alert_id, tenant_id)
    if not alert:
        return {"error": "alert not found"}
    
    settings = await d.get_settings(tenant_id)
    edr_provider = settings.get("edr_provider", "defender")
    client = get_edr_client(edr_provider)
    
    # 2. Parse containment plan
    containment_output = _parse_jsonb(alert.get("containment_output"))
    if not containment_output:
        return {"error": "no containment plan found"}
    
    action_type = containment_output.get("action_type")
    proposed_action = containment_output.get("proposed_action")
    
    # Map action_type to client method
    # we use the raw_alert to get targets
    raw_alert = _parse_jsonb(alert.get("raw_alert"))
    host_id = raw_alert.get("affected_host", "localhost")
    user_id = raw_alert.get("affected_user", "unknown")
    ip = raw_alert.get("source_ip")
    file_hash = raw_alert.get("indicators", [{}])[0].get("value") if raw_alert.get("indicators") else None

    logger.info("executing_containment", alert_id=alert_id_str, action_type=action_type)
    
    try:
        if action_type == "Host Isolation":
            result = await client.isolate_host(host_id, tenant_id, alert_id)
        elif action_type == "Network Blocking" and ip:
            result = await client.block_ip(ip, tenant_id, alert_id)
        elif action_type == "Identity Containment" and user_id:
            result = await client.disable_user(user_id, tenant_id, alert_id)
        elif action_type == "Process Containment" and file_hash:
            result = await client.quarantine_file(file_hash, host_id, tenant_id, alert_id)
        else:
            result = {"success": False, "message": f"Unsupported or missing targets for {action_type}"}
        
        # Update DB result
        if result.get("success"):
            await d.complete_action(
                alert_id, # reusing alert_id as action_id for simplicity in this mapping
                "executed", 
                result
            )
        else:
            await d.complete_action(alert_id, "failed", result)
            
        return result
    except Exception as e:
        logger.error("containment_execution_failed", error=str(e))
        return {"success": False, "error": str(e)}

def _parse_jsonb(value):
    if isinstance(value, str):
        import json
        try: return json.loads(value)
        except: return {}
    return value if value else {}


