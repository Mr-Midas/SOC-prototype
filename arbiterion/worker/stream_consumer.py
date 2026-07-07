"""Redis Stream consumer for alert ingestion.
Reads from 'alerts:ingest' and triggers the pipeline.
"""

import asyncio
import os
import redis
import structlog
from uuid import UUID

from arbiterion.db.postgres import Database
from arbiterion.pipeline.orchestrator import process_alert

logger = structlog.get_logger()

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
STREAM_NAME = "alerts:ingest"
GROUP_NAME = "pipeline_workers"
CONSUMER_NAME = "worker-1"

async def main():
    # Initialize DB
    db = Database()
    await db.connect()
    
    # Initialize Redis
    r = redis.from_url(REDIS_URL, decode_responses=True)
    
    # Create consumer group if it doesn't exist
    try:
        r.xgroup_create(STREAM_NAME, GROUP_NAME, id="0", mkstream=True)
    except redis.exceptions.ResponseError as e:
        if "already exists" not in str(e):
            raise e

    logger.info("stream_consumer_started", stream=STREAM_NAME, group=GROUP_NAME)

    while True:
        try:
            # Read new messages
            # count=1 for simplicity in MVP, can be increased
            messages = r.xreadgroup(GROUP_NAME, CONSUMER_NAME, {STREAM_NAME: ">"}, count=1, block=5000)
            
            if not messages:
                continue

            for stream, entries in messages:
                for message_id, data in entries:
                    alert_id_str = data.get("alert_id")
                    tenant_id_str = data.get("tenant_id")
                    
                    if not alert_id_str or not tenant_id_str:
                        logger.error("invalid_stream_message", message_id=message_id, data=data)
                        r.xack(STREAM_NAME, GROUP_NAME, message_id)
                        continue

                    try:
                        tenant_id = UUID(tenant_id_str)
                        alert_id = UUID(alert_id_str)
                        
                        settings = await db.get_settings(tenant_id)
                        
                        # Run the pipeline
                        logger.info("processing_alert_from_stream", alert_id=alert_id_str)
                        await process_alert(db, alert_id, tenant_id, settings)
                        
                        # Acknowledge message
                        r.xack(STREAM_NAME, GROUP_NAME, message_id)
                        logger.info("alert_processed_successfully", alert_id=alert_id_str)
                        
                    except Exception as e:
                        logger.error("pipeline_failed_from_stream", alert_id=alert_id_str, error=str(e))
                        # In a real system, we'd move this to a DLQ or retry. 
                        # For MVP, we ACK and log error to avoid blocking the stream.
                        r.xack(STREAM_NAME, GROUP_NAME, message_id)

        except Exception as e:
            logger.error("stream_consumer_error", error=str(e))
            await asyncio.sleep(1)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
