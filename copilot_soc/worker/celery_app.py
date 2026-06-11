"""Celery 5.x app configured for Redis broker + backend.

Exported as ``celery_app`` so both the worker binary and task definitions
import from the same instance.  Configuration here applies to all tasks:
- JSON serialization for portable results
- Late ACK + prefetch=1 for fair task distribution
- 180s soft / 200s hard timeouts (any LLM call that stalls beyond these
  limits gets killed instead of blocking the worker forever)
- Beat schedule polls the action queue every 30s

The app boots gracefully without Redis — ``.delay()`` calls will fail at
runtime rather than at import time, so the web server stays up.
"""

from __future__ import annotations

import os

from celery import Celery

BROKER_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

# Single Celery instance shared by all tasks in copilot_soc.worker.tasks
celery_app = Celery(
    "copilot_soc",
    broker=BROKER_URL,
    backend=BROKER_URL,
    include=["copilot_soc.worker.tasks"],
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    task_soft_time_limit=180,
    task_time_limit=200,
    # Beat schedule — poll the action queue every 30s
    beat_schedule={
        "process-action-queue": {
            "task": "copilot_soc.worker.tasks.process_action_queue",
            "schedule": int(os.getenv("ACTION_POLL_INTERVAL", "30")),
        },
    },
)
