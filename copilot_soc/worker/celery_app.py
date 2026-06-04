from __future__ import annotations

import os

from celery import Celery

BROKER_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

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
)
