from __future__ import annotations

import os
from typing import Optional


class Settings:
    database_url: str = os.getenv("DATABASE_URL", "postgresql://copilot:copilot@localhost:5432/copilot_soc")
    redis_url: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    session_secret: str = os.getenv("SESSION_SECRET", "change-this-session-secret")
    stripe_secret_key: Optional[str] = os.getenv("STRIPE_SECRET_KEY") or None
    stripe_webhook_secret: Optional[str] = os.getenv("STRIPE_WEBHOOK_SECRET") or None
    connector_mode: str = os.getenv("CONNECTOR_MODE", "dry_run")
    containment_webhook_url: Optional[str] = os.getenv("CONTAINMENT_WEBHOOK_URL") or None
    cors_origins: list[str] = os.getenv("CORS_ORIGINS", "http://localhost:5173,http://localhost:3000").split(",")
    log_level: str = os.getenv("LOG_LEVEL", "INFO")
    environment: str = os.getenv("ENVIRONMENT", "development")


settings = Settings()
