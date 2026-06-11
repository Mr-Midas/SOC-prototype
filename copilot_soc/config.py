"""Centralised app config loaded from environment variables.

All env-var reading happens in one place so every other module can
import `from copilot_soc.config import settings` without calling os.getenv.
"""

from __future__ import annotations

import os
from typing import Optional


class Settings:
    # Database
    database_url: str = os.getenv("DATABASE_URL", "postgresql://copilot:copilot@localhost:5432/copilot_soc")
    redis_url: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")

    # Auth
    session_secret: str = os.getenv("SESSION_SECRET", "change-this-session-secret")

    # Billing
    stripe_secret_key: Optional[str] = os.getenv("STRIPE_SECRET_KEY") or None
    session_secret: str = os.getenv("SESSION_SECRET", "change-this-session-secret")
    # Stripe webhook signature verification
    stripe_webhook_secret: Optional[str] = os.getenv("STRIPE_WEBHOOK_SECRET") or None

    # Action queue: "dry_run" logs only; "webhook" sends to CONTAINMENT_WEBHOOK_URL
    connector_mode: str = os.getenv("CONNECTOR_MODE", "dry_run")
    containment_webhook_url: Optional[str] = os.getenv("CONTAINMENT_WEBHOOK_URL") or None

    # CORS: comma-separated list of allowed origins
    cors_origins: list[str] = os.getenv("CORS_ORIGINS", "http://localhost:5173,http://localhost:3000").split(",")
    # Observability
    log_level: str = os.getenv("LOG_LEVEL", "INFO")
    environment: str = os.getenv("ENVIRONMENT", "development")

    # Python 3.14 compat: litellm may be unavailable, handled gracefully at call sites
    litellm_fallback: bool = os.getenv("LITELLM_FALLBACK", "true").lower() == "true"


settings = Settings()
