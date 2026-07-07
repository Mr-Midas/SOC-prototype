"""Centralised app config loaded from environment variables.

All env-var reading happens in one place so every other module can
import `from arbiterion.config import settings` without calling os.getenv.
"""

from __future__ import annotations

import os
from typing import Optional


class Settings:
    # Database
    database_url: str = os.getenv("DATABASE_URL", "postgresql://arbiterion:arbiterion@localhost:5432/arbiterion")
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

    # AI Defaults (Ollama / phi3)
    ollama_base_url: str = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
    ollama_model: str = os.getenv("OLLAMA_MODEL", "phi3")
    min_risk_for_ai: int = int(os.getenv("MIN_RISK_FOR_AI", "70"))


settings = Settings()

