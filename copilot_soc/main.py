"""FastAPI application entry point.

Boots the web server, mounts routes from all API modules, configures CORS,
serves static files, and provides a global exception handler.

The database connection is NOT established here — it is lazily created by
``get_db()`` in deps.py when the first route handler needs it. This means
``uvicorn copilot_soc.main:app`` succeeds instantly even without PostgreSQL.
"""

from __future__ import annotations

from pathlib import Path

import structlog
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from copilot_soc.api import alerts, auth, billing, frontend, ingestion, settings as settings_api
from copilot_soc.api.deps import close_db, get_db
from copilot_soc.config import settings

# Structured logging with ISO timestamps and console-friendly output
import logging as _logging
import sys as _sys

_processors = [
    structlog.stdlib.add_log_level,
    structlog.processors.TimeStamper(fmt="iso"),
]
if _sys.stdout and hasattr(_sys.stdout, "encoding") and _sys.stdout.encoding and "utf" in _sys.stdout.encoding.lower():
    _processors.append(structlog.dev.ConsoleRenderer())
else:
    _processors.append(structlog.processors.KeyValueRenderer())

structlog.configure(
    processors=_processors,
    context_class=dict,
    logger_factory=structlog.PrintLoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger()

app = FastAPI(
    title="Copilot SOC",
    version="2.0.0",
    description="AI-powered SOC triage copilot — multi-tenant SaaS backend",
)

# CORS: allow the React dev server (Phase 2) and local development
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register all API route modules
app.include_router(auth.router)
app.include_router(frontend.router)
app.include_router(ingestion.router)
app.include_router(alerts.router)
app.include_router(settings_api.router)
app.include_router(billing.router)


# Serve static assets (CSS, JS, images for Jinja2 templates)
STATIC_DIR = Path(__file__).resolve().parent.parent / "static"
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
else:
    logger.warning("static_dir_not_found", path=str(STATIC_DIR))


@app.on_event("startup")
async def startup():
    logger.info("copilot_soc_starting", env=settings.environment)
    await _bootstrap_database()


async def _bootstrap_database():
    """Auto-create schema + seed admin user on first boot (idempotent)."""
    import hashlib
    import secrets
    from uuid import uuid4

    import asyncpg

    schema_path = Path(__file__).resolve().parent / "db" / "schema.sql"
    dsn = settings.database_url
    if not dsn:
        return

    try:
        conn = await asyncpg.connect(dsn, timeout=10)
    except Exception:
        logger.warning("bootstrap_db_unavailable")
        return

    try:
        # Apply schema (idempotent)
        if schema_path.exists():
            raw = schema_path.read_text(encoding="utf-8")
            lines = [l for l in raw.splitlines() if not l.strip().startswith("--")]
            clean = "\n".join(lines)
            for stmt in clean.split(";"):
                stmt = stmt.strip()
                if not stmt:
                    continue
                try:
                    await conn.execute(stmt)
                except (asyncpg.exceptions.DuplicateObjectError,
                        asyncpg.exceptions.DuplicateTableError,
                        asyncpg.exceptions.UndefinedTableError):
                    pass

        # Add monitor_windows_events column if missing (migration for existing DBs)
        try:
            await conn.execute(
                "ALTER TABLE tenant_settings ADD COLUMN IF NOT EXISTS monitor_windows_events BOOLEAN NOT NULL DEFAULT FALSE"
            )
        except Exception:
            pass

        # Seed admin user if not present
        exists = await conn.fetchval(
            "SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)",
            "admin@copilot-soc.local",
        )
        if not exists:
            tenant_id = uuid4()
            admin_id = uuid4()
            salt = secrets.token_hex(16)
            digest = hashlib.pbkdf2_hmac("sha256", b"ChangeMe123!", salt.encode("utf-8"), 120000)
            pw_hash = f"{salt}${digest.hex()}"
            api_key = f"soc_{secrets.token_hex(32)}"
            webhook_secret = secrets.token_hex(32)

            await conn.execute(
                "INSERT INTO tenants (id, name, slug, plan_tier, alert_limit) VALUES ($1, 'Default Corp', 'default', 'starter', 100)",
                tenant_id,
            )
            await conn.execute(
                "INSERT INTO users (id, tenant_id, email, password_hash, role) VALUES ($1, $2, 'admin@copilot-soc.local', $3, 'admin')",
                admin_id, tenant_id, pw_hash,
            )
            await conn.execute(
                "INSERT INTO tenant_settings (tenant_id, llm_provider, llm_model, use_ai_triage, safe_mode, webhook_secret) VALUES ($1, 'openai', 'gpt-4o-mini', false, true, $2)",
                tenant_id, webhook_secret,
            )
            logger.info("bootstrap_seeded_admin", email="admin@copilot-soc.local")
    except Exception as exc:
        logger.warning("bootstrap_failed", error=str(exc))
    finally:
        await conn.close()


@app.on_event("shutdown")
async def shutdown():
    """Gracefully close the database pool on shutdown."""
    try:
        await close_db()
        logger.info("database_disconnected")
    except Exception:
        pass


@app.get("/api/health")
async def health():
    """Lightweight health check. Returns immediately without DB access."""
    return {"status": "ok", "service": "copilot-soc"}


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Catch-all that logs the exception and returns a generic 500."""
    try:
        logger.error("unhandled_exception", path=str(request.url), error=str(exc)[:200])
    except Exception:
        pass
    detail = str(exc)[:200] if settings.environment == "development" else "Internal server error."
    return JSONResponse(status_code=500, content={"detail": detail})
