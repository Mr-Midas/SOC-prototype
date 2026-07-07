"""FastAPI application entry point.

Boots the web server, mounts routes from all API modules, configures CORS,
serves static files, and provides a global exception handler.

The database connection is NOT established here â€” it is lazily created by
``get_db()`` in deps.py when the first route handler needs it. This means
``uvicorn arbiterion.main:app`` succeeds instantly even without PostgreSQL.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Optional

import structlog
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from arbiterion.api import alerts, auth, billing, frontend, ingestion, settings as settings_api
from arbiterion.api.deps import close_db, get_db
from arbiterion.config import settings

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
    title="Arbiterion",
    version="2.0.0",
    description="AI-powered SOC triage copilot â€” multi-tenant SaaS backend",
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
    logger.info("arbiterion_starting", env=settings.environment)
    await _bootstrap_database()
    _register_collector_callbacks()


def _register_collector_callbacks():
    """Wire settings toggle to collector start/stop."""
    from arbiterion.api.settings import register_collector_callbacks
    register_collector_callbacks(
        start_cb=_start_collector,
        stop_cb=_stop_collector,
        is_running_cb=lambda: _collector_task is not None and not _collector_task.done(),
    )


def _start_collector():
    global _collector_task
    if _collector_task and not _collector_task.done():
        return
    _collector_task = asyncio.create_task(_collector_loop())
    logger.info("collector_task_started")


def _stop_collector():
    _collector_stop_event.set()
    logger.info("collector_stop_requested")


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
            "admin@arbiterion.local",
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
                "INSERT INTO users (id, tenant_id, email, password_hash, role) VALUES ($1, $2, 'admin@arbiterion.local', $3, 'admin')",
                admin_id, tenant_id, pw_hash,
            )
            await conn.execute(
                "INSERT INTO tenant_settings (tenant_id, llm_provider, llm_model, use_ai_triage, safe_mode, webhook_secret) VALUES ($1, 'ollama', 'phi3', false, true, $2)",
                tenant_id, webhook_secret,
            )
            logger.info("bootstrap_seeded_admin", email="admin@arbiterion.local")
    except Exception as exc:
        logger.warning("bootstrap_failed", error=str(exc))
    finally:
        await conn.close()


@app.on_event("shutdown")
async def shutdown():
    """Gracefully close the database pool and stop the collector."""
    _collector_stop_event.set()
    try:
        await close_db()
        logger.info("database_disconnected")
    except Exception:
        pass


_collector_stop_event: asyncio.Event = asyncio.Event()
_collector_task: Optional[asyncio.Task] = None


async def _collector_loop():
    """Background task: polls Windows Security / Sysmon logs and feeds events into the pipeline."""
    import platform
    if platform.system().lower() != "windows":
        logger.info("collector_skipped", reason="not_windows")
        return

    try:
        from arbiterion.api.deps import get_db
        from arbiterion.api.auth import _resolve_tenant
    except ImportError:
        logger.warning("collector_import_failed")
        return

    logger.info("collector_started")
    while not _collector_stop_event.is_set():
        try:
            import sys as _sys
            _sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
            from collector import collect_pending_events

            events = await asyncio.to_thread(collect_pending_events, lookback_seconds=120)
            if events:
                db = await get_db()
                tenant_id = await _resolve_tenant(db)
                if tenant_id:
                    for ev in events:
                        try:
                            from arbiterion.api.ingestion import _ingest_event
                            await _ingest_event(db, tenant_id, ev)
                        except Exception as e:
                            logger.warning("collector_event_failed", error=str(e)[:100])
                    logger.info("collector_batch", count=len(events))
        except Exception as exc:
            logger.warning("collector_poll_failed", error=str(exc)[:200])

        try:
            await asyncio.wait_for(_collector_stop_event.wait(), timeout=30)
            break
        except asyncio.TimeoutError:
            pass

    logger.info("collector_stopped")


@app.get("/api/collector/status")
async def collector_status(request: Request):
    """Return whether the collector background task is running."""
    from arbiterion.api.auth import require_auth
    require_auth(request)
    running = _collector_task is not None and not _collector_task.done()
    return {"running": running, "platform": __import__("platform").system()}


@app.get("/api/health")
async def health():
    """Detailed health check. Verifies DB, Redis, and Queue depth."""
    health = {"status": "ok", "service": "arbiterion", "checks": {}}
    
    # 1. DB Check
    try:
        from arbiterion.api.deps import get_db
        db = await get_db()
        await db.pool.execute("SELECT 1")
        health["checks"]["database"] = "ok"
    except Exception as e:
        health["checks"]["database"] = f"fail: {str(e)}"
        health["status"] = "degraded"

    # 2. Redis Check
    try:
        import redis
        from arbiterion.config import settings
        r = redis.from_url(settings.redis_url if hasattr(settings, 'redis_url') else "redis://localhost:6379/0")
        r.ping()
        # Queue depth
        depth = r.xlen("alerts:ingest")
        health["checks"]["redis"] = "ok"
        health["checks"]["queue_depth"] = depth
    except Exception as e:
        health["checks"]["redis"] = f"fail: {str(e)}"
        health["status"] = "degraded"

    return health


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Catch-all that logs the exception and returns a generic 500."""
    try:
        logger.error("unhandled_exception", path=str(request.url), error=str(exc)[:200])
    except Exception:
        pass
    detail = str(exc)[:200] if settings.environment == "development" else "Internal server error."
    return JSONResponse(status_code=500, content={"detail": detail})

