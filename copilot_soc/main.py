from __future__ import annotations

import os

import structlog
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from copilot_soc.api import alerts, auth, billing, ingestion, settings as settings_api
from copilot_soc.api.deps import close_db, get_db
from copilot_soc.config import settings

structlog.configure(
    processors=[
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.dev.ConsoleRenderer(),
    ],
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

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(ingestion.router)
app.include_router(alerts.router)
app.include_router(settings_api.router)
app.include_router(billing.router)


@app.on_event("startup")
async def startup():
    logger.info("copilot_soc_starting", env=settings.environment)


@app.on_event("shutdown")
async def shutdown():
    await close_db()
    logger.info("database_disconnected")


@app.get("/api/health")
async def health():
    return {"status": "ok", "service": "copilot-soc"}


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.exception("unhandled_exception", path=str(request.url))
    return JSONResponse(status_code=500, content={"detail": "Internal server error."})
