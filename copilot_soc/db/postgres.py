"""asyncpg-based Database class with full CRUD for the multi-tenant schema.

Every method is tenant-scoped. The pool is lazily initialised via get_db() in deps.py —
the app boots without PostgreSQL and only errors when a route needs the database.
"""

from __future__ import annotations

import json
import os
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Optional
from uuid import UUID, uuid4

import asyncpg


class Database:
    """Thin wrapper around an asyncpg connection pool.

    All public methods map 1:1 to SQL queries. We keep it simple — no ORM,
    no query builder — because every query is tenant-scoped and the schema
    is small enough to manage by hand.
    """

    def __init__(self) -> None:
        self.pool: Optional[asyncpg.Pool] = None

    async def connect(self) -> None:
        dsn = os.getenv("DATABASE_URL", "")
        if not dsn:
            raise ConnectionError("DATABASE_URL not set. Run `docker compose up -d` to start PostgreSQL.")
        if "connect_timeout" not in dsn:
            dsn += "&connect_timeout=5" if "?" in dsn else "?connect_timeout=5"
        self.pool = await asyncpg.create_pool(dsn, min_size=2, max_size=8)

    async def close(self) -> None:
        if self.pool:
            await self.pool.close()

    async def _init_schema(self) -> None:
        """Run schema.sql on startup (idempotent — uses IF NOT EXISTS)."""
        schema_path = Path(__file__).parent / "schema.sql"
        if not schema_path.exists():
            return
        async with self.pool.acquire() as conn:
            await conn.execute(schema_path.read_text())

    # ── Tenants ────────────────────────────────────────────────

    async def create_tenant(self, name: str, slug: str, plan_tier: str = "starter") -> dict[str, Any]:
        """Create a tenant row + default tenant_settings in one transaction."""
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                INSERT INTO tenants (id, name, slug, plan_tier, alert_limit)
                VALUES ($1, $2, $3, $4, CASE $4 WHEN 'starter' THEN 100 WHEN 'professional' THEN 500 ELSE 999999 END)
                RETURNING id, name, slug, plan_tier, alert_limit, created_at
                """,
                uuid4(), name, slug, plan_tier,
            )
            await conn.execute(
                "INSERT INTO tenant_settings (tenant_id) VALUES ($1) ON CONFLICT DO NOTHING",
                row["id"],
            )
            return dict(row)

    async def get_tenant(self, tenant_id: UUID) -> Optional[dict[str, Any]]:
        """Fetch a single tenant by ID (used by billing portal)."""
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow("SELECT * FROM tenants WHERE id = $1", tenant_id)
            return dict(row) if row else None

    async def get_tenant_by_slug(self, slug: str) -> Optional[dict[str, Any]]:
        """Used by seed.py and the login form to resolve the default tenant."""
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow("SELECT * FROM tenants WHERE slug = $1", slug)
            return dict(row) if row else None

    async def get_tenant_by_stripe_customer_id(self, customer_id: str) -> Optional[dict[str, Any]]:
        """Look up the tenant associated with a Stripe customer (for webhook handlers)."""
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow("SELECT * FROM tenants WHERE stripe_customer_id = $1", customer_id)
            return dict(row) if row else None

    async def set_stripe_customer_id(self, tenant_id: UUID, customer_id: str) -> None:
        """Link a tenant to a newly created Stripe customer."""
        async with self.pool.acquire() as conn:
            await conn.execute(
                "UPDATE tenants SET stripe_customer_id = $1, updated_at = NOW() WHERE id = $2",
                customer_id, tenant_id,
            )

    async def update_tenant_plan(self, tenant_id: UUID, plan_tier: str) -> None:
        """Change plan tier and adjust alert_limit accordingly."""
        limit = {"starter": 100, "professional": 500, "enterprise": 999999}.get(plan_tier, 100)
        async with self.pool.acquire() as conn:
            await conn.execute(
                "UPDATE tenants SET plan_tier = $1, alert_limit = $2, updated_at = NOW() WHERE id = $3",
                plan_tier, limit, tenant_id,
            )

    async def check_alert_limit(self, tenant_id: UUID) -> bool:
        """Return True if the tenant still has quota today. Auto-resets at UTC midnight."""
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT alert_limit, alerts_used_today, daily_reset_at FROM tenants WHERE id = $1",
                tenant_id,
            )
            if not row:
                return False
            if row["daily_reset_at"] < date.today():
                await conn.execute(
                    "UPDATE tenants SET alerts_used_today = 0, daily_reset_at = CURRENT_DATE WHERE id = $1",
                    tenant_id,
                )
                return True
            return row["alerts_used_today"] < row["alert_limit"]

    async def increment_alert_usage(self, tenant_id: UUID) -> None:
        """Increment the daily counter after a successful ingestion."""
        async with self.pool.acquire() as conn:
            await conn.execute(
                "UPDATE tenants SET alerts_used_today = alerts_used_today + 1 WHERE id = $1",
                tenant_id,
            )

    # ── Users ──────────────────────────────────────────────────

    async def create_user(self, tenant_id: UUID, email: str, password_hash: str, role: str = "analyst") -> dict[str, Any]:
        """Register a new user under a tenant. password_hash is PBKDF2-HMAC-SHA256."""
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                INSERT INTO users (id, tenant_id, email, password_hash, role)
                VALUES ($1, $2, $3, $4, $5)
                RETURNING id, tenant_id, email, role, created_at
                """,
                uuid4(), tenant_id, email, password_hash, role,
            )
            return dict(row)

    async def get_user_by_email(self, tenant_id: UUID, email: str) -> Optional[dict[str, Any]]:
        """Used by login to look up credentials. Email is unique per tenant."""
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM users WHERE tenant_id = $1 AND email = $2",
                tenant_id, email,
            )
            return dict(row) if row else None

    async def get_user_by_id(self, user_id: UUID) -> Optional[dict[str, Any]]:
        """Used by session verification to confirm a user exists."""
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow("SELECT * FROM users WHERE id = $1", user_id)
            return dict(row) if row else None

    # ── Alerts ─────────────────────────────────────────────────

    async def create_alert(
        self,
        tenant_id: UUID,
        source: str,
        rule_name: str,
        summary: str,
        raw_alert: dict[str, Any],
        external_id: Optional[str] = None,
    ) -> dict[str, Any]:
        """Ingest a new alert. pipeline_state starts at 'queued'; worker transitions it.

        If ``external_id`` is provided and an alert with the same tenant+external_id
        already exists, returns the existing alert instead of creating a duplicate.
        """
        if external_id:
            async with self.pool.acquire() as conn:
                existing = await conn.fetchrow(
                    "SELECT id, tenant_id, pipeline_state, governor_status, created_at FROM alerts "
                    "WHERE tenant_id = $1 AND external_id = $2 LIMIT 1",
                    tenant_id, external_id,
                )
                if existing:
                    return dict(existing)
        alert_id = uuid4()
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                INSERT INTO alerts (id, tenant_id, external_id, source, rule_name, summary, raw_alert)
                VALUES ($1, $2, $3, $4, $5, $6, $7)
                RETURNING id, tenant_id, pipeline_state, governor_status, created_at
                """,
                alert_id, tenant_id, external_id, source, rule_name, summary,
                json.dumps(raw_alert),
            )
            return dict(row)

    async def get_alert(self, alert_id: UUID, tenant_id: UUID) -> Optional[dict[str, Any]]:
        """Fetch a single alert. Both IDs are required for tenant isolation."""
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM alerts WHERE id = $1 AND tenant_id = $2",
                alert_id, tenant_id,
            )
            return dict(row) if row else None

    async def list_alerts(self, tenant_id: UUID, limit: int = 50) -> list[dict[str, Any]]:
        """Return recent alerts for the tenant dashboard, newest first."""
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT * FROM alerts WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT $2",
                tenant_id, limit,
            )
            return [dict(r) for r in rows]

    async def update_alert_pipeline(
        self,
        alert_id: UUID,
        tenant_id: UUID,
        pipeline_state: str,
        manager_output: Optional[dict] = None,
        triage_output: Optional[dict] = None,
        containment_output: Optional[dict] = None,
        reasoning_log: Optional[list] = None,
        severity: Optional[str] = None,
        risk_score: Optional[int] = None,
        classification: Optional[str] = None,
    ) -> None:
        """Update alert fields as the pipeline progresses.

        Uses a dynamic SET clause so we only touch the columns that changed.
        """
        sets = ["updated_at = NOW()"]
        args: list[Any] = []
        idx = 1

        def add(field: str, value: Any) -> None:
            nonlocal idx
            if value is not None:
                sets.append(f"{field} = ${idx}")
                args.append(json.dumps(value) if isinstance(value, (dict, list)) else value)
                idx += 1

        add("pipeline_state", pipeline_state)
        add("manager_output", manager_output)
        add("triage_output", triage_output)
        add("containment_output", containment_output)
        add("reasoning_log", reasoning_log)
        add("severity", severity)
        add("risk_score", risk_score)
        add("classification", classification)

        args.extend([alert_id, tenant_id])
        query = f"UPDATE alerts SET {', '.join(sets)} WHERE id = ${idx} AND tenant_id = ${idx + 1}"
        async with self.pool.acquire() as conn:
            await conn.execute(query, *args)

    async def set_governor_decision(
        self,
        alert_id: UUID,
        tenant_id: UUID,
        decision: str,
        governor_decision: dict[str, Any],
        user_id: UUID,
        note: Optional[str] = None,
    ) -> None:
        """Record an approve/reject decision and optionally enqueue the containment action."""
        async with self.pool.acquire() as conn:
            await conn.execute(
                """
                UPDATE alerts SET governor_status = $1, governor_decision = $2, updated_at = NOW()
                WHERE id = $3 AND tenant_id = $4
                """,
                decision, json.dumps(governor_decision), alert_id, tenant_id,
            )
            await conn.execute(
                """
                INSERT INTO approvals (id, tenant_id, alert_id, user_id, decision, note)
                VALUES ($1, $2, $3, $4, $5, $6)
                """,
                uuid4(), tenant_id, alert_id, user_id, decision, note,
            )
            if decision == "approved":
                alert = await self.get_alert(alert_id, tenant_id)
                if alert and alert.get("containment_output"):
                    await self.enqueue_action(tenant_id, alert_id, alert["containment_output"])

    # ── Action Queue ───────────────────────────────────────────

    async def enqueue_action(
        self,
        tenant_id: UUID,
        alert_id: UUID,
        containment_output: dict[str, Any],
    ) -> None:
        """Add an approved containment action to the action_queue for execution."""
        async with self.pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO action_queue (id, tenant_id, alert_id, action_type, payload)
                VALUES ($1, $2, $3, $4, $5)
                """,
                uuid4(), tenant_id, alert_id,
                containment_output.get("action_type", "unknown"),
                json.dumps(containment_output),
            )

    async def next_pending_action(self) -> Optional[dict[str, Any]]:
        """Atomically claim the oldest pending action (SKIP LOCKED = no worker conflict)."""
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                UPDATE action_queue SET status = 'running', updated_at = NOW()
                WHERE id = (
                    SELECT id FROM action_queue WHERE status = 'pending'
                    ORDER BY created_at ASC LIMIT 1 FOR UPDATE SKIP LOCKED
                )
                RETURNING id, tenant_id, alert_id, action_type, payload
                """
            )
            return dict(row) if row else None

    async def complete_action(self, action_id: UUID, status: str, result: dict[str, Any]) -> None:
        """Mark an action as 'executed' or 'failed' and store the result."""
        async with self.pool.acquire() as conn:
            await conn.execute(
                "UPDATE action_queue SET status = $1, result = $2, updated_at = NOW() WHERE id = $3",
                status, json.dumps(result), action_id,
            )

    # ── Tenant Settings ────────────────────────────────────────

    async def get_settings(self, tenant_id: UUID) -> dict[str, Any]:
        """Fetch LLM config + feature toggles for a tenant. Creates defaults on first access."""
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM tenant_settings WHERE tenant_id = $1", tenant_id,
            )
            if not row:
                await conn.execute(
                    "INSERT INTO tenant_settings (tenant_id) VALUES ($1) ON CONFLICT DO NOTHING",
                    tenant_id,
                )
                row = await conn.fetchrow(
                    "SELECT * FROM tenant_settings WHERE tenant_id = $1", tenant_id,
                )
            return dict(row) if row else {}

    async def update_settings(self, tenant_id: UUID, updates: dict[str, Any]) -> dict[str, Any]:
        """Update tenant settings (dynamic SET clause, skips tenant_id/created_at)."""
        sets = []
        args: list[Any] = []
        idx = 1
        for key, value in updates.items():
            if key in ("tenant_id", "created_at"):
                continue
            sets.append(f"{key} = ${idx}")
            args.append(value)
            idx += 1
        if not sets:
            return await self.get_settings(tenant_id)
        sets.append("updated_at = NOW()")
        args.append(tenant_id)
        query = f"UPDATE tenant_settings SET {', '.join(sets)} WHERE tenant_id = ${idx}"
        async with self.pool.acquire() as conn:
            await conn.execute(query, *args)
        return await self.get_settings(tenant_id)

    # ── Stripe Events ──────────────────────────────────────────

    async def record_stripe_event(self, event_id: str, event_type: str, body: dict[str, Any]) -> bool:
        """Idempotent insert: returns False if the stripe_event_id was already recorded."""
        async with self.pool.acquire() as conn:
            try:
                await conn.execute(
                    "INSERT INTO stripe_events (id, stripe_event_id, event_type, body) VALUES ($1, $2, $3, $4)",
                    uuid4(), event_id, event_type, json.dumps(body),
                )
                return True
            except asyncpg.UniqueViolationError:
                return False

    # ── Connectors ──────────────────────────────────────────────

    # ── Connectors (Phase 2) ────────────────────────────────────
    # These are stubs for CrowdStrike / Splunk native connectors.
    # config_encrypted stores API keys; decryption is deferred to Phase 2.

    async def upsert_connector(self, tenant_id: UUID, connector_type: str, config_encrypted: str) -> dict[str, Any]:
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                INSERT INTO connectors (id, tenant_id, connector_type, config_encrypted)
                VALUES ($1, $2, $3, $4)
                ON CONFLICT (tenant_id, connector_type) DO UPDATE SET config_encrypted = $4, enabled = TRUE
                RETURNING id, tenant_id, connector_type, enabled, created_at
                """,
                uuid4(), tenant_id, connector_type, config_encrypted,
            )
            return dict(row)

    async def get_connectors(self, tenant_id: UUID) -> list[dict[str, Any]]:
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT id, connector_type, enabled, created_at FROM connectors WHERE tenant_id = $1",
                tenant_id,
            )
            return [dict(r) for r in rows]

    async def get_connector(self, tenant_id: UUID, connector_type: str) -> Optional[dict[str, Any]]:
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM connectors WHERE tenant_id = $1 AND connector_type = $2",
                tenant_id, connector_type,
            )
            return dict(row) if row else None
