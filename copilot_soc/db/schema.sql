-- Copilot SOC PostgreSQL Schema
-- Multi-tenant schema for the AI-powered SOC triage copilot.
-- Every data row is scoped to a tenant_id for Phase 1; Phase 2 adds PostgreSQL RLS.
-- Run against a fresh PostgreSQL 16+ database. The Docker Compose setup runs this
-- automatically via docker-entrypoint-initdb.d.

-- pgcrypto provides gen_random_uuid() for UUID primary keys
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ── Enums ──────────────────────────────────────────────────────────────────
-- PipelineState: tracks the 3-agent chain through its lifecycle.
-- Each agent has a _failed state so retry logic can distinguish "retry" from "skip".
CREATE TYPE pipeline_state AS ENUM (
    'queued',
    'classifying',
    'classifying_failed',
    'triaging',
    'triaging_failed',
    'planning',
    'planning_failed',
    'completed',
    'failed'
);

-- GovernorStatus: every alert starts pending; only a human governor can approve/reject.
CREATE TYPE governor_status AS ENUM (
    'pending',
    'approved',
    'rejected'
);

-- UserRole: governs access to the /governor endpoint (governor+admin only).
CREATE TYPE user_role AS ENUM (
    'analyst',
    'governor',
    'admin'
);

-- ConnectorType: reserved for Phase 2 when we add native EDR/SIEM connectors.
CREATE TYPE connector_type AS ENUM (
    'webhook',
    'crowdstrike',
    'splunk'
);

-- PlanTier: maps to Stripe pricing tiers and sets daily alert limits.
CREATE TYPE plan_tier AS ENUM (
    'starter',
    'professional',
    'enterprise'
);

-- ── Tenants ────────────────────────────────────────────────────────────────
-- Top-level organizational unit. Every other table references this via tenant_id.
-- alert_limit and alerts_used_today implement per-tenant daily rate limiting.
CREATE TABLE tenants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    slug TEXT NOT NULL UNIQUE,
    stripe_customer_id TEXT,
    plan_tier plan_tier NOT NULL DEFAULT 'starter',
    alert_limit INT NOT NULL DEFAULT 100,
    alerts_used_today INT NOT NULL DEFAULT 0,
    daily_reset_at DATE NOT NULL DEFAULT CURRENT_DATE,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── Users ──────────────────────────────────────────────────────────────────
-- Each user belongs to exactly one tenant. email is unique per tenant.
-- password_hash uses PBKDF2-HMAC-SHA256 (see api/auth.py).
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    role user_role NOT NULL DEFAULT 'analyst',
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, email)
);

-- ── Alerts ─────────────────────────────────────────────────────────────────
-- The central table. Every alert passes through the pipeline and its state,
-- agent outputs, and governor decision are stored in JSONB columns.
-- The pipeline appends reasoning steps to reasoning_log as it progresses.
CREATE TABLE alerts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    external_id TEXT,                          -- upstream event ID for dedup
    source TEXT NOT NULL,                      -- "Wazuh", "CrowdStrike", "Sample Generator", etc.
    rule_name TEXT NOT NULL,
    summary TEXT NOT NULL,
    severity TEXT,
    risk_score INT,
    classification TEXT,
    pipeline_state pipeline_state NOT NULL DEFAULT 'queued',
    governor_status governor_status NOT NULL DEFAULT 'pending',
    manager_output JSONB,                      -- ManagerDecision as dict
    triage_output JSONB,                       -- TriageFinding as dict
    containment_output JSONB,                  -- ContainmentPlan as dict
    reasoning_log JSONB NOT NULL DEFAULT '[]'::jsonb,
    governor_decision JSONB,
    raw_alert JSONB NOT NULL DEFAULT '{}'::jsonb, -- original ingested payload
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index alerts by tenant (for the dashboard list view) and by state (for worker queries).
CREATE INDEX idx_alerts_tenant_created ON alerts(tenant_id, created_at DESC);
CREATE INDEX idx_alerts_pipeline_state ON alerts(pipeline_state);

-- ── Approvals ──────────────────────────────────────────────────────────────
-- Audit trail for every governor approve/reject action.
CREATE TABLE approvals (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    alert_id UUID NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id),
    decision governor_status NOT NULL,
    note TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_approvals_alert ON approvals(alert_id);

-- ── Action Queue ───────────────────────────────────────────────────────────
-- Approved containment actions are enqueued here. The Celery worker picks them
-- up via SKIP LOCKED (see next_pending_action in postgres.py).
CREATE TABLE action_queue (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    alert_id UUID NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    action_type TEXT NOT NULL,
    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    status TEXT NOT NULL DEFAULT 'pending',
    result JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_action_queue_status ON action_queue(status);

-- ── Connectors ─────────────────────────────────────────────────────────────
-- Per-tenant connector configuration (Phase 2). Encrypted API keys/tokens.
CREATE TABLE connectors (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    connector_type connector_type NOT NULL,
    config_encrypted TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, connector_type)
);

-- ── Tenant Settings ────────────────────────────────────────────────────────
-- Per-tenant LLM provider config and feature toggles.
-- llm_api_key is stored encrypted (via pgcrypto or app-level encryption in Phase 2).
CREATE TABLE tenant_settings (
    tenant_id UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    llm_provider TEXT NOT NULL DEFAULT 'openai',
    llm_model TEXT NOT NULL DEFAULT 'gpt-4o-mini',
    llm_api_key_encrypted TEXT,
    webhook_secret TEXT,
    safe_mode BOOLEAN NOT NULL DEFAULT TRUE,
    use_ai_triage BOOLEAN NOT NULL DEFAULT TRUE,
    threat_intel_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    sample_events_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    collector_interval_seconds INT NOT NULL DEFAULT 30,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── Stripe Events ──────────────────────────────────────────────────────────
-- Idempotent log of incoming Stripe webhook events. Prevents double-processing.
CREATE TABLE stripe_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    stripe_event_id TEXT NOT NULL UNIQUE,
    event_type TEXT NOT NULL,
    body JSONB NOT NULL DEFAULT '{}'::jsonb,
    processed BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── Daily Usage ────────────────────────────────────────────────────────────
-- Hourly-resolution usage tracking per tenant (reserved for billing metering).
CREATE TABLE daily_usage (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    alert_date DATE NOT NULL DEFAULT CURRENT_DATE,
    alerts_ingested INT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, alert_date)
);
