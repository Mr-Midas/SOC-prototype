CREATE EXTENSION IF NOT EXISTS pgcrypto;

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

CREATE TYPE governor_status AS ENUM (
    'pending',
    'approved',
    'rejected'
);

CREATE TYPE user_role AS ENUM (
    'analyst',
    'governor',
    'admin'
);

CREATE TYPE connector_type AS ENUM (
    'webhook',
    'crowdstrike',
    'splunk'
);

CREATE TYPE plan_tier AS ENUM (
    'starter',
    'professional',
    'enterprise'
);

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

CREATE TABLE alerts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    external_id TEXT,
    source TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    summary TEXT NOT NULL,
    severity TEXT,
    risk_score INT,
    classification TEXT,
    pipeline_state pipeline_state NOT NULL DEFAULT 'queued',
    governor_status governor_status NOT NULL DEFAULT 'pending',
    manager_output JSONB,
    triage_output JSONB,
    containment_output JSONB,
    reasoning_log JSONB NOT NULL DEFAULT '[]'::jsonb,
    governor_decision JSONB,
    raw_alert JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_alerts_tenant_created ON alerts(tenant_id, created_at DESC);
CREATE INDEX idx_alerts_pipeline_state ON alerts(pipeline_state);

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

CREATE TABLE connectors (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    connector_type connector_type NOT NULL,
    config_encrypted TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, connector_type)
);

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

CREATE TABLE stripe_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    stripe_event_id TEXT NOT NULL UNIQUE,
    event_type TEXT NOT NULL,
    body JSONB NOT NULL DEFAULT '{}'::jsonb,
    processed BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE daily_usage (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    alert_date DATE NOT NULL DEFAULT CURRENT_DATE,
    alerts_ingested INT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, alert_date)
);
