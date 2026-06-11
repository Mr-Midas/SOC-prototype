# Copilot SOC — Architecture & Design Rationale

## Why This Architecture Exists

This codebase refactors a monolithic FastAPI prototype ("Endpoint SOC Copilot") into a
multi-tenant SaaS backend called **Copilot SOC**. The original prototype worked — it had
a 3-agent AI pipeline, deterministic fallback, webhook ingestion, and a Jinja2 dashboard.
But it was a single-file app with SQLite, hardcoded tenants, and no background worker.

The refactoring preserves every capability while adding:
- Multi-tenancy (tenant_id on every row, RLS-ready schema)
- Scalable PostgreSQL instead of SQLite
- Celery background worker for async alert processing
- LiteLLM unified gateway for OpenAI/Anthropic/Gemini/Ollama
- Stripe billing integration
- Clean module separation so each piece can be tested and deployed independently

## Two-Phase Strategy

**Phase 1** (current) ships in ~8 weeks at $249/mo:
- Generic webhook ingestion (any EDR/SIEM can POST alerts)
- 100 alerts/day per tenant
- PostgreSQL with tenant_id scoping (no RLS yet)
- Deterministic fallback + optional AI via LiteLLM
- Jinja2 dashboard (existing templates reused)

**Phase 2** (~14 weeks total, $3K-$5K/mo):
- CrowdStrike + Splunk native connectors
- PostgreSQL Row-Level Security
- Unlimited alerts
- Full React frontend (Vite + Tailwind + shadcn/ui)

## Module Layout

```
copilot_soc/
  main.py              — FastAPI app entry, CORS, route registration
  config.py            — Env-based settings (singleton)
  models.py            — Pydantic request/response schemas
  db/
    schema.sql         — PostgreSQL DDL: 11 tables, enums, indexes
    postgres.py        — asyncpg Database class with all CRUD
  llm/
    client.py          — LiteLLM acompletion wrapper + model map
  pipeline/
    state_machine.py   — PipelineState enum + Transition validation
    fallback.py        — Deterministic fallback for 6 attack scenarios
    orchestrator.py    — Manager→Triage→Containment orchestration
  api/
    deps.py            — Database singleton lifecycle
    auth.py            — PBKDF2 + HMAC session auth
    ingestion.py       — Webhook + endpoint-event ingestion
    alerts.py          — Alert list, detail, governor approval
    frontend.py        — Jinja2 dashboard pages + backward compat
    settings.py        — Tenant LLM provider config
    billing.py         — Stripe portal + webhook
  worker/
    celery_app.py      — Celery 5.x app with Redis broker
    tasks.py           — Async alert pipeline + action queue consumer
```

## Key Design Decisions

### Lightweight State Machine Over LangGraph

The original prototype used a linear 3-agent chain: Manager→Triage→Containment.
LangGraph adds a heavy dependency (and frequent breaking changes) for what is
fundamentally a sequential pipeline with retry logic.

The state machine in `pipeline/state_machine.py` is ~70 lines:
- A `PipelineState` enum with valid→next transitions
- A `StateMachine` class that validates each transition
- A `run_with_retry` helper (3 attempts, exponential backoff)

If the pipeline grows to need branching, parallel agents, or dynamic routing,
LangGraph can be introduced then. For now the simple state machine is easier
to understand, debug, and deploy.

### LiteLLM Over Raw Provider Clients

The old code had separate HTTP/OpenAI/Gemini clients. LiteLLM wraps them all
behind a single `acompletion()` call with the model string `provider/model`:
- `openai/gpt-4o-mini`
- `anthropic/claude-sonnet-4-20250514`
- `gemini/gemini-2.5-flash`
- `ollama/llama3.1:8b`

This means adding a new provider is just adding a model string — no new client code.
The `call_llm` function in `client.py` gracefully falls back to returning `""` if
litellm is not installed (e.g., Python 3.14 which removed `cgi` module that litellm
depends on), which triggers the deterministic fallback logic.

### Deterministic Fallback as Safety Net

**Why have fallback at all?** Because:
1. Local dev often has no AI provider configured
2. Public APIs can be rate-limited or down
3. Some deployments want air-gapped operation
4. The $249/mo Starter plan includes fallback-only operation

The fallback logic in `fallback.py` covers every scenario the original prototype
handled: phishing, ransomware, brute-force, data exfiltration, C2 beaconing,
and generic detection. Each fallback function returns a valid `ManagerDecision`,
`TriageFinding`, or `ContainmentPlan` — the same types the AI would return.

The orchestrator tries AI first. If it fails or returns low confidence, it uses
fallback as a default. The reasoning log records which path was taken.

### Multi-Tenancy: Simple Scoping First, RLS Later

Phase 1 uses `WHERE tenant_id = $1` on every query. This is explicit, auditable,
and easy to debug. Phase 2 will add PostgreSQL Row-Level Security as a defense-in-depth
layer — RLS means even if a query omits the tenant_id filter, the row is still hidden.

The schema stores `tenant_id` in every table that holds tenant data. The Database
class methods always accept `tenant_id` as a parameter. There is no global "current
tenant" context — it's always explicit.

### Celery + Redis for Async Processing

Alerts can arrive via webhook at any time. The 3-agent pipeline takes 3–15 seconds
(depending on AI response time). Blocking the HTTP request for that long would:
- Exhaust uvicorn worker threads under load
- Give a poor UX (the POST hangs for seconds)
- Lose alerts if the server restarts mid-pipeline

Instead, the ingestion endpoint:
1. Validates + persists the alert to PostgreSQL (fast, ~5ms)
2. Enqueues a Celery task (`run_alert_pipeline.delay(...)`)
3. Returns HTTP 202 immediately

The Celery worker picks up the task, runs the pipeline, and updates the alert row.
The frontend polls `GET /api/alerts` to see results.

### Governor Approval Workflow

The pipeline always produces a containment plan, but it is never executed without
human approval. The flow:
1. Pipeline completes → `governor_status = "pending"`
2. Operator sees the plan in the dashboard
3. Governor clicks Approve or Reject (`POST /api/alerts/{id}/governor`)
4. If approved → action is enqueued in `action_queue`
5. Celery's `process_action_queue` task picks it up and dispatches via webhook

In `dry_run` mode (default), the action is recorded but not sent anywhere.
In `webhook` mode, it POSTs to `CONTAINMENT_WEBHOOK_URL`.

## Extending With New Connectors

Phase 2 connector pattern (CrowdStrike, Splunk):
- Connector config stored encrypted in `connectors` table
- Connector-specific ingestion endpoint or Celery beat schedule
- The generic webhook endpoint already works for any source
- A new connector = a new auth wrapper + field mapping, reusing the pipeline

## Database Schema

11 tables, all with `tenant_id`:
- `tenants` — top-level org, stripe_customer_id, alert limits
- `users` — auth credentials, role (analyst/governor/admin)
- `alerts` — pipeline state, agent outputs, governor decision
- `approvals` — audit trail of every approve/reject action
- `action_queue` — pending/running/completed containment actions
- `connectors` — per-tenant connector config (Phase 2)
- `tenant_settings` — LLM provider, safe_mode, webhook_secret
- `stripe_events` — idempotent Stripe webhook event log
- `daily_usage` — per-day, per-tenant alert count (hourly buckets)
- `alert_tags`, `alert_comments` — (reserved for Phase 2)

## Development vs Production

| Aspect | Dev (docker compose) | Production |
|--------|---------------------|------------|
| Database | PostgreSQL 16 container | Managed Postgres (Railway/Render) |
| Queue | Redis 7 container | Managed Redis |
| Worker | Celery in same compose | Celery workers on separate nodes |
| Frontend | Jinja2 templates (legacy) | React app (Vite + shadcn/ui) |
| LLM | Ollama local or free API keys | Byo API key per tenant |
