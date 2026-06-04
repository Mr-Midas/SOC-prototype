# Copilot SOC

AI-powered SOC triage copilot — multi-tenant SaaS backend (Phase 1).

Ingests security alerts via webhook, runs a 3-agent AI pipeline (Manager → Triage → Containment), and keeps final containment decisions in human hands via a Governor approval workflow.

## Quick Start (Windows)

```powershell
# 1. Clone and enter the directory
cd C:\Users\thome\Documents\Codex\2026-04-27\act-as-a-senior-security-architect-3

# 2. Create virtual environment
python -m venv .venv

# 3. Activate it
.venv\Scripts\activate

# 4. Install dependencies
pip install -r requirements.txt

# 5. Set up environment (copy defaults)
Copy-Item .env.example .env

# 6. Start the app (uses SQLite fallback, no Postgres required for dev)
uvicorn copilot_soc.main:app --reload

# 7. Open in browser
start http://127.0.0.1:8000
```

## Quick Start (Linux / macOS)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
uvicorn copilot_soc.main:app --reload
```

## Full Stack with Docker

Requires Docker Desktop with WSL2 backend.

```powershell
docker compose up -d
python scripts/seed.py     # Bootstrap first tenant + admin user
```

This starts: FastAPI app (`:8000`), Celery worker, PostgreSQL 16, Redis 7.

## Architecture

```
                      ┌──────────────┐
        Webhook ─────►│  FastAPI app  │──► Celery Worker ──► Agent Pipeline
                      │  (stateless)  │                        │
                      └──────┬───────┘                    ┌────┴────┐
                             │                            │ Manager │
                      ┌──────┴──────┐                     ├─────────┤
                      │  PostgreSQL │                     │ Triage  │
                      │  (multi-    │                     ├─────────┤
                      │   tenant)   │                     │Contain- │
                      └─────────────┘                     │ ment    │
                             ▲                            └────┬────┘
                      ┌──────┴──────┐                         │
                      │    Redis    │                   ┌──────┴──────┐
                      │  (Celery    │                   │   Governor  │
                      │   broker)   │                   │  (approval) │
                      └─────────────┘                   └─────────────┘
```

## API Routes

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/login` | PBKDF2 auth, returns session cookie |
| POST | `/api/logout` | Clears session |
| GET | `/api/me` | Current user info |
| POST | `/api/v1/ingest/alert` | Ingest alert via webhook (HMAC-signed) |
| GET | `/api/alerts` | Paginated alert list |
| GET | `/api/alerts/{id}` | Alert detail with reasoning log |
| POST | `/api/alerts/{id}/governor` | Approve/reject containment |
| GET | `/api/settings` | Tenant LLM provider config |
| PUT | `/api/settings` | Update tenant settings |
| POST | `/api/billing/portal` | Stripe billing portal |
| POST | `/api/billing/webhook` | Stripe event webhook |
| GET | `/api/health` | Health check |

## Environment Variables

Copy `.env.example` to `.env` and configure:

```env
# Database (omit for SQLite dev fallback)
DATABASE_URL=postgresql://copilot:copilot@localhost:5432/copilot_soc

# Redis (required for Celery worker)
REDIS_URL=redis://localhost:6379/0

# Session secret — change to random 64-char string
SESSION_SECRET=change-this-to-a-random-64-char-string

# LLM provider (optional — falls back to deterministic logic if unset)
# Set LLM_API_KEY via settings API or tenant_settings table

# Stripe (optional — for billing portal)
STRIPE_SECRET_KEY=
STRIPE_WEBHOOK_SECRET=

# Connector mode: dry_run (default) or webhook
CONNECTOR_MODE=dry_run
CONTAINMENT_WEBHOOK_URL=

# CORS for React frontend dev server
CORS_ORIGINS=http://localhost:5173,http://localhost:3000
```

## Default Login

After running `python scripts/seed.py`:

- Email: `admin@copilot-soc.local`
- Password: `admin123`

## Ingesting Alerts

```powershell
curl.exe -X POST http://127.0.0.1:8000/api/v1/ingest/alert `
  -H "Content-Type: application/json" `
  -d '{
    "source": "Wazuh",
    "rule_name": "SSH Brute Force Detected",
    "summary": "Multiple failed SSH logins from 8.8.8.8",
    "severity": "High",
    "mitre_tactic": "Initial Access",
    "affected_user": "root",
    "affected_host": "prod-web-01",
    "source_ip": "8.8.8.8",
    "indicators": ["8.8.8.8", "ssh", "failed_login"],
    "telemetry": ["42 failed logins in 3 minutes"]
  }'
```

## Phase 1 vs Phase 2

| Feature | Phase 1 ($249/mo) | Phase 2 ($3K-$5K/mo) |
|---------|-------------------|----------------------|
| Ingestion | Generic webhook | CrowdStrike + Splunk connectors |
| Alert limit | 100/day | Unlimited |
| Database | PostgreSQL tenant_id scoping | + Row-Level Security |
| LLM | Deterministic fallback + optional AI | Full AI pipeline |
| Frontend | React (Vite + Tailwind) | Same + RBAC |
| Target | ~8 weeks | ~14 weeks total |
