# Arbiterion

AI-powered SOC triage platform — multi-tenant SaaS backend (Phase 1).

Ingests security alerts via webhook, runs a 3-agent AI pipeline (Manager â†’ Triage â†’ Containment), and keeps final containment decisions in human hands via a Governor approval workflow.

## Quick Start (Windows — One-Click)

Double-click **`Start Arbiterion.bat`** (runs `Install.bat` first if needed, then launches the app and opens your browser).

Or manually — this script auto-detects Python and installs it if missing:

```powershell
# 1. Auto-detect Python; download & install if not found
$python = (Get-Command python -ErrorAction SilentlyContinue)?.Source
if (-not $python) {
    Write-Host "Python not found. Downloading Python 3.11..."
    $url = "https://www.python.org/ftp/python/3.11.9/python-3.11.9-amd64.exe"
    $installer = "$env:TEMP\python-installer.exe"
    Invoke-WebRequest -Uri $url -OutFile $installer
    Start-Process -FilePath $installer -ArgumentList '/quiet InstallAllUsers=1 PrependPath=1' -Wait
    # Refresh PATH
    $env:PATH = [Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [Environment]::GetEnvironmentVariable("Path","User")
}
python --version

# 2. Create virtual environment
python -m venv .venv

# 3. Activate it
.venv\Scripts\activate

# 4. Install dependencies
pip install -r requirements.txt

# 5. Set up environment (copy defaults)
copy .env.example .env >nul

# 6. Start the app (no Postgres required for dev — boots instantly)
uvicorn arbiterion.main:app --reload

# 7. Open in browser
start http://127.0.0.1:8000
```

> **Note**: The `.bat` files (`Install.bat`, `Start Arbiterion.bat`) and `launcher.py` are legacy convenience wrappers. They work with the refactored backend.

## Quick Start (Linux / macOS)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
uvicorn arbiterion.main:app --reload
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
                      â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
        Webhook â”€â”€â”€â”€â”€â–ºâ”‚  FastAPI app  â”‚â”€â”€â–º Celery Worker â”€â”€â–º Agent Pipeline
                      â”‚  (stateless)  â”‚                        â”‚
                      â””â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”˜                    â”Œâ”€â”€â”€â”€â”´â”€â”€â”€â”€â”
                             â”‚                            â”‚ Manager â”‚
                      â”Œâ”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”                     â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
                      â”‚  PostgreSQL â”‚                     â”‚ Triage  â”‚
                      â”‚  (multi-    â”‚                     â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
                      â”‚   tenant)   â”‚                     â”‚Contain- â”‚
                      â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜                     â”‚ ment    â”‚
                             â–²                            â””â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”˜
                      â”Œâ”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”                         â”‚
                      â”‚    Redis    â”‚                   â”Œâ”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”
                      â”‚  (Celery    â”‚                   â”‚   Governor  â”‚
                      â”‚   broker)   â”‚                   â”‚  (approval) â”‚
                      â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜                   â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
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
# Database (PostgreSQL â€” app boots without it via graceful error message)
DATABASE_URL=postgresql://arbiterion:arbiterion@localhost:5432/arbiterion

# Redis (required for Celery worker)
REDIS_URL=redis://localhost:6379/0

# Session secret â€” change to random 64-char string
SESSION_SECRET=change-this-to-a-random-64-char-string

# LLM provider (optional â€” falls back to deterministic logic if unset)
# Set LLM_API_KEY via settings API or tenant_settings table

# Stripe (optional â€” for billing portal)
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

- Email: `admin@arbiterion.local`
- Password: `ChangeMe123!`

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

