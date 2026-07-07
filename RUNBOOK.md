# Arbiterion Operations Runbook

## Overview
Arbiterion is an AI-powered SOC triage tool. It collects Windows events, runs them through a 3-agent pipeline, and provides a Governor interface for containment.

## Setup & Deployment
1. **Prerequisites**: Docker Desktop, Python 3.12+, Admin privileges (for Sysmon/Defender).
2. **Run**: `python launcher.py` (or `./deploy.ps1` on Windows).
3. **Admin Login**: `admin@arbiterion.local` / `ChangeMe123!`.

## Core Components
- **Collector**: Tails Windows Security/Sysmon logs.
- **Redis Stream**: `alerts:ingest` buffers incoming alerts.
- **Stream Consumer**: Reads from Redis and triggers `process_alert`.
- **AI Pipeline**: Manager $\rightarrow$ Triage $\rightarrow$ Containment.
- **EDR**: Executes actions via Windows Defender PowerShell cmdlets.

## Operational Tasks

### Adding a Tenant
Use the DB console:
```sql
INSERT INTO tenants (id, name, slug, plan_tier, alert_limit) 
VALUES (gen_random_uuid(), 'New Corp', 'newcorp', 'starter', 100);
```

### Rotating Session Secret
1. Update `SESSION_SECRET` in `.env`.
2. Restart the server. (All users will be logged out).

### Troubleshooting AI
- If AI is unavailable, Arbiterion uses **Deterministic Fallback**.
- Check `/api/health` for Redis/DB status.
- Verify Ollama is running: `curl http://localhost:11434/api/tags`.

## Containment Flow
1. Alert Ingested $\rightarrow$ AI Pipeline creates `proposed_action`.
2. Governor views alert $\rightarrow$ Clicks **Approve**.
3. `execute_containment` task runs $\rightarrow$ calls Defender Client $\rightarrow$ executes PowerShell $\rightarrow$ result logged to DB.
