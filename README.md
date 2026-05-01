# Agentic Security Operations Center

A polished FastAPI prototype for a coding challenge that simulates a manager-worker SOC. The app generates realistic security alerts, routes them through AI-driven triage, and keeps the final containment decision in human hands.

## Directory Structure

```text
.
|-- app.py
|-- requirements.txt
|-- .env.example
|-- .gitignore
|-- README.md
|-- templates/
|   `-- index.html
`-- static/
    |-- css/
    |   `-- styles.css
    `-- js/
        `-- app.js
```

## Features

- Mock SIEM alert generation through both a startup seed and manual button-driven creation
- Real webhook ingestion endpoint for live alerts: `/api/ingest/webhook`
- Optional free threat-intelligence enrichment with AbuseIPDB and AlienVault OTX
- SQLite persistence for incidents, approvals, users, and queued actions
- Local authentication with seeded operator accounts and role-gated governor approvals
- DB-backed containment action queue with `dry_run` or webhook connector execution
- Manager Agent that assigns severity and routes investigative focus
- Triage Worker that summarizes evidence and scores true-positive confidence
- Containment Worker that proposes a human-reviewable response action
- Transparent reasoning log for every agent stage
- Tier 4 Governor approval or rejection workflow
- Live OpenAI mode with deterministic fallback behavior when no API key is configured

## Quick Start

1. Create a virtual environment, install dependencies, and start the app:

   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   python -m pip install -r requirements.txt
   python -m uvicorn app:app --reload
   ```

2. Create an environment file:

   ```powershell
   Copy-Item .env.example .env
   ```

2. Create an environment file:

   ```bash
   cp .env.example .env
   ```

3. Update `.env` for your preferred provider.

   Ollama setup:

   ```env
   AI_PROVIDER=ollama
   OLLAMA_BASE_URL=http://localhost:11434/api
   OLLAMA_MODEL=llama3.1:8b
   OLLAMA_TIMEOUT_SECONDS=120
   WEBHOOK_SHARED_SECRET=optional_shared_secret
   SESSION_SECRET=change-this-session-secret
   DEFAULT_ADMIN_USERNAME=admin
   DEFAULT_ADMIN_PASSWORD=ChangeMe123!
   DEFAULT_GOVERNOR_USERNAME=governor
   DEFAULT_GOVERNOR_PASSWORD=ChangeMe123!
   CONNECTOR_MODE=dry_run
   CONTAINMENT_WEBHOOK_URL=
   ABUSEIPDB_API_KEY=
   OTX_API_KEY=
   ```

   Gemini setup:

   ```env
   AI_PROVIDER=gemini
   GEMINI_API_KEY=your_real_gemini_key
   GEMINI_MODEL=gemini-2.5-flash
   ```

   OpenAI setup:

   ```env
   AI_PROVIDER=openai
   OPENAI_API_KEY=your_real_openai_key
   OPENAI_MODEL=gpt-4o-mini
   ```

4. Open the dashboard in your browser:

   ```text
   http://127.0.0.1:8000
   ```

## Default Login

The app seeds local users from environment variables:

- `admin / ChangeMe123!`
- `governor / ChangeMe123!`

Change those immediately in `.env` for any shared environment.

## AI Provider Notes

- The app supports Ollama, Gemini, and OpenAI.
- Ollama is the default provider and is called directly through its local HTTP API.
- The default Ollama base URL is `http://localhost:11434/api`, which matches the official Ollama API base URL.
- Set `AI_PROVIDER=gemini` to use Google Gemini through the official OpenAI-compatible endpoint.
- Set `AI_PROVIDER=openai` to use the OpenAI Responses API path.
- Set `AI_PROVIDER=ollama` to use a local model for more reliable 24/7 operation when public hosted APIs are rate-limited or unavailable.
- If the configured API key is missing or the SDK call fails, the workflow falls back to deterministic local logic so the demo remains fully usable.

## Real Alert Ingestion

The app now supports real inbound alerts through:

```text
POST /api/ingest/webhook
```

Expected JSON body:

```json
{
  "source": "Wazuh",
  "rule_name": "SSH Brute Force Detected",
  "summary": "Multiple failed SSH logins observed against an internet-exposed host.",
  "severity": "High",
  "mitre_tactic": "Initial Access",
  "affected_user": "root",
  "affected_host": "prod-web-01",
  "source_ip": "8.8.8.8",
  "indicators": ["8.8.8.8", "ssh", "failed_login"],
  "telemetry": [
    "42 failed logins in 3 minutes",
    "The source IP is external to the corporate network"
  ],
  "metadata": {
    "vendor_event_id": "abc-123"
  }
}
```

Optional webhook signing:

- Set `WEBHOOK_SHARED_SECRET` in `.env`
- Send `X-Signature: sha256=<hex hmac of raw body>`

Example curl:

```bash
curl -X POST http://127.0.0.1:8000/api/ingest/webhook \
  -H "Content-Type: application/json" \
  -d '{
    "source": "Wazuh",
    "rule_name": "SSH Brute Force Detected",
    "summary": "Multiple failed SSH logins observed against an internet-exposed host.",
    "severity": "High",
    "mitre_tactic": "Initial Access",
    "affected_user": "root",
    "affected_host": "prod-web-01",
    "source_ip": "8.8.8.8",
    "indicators": ["8.8.8.8", "ssh", "failed_login"],
    "telemetry": ["42 failed logins in 3 minutes"]
  }'
```

Free enrichment options:

- AbuseIPDB free tier: 1,000 checks/day according to [AbuseIPDB pricing](https://www.abuseipdb.com/pricing)
- VirusTotal public API exists, but its public terms are restrictive and rate limited; I did not wire it in as the default production-style path
- AlienVault OTX has a free API key model for indicator lookups

This means the app is no longer limited to mock-generated alerts. You can now feed it live events from any free-capable source that can send webhooks or HTTP POSTs, including Wazuh, custom detection scripts, Fail2Ban hooks, or a SIEM forwarder.

## Durable Workflow

- Alerts are persisted to `soc.db`
- Human approvals are written to the database
- Approved actions are enqueued in a DB-backed action queue
- `CONNECTOR_MODE=dry_run` records the action without sending it
- `CONNECTOR_MODE=webhook` sends approved actions to `CONTAINMENT_WEBHOOK_URL`

## Debugging

The backend prints each stage of the workflow to the console, including:

- mock alert generation
- manager severity scoring
- triage classification
- containment recommendation
- final governor approval or rejection
