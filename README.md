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
- Manager Agent that assigns severity and routes investigative focus
- Triage Worker that summarizes evidence and scores true-positive confidence
- Containment Worker that proposes a human-reviewable response action
- Transparent reasoning log for every agent stage
- Tier 4 Governor approval or rejection workflow
- Live OpenAI mode with deterministic fallback behavior when no API key is configured

## Quick Start

1. Create a virtual environment and install dependencies:

   ```powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   ```

2. Create an environment file:

   ```powershell
   Copy-Item .env.example .env
   ```

3. Update `.env` with your OpenAI API key if you want live model-backed reasoning.

4. Start the app:

   ```powershell
   uvicorn app:app --reload
   ```

5. Open the dashboard in your browser:

   ```text
   http://127.0.0.1:8000
   ```

## OpenAI Notes

- The app reads `OPENAI_API_KEY` from the environment.
- The default model is `gpt-4o-mini`, but you can override it with `OPENAI_MODEL`.
- If the API key is missing or the SDK call fails, the workflow falls back to deterministic local logic so the demo remains fully usable.

## Debugging

The backend prints each stage of the workflow to the console, including:

- mock alert generation
- manager severity scoring
- triage classification
- containment recommendation
- final governor approval or rejection
