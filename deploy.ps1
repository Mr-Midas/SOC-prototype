# Arbiterion Deployment Script (Windows)
# Usage: powershell ./deploy.ps1

Write-Host "--- Arbiterion One-Click Deployment ---" -ForegroundColor Cyan

# 1. Environment Check
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Error "Docker is not installed. Please install Docker Desktop."
    exit 1
}

# 2. Start Infrastructure
Write-Host "[1/4] Starting Infrastructure..." -ForegroundColor Yellow
docker compose up -d postgres redis
Write-Host "Waiting for PostgreSQL to be ready..."
$retry = 0
while ($retry -lt 30) {
    $res = docker compose exec -T postgres pg_isready -U arbiterion -d arbiterion
    if ($res.returncode -eq 0) { break }
    Start-Sleep -Seconds 2
    $retry++
}
if ($retry -eq 30) { Write-Error "Postgres failed to start."; exit 1 }

# 3. Sysmon Setup
Write-Host "[2/4] Ensuring Sysmon is running..." -ForegroundColor Yellow
# We use the launcher.py logic mostly, but for a deploy script we can just trigger launcher
# or run the specific commands. Let's rely on launcher for the actual installation.

# 4. Start Application
Write-Host "[3/4] Launching Arbiterion..." -ForegroundColor Yellow
# We start launcher.py which handles everything else
python launcher.py

Write-Host "[4/4] Deployment Complete!" -ForegroundColor Green
Write-Host "Access Dashboard: http://127.0.0.1:8000/login"
