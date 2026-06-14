"""
Tiny Windows event collector for Arbiterion.

Tails Security + Sysmon logs, applies local noise filters, and POSTs suspicious
events to /api/ingest/endpoint-event with optional HMAC signing.

Requires: Windows, Python 3.10+, httpx (see requirements.txt)
Run as Administrator if you need access to the Security log.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import platform
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import httpx
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

STATE_PATH = BASE_DIR / ".collector_state.json"

# Sysmon Operational + classic Security log
SYSMON_LOG = "Microsoft-Windows-Sysmon/Operational"
SECURITY_LOG = "Security"

SYSMON_EVENT_IDS = {1, 3, 10, 11, 22, 23, 25}
SECURITY_EVENT_IDS = {4624, 4625, 4688, 4720, 4732}

# Local pre-filter: only forward events that match at least one rule.
SUSPICIOUS_TERMS = (
    "powershell",
    "-enc",
    "-encodedcommand",
    "downloadstring",
    "invoke-expression",
    "iex",
    "mimikatz",
    "lsass",
    "certutil",
    "bitsadmin",
    "rundll32",
    "regsvr32",
    "wscript",
    "cscript",
    "mshta",
    "vssadmin",
    "bcdedit",
    "wevtutil cl",
)

NOISY_PROCESS_NAMES = {
    "chrome.exe",
    "msedge.exe",
    "firefox.exe",
    "code.exe",
    "cursor.exe",
    "searchhost.exe",
    "runtimebroker.exe",
}


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_state() -> dict[str, Any]:
    if not STATE_PATH.exists():
        return {"logs": {}, "posted_fingerprints": []}
    try:
        return json.loads(STATE_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {"logs": {}, "posted_fingerprints": []}


def save_state(state: dict[str, Any]) -> None:
    state["posted_fingerprints"] = state.get("posted_fingerprints", [])[-500:]
    STATE_PATH.write_text(json.dumps(state, indent=2), encoding="utf-8")


def host_id() -> str:
    return os.getenv("COLLECTOR_HOST_ID", socket.gethostname())


def sign_body(raw_body: bytes, secret: str) -> str:
    digest = hmac.new(secret.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def run_powershell(script: str) -> str:
    completed = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0 and completed.stderr.strip():
        raise RuntimeError(completed.stderr.strip())
    return completed.stdout.strip()


def fetch_events(log_name: str, event_ids: set[int], start_time_iso: str) -> list[dict[str, Any]]:
    ids_csv = ",".join(str(item) for item in sorted(event_ids))
    # PowerShell emits one JSON object per event for easier parsing.
    script = f"""
$ErrorActionPreference = 'SilentlyContinue'
$start = [datetime]::Parse('{start_time_iso}')
$events = Get-WinEvent -FilterHashtable @{{
    LogName = '{log_name}'
    ID = @({ids_csv})
    StartTime = $start
}} | Sort-Object TimeCreated

foreach ($event in $events) {{
    $xml = [xml]$event.ToXml()
    $data = @{{}}
    foreach ($node in $xml.Event.EventData.Data) {{
        if ($node.Name) {{ $data[$node.Name] = [string]$node.'#text' }}
    }}
    [pscustomobject]@{{
        RecordId = $event.RecordId
        TimeCreated = $event.TimeCreated.ToUniversalTime().ToString('o')
        Id = $event.Id
        ProviderName = $event.ProviderName
        Message = $event.Message
        Data = $data
    }} | ConvertTo-Json -Compress
}}
"""
    output = run_powershell(script)
    if not output:
        return []

    events: list[dict[str, Any]] = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return events


def event_fingerprint(log_name: str, event: dict[str, Any]) -> str:
    record_id = event.get("RecordId")
    event_id = event.get("Id")
    created = event.get("TimeCreated", "")
    return f"{log_name}:{event_id}:{record_id}:{created}"


def already_posted(state: dict[str, Any], fingerprint: str) -> bool:
    return fingerprint in state.get("posted_fingerprints", [])


def mark_posted(state: dict[str, Any], fingerprint: str) -> None:
    posted = state.setdefault("posted_fingerprints", [])
    posted.append(fingerprint)


def text_blob(event: dict[str, Any]) -> str:
    data = event.get("Data") or {}
    parts = [event.get("Message") or ""]
    if isinstance(data, dict):
        parts.extend(str(value) for value in data.values())
    return " ".join(parts).lower()


def should_forward(log_name: str, event: dict[str, Any]) -> bool:
    event_id = int(event.get("Id") or 0)
    data = event.get("Data") or {}
    blob = text_blob(event)

    if log_name == SECURITY_LOG:
        if event_id == 4625:
            return True
        if event_id in {4720, 4732}:
            return True
        if event_id == 4688:
            return any(term in blob for term in SUSPICIOUS_TERMS)
        if event_id == 4624:
            # Successful logon type 10 (remote interactive/RDP) is worth a look.
            return data.get("LogonType") == "10"

    if log_name == SYSMON_LOG:
        process_name = (data.get("Image") or data.get("SourceImage") or "").split("\\")[-1].lower()
        if process_name in NOISY_PROCESS_NAMES and event_id in {1, 3, 22}:
            return False

        if event_id == 1:
            return any(term in blob for term in SUSPICIOUS_TERMS) or data.get("ParentImage", "").lower().endswith(
                ("\\cmd.exe", "\\powershell.exe", "\\pwsh.exe")
            )

        if event_id == 3:
            destination_ip = data.get("DestinationIp") or ""
            if destination_ip.startswith(("10.", "172.", "192.168.", "127.")):
                return False
            return True

        if event_id in {10, 11, 23, 25}:
            return True

        if event_id == 22:
            query = (data.get("QueryName") or "").lower()
            return query and not query.endswith((".microsoft.com", ".windows.com", ".office.com"))

    return False


def map_event(log_name: str, event: dict[str, Any]) -> Optional[dict[str, Any]]:
    if not should_forward(log_name, event):
        return None

    event_id = int(event.get("Id") or 0)
    data = event.get("Data") or {}
    blob = text_blob(event)
    process_name = (data.get("Image") or data.get("SourceImage") or "").split("\\")[-1] or None
    command_line = data.get("CommandLine") or data.get("Commandline")
    username = data.get("TargetUserName") or data.get("User") or data.get("AccountName")
    source_ip = data.get("IpAddress") or data.get("SourceIp") or data.get("DestinationIp")

    if log_name == SECURITY_LOG and event_id == 4625:
        event_type = "failed_logon"
        summary = (
            f"Failed logon for account {username or 'unknown'} from {source_ip or 'unknown source'} "
            f"on {host_id()}."
        )
        severity_hint = "Medium"
    elif log_name == SECURITY_LOG and event_id == 4720:
        event_type = "account_created"
        summary = f"New local/domain account created on {host_id()} ({username or 'unknown account'})."
        severity_hint = "High"
    elif log_name == SECURITY_LOG and event_id == 4732:
        event_type = "group_membership_change"
        summary = f"Security group membership changed on {host_id()}."
        severity_hint = "High"
    elif log_name == SYSMON_LOG and event_id == 1:
        event_type = "process_create"
        summary = f"Process created on {host_id()}: {process_name or 'unknown process'}."
        severity_hint = "High" if any(term in blob for term in ("-enc", "downloadstring", "invoke-expression")) else "Medium"
    elif log_name == SYSMON_LOG and event_id == 3:
        event_type = "network_connection"
        summary = (
            f"Outbound network connection from {process_name or 'unknown process'} to "
            f"{data.get('DestinationIp')}:{data.get('DestinationPort')} on {host_id()}."
        )
        severity_hint = "Medium"
    elif log_name == SYSMON_LOG and event_id == 10:
        event_type = "process_access"
        summary = f"Process access event detected on {host_id()} (possible credential access pattern)."
        severity_hint = "High"
    elif log_name == SYSMON_LOG and event_id == 11:
        event_type = "file_create"
        summary = f"Suspicious file creation on {host_id()} at {data.get('TargetFilename') or 'unknown path'}."
        severity_hint = "Medium"
    elif log_name == SYSMON_LOG and event_id == 22:
        event_type = "dns_query"
        summary = f"DNS query on {host_id()} for {data.get('QueryName') or 'unknown domain'}."
        severity_hint = "Low"
    elif log_name == SYSMON_LOG and event_id in {23, 25}:
        event_type = "file_tampering"
        summary = f"File delete/rename activity detected on {host_id()}."
        severity_hint = "High"
    else:
        event_type = f"event_{event_id}"
        summary = f"Security event {event_id} detected on {host_id()}."
        severity_hint = None

    indicators = [
        value
        for value in [
            process_name,
            source_ip,
            data.get("DestinationIp"),
            data.get("QueryName"),
            data.get("TargetFilename"),
            data.get("Hashes"),
            username,
        ]
        if value
    ]

    telemetry = [
        f"Log: {log_name}",
        f"Event ID: {event_id}",
        f"Provider: {event.get('ProviderName') or 'unknown'}",
        f"Record ID: {event.get('RecordId')}",
    ]
    if data.get("ParentCommandLine"):
        telemetry.append(f"Parent command line: {str(data['ParentCommandLine'])[:220]}")

    return {
        "host_id": host_id(),
        "event_type": event_type,
        "summary": summary[:600],
        "severity_hint": severity_hint,
        "username": username,
        "source_ip": source_ip if source_ip not in {"-", "::1", "127.0.0.1"} else None,
        "process_name": process_name,
        "command_line": (command_line or "")[:500] or None,
        "indicators": indicators[:25],
        "telemetry": telemetry[:25],
        "metadata": {
            "log_name": log_name,
            "event_id": event_id,
            "record_id": event.get("RecordId"),
            "time_created": event.get("TimeCreated"),
            "raw_data": data,
        },
    }


def post_event(client: httpx.Client, endpoint: str, secret: str, payload: dict[str, Any]) -> None:
    raw_body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if secret:
        headers["X-Signature"] = sign_body(raw_body, secret)

    response = client.post(endpoint, content=raw_body, headers=headers)
    response.raise_for_status()
    body = response.json()
    print(
        f"[POST] {payload['event_type']} -> alert_id={body.get('id')} "
        f"severity={body.get('manager', {}).get('severity')}"
    )


def collect_pending_events(lookback_seconds: int) -> list[dict[str, Any]]:
    """Read Windows logs and return mapped endpoint events (no HTTP)."""
    if platform.system().lower() != "windows":
        raise RuntimeError("Windows event collection only works on Windows.")

    state = load_state()
    now = datetime.now(timezone.utc)
    start_time = now.timestamp() - lookback_seconds
    start_iso = datetime.fromtimestamp(start_time, tz=timezone.utc).isoformat()

    pending: list[dict[str, Any]] = []
    for log_name, event_ids in ((SYSMON_LOG, SYSMON_EVENT_IDS), (SECURITY_LOG, SECURITY_EVENT_IDS)):
        try:
            events = fetch_events(log_name, event_ids, start_iso)
        except Exception as exc:
            print(f"[WARN] Failed reading {log_name}: {exc}")
            continue

        for event in events:
            fingerprint = event_fingerprint(log_name, event)
            if already_posted(state, fingerprint):
                continue

            mapped = map_event(log_name, event)
            if not mapped:
                continue

            mark_posted(state, fingerprint)
            pending.append(mapped)

    state["logs"]["last_poll_at"] = utc_now_iso()
    save_state(state)
    return pending


def poll_once(
    *,
    endpoint: str,
    secret: str,
    lookback_seconds: int,
    dry_run: bool,
) -> int:
    if platform.system().lower() != "windows":
        raise RuntimeError("collector.py only runs on Windows.")

    pending = collect_pending_events(lookback_seconds)
    sent = 0
    with httpx.Client(timeout=20.0) as client:
        for mapped in pending:
            if dry_run:
                print(f"[DRY-RUN] Would post {mapped['event_type']}: {mapped['summary']}")
            else:
                try:
                    post_event(client, endpoint, secret, mapped)
                except Exception as exc:
                    print(f"[ERROR] Post failed for {mapped['event_type']}: {exc}")
                    continue
            sent += 1
    return sent


def main() -> int:
    parser = argparse.ArgumentParser(description="Collect Windows Security/Sysmon events for Arbiterion.")
    parser.add_argument(
        "--endpoint",
        default=os.getenv("COLLECTOR_ENDPOINT", "http://127.0.0.1:8000/api/ingest/endpoint-event"),
        help="Ingest URL for endpoint events.",
    )
    parser.add_argument(
        "--secret",
        default=os.getenv("WEBHOOK_SHARED_SECRET", os.getenv("COLLECTOR_SHARED_SECRET", "")),
        help="Shared secret for X-Signature HMAC (must match app WEBHOOK_SHARED_SECRET).",
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=int(os.getenv("COLLECTOR_INTERVAL_SECONDS", "30")),
        help="Polling interval in seconds.",
    )
    parser.add_argument(
        "--lookback",
        type=int,
        default=int(os.getenv("COLLECTOR_LOOKBACK_SECONDS", "120")),
        help="How far back to read events on each poll.",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Poll one time and exit.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Map/filter events but do not POST.",
    )
    args = parser.parse_args()

    print(f"[COLLECTOR] endpoint={args.endpoint} interval={args.interval}s lookback={args.lookback}s")
    if not args.secret:
        print("[COLLECTOR] Warning: no shared secret configured; ingest endpoint accepts unsigned requests.")

    while True:
        try:
            count = poll_once(
                endpoint=args.endpoint,
                secret=args.secret,
                lookback_seconds=args.lookback,
                dry_run=args.dry_run,
            )
            print(f"[COLLECTOR] forwarded={count} at {utc_now_iso()}")
        except Exception as exc:
            print(f"[COLLECTOR] poll failed: {exc}")

        if args.once:
            break
        time.sleep(max(5, args.interval))

    return 0


if __name__ == "__main__":
    sys.exit(main())
