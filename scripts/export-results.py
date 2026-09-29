#!/usr/bin/env python3
"""Export Arbiterion analysis results from PostgreSQL.

Subcommands:
  secret   Print the default tenant's webhook_secret (used to configure the VM collector).
  export   Dump alerts for a given analysis host to a timestamped directory on the Desktop
           as JSON + a human-readable markdown report. Required before VM snapshot rollback.

Usage:
  python scripts/export-results.py secret
  python scripts/export-results.py export --host <host_id> [--out <dir>]
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
from datetime import datetime, timezone
from pathlib import Path

import asyncpg

ROOT = Path(__file__).resolve().parents[1]


def database_url() -> str:
    env_path = ROOT / ".env"
    if env_path.exists():
        for line in env_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line.startswith("DATABASE_URL="):
                return line.split("=", 1)[1].strip().strip('"').strip("'")
    return os.getenv("DATABASE_URL", "postgresql://arbiterion:arbiterion@localhost:5432/arbiterion")


async def fetch_webhook_secret(conn: asyncpg.Connection) -> str | None:
    row = await conn.fetchrow(
        """
        SELECT s.webhook_secret
        FROM tenant_settings s
        JOIN tenants t ON t.id = s.tenant_id
        WHERE t.slug = 'default'
        """
    )
    if row and row["webhook_secret"]:
        return row["webhook_secret"]
    row = await conn.fetchrow("SELECT webhook_secret FROM tenant_settings LIMIT 1")
    return row["webhook_secret"] if row else None


async def cmd_secret() -> int:
    conn = await asyncpg.connect(database_url())
    try:
        secret = await fetch_webhook_secret(conn)
        if not secret:
            print("ERROR: no webhook_secret configured for any tenant.", file=os.sys.stderr)
            return 1
        print(secret)
        return 0
    finally:
        await conn.close()


async def cmd_export(host: str, out: str | None) -> int:
    conn = await asyncpg.connect(database_url())
    try:
        rows = await conn.fetch(
            """
            SELECT
                a.id, a.source, a.rule_name, a.summary, a.severity, a.risk_score,
                a.classification, a.pipeline_state, a.governor_status,
                a.manager_output, a.triage_output, a.containment_output,
                a.reasoning_log, a.governor_decision, a.raw_alert,
                a.created_at, a.updated_at
            FROM alerts a
            WHERE a.source = 'Local Endpoint Agent'
              AND (a.raw_alert->>'affected_host' = $1
                   OR a.raw_alert->>'host_id' = $1)
            ORDER BY a.created_at
            """,
            host,
        )
    finally:
        await conn.close()

    if not rows:
        print(f"No alerts found for host '{host}'. Nothing to export.")
        return 1

    out_dir = Path(out) if out else Path.home() / "Desktop" / f"arbiterion-analysis-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    out_dir.mkdir(parents=True, exist_ok=True)

    def serializable(row: asyncpg.Record) -> dict:
        result = dict(row)
        for key, value in result.items():
            if isinstance(value, datetime):
                result[key] = value.astimezone(timezone.utc).isoformat()
            elif isinstance(value, str) and key in {
                "manager_output",
                "triage_output",
                "containment_output",
                "reasoning_log",
                "governor_decision",
                "raw_alert",
            }:
                try:
                    result[key] = json.loads(value)
                except json.JSONDecodeError:
                    pass
        return result

    alerts = [serializable(row) for row in rows]
    manifest = {
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "host": host,
        "alert_count": len(alerts),
        "alerts": alerts,
    }

    (out_dir / "alerts.json").write_text(
        json.dumps(manifest, indent=2, default=str), encoding="utf-8"
    )

    lines = [
        f"# Arbiterion Analysis Export",
        "",
        f"**Host:** `{host}`  ",
        f"**Exported:** {manifest['exported_at']}  ",
        f"**Alert count:** {len(alerts)}",
        "",
        "| # | Time (UTC) | Event | Rule | Severity | Risk | State | Governor |",
        "|---|------------|-------|------|----------|------|-------|----------|",
    ]
    for idx, alert in enumerate(alerts, start=1):
        raw = alert["raw_alert"] or {}
        created = alert["created_at"]
        event_type = raw.get("event_type") or raw.get("rule_name") or ""
        lines.append(
            f"| {idx} | {created} | {event_type} | {alert['rule_name']} "
            f"| {alert['severity'] or '-'} | {alert['risk_score'] if alert['risk_score'] is not None else '-'} "
            f"| {alert['pipeline_state']} | {alert['governor_status']} |"
        )

    lines += ["", "## Detail", ""]
    for idx, alert in enumerate(alerts, start=1):
        raw = alert["raw_alert"] or {}
        lines.append(f"### {idx}. {alert['rule_name']}")
        lines.append(f"- **ID:** `{alert['id']}`")
        lines.append(f"- **Summary:** {alert['summary']}")
        lines.append(f"- **Classification:** {alert['classification'] or '-'}")
        lines.append(f"- **Governor decision:** {alert['governor_decision'] or '-'}")
        lines.append(f"- **Indicators:** {', '.join(raw.get('indicators', []) or []) or '-'}")
        command_line = raw.get("command_line")
        if command_line:
            lines.append(f"- **Command line:** `{command_line}`")
        telemetry = raw.get("telemetry") or []
        if telemetry:
            lines.append(f"- **Telemetry:**")
            for item in telemetry:
                lines.append(f"  - {item}")
        lines.append("")

    (out_dir / "report.md").write_text("\n".join(lines), encoding="utf-8")
    (out_dir / "manifest.json").write_text(
        json.dumps({"exported_at": manifest["exported_at"], "host": host, "alert_count": len(alerts)}, indent=2),
        encoding="utf-8",
    )

    print(f"Exported {len(alerts)} alerts to {out_dir}")
    print(f"  - alerts.json")
    print(f"  - report.md")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Export Arbiterion analysis results.")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("secret", help="Print the default tenant webhook_secret.")

    export = sub.add_parser("export", help="Export alerts for an analysis host.")
    export.add_argument("--host", required=True, help="VM host_id / affected_host to export.")
    export.add_argument("--out", default=None, help="Output directory (default: Desktop\\arbiterion-analysis-<ts>).")

    args = parser.parse_args()
    if args.command == "secret":
        return asyncio.run(cmd_secret())
    if args.command == "export":
        return asyncio.run(cmd_export(args.host, args.out))
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
