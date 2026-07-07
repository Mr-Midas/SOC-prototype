"""Notification delivery system for Arbiterion.
Supports Webhooks, Slack, and Windows Toast Notifications.
"""

import os
import httpx
import structlog
import subprocess
import sys
from typing import Any, Dict

logger = structlog.get_logger()

# Env vars
NOTIF_WEBHOOK_URL = os.getenv("NOTIFICATION_WEBHOOK_URL")
NOTIF_SLACK_URL = os.getenv("NOTIFICATION_SLACK_WEBHOOK")
NOTIF_WINDOWS_TOAST = os.getenv("NOTIFICATION_WINDOWS_TOAST", "true").lower() == "true"


async def notify(event_type: str, data: Dict[str, Any]):
    """
    Generic notification dispatcher.
    event_type: 'alert_created' | 'governor_decision' | 'governor_pending'
    """
    payload = {
        "event": event_type,
        "data": data
    }

    tasks = []
    
    # 1. Generic Webhook
    if NOTIF_WEBHOOK_URL:
        tasks.append(_send_webhook(NOTIF_WEBHOOK_URL, payload))
    
    # 2. Slack
    if NOTIF_SLACK_URL:
        slack_payload = _format_for_slack(event_type, data)
        tasks.append(_send_webhook(NOTIF_SLACK_URL, slack_payload))

    # 3. Windows Toast Notification (native, no deps)
    if NOTIF_WINDOWS_TOAST and sys.platform == "win32":
        _send_windows_toast(event_type, data)

    if tasks:
        async with httpx.AsyncClient(timeout=10.0) as client:
            import asyncio
            await asyncio.gather(*tasks, return_exceptions=True)


async def _send_webhook(url: str, payload: Dict[str, Any]):
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(url, json=payload)
            resp.raise_for_status()
            logger.info("notification_sent", url=url)
    except Exception as e:
        logger.error("notification_failed", url=url, error=str(e))


def _send_windows_toast(event_type: str, data: Dict[str, Any]):
    """Send a native Windows 10/11 toast notification via PowerShell."""
    try:
        title, message = _format_for_windows_toast(event_type, data)
        
        # PowerShell script for Windows Toast Notification
        # Uses the Windows.UI.Notifications API via BurntToast or native method
        ps_script = f'''
        [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
        [Windows.UI.Notifications.ToastNotification, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
        [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null

        $appId = "Arbiterion.SOC"
        $template = @"
        <toast activationType="protocol" launch="arbiterion://alert/{data.get('alert_id', '')}">
            <visual>
                <binding template="ToastGeneric">
                    <text>{title}</text>
                    <text>{message}</text>
                </binding>
            </visual>
            <actions>
                <action content="Open Dashboard" activationType="protocol" arguments="arbiterion://dashboard"/>
                <action content="Dismiss" activationType="system" arguments="dismiss"/>
            </actions>
        </toast>
"@
        $xml = New-Object Windows.Data.Xml.Dom.XmlDocument
        $xml.LoadXml($template)
        $toast = New-Object Windows.UI.Notifications.ToastNotification $xml
        $notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($appId)
        $notifier.Show($toast)
        '''
        
        # Run PowerShell script hidden
        subprocess.run(
            ["powershell", "-NoProfile", "-WindowStyle", "Hidden", "-Command", ps_script],
            capture_output=True,
            timeout=10,
            check=False
        )
        logger.info("windows_toast_sent", event_type=event_type)
    except Exception as e:
        logger.error("windows_toast_failed", error=str(e))


def _format_for_windows_toast(event_type: str, data: Dict[str, Any]) -> tuple[str, str]:
    """Format notification for Windows Toast (title, message)."""
    if event_type == "alert_created":
        severity = data.get('severity', 'Medium')
        icon = "🔴" if severity == "Critical" else "🟠" if severity == "High" else "🟡"
        title = f"{icon} Arbiterion: {severity} Alert"
        message = f"{data.get('rule_name', 'Unknown')} on {data.get('affected_host', 'unknown host')}"
    elif event_type == "governor_pending":
        title = "⚖️ Arbiterion: Governor Approval Required"
        message = f"Alert {data.get('alert_id', 'N/A')[:8]}... needs your decision on {data.get('action', 'containment')}"
    elif event_type == "governor_decision":
        decision = data.get("decision", "unknown")
        icon = "✅" if decision == "approved" else "❌"
        title = f"{icon} Arbiterion: Governor {decision.capitalize()}"
        message = f"Alert {data.get('alert_id', 'N/A')[:8]}... - {data.get('action', 'action')}"
    else:
        title = "Arbiterion Notification"
        message = str(data)[:100]
    return title, message


def _format_for_slack(event_type: str, data: Dict[str, Any]) -> Dict[str, Any]:
    """Formats the notification for Slack's incoming webhook format."""
    if event_type == "alert_created":
        text = (
            f"🚨 *New High-Risk Alert*\n"
            f"*Rule:* {data.get('rule_name')}\n"
            f"*Host:* {data.get('affected_host')}\n"
            f"*Severity:* {data.get('severity')}\n"
            f"*Summary:* {data.get('summary')}"
        )
    elif event_type == "governor_decision":
        decision = data.get("decision")
        text = (
            f"⚖️ *Governor Decision*\n"
            f"*Alert:* {data.get('alert_id')}\n"
            f"*Decision:* {decision.upper()}\n"
            f"*Action:* {data.get('action')}\n"
            f"*User:* {data.get('governor')}"
        )
    elif event_type == "governor_pending":
        text = (
            f"⚖️ *Governor Approval Required*\n"
            f"*Alert:* {data.get('alert_id')}\n"
            f"*Action:* {data.get('action')}\n"
            f"*Host:* {data.get('affected_host')}\n"
            f"*Severity:* {data.get('severity')}\n"
            f"*Action Required:* Open dashboard to approve/reject"
        )
    else:
        text = f"Arbiterion Notification: {event_type}\nData: {data}"

    return {"text": text}
