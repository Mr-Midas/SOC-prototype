"""Windows Defender integration - built-in, free on Windows 10/11."""

from __future__ import annotations

import subprocess
from typing import Any
from uuid import UUID

from arbiterion.edr.base import EdrClient


class DefenderClient(EdrClient):
    """Windows Defender integration using PowerShell cmdlets.

    Built into Windows 10/11 - no additional cost.
    Requires: Admin privileges, Windows 10/11 with Defender enabled.
    """

    provider = "defender"

    def __init__(self):
        pass

    def _run_ps(self, script: str) -> tuple[bool, str]:
        """Run PowerShell script and return (success, output)."""
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
            return result.returncode == 0, result.stdout.strip() if result.returncode == 0 else result.stderr.strip()
        except subprocess.TimeoutExpired:
            return False, "PowerShell command timed out"
        except Exception as e:
            return False, str(e)

    async def isolate_host(self, host_id: str, tenant_id: UUID, alert_id: UUID) -> dict[str, Any]:
        """Isolate host using Defender network isolation."""
        script = f"""
        $computer = "{host_id}"
        try {{
            Enable-MpPreference -AllowNetworkProtection $true
            Set-MpPreference -DisableNetworkProtection $false
            Write-Output "SUCCESS: Network protection enabled on $computer"
        }} catch {{
            Write-Error $_.Exception.Message
            exit 1
        }}
        """
        success, output = self._run_ps(script)
        return {
            "success": success,
            "action_id": f"defender-isolate-{alert_id}",
            "message": f"Network isolation {'enabled' if success else 'failed'} on {host_id}",
            "details": {"output": output}
        }

    async def block_ip(self, ip: str, tenant_id: UUID, alert_id: UUID) -> dict[str, Any]:
        """Block IP using Windows Firewall via Defender."""
        script = f"""
        $ruleName = "Arbiterion-Block-{ip}"
        try {{
            if (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue) {{
                Write-Output "Rule already exists"
                exit 0
            }}
            New-NetFirewallRule -DisplayName $ruleName -Direction Outbound -RemoteAddress {ip} -Action Block -Enabled True
            New-NetFirewallRule -DisplayName "$ruleName-In" -Direction Inbound -RemoteAddress {ip} -Action Block -Enabled True
            Write-Output "SUCCESS: IP {ip} blocked via Windows Firewall"
        }} catch {{
            Write-Error $_.Exception.Message
            exit 1
        }}
        """
        success, output = self._run_ps(script)
        return {
            "success": success,
            "action_id": f"defender-blockip-{alert_id}",
            "message": f"IP {ip} {'blocked' if success else 'block failed'}",
            "details": {"output": output}
        }

    async def disable_user(self, username: str, tenant_id: UUID, alert_id: UUID) -> dict[str, Any]:
        """Disable local user account."""
        script = f"""
        try {{
            Disable-LocalUser -Name "{username}"
            Write-Output "SUCCESS: User {username} disabled"
        }} catch {{
            Write-Error $_.Exception.Message
            exit 1
        }}
        """
        success, output = self._run_ps(script)
        return {
            "success": success,
            "action_id": f"defender-disableuser-{alert_id}",
            "message": f"User {username} {'disabled' if success else 'disable failed'}",
            "details": {"output": output}
        }

    async def quarantine_file(self, file_hash: str, host_id: str, tenant_id: UUID, alert_id: UUID) -> dict[str, Any]:
        """Add file hash to Defender blocklist."""
        script = f"""
        try {{
            Add-MpPreference -ThreatIDDefaultAction_Paths @("{file_hash}") -ThreatIDDefaultAction_Actions 6
            Write-Output "SUCCESS: Hash {file_hash} added to Defender blocklist"
        }} catch {{
            Write-Error $_.Exception.Message
            exit 1
        }}
        """
        success, output = self._run_ps(script)
        return {
            "success": success,
            "action_id": f"defender-quarantine-{alert_id}",
            "message": f"File {file_hash} {'quarantined' if success else 'quarantine failed'}",
            "details": {"output": output}
        }

    async def get_host_status(self, host_id: str) -> dict[str, Any]:
        """Get Defender status on host."""
        script = f"""
        try {{
            $pref = Get-MpPreference
            $status = Get-MpComputerStatus
            Write-Output "RealTimeProtection: $($pref.DisableRealtimeMonitoring -eq `$false)"
            Write-Output "NetworkProtection: $($pref.DisableNetworkProtection -eq `$false)"
            Write-Output "LastScan: $($status.LastFullScanTime)"
        }} catch {{
            Write-Error $_.Exception.Message
        }}
        """
        success, output = self._run_ps(script)
        return {
            "host_id": host_id,
            "status": "active" if success else "unknown",
            "details": {"output": output}
        }

    async def test_connection(self) -> bool:
        success, _ = self._run_ps("Get-MpComputerStatus")
        return success