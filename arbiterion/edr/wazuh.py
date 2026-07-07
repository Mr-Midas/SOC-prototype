"""Wazuh EDR integration - free, open source with active response."""

from __future__ import annotations

import base64
import os
from datetime import datetime
from typing import Any
from uuid import UUID

import httpx

from arbiterion.edr.base import EdrClient


class WazuhClient(EdrClient):
    """Wazuh EDR integration using the REST API.

    Wazuh is free, open source, and has active response capabilities.
    Requires: Wazuh manager running with API enabled.
    """

    provider = "wazuh"

    def __init__(
        self,
        api_url: str,
        username: str,
        password: str,
        verify_ssl: bool = False,
    ):
        self.api_url = api_url.rstrip("/")
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self._token: str | None = None
        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=self.api_url,
                verify=self.verify_ssl,
                timeout=30.0,
            )
        return self._client

    async def _authenticate(self) -> str:
        """Get or refresh JWT token."""
        if self._token:
            return self._token

        client = await self._get_client()
        resp = await client.post(
            "/security/user/authenticate",
            auth=(self.username, self.password),
        )
        resp.raise_for_status()
        data = resp.json()
        self._token = data.get("data", {}).get("token")
        if not self._token:
            raise RuntimeError("Failed to get Wazuh token")
        return self._token

    async def _request(self, method: str, endpoint: str, **kwargs) -> dict[str, Any]:
        token = await self._authenticate()
        client = await self._get_client()
        headers = kwargs.pop("headers", {})
        headers["Authorization"] = f"Bearer {self._token}"
        resp = await client.request(method, endpoint, headers=headers, **kwargs)
        if resp.status_code == 401:
            self._token = None
            token = await self._authenticate()
            headers["Authorization"] = f"Bearer {self._token}"
            resp = await client.request(method, endpoint, headers=headers, **kwargs)
        resp.raise_for_status()
        return resp.json()

    async def isolate_host(self, host_id: str, tenant_id: UUID, alert_id: UUID) -> dict[str, Any]:
        """Isolate host using Wazuh active response - firewall-drop."""
        result = await self._request(
            "PUT",
            f"/active-response/agent/{host_id}/firewall-drop",
            json={"alert_id": str(alert_id)},
        )
        return {"success": True, "action_id": result.get("data", {}).get("id"), "message": f"Host {host_id} isolated via firewall-drop", "details": result}

    async def block_ip(self, ip: str, tenant_id: UUID, alert_id: UUID) -> dict[str, Any]:
        """Block IP using Wazuh active response - firewall-drop on all agents."""
        result = await self._request(
            "PUT",
            "/active-response/global/firewall-drop",
            json={"ip": ip, "alert_id": str(alert_id)},
        )
        return {"success": True, "action_id": result.get("data", {}).get("id"), "message": f"IP {ip} blocked globally", "details": result}

    async def disable_user(self, username: str, tenant_id: UUID, alert_id: UUID) -> dict[str, Any]:
        """Disable user via Wazuh active response - user-disable (Linux) or custom script."""
        result = await self._request(
            "POST",
            "/active-response/custom",
            json={
                "command": "disable-account",
                "arguments": [username],
                "alert_id": str(alert_id),
            },
        )
        return {"success": True, "action_id": result.get("data", {}).get("id"), "message": f"User {username} disabled", "details": result}

    async def quarantine_file(self, file_hash: str, host_id: str, tenant_id: UUID, alert_id: UUID) -> dict[str, Any]:
        """Quarantine file using Wazuh active response - remove-threat."""
        result = await self._request(
            "PUT",
            f"/active-response/agent/{host_id}/remove-threat",
            json={"hash": file_hash, "alert_id": str(alert_id)},
        )
        return {"success": True, "action_id": result.get("data", {}).get("id"), "message": f"File {file_hash} quarantined on {host_id}", "details": result}

    async def get_host_status(self, host_id: str) -> dict[str, Any]:
        """Get agent status from Wazuh."""
        result = await self._request("GET", f"/agents/{host_id}")
        data = result.get("data", {})
        return {
            "host_id": host_id,
            "status": data.get("status", "unknown"),
            "isolated": False,
            "last_seen": data.get("last_keep_alive"),
            "ip": data.get("ip"),
            "os": data.get("os", {}).get("name"),
        }

    async def test_connection(self) -> bool:
        try:
            await self._authenticate()
            return True
        except Exception:
            return False

    async def close(self):
        if self._client:
            await self._client.aclose()
            self._client = None


def get_wazuh_client_from_settings(settings: dict[str, Any]) -> WazuhClient | None:
    """Create Wazuh client from tenant settings."""
    edr_config = settings.get("edr_config", {})
    if not edr_config:
        return None
    return WazuhClient(
        api_url=edr_config.get("api_url", "https://localhost:55000"),
        username=edr_config.get("username", "wazuh"),
        password=edr_config.get("password", ""),
        verify_ssl=edr_config.get("verify_ssl", False),
    )