"""Base EDR client interface."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any
from uuid import UUID


class EdrClient(ABC):
    """Abstract base class for EDR integrations."""

    provider: str

    @abstractmethod
    async def isolate_host(self, host_id: str, tenant_id: UUID, alert_id: UUID) -> dict[str, Any]:
        """Isolate a host from the network."""
        pass

    @abstractmethod
    async def block_ip(self, ip: str, tenant_id: UUID, alert_id: UUID) -> dict[str, Any]:
        """Block an IP address at the EDR level."""
        pass

    @abstractmethod
    async def disable_user(self, username: str, tenant_id: UUID, alert_id: UUID) -> dict[str, Any]:
        """Disable a user account."""
        pass

    @abstractmethod
    async def quarantine_file(self, file_hash: str, host_id: str, tenant_id: UUID, alert_id: UUID) -> dict[str, Any]:
        """Quarantine a file by hash."""
        pass

    @abstractmethod
    async def get_host_status(self, host_id: str) -> dict[str, Any]:
        """Get current status of a host."""
        pass

    @abstractmethod
    async def test_connection(self) -> bool:
        """Test if the EDR API is reachable and authenticated."""
        pass


class MockEdrClient(EdrClient):
    """Mock EDR client for testing/development - logs actions but doesn't execute."""

    provider = "mock"

    def __init__(self, log_actions: bool = True):
        self.log_actions = log_actions
        self._actions_log: list[dict[str, Any]] = []

    def _log(self, action: str, **kwargs) -> dict[str, Any]:
        entry = {"action": action, "timestamp": datetime.utcnow().isoformat(), **kwargs}
        self._actions_log.append(entry)
        if self.log_actions:
            print(f"[MOCK EDR] {action}: {kwargs}")
        return {"success": True, "action_id": f"mock-{len(self._actions_log)}", "message": f"Mock {action} logged", "details": entry}


    async def isolate_host(self, host_id: str, tenant_id: UUID, alert_id: UUID) -> dict[str, Any]:
        return self._log("isolate_host", host_id=host_id, tenant_id=str(tenant_id), alert_id=str(alert_id))

    async def block_ip(self, ip: str, tenant_id: UUID, alert_id: UUID) -> dict[str, Any]:
        return self._log("block_ip", ip=ip, tenant_id=str(tenant_id), alert_id=str(alert_id))

    async def disable_user(self, username: str, tenant_id: UUID, alert_id: UUID) -> dict[str, Any]:
        return self._log("disable_user", username=username, tenant_id=str(tenant_id), alert_id=str(alert_id))

    async def quarantine_file(self, file_hash: str, host_id: str, tenant_id: UUID, alert_id: UUID) -> dict[str, Any]:
        return self._log("quarantine_file", file_hash=file_hash, host_id=host_id, tenant_id=str(tenant_id), alert_id=str(alert_id))

    async def get_host_status(self, host_id: str) -> dict[str, Any]:
        return {"host_id": host_id, "status": "active", "isolated": False, "last_seen": datetime.utcnow().isoformat()}

    async def test_connection(self) -> bool:
        return True

    def get_actions_log(self) -> list[dict[str, Any]]:
        return self._actions_log


from datetime import datetime