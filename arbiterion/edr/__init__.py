"""EDR Client Factory for Arbiterion.
Allows switching between different EDR providers (Defender, Wazuh, etc.) via settings.
"""

from __future__ import annotations
from typing import Any
from uuid import UUID

from arbiterion.edr.base import EdrClient
from arbiterion.edr.defender import DefenderClient
from arbiterion.edr.wazuh import WazuhClient

def get_edr_client(provider: str) -> EdrClient:
    """Return an instance of the requested EDR client."""
    provider = provider.lower().strip()
    
    if provider == "defender":
        return DefenderClient()
    elif provider == "wazuh":
        # Note: WazuhClient requires API keys/secrets usually passed via env or settings
        return WazuhClient()
    else:
        # Default to Defender for MVP as it's built-in
        return DefenderClient()
