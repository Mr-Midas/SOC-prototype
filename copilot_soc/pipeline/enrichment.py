"""IP reputation enrichment via AbuseIPDB and AlienVault OTX.

Ported from the legacy app.py enrichment logic. Provides real HTTP lookups
when API keys are configured, with graceful degradation when keys are absent.
"""

from __future__ import annotations

import ipaddress
import os
from typing import Any, Optional

try:
    import httpx
except ImportError:
    httpx = None  # type: ignore[assignment]


def _is_public_ip(ip: str) -> bool:
    """Return True if the IP is routable (not private/reserved)."""
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_global and not addr.is_private
    except ValueError:
        return False


def _lookup_abuseipdb(ip: str, api_key: str) -> dict[str, Any]:
    """Query AbuseIPDB v2 /check endpoint."""
    if not api_key or not httpx:
        return {}
    try:
        resp = httpx.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": "90"},
            timeout=15.0,
        )
        resp.raise_for_status()
        data = resp.json().get("data", {})
        return {
            "abuseConfidenceScore": data.get("abuseConfidenceScore", 0),
            "totalReports": data.get("totalReports", 0),
            "usageType": data.get("usageType", "Unknown"),
            "countryCode": data.get("countryCode", ""),
            "isp": data.get("isp", ""),
            "domain": data.get("domain", ""),
            "isPublic": data.get("isPublic", True),
        }
    except Exception:
        return {}


def _lookup_otx(ip: str, api_key: str) -> dict[str, Any]:
    """Query AlienVault OTX general indicator endpoint."""
    if not api_key or not httpx:
        return {}
    try:
        resp = httpx.get(
            f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
            headers={"X-OTX-API-KEY": api_key},
            timeout=15.0,
        )
        resp.raise_for_status()
        data = resp.json()
        return {
            "reputation": data.get("reputation", 0),
            "pulse_count": data.get("pulse_count", 0),
            "country_name": data.get("country_name", ""),
            "validation": [v.get("name", "") for v in data.get("validation", [])[:5]],
        }
    except Exception:
        return {}


def _summarize_enrichments(enrichments: dict[str, Any]) -> str:
    """Build a human-readable summary string from enrichment results."""
    parts = []
    abuse = enrichments.get("abuseipdb", {})
    if abuse:
        score = abuse.get("abuseConfidenceScore", 0)
        reports = abuse.get("totalReports", 0)
        usage = abuse.get("usageType", "Unknown")
        country = abuse.get("countryCode", "")
        parts.append(f"AbuseIPDB: score={score}/100, reports={reports}, type={usage}, country={country}")
    otx = enrichments.get("otx", {})
    if otx:
        rep = otx.get("reputation", 0)
        pulses = otx.get("pulse_count", 0)
        country = otx.get("country_name", "")
        parts.append(f"OTX: reputation={rep}, pulses={pulses}, country={country}")
    return "; ".join(parts) if parts else "No threat intel data"


async def enrich_alert(raw_alert: dict[str, Any], settings: dict[str, Any]) -> dict[str, Any]:
    """Enrich a raw alert with IP reputation data.

    Mutates raw_alert in-place by adding an 'enrichment' key.
    Returns the enriched dict for convenience.
    """
    if not settings.get("threat_intel_enabled", False):
        raw_alert["enrichment"] = {"skipped": True, "reason": "threat_intel_disabled"}
        return raw_alert

    source_ip = raw_alert.get("source_ip") or raw_alert.get("metadata", {}).get("source_ip")
    if not source_ip or not _is_public_ip(source_ip):
        raw_alert["enrichment"] = {
            "skipped": True,
            "reason": "no_public_ip",
            "ip": source_ip,
        }
        return raw_alert

    abuse_key = os.environ.get("ABUSEIPDB_API_KEY", "").strip()
    otx_key = os.environ.get("OTX_API_KEY", "").strip()

    enrichments: dict[str, Any] = {}
    if abuse_key:
        enrichments["abuseipdb"] = _lookup_abuseipdb(source_ip, abuse_key)
    if otx_key:
        enrichments["otx"] = _lookup_otx(source_ip, otx_key)

    raw_alert["enrichment"] = {
        "ip": source_ip,
        "results": enrichments,
        "summary": _summarize_enrichments(enrichments),
        "skipped": False,
    }
    return raw_alert
