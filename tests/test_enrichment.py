"""Tests for the IP reputation enrichment module."""

import os
import pytest
from unittest.mock import patch, MagicMock

from arbiterion.pipeline.enrichment import (
    _is_public_ip,
    _summarize_enrichments,
    enrich_alert,
)


class TestIsPublicIp:
    def test_public_ip(self):
        assert _is_public_ip("8.8.8.8") is True

    def test_private_ip(self):
        assert _is_public_ip("192.168.1.1") is False

    def test_loopback(self):
        assert _is_public_ip("127.0.0.1") is False

    def test_invalid(self):
        assert _is_public_ip("not-an-ip") is False

    def test_cloudflare(self):
        assert _is_public_ip("1.1.1.1") is True

    def test_reserved(self):
        assert _is_public_ip("10.0.0.1") is False


class TestSummarizeEnrichments:
    def test_empty(self):
        assert _summarize_enrichments({}) == "No threat intel data"

    def test_abuseipdb_only(self):
        data = {"abuseipdb": {"abuseConfidenceScore": 85, "totalReports": 120, "usageType": "Data Center", "countryCode": "US"}}
        result = _summarize_enrichments(data)
        assert "AbuseIPDB" in result
        assert "85" in result

    def test_otx_only(self):
        data = {"otx": {"reputation": -3, "pulse_count": 5, "country_name": "Russia"}}
        result = _summarize_enrichments(data)
        assert "OTX" in result
        assert "Russia" in result

    def test_both(self):
        data = {
            "abuseipdb": {"abuseConfidenceScore": 50, "totalReports": 10, "usageType": "ISP", "countryCode": "DE"},
            "otx": {"reputation": 0, "pulse_count": 1, "country_name": "Germany"},
        }
        result = _summarize_enrichments(data)
        assert "AbuseIPDB" in result
        assert "OTX" in result


class TestEnrichAlert:
    @pytest.mark.asyncio
    async def test_skips_when_disabled(self):
        raw = {"source_ip": "8.8.8.8"}
        result = await enrich_alert(raw, {"threat_intel_enabled": False})
        assert result["enrichment"]["skipped"] is True
        assert result["enrichment"]["reason"] == "threat_intel_disabled"

    @pytest.mark.asyncio
    async def test_skips_private_ip(self):
        raw = {"source_ip": "192.168.1.1"}
        result = await enrich_alert(raw, {"threat_intel_enabled": True})
        assert result["enrichment"]["skipped"] is True
        assert result["enrichment"]["reason"] == "no_public_ip"

    @pytest.mark.asyncio
    async def test_skips_no_ip(self):
        raw = {"telemetry": ["some data"]}
        result = await enrich_alert(raw, {"threat_intel_enabled": True})
        assert result["enrichment"]["skipped"] is True

    @pytest.mark.asyncio
    async def test_calls_abuseipdb_with_key(self):
        raw = {"source_ip": "8.8.8.8"}
        settings = {"threat_intel_enabled": True}

        with patch.dict(os.environ, {"ABUSEIPDB_API_KEY": "test-key-123", "OTX_API_KEY": ""}):
            with patch("arbiterion.pipeline.enrichment._lookup_abuseipdb") as mock_lookup:
                mock_lookup.return_value = {"abuseConfidenceScore": 90, "totalReports": 500, "usageType": "Data Center", "countryCode": "US"}
                result = await enrich_alert(raw, settings)
                mock_lookup.assert_called_once_with("8.8.8.8", "test-key-123")
                assert result["enrichment"]["results"]["abuseipdb"]["abuseConfidenceScore"] == 90

    @pytest.mark.asyncio
    async def test_calls_otx_with_key(self):
        raw = {"source_ip": "1.1.1.1"}
        settings = {"threat_intel_enabled": True}

        with patch.dict(os.environ, {"ABUSEIPDB_API_KEY": "", "OTX_API_KEY": "otx-key-456"}):
            with patch("arbiterion.pipeline.enrichment._lookup_otx") as mock_lookup:
                mock_lookup.return_value = {"reputation": -5, "pulse_count": 10, "country_name": "Australia"}
                result = await enrich_alert(raw, settings)
                mock_lookup.assert_called_once_with("1.1.1.1", "otx-key-456")
                assert result["enrichment"]["results"]["otx"]["reputation"] == -5

    @pytest.mark.asyncio
    async def test_no_keys_skips_lookup(self):
        raw = {"source_ip": "8.8.8.8"}
        settings = {"threat_intel_enabled": True}

        with patch.dict(os.environ, {"ABUSEIPDB_API_KEY": "", "OTX_API_KEY": ""}):
            result = await enrich_alert(raw, settings)
            assert result["enrichment"]["skipped"] is False
            assert result["enrichment"]["results"] == {}

