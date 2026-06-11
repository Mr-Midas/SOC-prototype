"""Tests for the pipeline orchestrator with mocked LLM and database.

Covers:
- AI path: LLM returns valid JSON → pipeline uses AI output
- Fallback path: LLM returns empty → pipeline uses deterministic fallback
- No AI configured: api_key missing → pipeline uses deterministic fallback
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch
from uuid import UUID, uuid4

import pytest

from copilot_soc.pipeline.orchestrator import process_alert


@pytest.fixture
def mock_db():
    db = MagicMock()
    # get_alert returns a basic alert with raw_alert
    db.get_alert = AsyncMock(return_value={
        "id": uuid4(),
        "tenant_id": uuid4(),
        "raw_alert": {
            "scenario_id": "ransomware_behavior",
            "affected_user": "jsmith",
            "affected_host": "CORP-LAPTOP-42",
            "source_ip": "10.0.0.55",
            "process_name": "powershell.exe",
        },
    })
    db.update_alert_pipeline = AsyncMock()
    db.get_settings = AsyncMock(return_value={
        "llm_provider": "openai",
        "llm_model": "gpt-4o-mini",
        "llm_api_key": None,  # no AI key → forces fallback
        "use_ai_triage": True,
        "safe_mode": True,
        "min_risk_for_ai": 70,
    })
    return db


@pytest.fixture
def alert_id() -> UUID:
    return uuid4()


@pytest.fixture
def tenant_id() -> UUID:
    return uuid4()


@pytest.mark.asyncio
async def test_pipeline_uses_fallback_when_no_api_key(mock_db, alert_id, tenant_id):
    """No API key configured → deterministic fallback is used for all three agents."""
    result = await process_alert(mock_db, alert_id, tenant_id, mock_db.get_settings.return_value)
    assert result["pipeline_state"] == "completed"
    assert result["manager"]["severity"] == "Critical"
    assert result["manager"]["risk_score"] == 98
    assert result["triage"]["classification"] == "True Positive"
    assert result["containment"]["action_type"] == "Host Isolation"


@pytest.mark.asyncio
async def test_pipeline_fallback_when_ai_returns_empty(mock_db, alert_id, tenant_id):
    """API key present but LLM returns empty string → fallback used."""
    mock_db.get_settings.return_value["llm_api_key"] = "sk-test"
    mock_db.get_settings.return_value["use_ai_triage"] = True

    with patch("copilot_soc.pipeline.orchestrator.call_llm", new=AsyncMock(return_value="")):
        result = await process_alert(mock_db, alert_id, tenant_id, mock_db.get_settings.return_value)
    assert result["pipeline_state"] == "completed"


@pytest.mark.asyncio
async def test_pipeline_uses_ai_when_valid_json_returned(mock_db, alert_id, tenant_id):
    """LLM returns valid JSON → pipeline uses AI outputs."""
    mock_db.get_settings.return_value["llm_api_key"] = "sk-test"
    mock_db.get_settings.return_value["use_ai_triage"] = True

    manager_json = (
        '{"severity":"High","risk_score":75,"routing_rationale":"AI routed",'
        '"triage_focus":["check A","check B"],"notable_entities":["host"]}'
    )
    triage_json = (
        '{"investigation_summary":"AI investigation","confidence_score":90,'
        '"classification":"True Positive","supporting_evidence":["evidence1"]}'
    )
    containment_json = (
        '{"proposed_action":"AI action","action_type":"Custom Action",'
        '"operator_brief":"AI brief","pre_approval_checklist":["check1"]}'
    )

    with patch("copilot_soc.pipeline.orchestrator.call_llm", new=AsyncMock(side_effect=[
        manager_json, triage_json, containment_json,
    ])):
        result = await process_alert(mock_db, alert_id, tenant_id, mock_db.get_settings.return_value)
    assert result["pipeline_state"] == "completed"
    assert result["manager"]["severity"] == "High"
    assert result["manager"]["risk_score"] == 75
    assert result["manager"]["routing_rationale"] == "AI routed"
    assert result["triage"]["classification"] == "True Positive"
    assert result["containment"]["action_type"] == "Custom Action"


@pytest.mark.asyncio
async def test_pipeline_fallback_on_bad_json(mock_db, alert_id, tenant_id):
    """LLM returns invalid JSON → fallback used."""
    mock_db.get_settings.return_value["llm_api_key"] = "sk-test"

    with patch("copilot_soc.pipeline.orchestrator.call_llm", new=AsyncMock(return_value="not json at all")):
        result = await process_alert(mock_db, alert_id, tenant_id, mock_db.get_settings.return_value)
    assert result["pipeline_state"] == "completed"
    # fallback values for ransomware scenario
    assert result["manager"]["severity"] == "Critical"


@pytest.mark.asyncio
async def test_pipeline_fallback_when_ai_off(mock_db, alert_id, tenant_id):
    """use_ai_triage=False → always use fallback even with API key present."""
    mock_db.get_settings.return_value["llm_api_key"] = "sk-test"
    mock_db.get_settings.return_value["use_ai_triage"] = False

    with patch("copilot_soc.pipeline.orchestrator.call_llm") as mock_llm:
        result = await process_alert(mock_db, alert_id, tenant_id, mock_db.get_settings.return_value)
        mock_llm.assert_not_called()
    assert result["pipeline_state"] == "completed"


@pytest.mark.asyncio
async def test_pipeline_alert_not_found(mock_db, alert_id, tenant_id):
    """If alert vanishes between ingestion and pipeline run, return error."""
    mock_db.get_alert = AsyncMock(return_value=None)
    result = await process_alert(mock_db, alert_id, tenant_id, mock_db.get_settings.return_value)
    assert "error" in result
    assert result["error"] == "alert not found"
