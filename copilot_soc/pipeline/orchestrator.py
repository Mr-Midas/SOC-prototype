"""Alert pipeline orchestrator — coordinates the 3-agent chain.

For every ingested alert the orchestrator:
  1. Runs the Manager agent (classify + severity score)
  2. Runs the Triage agent (investigation + confidence)
  3. Runs the Containment agent (action plan + checklist)

Each step tries the AI model first (via LiteLLM), then falls back to
deterministic logic.  The entire pipeline runs inside a Celery task so
the ingestion endpoint returns HTTP 202 without blocking.
"""

from __future__ import annotations

import json
from typing import Any, Optional
from uuid import UUID

import structlog

from copilot_soc.db.postgres import Database
from copilot_soc.llm.client import call_llm, resolve_model_key
from copilot_soc.models import (
    ContainmentPlan,
    ManagerDecision,
    ReasoningStep,
    TriageFinding,
)
from copilot_soc.pipeline.fallback import (
    fallback_containment,
    fallback_manager,
    fallback_triage,
)
from copilot_soc.pipeline.state_machine import PipelineState, StateMachine, run_with_retry

logger = structlog.get_logger()

MANAGER_PROMPT = """You are the Manager Agent inside an Agentic Security Operations Center.
Read the incoming alert and decide how severe it is before routing it to the Triage Worker.
Return valid JSON only with exactly these keys:
- severity: one of Low, Medium, High, Critical
- risk_score: integer from 0 to 100
- routing_rationale: short SOC-focused explanation
- triage_focus: array of 2 to 4 concrete investigative priorities
- notable_entities: array of usernames, hosts, IPs, or artifacts that deserve attention
Keep the explanation concise, practical, and defensible for a human operator."""

TRIAGE_PROMPT = """You are the Triage Worker inside an Agentic Security Operations Center.
Use the raw alert and the Manager Agent output to produce a short investigative assessment.
Return valid JSON only with exactly these keys:
- investigation_summary: a 2 to 3 sentence summary
- confidence_score: integer from 0 to 100 representing confidence in the classification
- classification: one of True Positive, False Positive, Needs More Data
- supporting_evidence: array of 2 to 4 concrete observations
Your summary should sound like a senior SOC analyst writing a fast case note."""

CONTAINMENT_PROMPT = """You are the Containment Worker inside an Agentic Security Operations Center.
Recommend a specific action that a human Tier 4 Governor could approve.
Return valid JSON only with exactly these keys:
- proposed_action: the precise containment or remediation command in plain English
- action_type: short category such as Host Isolation, Identity Containment, or Network Blocking
- operator_brief: 1 to 2 sentences explaining why the action is the safest next move
- pre_approval_checklist: array of 2 to 4 checks the human should confirm before approving
Optimize for least-privilege containment that still meaningfully reduces risk."""


async def _run_agent(
    agent_name: str,
    prompt: str,
    payload: dict[str, Any],
    model_key: str,
    api_key: Optional[str],
) -> Optional[str]:
    return await call_llm(
        model_key=model_key,
        system_prompt=prompt,
        user_payload=payload,
        api_key=api_key,
    )


def _parse_json_response(raw: Optional[str], model_type: type) -> Optional[Any]:
    if not raw:
        return None
    try:
        data = json.loads(raw)
        return model_type.model_validate(data)
    except Exception:
        return None


async def process_alert(
    db: Database,
    alert_id: UUID,
    tenant_id: UUID,
    settings: dict[str, Any],
) -> dict[str, Any]:
    state_machine = StateMachine()
    sm = state_machine  # shorthand
    reasoning_log: list[dict[str, Any]] = []
    llm_provider = settings.get("llm_provider", "openai")
    llm_model = settings.get("llm_model", "gpt-4o-mini")
    api_key = settings.get("llm_api_key")
    use_ai = bool(api_key) and settings.get("use_ai_triage", True) is True
    model_key = resolve_model_key(llm_provider, llm_model)

    alert = await db.get_alert(alert_id, tenant_id)
    if not alert:
        logger.error("alert_not_found", alert_id=str(alert_id))
        return {"error": "alert not found"}

    raw_alert = alert.get("raw_alert") or {}
    if isinstance(raw_alert, str):
        raw_alert = json.loads(raw_alert)

    from copilot_soc.pipeline.enrichment import enrich_alert
    raw_alert = await enrich_alert(raw_alert, settings)
    if raw_alert.get("enrichment", {}).get("summary"):
        logger.info("ip_enrichment", alert_id=str(alert_id), summary=raw_alert["enrichment"]["summary"])

    min_risk_for_ai = int(settings.get("min_risk_for_ai", 70))

    # ── Step 1: Manager / Classify ─────────────────────────────
    sm.transition_to(PipelineState.CLASSIFYING)
    await db.update_alert_pipeline(alert_id, tenant_id, pipeline_state="classifying")

    manager_fb = fallback_manager(raw_alert)
    manager = manager_fb
    ai_used = False

    if use_ai and raw_alert.get("scenario_id") != "endpoint_sample":
        raw_text, ok = await run_with_retry(
            _run_agent,
            args=("Manager", MANAGER_PROMPT, raw_alert, model_key, api_key),
            kwargs={},
        )
        if ok:
            parsed = _parse_json_response(raw_text, ManagerDecision)
            if parsed:
                manager = parsed
                ai_used = True

    reasoning_log.append({
        "stage": "Manager Agent",
        "agent_role": "Router / Severity Scorer",
        "summary": manager.routing_rationale,
        "output": manager.model_dump(),
    })

    if ai_used and manager.risk_score < min_risk_for_ai:
        ai_used = False

    await db.update_alert_pipeline(
        alert_id, tenant_id,
        pipeline_state="classifying",
        manager_output=manager.model_dump(),
        severity=manager.severity,
        risk_score=manager.risk_score,
        reasoning_log=reasoning_log,
    )

    # ── Step 2: Triage ─────────────────────────────────────────
    sm.transition_to(PipelineState.TRIAGING)
    await db.update_alert_pipeline(alert_id, tenant_id, pipeline_state="triaging")

    triage = fallback_triage(raw_alert, manager)
    if ai_used:
        triage_payload = {"raw_alert": raw_alert, "manager_output": manager.model_dump()}
        raw_text, ok = await run_with_retry(
            _run_agent,
            args=("Triage", TRIAGE_PROMPT, triage_payload, model_key, api_key),
            kwargs={},
        )
        if ok:
            parsed = _parse_json_response(raw_text, TriageFinding)
            if parsed:
                triage = parsed

    reasoning_log.append({
        "stage": "Triage Worker",
        "agent_role": "Investigator / Evidence Reviewer",
        "summary": triage.investigation_summary,
        "output": triage.model_dump(),
    })

    await db.update_alert_pipeline(
        alert_id, tenant_id,
        pipeline_state="triaging",
        triage_output=triage.model_dump(),
        classification=triage.classification,
        reasoning_log=reasoning_log,
    )

    # ── Step 3: Containment ────────────────────────────────────
    sm.transition_to(PipelineState.PLANNING)
    await db.update_alert_pipeline(alert_id, tenant_id, pipeline_state="planning")

    containment = fallback_containment(raw_alert, manager, triage)
    if ai_used:
        plan_payload = {
            "raw_alert": raw_alert,
            "manager_output": manager.model_dump(),
            "triage_output": triage.model_dump(),
        }
        raw_text, ok = await run_with_retry(
            _run_agent,
            args=("Containment", CONTAINMENT_PROMPT, plan_payload, model_key, api_key),
            kwargs={},
        )
        if ok:
            parsed = _parse_json_response(raw_text, ContainmentPlan)
            if parsed:
                containment = parsed

    reasoning_log.append({
        "stage": "Containment Worker",
        "agent_role": "Responder / Containment Planner",
        "summary": containment.operator_brief,
        "output": containment.model_dump(),
    })

    reasoning_log.append({
        "stage": "Token Policy",
        "agent_role": "Cost Guardrail",
        "summary": "Live model inference was used." if ai_used else "Fallback reasoning used.",
        "output": {"ai_used": ai_used, "min_risk_for_ai": min_risk_for_ai},
    })

    # ── Complete ───────────────────────────────────────────────
    sm.transition_to(PipelineState.COMPLETED)
    await db.update_alert_pipeline(
        alert_id, tenant_id,
        pipeline_state="completed",
        containment_output=containment.model_dump(),
        reasoning_log=reasoning_log,
    )

    logger.info(
        "pipeline_completed",
        alert_id=str(alert_id),
        tenant_id=str(tenant_id),
        severity=manager.severity,
        risk_score=manager.risk_score,
        classification=triage.classification,
        action=containment.action_type,
        ai_used=ai_used,
    )

    return {
        "id": str(alert_id),
        "pipeline_state": "completed",
        "manager": manager.model_dump(),
        "triage": triage.model_dump(),
        "containment": containment.model_dump(),
    }
