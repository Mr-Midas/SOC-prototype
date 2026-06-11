"""Pydantic models for Copilot SOC — shared data contracts across all layers."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal, Optional
from uuid import UUID

from pydantic import BaseModel, Field

SeverityLevel = Literal["Low", "Medium", "High", "Critical"]
Classification = Literal["True Positive", "False Positive", "Needs More Data"]
GovernorStatus = Literal["pending", "approved", "rejected"]
PipelineState = Literal[
    "queued", "classifying", "classifying_failed",
    "triaging", "triaging_failed",
    "planning", "planning_failed",
    "completed", "failed",
]


class ManagerDecision(BaseModel):
    severity: SeverityLevel
    risk_score: int = Field(ge=0, le=100)
    routing_rationale: str
    triage_focus: list[str]
    notable_entities: list[str]


class TriageFinding(BaseModel):
    investigation_summary: str
    confidence_score: int = Field(ge=0, le=100)
    classification: Classification
    supporting_evidence: list[str]


class ContainmentPlan(BaseModel):
    proposed_action: str
    action_type: str
    operator_brief: str
    pre_approval_checklist: list[str]


class GovernorDecision(BaseModel):
    status: GovernorStatus = "pending"
    operator_note: Optional[str] = None
    decided_at: Optional[datetime] = None
    decided_by: Optional[str] = None


class ReasoningStep(BaseModel):
    stage: str
    agent_role: str
    summary: str
    output: dict[str, Any]


class AlertResponse(BaseModel):
    id: UUID
    tenant_id: UUID
    source: str
    rule_name: str
    summary: str
    severity: Optional[str] = None
    risk_score: Optional[int] = None
    classification: Optional[str] = None
    pipeline_state: PipelineState = "queued"
    governor_status: GovernorStatus = "pending"
    manager_output: Optional[ManagerDecision] = None
    triage_output: Optional[TriageFinding] = None
    containment_output: Optional[ContainmentPlan] = None
    reasoning_log: list[ReasoningStep] = []
    governor_decision: Optional[GovernorDecision] = None
    created_at: datetime
    updated_at: datetime


class IngestionRequest(BaseModel):
    source: str = Field(default="External Webhook", min_length=1, max_length=80)
    rule_name: str = Field(min_length=3, max_length=160)
    summary: str = Field(min_length=10, max_length=600)
    severity: Optional[SeverityLevel] = None
    mitre_tactic: str = Field(default="Unknown", max_length=80)
    scenario_id: str = Field(default="external_detection", max_length=80)
    affected_user: Optional[str] = Field(default=None, max_length=120)
    affected_host: Optional[str] = Field(default=None, max_length=120)
    source_ip: Optional[str] = Field(default=None, max_length=80)
    indicators: list[str] = Field(default_factory=list, max_length=25)
    telemetry: list[str] = Field(default_factory=list, max_length=25)
    metadata: dict[str, Any] = Field(default_factory=dict)


class DecisionRequest(BaseModel):
    decision: Literal["approve", "reject"]
    operator_note: Optional[str] = Field(default=None, max_length=400)


class LoginRequest(BaseModel):
    email: str = Field(min_length=5, max_length=120)
    password: str = Field(min_length=8, max_length=200)


class TenantSettingsResponse(BaseModel):
    llm_provider: str = "openai"
    llm_model: str = "gpt-4o-mini"
    safe_mode: bool = True
    use_ai_triage: bool = True
    threat_intel_enabled: bool = False
    sample_events_enabled: bool = True
    webhook_secret: Optional[str] = None


class TenantSettingsUpdate(BaseModel):
    llm_provider: Optional[str] = None
    llm_model: Optional[str] = None
    safe_mode: Optional[bool] = None
    use_ai_triage: Optional[bool] = None
    threat_intel_enabled: Optional[bool] = None
    sample_events_enabled: Optional[bool] = None
    llm_api_key: Optional[str] = None
    webhook_secret: Optional[str] = None
