from __future__ import annotations

import asyncio
import json
import os
import random
import uuid
from contextlib import asynccontextmanager, suppress
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal, Optional

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field, ValidationError

OPENAI_IMPORT_ERROR: Optional[Exception] = None

try:
    from openai import OpenAI
except Exception as exc:  # pragma: no cover - keeps the prototype runnable without the SDK installed
    OpenAI = None  # type: ignore[assignment]
    OPENAI_IMPORT_ERROR = exc


BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

SeverityLevel = Literal["Low", "Medium", "High", "Critical"]
Classification = Literal["True Positive", "False Positive", "Needs More Data"]
GovernorStatus = Literal["Pending Approval", "Approved", "Rejected"]


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
    status: GovernorStatus = "Pending Approval"
    operator_note: Optional[str] = None
    decided_at: Optional[datetime] = None


class ReasoningStep(BaseModel):
    stage: str
    agent_role: str
    summary: str
    output: dict[str, Any]


class AlertRecord(BaseModel):
    id: str
    created_at: datetime
    trigger: str
    source: str
    scenario_id: str
    rule_name: str
    summary: str
    mitre_tactic: str
    affected_user: Optional[str] = None
    affected_host: Optional[str] = None
    source_ip: Optional[str] = None
    indicators: list[str]
    telemetry: list[str]
    manager: ManagerDecision
    triage: TriageFinding
    containment: ContainmentPlan
    governor: GovernorDecision = Field(default_factory=GovernorDecision)
    reasoning_log: list[ReasoningStep]
    raw_alert: dict[str, Any]


class DecisionRequest(BaseModel):
    decision: Literal["approve", "reject"]
    operator_note: Optional[str] = Field(default=None, max_length=400)


class RuntimeStatus(BaseModel):
    live_ai_mode: bool
    model: str
    auto_generate: bool
    generation_interval_seconds: int
    max_alerts: int


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def env_flag(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


class AgenticSOCService:
    def __init__(self) -> None:
        self.model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
        self.auto_generate = env_flag("ENABLE_AUTO_ALERTS", True)
        self.generation_interval_seconds = max(15, int(os.getenv("ALERT_INTERVAL_SECONDS", "45")))
        self.max_alerts = max(10, int(os.getenv("MAX_STORED_ALERTS", "40")))
        self.client = self._build_openai_client()
        self.alerts: list[AlertRecord] = []
        self.lock = asyncio.Lock()
        self.generator_task: Optional[asyncio.Task[None]] = None

    def _build_openai_client(self) -> Any:
        api_key = os.getenv("OPENAI_API_KEY")

        if not api_key:
            print("[CONFIG] OPENAI_API_KEY not found. Running in deterministic fallback mode.")
            return None

        if OpenAI is None:
            print(
                f"[CONFIG] OpenAI SDK unavailable ({OPENAI_IMPORT_ERROR}). "
                "Running in deterministic fallback mode."
            )
            return None

        print(f"[CONFIG] Live OpenAI mode enabled. model={self.model}")
        return OpenAI(api_key=api_key)

    def runtime_status(self) -> RuntimeStatus:
        return RuntimeStatus(
            live_ai_mode=bool(self.client),
            model=self.model,
            auto_generate=self.auto_generate,
            generation_interval_seconds=self.generation_interval_seconds,
            max_alerts=self.max_alerts,
        )

    def frontend_bootstrap(self) -> dict[str, Any]:
        status = self.runtime_status()
        return {
            "liveAiMode": status.live_ai_mode,
            "model": status.model,
            "autoGenerate": status.auto_generate,
            "generationIntervalSeconds": status.generation_interval_seconds,
            "maxAlerts": status.max_alerts,
        }

    async def start(self) -> None:
        print("[APP] Starting Agentic SOC service.")
        if not self.alerts:
            await self.generate_and_store_alert("startup-seed")

        if self.auto_generate and self.generator_task is None:
            self.generator_task = asyncio.create_task(self._generator_loop())
            print(
                f"[APP] Automatic alert generation enabled every "
                f"{self.generation_interval_seconds} seconds."
            )

    async def stop(self) -> None:
        print("[APP] Stopping Agentic SOC service.")
        if self.generator_task:
            self.generator_task.cancel()
            with suppress(asyncio.CancelledError):
                await self.generator_task
            self.generator_task = None

    async def _generator_loop(self) -> None:
        try:
            while True:
                await asyncio.sleep(self.generation_interval_seconds)
                await self.generate_and_store_alert("timer")
        except asyncio.CancelledError:
            print("[APP] Background generator loop cancelled.")
            raise

    async def list_alerts(self) -> list[AlertRecord]:
        async with self.lock:
            return [alert.model_copy(deep=True) for alert in self.alerts]

    async def get_alert(self, alert_id: str) -> AlertRecord:
        async with self.lock:
            for alert in self.alerts:
                if alert.id == alert_id:
                    return alert.model_copy(deep=True)

        raise KeyError(alert_id)

    async def record_decision(self, alert_id: str, payload: DecisionRequest) -> AlertRecord:
        decision_status: GovernorStatus = "Approved" if payload.decision == "approve" else "Rejected"
        decision_summary = (
            "Tier 4 Governor approved the containment action and cleared it for execution."
            if payload.decision == "approve"
            else "Tier 4 Governor rejected the proposed action and sent the case back for analyst review."
        )

        async with self.lock:
            for index, alert in enumerate(self.alerts):
                if alert.id != alert_id:
                    continue

                updated_log = [step for step in alert.reasoning_log if step.stage != "Tier 4 Governor"]
                updated_log.append(
                    ReasoningStep(
                        stage="Tier 4 Governor",
                        agent_role="Human Approval",
                        summary=decision_summary,
                        output={
                            "decision": decision_status,
                            "operator_note": payload.operator_note or "No operator note supplied.",
                            "decided_at": utc_now().isoformat(),
                        },
                    )
                )

                alert.governor = GovernorDecision(
                    status=decision_status,
                    operator_note=payload.operator_note,
                    decided_at=utc_now(),
                )
                alert.reasoning_log = updated_log
                self.alerts[index] = alert

                print(
                    f"[GOVERNOR] alert_id={alert.id} decision={decision_status} "
                    f"note={payload.operator_note or 'n/a'}"
                )
                return alert.model_copy(deep=True)

        raise KeyError(alert_id)

    async def generate_and_store_alert(self, trigger: str) -> AlertRecord:
        raw_alert = self._generate_mock_alert()
        print(
            f"[SIEM] Generated alert_id={raw_alert['alert_id']} "
            f"scenario={raw_alert['scenario_id']} trigger={trigger}"
        )

        processed_alert = await asyncio.to_thread(self._process_alert, raw_alert, trigger)

        async with self.lock:
            self.alerts.insert(0, processed_alert)
            self.alerts = self.alerts[: self.max_alerts]

        return processed_alert.model_copy(deep=True)

    def _process_alert(self, raw_alert: dict[str, Any], trigger: str) -> AlertRecord:
        manager = self._run_manager_agent(raw_alert)
        triage = self._run_triage_worker(raw_alert, manager)
        containment = self._run_containment_worker(raw_alert, manager, triage)

        print(
            f"[PIPELINE] alert_id={raw_alert['alert_id']} severity={manager.severity} "
            f"confidence={triage.confidence_score} action={containment.action_type}"
        )

        return AlertRecord(
            id=raw_alert["alert_id"],
            created_at=datetime.fromisoformat(raw_alert["generated_at"]),
            trigger=trigger,
            source=raw_alert["source"],
            scenario_id=raw_alert["scenario_id"],
            rule_name=raw_alert["rule_name"],
            summary=raw_alert["summary"],
            mitre_tactic=raw_alert["mitre_tactic"],
            affected_user=raw_alert.get("affected_user"),
            affected_host=raw_alert.get("affected_host"),
            source_ip=raw_alert.get("source_ip"),
            indicators=raw_alert["indicators"],
            telemetry=raw_alert["telemetry"],
            manager=manager,
            triage=triage,
            containment=containment,
            reasoning_log=[
                ReasoningStep(
                    stage="Manager Agent",
                    agent_role="Router / Severity Scorer",
                    summary=manager.routing_rationale,
                    output=manager.model_dump(),
                ),
                ReasoningStep(
                    stage="Triage Worker",
                    agent_role="Investigator / Evidence Reviewer",
                    summary=triage.investigation_summary,
                    output=triage.model_dump(),
                ),
                ReasoningStep(
                    stage="Containment Worker",
                    agent_role="Responder / Containment Planner",
                    summary=containment.operator_brief,
                    output=containment.model_dump(),
                ),
            ],
            raw_alert=raw_alert,
        )

    def _run_manager_agent(self, raw_alert: dict[str, Any]) -> ManagerDecision:
        fallback = self._fallback_manager(raw_alert)
        prompt = """
You are the Manager Agent inside an Agentic Security Operations Center.
Read the incoming alert and decide how severe it is before routing it to the Triage Worker.

Return valid JSON only with exactly these keys:
- severity: one of Low, Medium, High, Critical
- risk_score: integer from 0 to 100
- routing_rationale: short SOC-focused explanation
- triage_focus: array of 2 to 4 concrete investigative priorities
- notable_entities: array of usernames, hosts, IPs, or artifacts that deserve attention

Keep the explanation concise, practical, and defensible for a human operator.
"""
        result = self._call_ai_model(
            agent_name="Manager",
            prompt=prompt,
            payload=raw_alert,
            model_class=ManagerDecision,
            fallback=fallback,
        )
        print(
            f"[MANAGER] alert_id={raw_alert['alert_id']} severity={result.severity} "
            f"risk_score={result.risk_score}"
        )
        return result

    def _run_triage_worker(
        self, raw_alert: dict[str, Any], manager: ManagerDecision
    ) -> TriageFinding:
        fallback = self._fallback_triage(raw_alert, manager)
        prompt = """
You are the Triage Worker inside an Agentic Security Operations Center.
Use the raw alert and the Manager Agent output to produce a short investigative assessment.

Return valid JSON only with exactly these keys:
- investigation_summary: a 2 to 3 sentence summary
- confidence_score: integer from 0 to 100 representing confidence in the classification
- classification: one of True Positive, False Positive, Needs More Data
- supporting_evidence: array of 2 to 4 concrete observations

Your summary should sound like a senior SOC analyst writing a fast case note.
"""
        payload = {
            "raw_alert": raw_alert,
            "manager_output": manager.model_dump(),
        }
        result = self._call_ai_model(
            agent_name="Triage",
            prompt=prompt,
            payload=payload,
            model_class=TriageFinding,
            fallback=fallback,
        )
        print(
            f"[TRIAGE] alert_id={raw_alert['alert_id']} classification={result.classification} "
            f"confidence={result.confidence_score}"
        )
        return result

    def _run_containment_worker(
        self,
        raw_alert: dict[str, Any],
        manager: ManagerDecision,
        triage: TriageFinding,
    ) -> ContainmentPlan:
        fallback = self._fallback_containment(raw_alert, manager, triage)
        prompt = """
You are the Containment Worker inside an Agentic Security Operations Center.
Recommend a specific action that a human Tier 4 Governor could approve.

Return valid JSON only with exactly these keys:
- proposed_action: the precise containment or remediation command in plain English
- action_type: short category such as Host Isolation, Identity Containment, or Network Blocking
- operator_brief: 1 to 2 sentences explaining why the action is the safest next move
- pre_approval_checklist: array of 2 to 4 checks the human should confirm before approving

Optimize for least-privilege containment that still meaningfully reduces risk.
"""
        payload = {
            "raw_alert": raw_alert,
            "manager_output": manager.model_dump(),
            "triage_output": triage.model_dump(),
        }
        result = self._call_ai_model(
            agent_name="Containment",
            prompt=prompt,
            payload=payload,
            model_class=ContainmentPlan,
            fallback=fallback,
        )
        print(
            f"[CONTAINMENT] alert_id={raw_alert['alert_id']} action_type={result.action_type} "
            f"proposed_action={result.proposed_action}"
        )
        return result

    def _call_ai_model(
        self,
        *,
        agent_name: str,
        prompt: str,
        payload: dict[str, Any],
        model_class: type[BaseModel],
        fallback: BaseModel,
    ) -> Any:
        if not self.client:
            print(f"[OPENAI:{agent_name}] Live AI unavailable. Using fallback reasoning.")
            return fallback

        try:
            response = self.client.responses.create(
                model=self.model,
                input=[
                    {"role": "developer", "content": prompt},
                    {"role": "user", "content": json.dumps(payload, indent=2)},
                ],
                text={"format": {"type": "json_object"}},
            )

            raw_text = (response.output_text or "").strip()
            print(f"[OPENAI:{agent_name}] raw_response={raw_text}")

            if not raw_text:
                raise ValueError("Model returned an empty response.")

            data = json.loads(raw_text)
            return model_class.model_validate(data)
        except (json.JSONDecodeError, ValidationError, ValueError) as exc:
            print(f"[OPENAI:{agent_name}] Response validation failed: {exc}. Using fallback.")
        except Exception as exc:  # pragma: no cover - external API behavior
            print(f"[OPENAI:{agent_name}] API call failed: {exc}. Using fallback.")

        return fallback

    def _scenario_profile(self, raw_alert: dict[str, Any]) -> dict[str, Any]:
        scenario_id = raw_alert["scenario_id"]
        user = raw_alert.get("affected_user") or "unknown-user"
        host = raw_alert.get("affected_host") or "unknown-host"
        source_ip = raw_alert.get("source_ip") or "unknown-ip"

        profiles: dict[str, dict[str, Any]] = {
            "impossible_travel": {
                "severity": "High",
                "risk_score": 86,
                "confidence_score": 82,
                "classification": "True Positive",
                "routing_rationale": (
                    "The alert shows a successful identity event from geographically distant regions within an "
                    "unrealistic window, which is consistent with account takeover or token abuse."
                ),
                "triage_focus": [
                    "Validate whether MFA was satisfied for both sessions",
                    "Review session revocation and impossible travel suppression history",
                    f"Confirm whether {user} had any approved travel or VPN exception",
                ],
                "notable_entities": [user, source_ip, raw_alert["locations"][0], raw_alert["locations"][1]],
                "investigation_summary": (
                    f"{user} authenticated from {raw_alert['locations'][0]} and {raw_alert['locations'][1]} within "
                    "minutes, making normal travel improbable. No business context is attached to the alert, so the "
                    "activity should be treated as likely credential misuse until the session history is verified."
                ),
                "supporting_evidence": [
                    "Two distant successful logins occurred inside the same identity timeline",
                    "Session locations imply impossible travel without teleporting or proxy chaining",
                    "The alert originated from identity telemetry rather than user-reported activity",
                ],
                "action_type": "Identity Containment",
                "proposed_action": (
                    f"Revoke active sessions for {user}, force password reset, and temporarily block access from "
                    f"{source_ip} pending identity verification."
                ),
                "operator_brief": (
                    "This action reduces account takeover risk while preserving a clear rollback path if the activity "
                    "turns out to be benign travel through a trusted broker."
                ),
                "pre_approval_checklist": [
                    "Confirm whether the user is traveling or using an approved secure access gateway",
                    "Check for other high-risk sign-ins tied to the same user in the last 24 hours",
                    "Ensure the identity team is ready to handle user re-verification",
                ],
            },
            "ransomware_behavior": {
                "severity": "Critical",
                "risk_score": 98,
                "confidence_score": 96,
                "classification": "True Positive",
                "routing_rationale": (
                    "Mass encryption behavior on a production endpoint indicates active impact-stage malware and "
                    "requires immediate host containment."
                ),
                "triage_focus": [
                    f"Confirm whether {host} touched mapped drives or file shares",
                    "Determine if the encryption process spawned from a user context or remote tool",
                    "Validate whether backup or EDR tampering occurred before encryption",
                ],
                "notable_entities": [host, user, raw_alert["process_name"]],
                "investigation_summary": (
                    f"{host} is exhibiting mass file rename and encryption activity from {raw_alert['process_name']}, "
                    "which aligns strongly with ransomware tradecraft. Because the activity is already in the impact "
                    "phase, containment speed matters more than perfect attribution."
                ),
                "supporting_evidence": [
                    "EDR observed rapid sequential file modifications with encrypted extensions",
                    "The process lineage includes a non-standard binary executing from a writable path",
                    "Behavior is destructive and not consistent with patching or backup software",
                ],
                "action_type": "Host Isolation",
                "proposed_action": (
                    f"Immediately isolate {host} from the network, disable the user session for {user}, and block "
                    "the observed ransomware hash across EDR."
                ),
                "operator_brief": (
                    "Isolating the endpoint is the lowest-risk high-impact action because it stops lateral movement "
                    "and further encryption while preserving the host for forensics."
                ),
                "pre_approval_checklist": [
                    "Notify incident command and desktop support before isolation if the asset is business critical",
                    "Confirm whether the host has active server connections that need controlled shutdown",
                    "Snapshot volatile evidence if the EDR platform supports it without delaying containment",
                ],
            },
            "brute_force": {
                "severity": "Medium",
                "risk_score": 68,
                "confidence_score": 74,
                "classification": "True Positive",
                "routing_rationale": (
                    "A concentrated burst of failed authentication attempts against an administrative identity is "
                    "consistent with password spraying or targeted brute force."
                ),
                "triage_focus": [
                    f"Check whether {user} also had successful logins after the failed attempts",
                    "Review whether the source IP appears in any threat intelligence or deny lists",
                    "Determine whether other privileged accounts were targeted in the same window",
                ],
                "notable_entities": [user, source_ip, str(raw_alert["failed_login_count"])],
                "investigation_summary": (
                    f"The alert shows {raw_alert['failed_login_count']} failed sign-in attempts against {user} from "
                    f"{source_ip}, which is above normal error rates and suggests deliberate password guessing. The "
                    "case should stay open until we confirm there was no eventual success from the same source."
                ),
                "supporting_evidence": [
                    "The failed attempts cluster tightly in time from a single origin",
                    "The targeted account carries elevated privileges",
                    "The pattern exceeds a normal human typo rate by a wide margin",
                ],
                "action_type": "Network Blocking",
                "proposed_action": (
                    f"Block {source_ip} at the perimeter, enable a temporary lockout for {user}, and monitor for "
                    "follow-on attempts against adjacent admin accounts."
                ),
                "operator_brief": (
                    "Blocking the source and throttling the account is proportional containment that reduces the chance "
                    "of compromise without unnecessarily isolating systems."
                ),
                "pre_approval_checklist": [
                    "Confirm the source IP is not a corporate NAT or VPN egress point",
                    "Check whether the account is tied to an automation job that would be disrupted",
                    "Verify lockout thresholds will not create a broader availability issue",
                ],
            },
            "suspicious_powershell": {
                "severity": "High",
                "risk_score": 84,
                "confidence_score": 79,
                "classification": "True Positive",
                "routing_rationale": (
                    "Encoded PowerShell launching a remote payload is common post-exploitation behavior and should be "
                    "treated as malicious until proven otherwise."
                ),
                "triage_focus": [
                    "Review the process tree for parent-child execution anomalies",
                    "Check whether the downloaded payload was written to disk or injected in memory",
                    f"Assess whether {host} initiated any suspicious outbound connections after execution",
                ],
                "notable_entities": [host, user, raw_alert["payload_domain"]],
                "investigation_summary": (
                    f"{host} executed an encoded PowerShell command under {user}, followed by traffic to "
                    f"{raw_alert['payload_domain']}. The sequence is consistent with staged malware delivery and "
                    "warrants rapid scoping before the host pivots further into the environment."
                ),
                "supporting_evidence": [
                    "The command line contains base64-encoded arguments",
                    "The process made outbound contact to a previously unseen domain",
                    "Execution occurred outside a sanctioned administrative change window",
                ],
                "action_type": "Host Isolation",
                "proposed_action": (
                    f"Isolate {host}, block the domain {raw_alert['payload_domain']} at the proxy, and suspend "
                    f"{user}'s active session pending review."
                ),
                "operator_brief": (
                    "This contains both the suspected compromised endpoint and the command-and-control channel while "
                    "keeping the response targeted."
                ),
                "pre_approval_checklist": [
                    "Verify the domain is not part of an approved internal automation workflow",
                    "Capture the command line and parent process details for later triage",
                    "Confirm whether the user is currently on a support call performing legitimate remediation",
                ],
            },
            "data_exfiltration": {
                "severity": "Critical",
                "risk_score": 94,
                "confidence_score": 88,
                "classification": "True Positive",
                "routing_rationale": (
                    "A large outbound transfer to an unsanctioned external destination indicates potential data loss "
                    "and should be escalated immediately."
                ),
                "triage_focus": [
                    f"Identify the data owner for the files accessed by {user}",
                    "Confirm whether the destination is an approved partner or shadow IT service",
                    f"Scope any other outbound transfers from {host} in the same period",
                ],
                "notable_entities": [user, host, source_ip, raw_alert["data_volume"]],
                "investigation_summary": (
                    f"{user} initiated an outbound transfer of {raw_alert['data_volume']} from {host} to an "
                    f"unapproved destination at {source_ip}. The size and direction of the flow exceed the profile "
                    "for routine SaaS use, making suspected exfiltration the leading hypothesis."
                ),
                "supporting_evidence": [
                    "Outbound volume is materially above the user's established baseline",
                    "The destination has no allow-list exception in the alert context",
                    "The event correlates with access to sensitive document repositories",
                ],
                "action_type": "Data Loss Containment",
                "proposed_action": (
                    f"Quarantine {host} from high-risk egress, suspend {user}'s access to data repositories, and block "
                    f"the destination {source_ip} until the data owner validates the transfer."
                ),
                "operator_brief": (
                    "The proposed action narrows egress and repository access without forcing an enterprise-wide block, "
                    "which is useful while ownership and business context are still being confirmed."
                ),
                "pre_approval_checklist": [
                    "Confirm the destination is not an approved merger, legal, or finance transfer endpoint",
                    "Coordinate with the data owner before revoking repository access if the user is business critical",
                    "Preserve netflow or proxy evidence for the full transfer timeline",
                ],
            },
            "privilege_escalation": {
                "severity": "High",
                "risk_score": 81,
                "confidence_score": 77,
                "classification": "Needs More Data",
                "routing_rationale": (
                    "Unexpected addition to a privileged group may indicate abuse of administrative rights or a change "
                    "control gap, both of which merit urgent review."
                ),
                "triage_focus": [
                    "Check whether there is a matching change request or service desk ticket",
                    "Validate who performed the group change and from which workstation",
                    f"Review any privileged actions executed by {user} after the elevation",
                ],
                "notable_entities": [user, host, raw_alert["group_name"]],
                "investigation_summary": (
                    f"{user} was added to {raw_alert['group_name']} from {host} without embedded change context. The "
                    "event could be legitimate administration, but the lack of a ticket reference means we should "
                    "treat it as suspicious until the actor and purpose are verified."
                ),
                "supporting_evidence": [
                    "Privileged group membership changed outside the normal approval trail",
                    "The originating workstation is included as a relevant investigation pivot",
                    "The alert has impact potential even if the change later proves authorized",
                ],
                "action_type": "Privilege Revocation",
                "proposed_action": (
                    f"Temporarily remove {user} from {raw_alert['group_name']}, keep {host} under heightened "
                    "monitoring, and require change owner validation before restoring privileges."
                ),
                "operator_brief": (
                    "Temporary privilege rollback reduces risk quickly while keeping the response reversible if the "
                    "change turns out to be legitimate."
                ),
                "pre_approval_checklist": [
                    "Confirm whether the group change aligns with an emergency maintenance window",
                    "Check whether removing the role would break production support obligations",
                    "Identify the administrator who performed the change for verbal validation",
                ],
            },
        }

        return profiles[scenario_id]

    def _fallback_manager(self, raw_alert: dict[str, Any]) -> ManagerDecision:
        profile = self._scenario_profile(raw_alert)
        return ManagerDecision(
            severity=profile["severity"],
            risk_score=profile["risk_score"],
            routing_rationale=profile["routing_rationale"],
            triage_focus=profile["triage_focus"],
            notable_entities=profile["notable_entities"],
        )

    def _fallback_triage(
        self, raw_alert: dict[str, Any], manager: ManagerDecision
    ) -> TriageFinding:
        profile = self._scenario_profile(raw_alert)
        return TriageFinding(
            investigation_summary=profile["investigation_summary"],
            confidence_score=profile["confidence_score"],
            classification=profile["classification"],
            supporting_evidence=profile["supporting_evidence"],
        )

    def _fallback_containment(
        self,
        raw_alert: dict[str, Any],
        manager: ManagerDecision,
        triage: TriageFinding,
    ) -> ContainmentPlan:
        profile = self._scenario_profile(raw_alert)
        return ContainmentPlan(
            proposed_action=profile["proposed_action"],
            action_type=profile["action_type"],
            operator_brief=profile["operator_brief"],
            pre_approval_checklist=profile["pre_approval_checklist"],
        )

    def _generate_mock_alert(self) -> dict[str, Any]:
        scenario = random.choice(
            [
                self._impossible_travel_alert,
                self._ransomware_alert,
                self._brute_force_alert,
                self._suspicious_powershell_alert,
                self._data_exfiltration_alert,
                self._privilege_escalation_alert,
            ]
        )
        return scenario()

    def _new_alert_id(self) -> str:
        return f"ALR-{utc_now().strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6].upper()}"

    def _choice(self, values: list[str]) -> str:
        return random.choice(values)

    def _public_ip(self) -> str:
        block = self._choice(["198.51.100", "203.0.113", "192.0.2"])
        return f"{block}.{random.randint(10, 240)}"

    def _host(self) -> str:
        return self._choice(
            [
                "HOST-ABC",
                "WKSTN-441",
                "ENG-LAPTOP-12",
                "FIN-WS-07",
                "RND-ENDPT-33",
                "OPS-JUMP-02",
            ]
        )

    def _user(self) -> str:
        return self._choice(
            [
                "alex.chen",
                "maria.garcia",
                "samir.patel",
                "olivia.brooks",
                "tier2.admin",
                "svc.backup",
            ]
        )

    def _impossible_travel_alert(self) -> dict[str, Any]:
        locations = self._choice(
            [
                ("New York, USA", "Moscow, Russia"),
                ("Austin, USA", "Singapore"),
                ("Toronto, Canada", "Berlin, Germany"),
            ]
        )
        user = self._choice(["alex.chen", "maria.garcia", "olivia.brooks"])
        return {
            "alert_id": self._new_alert_id(),
            "generated_at": utc_now().isoformat(),
            "scenario_id": "impossible_travel",
            "source": "Okta Identity Cloud",
            "rule_name": "Impossible Travel: Successful Logins from Distant Regions",
            "summary": f"User {user} authenticated from {locations[0]} and {locations[1]} inside a 10-minute window.",
            "mitre_tactic": "Credential Access",
            "affected_user": user,
            "affected_host": "N/A",
            "source_ip": self._public_ip(),
            "locations": list(locations),
            "indicators": [user, locations[0], locations[1], "successful_login", "impossible_travel"],
            "telemetry": [
                "Identity provider flagged two successful MFA-backed sessions inside the same timeline.",
                "Geo-velocity exceeded internal travel threshold by more than 25x.",
                "No approved travel exception was attached to the alert payload.",
            ],
        }

    def _ransomware_alert(self) -> dict[str, Any]:
        host = self._host()
        user = self._choice(["maria.garcia", "samir.patel", "svc.backup"])
        process_name = self._choice(["encryptor.exe", "locker32.exe", "svhosts.exe"])
        return {
            "alert_id": self._new_alert_id(),
            "generated_at": utc_now().isoformat(),
            "scenario_id": "ransomware_behavior",
            "source": "CrowdStrike Falcon",
            "rule_name": "Ransomware Behavior: Mass File Encryption",
            "summary": f"Mass file encryption detected on {host} under process {process_name}.",
            "mitre_tactic": "Impact",
            "affected_user": user,
            "affected_host": host,
            "source_ip": self._public_ip(),
            "process_name": process_name,
            "indicators": [host, process_name, user, "mass_encryption", "shadow_copy_deletion"],
            "telemetry": [
                "Rapid file rename burst with newly encrypted extensions across user profile folders.",
                "Process attempted to disable recovery artifacts before encryption accelerated.",
                "EDR classified the binary as unknown and executing from a writable path.",
            ],
        }

    def _brute_force_alert(self) -> dict[str, Any]:
        user = self._choice(["tier2.admin", "olivia.brooks", "alex.chen"])
        failed_count = random.randint(45, 95)
        return {
            "alert_id": self._new_alert_id(),
            "generated_at": utc_now().isoformat(),
            "scenario_id": "brute_force",
            "source": "Microsoft Entra ID",
            "rule_name": "Brute Force: Repeated Failed Logins",
            "summary": f"{failed_count} failed sign-in attempts detected for {user} from a single source IP.",
            "mitre_tactic": "Initial Access",
            "affected_user": user,
            "affected_host": "N/A",
            "source_ip": self._public_ip(),
            "failed_login_count": failed_count,
            "indicators": [user, "failed_logins", f"count:{failed_count}", "admin_target"],
            "telemetry": [
                "Failed sign-ins were concentrated inside a short authentication window.",
                "No successful login has yet been confirmed from the same source IP.",
                "The targeted identity belongs to a privileged or elevated user profile.",
            ],
        }

    def _suspicious_powershell_alert(self) -> dict[str, Any]:
        host = self._host()
        user = self._user()
        domain = self._choice(["cdn-sync-update.net", "assets-sharepoint-login.com", "media-patch-cache.io"])
        return {
            "alert_id": self._new_alert_id(),
            "generated_at": utc_now().isoformat(),
            "scenario_id": "suspicious_powershell",
            "source": "Microsoft Defender for Endpoint",
            "rule_name": "Suspicious PowerShell: Encoded Command Download Cradle",
            "summary": f"Encoded PowerShell executed on {host} and contacted {domain}.",
            "mitre_tactic": "Execution",
            "affected_user": user,
            "affected_host": host,
            "source_ip": self._public_ip(),
            "payload_domain": domain,
            "indicators": [host, user, domain, "powershell", "encoded_command"],
            "telemetry": [
                "PowerShell launched with base64-encoded arguments and hidden window flags.",
                "The process established outbound traffic to a never-before-seen domain.",
                "A follow-on child process spawned outside the expected admin tooling baseline.",
            ],
        }

    def _data_exfiltration_alert(self) -> dict[str, Any]:
        host = self._host()
        user = self._choice(["samir.patel", "alex.chen", "maria.garcia"])
        data_volume = self._choice(["14.2 GB", "27.8 GB", "41.5 GB"])
        return {
            "alert_id": self._new_alert_id(),
            "generated_at": utc_now().isoformat(),
            "scenario_id": "data_exfiltration",
            "source": "Palo Alto Cortex XDR",
            "rule_name": "Data Exfiltration: Abnormal Outbound Transfer",
            "summary": f"{user} transferred {data_volume} from {host} to an unsanctioned external destination.",
            "mitre_tactic": "Exfiltration",
            "affected_user": user,
            "affected_host": host,
            "source_ip": self._public_ip(),
            "data_volume": data_volume,
            "indicators": [host, user, data_volume, "outbound_transfer", "unapproved_destination"],
            "telemetry": [
                "Transfer volume materially exceeded the 30-day baseline for the user.",
                "The destination has no approved business justification in the alert context.",
                "Sensitive file repository access occurred shortly before the transfer began.",
            ],
        }

    def _privilege_escalation_alert(self) -> dict[str, Any]:
        user = self._choice(["olivia.brooks", "samir.patel", "alex.chen"])
        host = self._choice(["OPS-JUMP-02", "IAM-ADMIN-01", "HELPDESK-44"])
        group_name = self._choice(["Domain Admins", "Global Administrators", "Backup Operators"])
        return {
            "alert_id": self._new_alert_id(),
            "generated_at": utc_now().isoformat(),
            "scenario_id": "privilege_escalation",
            "source": "Microsoft Sentinel",
            "rule_name": "Privilege Escalation: Unexpected Administrative Group Membership",
            "summary": f"{user} was added to {group_name} from {host} without a linked change ticket.",
            "mitre_tactic": "Privilege Escalation",
            "affected_user": user,
            "affected_host": host,
            "source_ip": self._public_ip(),
            "group_name": group_name,
            "indicators": [user, host, group_name, "admin_group_change"],
            "telemetry": [
                "Administrative group membership changed outside the normal service catalog workflow.",
                "The event source does not include an approved ticket or CAB reference.",
                "The target identity gained materially expanded rights immediately after the change.",
            ],
        }


soc_service = AgenticSOCService()


@asynccontextmanager
async def lifespan(_: FastAPI):
    await soc_service.start()
    yield
    await soc_service.stop()


app = FastAPI(
    title="Agentic Security Operations Center",
    description="Prototype Manager-Worker SOC with human-in-the-loop containment governance.",
    version="1.0.0",
    lifespan=lifespan,
)

app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


@app.get("/", response_class=HTMLResponse)
async def index(request: Request) -> HTMLResponse:
    bootstrap_json = json.dumps(soc_service.frontend_bootstrap())
    return templates.TemplateResponse(
        "index.html",
        {"request": request, "bootstrap_json": bootstrap_json},
    )


@app.get("/api/status", response_model=RuntimeStatus)
async def get_status() -> RuntimeStatus:
    print("[API] /api/status requested")
    return soc_service.runtime_status()


@app.get("/api/alerts", response_model=list[AlertRecord])
async def list_alerts() -> list[AlertRecord]:
    print("[API] /api/alerts requested")
    return await soc_service.list_alerts()


@app.post("/api/alerts/generate", response_model=AlertRecord)
async def generate_alert() -> AlertRecord:
    print("[API] /api/alerts/generate requested")
    return await soc_service.generate_and_store_alert("manual")


@app.get("/api/alerts/{alert_id}", response_model=AlertRecord)
async def get_alert(alert_id: str) -> AlertRecord:
    print(f"[API] /api/alerts/{alert_id} requested")
    try:
        return await soc_service.get_alert(alert_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Alert not found.") from exc


@app.post("/api/alerts/{alert_id}/decision", response_model=AlertRecord)
async def record_decision(alert_id: str, payload: DecisionRequest) -> AlertRecord:
    print(f"[API] /api/alerts/{alert_id}/decision requested with decision={payload.decision}")
    try:
        return await soc_service.record_decision(alert_id, payload)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Alert not found.") from exc
