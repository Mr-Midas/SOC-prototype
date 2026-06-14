"""Deterministic fallback logic for all three pipeline agents.

When LiteLLM is unavailable, the API key is missing, the model returns garbage
JSON, or the confidence threshold is not met, these functions produce safe defaults.

Each function covers six canonical attack scenarios plus a generic catch-all.
The scenario-specific branches produce richer output than the generic fallback,
which is designed to never produce a dangerous "do nothing" recommendation.
"""

from __future__ import annotations

from typing import Any

from arbiterion.models import ContainmentPlan, ManagerDecision, TriageFinding


def fallback_manager(raw_alert: dict[str, Any]) -> ManagerDecision:
    scenario = raw_alert.get("scenario_id", "external_detection")
    telemetry = raw_alert.get("telemetry", [])
    indicators = raw_alert.get("indicators", [])
    user = raw_alert.get("affected_user") or "unknown-user"
    host = raw_alert.get("affected_host") or "unknown-host"
    source_ip = raw_alert.get("source_ip") or "unknown-ip"

    if scenario == "ransomware_behavior":
        return ManagerDecision(
            severity="Critical", risk_score=98,
            routing_rationale="Mass encryption behavior on a production endpoint indicates active impact-stage malware.",
            triage_focus=["Confirm whether host touched mapped drives", "Determine encryption process origin", "Validate backup tampering"],
            notable_entities=[host, user, raw_alert.get("process_name", "unknown-process")],
        )

    if scenario == "impossible_travel":
        return ManagerDecision(
            severity="High", risk_score=86,
            routing_rationale="Geographically distant logins within an unrealistic window indicate account takeover.",
            triage_focus=["Validate MFA satisfaction", "Review session revocation history", "Confirm approved travel"],
            notable_entities=[user, source_ip],
        )

    if scenario == "suspicious_powershell":
        return ManagerDecision(
            severity="High", risk_score=84,
            routing_rationale="Encoded PowerShell launching a remote payload is common post-exploitation behavior.",
            triage_focus=["Review process tree", "Check downloaded payload", "Assess outbound connections"],
            notable_entities=[host, user, raw_alert.get("payload_domain", "unknown-domain")],
        )

    if scenario == "data_exfiltration":
        return ManagerDecision(
            severity="Critical", risk_score=94,
            routing_rationale="Large outbound transfer to unsanctioned destination indicates potential data loss.",
            triage_focus=["Identify data owner", "Confirm destination status", "Scope other transfers"],
            notable_entities=[user, host, source_ip, raw_alert.get("data_volume", "unknown-volume")],
        )

    if scenario == "privilege_escalation":
        return ManagerDecision(
            severity="High", risk_score=81,
            routing_rationale="Unexpected privileged group addition may indicate abuse or change control gap.",
            triage_focus=["Check change request", "Validate who performed change", "Review post-elevation actions"],
            notable_entities=[user, host, raw_alert.get("group_name", "unknown-group")],
        )

    if scenario in ("brute_force",):
        failed_count = raw_alert.get("failed_login_count", 0)
        return ManagerDecision(
            severity="Medium", risk_score=68,
            routing_rationale="Concentrated failed authentication against an administrative identity.",
            triage_focus=["Check successful logins after failures", "Review source IP reputation", "Determine other targeted accounts"],
            notable_entities=[user, source_ip, str(failed_count)],
        )

    if scenario in ("endpoint_detection", "endpoint_sample"):
        severity = raw_alert.get("analyst_supplied_severity", "Medium")
        risk = 36 if severity == "Low" else 64 if severity == "Medium" else 84 if severity == "High" else 95
        event_type = raw_alert.get("event_type", "endpoint_event")
        return ManagerDecision(
            severity=severity, risk_score=risk,
            routing_rationale="Endpoint event normalized for single-endpoint triage.",
            triage_focus=["Verify endpoint event integrity", "Confirm admin or automation context", "Check for repeated patterns"],
            notable_entities=[item for item in [user, host, source_ip] if item and "unknown" not in str(item)],
        )

    analyst_supplied = raw_alert.get("analyst_supplied_severity", "Medium")
    risk_map = {"Low": 35, "Medium": 62, "High": 83, "Critical": 95}
    return ManagerDecision(
        severity=analyst_supplied, risk_score=risk_map.get(analyst_supplied, 62),
        routing_rationale="External alert normalized and scored using metadata plus available threat intelligence.",
        triage_focus=["Validate alert source telemetry", "Confirm indicator mapping to affected assets", "Correlate with surrounding activity"],
        notable_entities=[item for item in [user, host, source_ip] if item and "unknown" not in str(item)],
    )


def fallback_triage(raw_alert: dict[str, Any], manager: ManagerDecision) -> TriageFinding:
    scenario = raw_alert.get("scenario_id", "external_detection")
    host = raw_alert.get("affected_host") or "unknown-host"
    user = raw_alert.get("affected_user") or "unknown-user"

    if scenario == "ransomware_behavior":
        return TriageFinding(
            investigation_summary=f"{host} exhibiting mass file encryption from {raw_alert.get('process_name', 'unknown')}. Containment speed matters more than perfect attribution.",
            confidence_score=96, classification="True Positive",
            supporting_evidence=["Rapid sequential file modifications with encrypted extensions", "Non-standard binary from writable path", "Destructive behavior inconsistent with patching"],
        )
    if scenario == "impossible_travel":
        return TriageFinding(
            investigation_summary=f"{user} authenticated from distant locations within minutes. Treat as credential misuse until verified.",
            confidence_score=82, classification="True Positive",
            supporting_evidence=["Distant successful logins inside same timeline", "Geo-velocity exceeds travel threshold", "No travel exception attached"],
        )
    if scenario == "suspicious_powershell":
        return TriageFinding(
            investigation_summary=f"{host} executed encoded PowerShell under {user}, followed by traffic to unknown domain.",
            confidence_score=79, classification="True Positive",
            supporting_evidence=["Base64-encoded arguments in command line", "Outbound contact to previously unseen domain", "Execution outside admin change window"],
        )
    if scenario == "data_exfiltration":
        return TriageFinding(
            investigation_summary=f"{user} initiated outbound transfer of {raw_alert.get('data_volume', 'unknown')} from {host} to unapproved destination.",
            confidence_score=88, classification="True Positive",
            supporting_evidence=["Volume above user's baseline", "Destination has no allow-list exception", "Sensitive repository access preceded transfer"],
        )
    if scenario == "privilege_escalation":
        return TriageFinding(
            investigation_summary=f"{user} added to {raw_alert.get('group_name', 'unknown')} from {host} without change context.",
            confidence_score=77, classification="Needs More Data",
            supporting_evidence=["Membership change outside approval trail", "Originating workstation identified", "Impact potential even if authorized"],
        )
    if scenario == "brute_force":
        return TriageFinding(
            investigation_summary=f"{raw_alert.get('failed_login_count', 0)} failed attempts against {user} from {source_ip(raw_alert)}.",
            confidence_score=74, classification="True Positive",
            supporting_evidence=["Attempts cluster tightly from single origin", "Targeted account has elevated privileges", "Exceeds normal typo rate"],
        )
    if scenario in ("endpoint_detection", "endpoint_sample"):
        severity = raw_alert.get("analyst_supplied_severity", "Medium")
        confidence = 58 if severity == "Low" else 74 if severity == "Medium" else 86
        return TriageFinding(
            investigation_summary=f"Endpoint event '{raw_alert.get('event_type', 'unknown')}' on {host}. Low-cost triage with selective AI escalation.",
            confidence_score=confidence, classification="True Positive" if confidence >= 80 else "Needs More Data",
            supporting_evidence=(raw_alert.get("telemetry") or ["Endpoint telemetry received and normalized."])[:3],
        )

    confidence = 72 if manager.severity in ("Low", "Medium") else 84
    return TriageFinding(
        investigation_summary=f"External alert from {raw_alert.get('source', 'unknown')}. Validate against original telemetry before response.",
        confidence_score=confidence, classification="True Positive" if confidence >= 80 else "Needs More Data",
        supporting_evidence=(raw_alert.get("telemetry") or ["Alert received from external source."])[:3],
    )


def fallback_containment(raw_alert: dict[str, Any], manager: ManagerDecision, triage: TriageFinding) -> ContainmentPlan:
    scenario = raw_alert.get("scenario_id", "external_detection")
    host = raw_alert.get("affected_host") or "unknown-host"
    user = raw_alert.get("affected_user") or "unknown-user"
    source_ip_val = raw_alert.get("source_ip") or "unknown-ip"
    process_name = raw_alert.get("process_name") or "unknown-process"

    if scenario == "ransomware_behavior":
        return ContainmentPlan(
            proposed_action=f"Immediately isolate {host}, disable session for {user}, block ransomware hash across EDR.",
            action_type="Host Isolation",
            operator_brief="Isolating the endpoint stops lateral movement and further encryption while preserving forensics.",
            pre_approval_checklist=["Notify incident command before isolation if business critical", "Confirm active server connections need controlled shutdown", "Snapshot volatile evidence if possible"],
        )
    if scenario == "impossible_travel":
        return ContainmentPlan(
            proposed_action=f"Revoke active sessions for {user}, force password reset, block access from {source_ip_val} pending verification.",
            action_type="Identity Containment",
            operator_brief="Reduces account takeover risk while preserving rollback path if benign.",
            pre_approval_checklist=["Confirm user is not traveling via approved gateway", "Check other high-risk sign-ins in last 24 hours", "Ensure identity team ready for re-verification"],
        )
    if scenario == "suspicious_powershell":
        return ContainmentPlan(
            proposed_action=f"Isolate {host}, block domain {raw_alert.get('payload_domain', 'unknown')} at proxy, suspend {user} session.",
            action_type="Host Isolation",
            operator_brief="Contains compromised endpoint and C2 channel while keeping response targeted.",
            pre_approval_checklist=["Verify domain is not approved internal automation", "Capture command line and parent process", "Confirm user is not on legitimate remediation"],
        )
    if scenario == "data_exfiltration":
        return ContainmentPlan(
            proposed_action=f"Quarantine {host} from high-risk egress, suspend {user} data repository access, block destination {source_ip_val}.",
            action_type="Data Loss Containment",
            operator_brief="Narrows egress and repository access without enterprise-wide block while ownership is confirmed.",
            pre_approval_checklist=["Confirm destination is not approved transfer endpoint", "Coordinate with data owner before revoking access", "Preserve netflow evidence"],
        )
    if scenario == "privilege_escalation":
        return ContainmentPlan(
            proposed_action=f"Temporarily remove {user} from {raw_alert.get('group_name', 'unknown')}, keep {host} under heightened monitoring.",
            action_type="Privilege Revocation",
            operator_brief="Temporary rollback reduces risk quickly while keeping response reversible if legitimate.",
            pre_approval_checklist=["Confirm change does not align with emergency maintenance", "Check removing role would not break support", "Identify admin who performed change"],
        )
    if scenario == "brute_force":
        return ContainmentPlan(
            proposed_action=f"Block {source_ip_val} at perimeter, enable temporary lockout for {user}, monitor for follow-on attempts.",
            action_type="Network Blocking",
            operator_brief="Proportional containment that reduces compromise chance without unnecessary isolation.",
            pre_approval_checklist=["Confirm source IP is not corporate NAT/VPN", "Check account is not tied to automation job", "Verify lockout thresholds will not cause availability issue"],
        )
    if scenario in ("endpoint_detection", "endpoint_sample"):
        return ContainmentPlan(
            proposed_action=f"Contain process {process_name} on {host}, collect forensic artifacts, scope outbound controls to observed indicators."
            if process_name != "unknown-process" else f"Place {host} into heightened monitoring pending analyst confirmation.",
            action_type="Process Containment" if process_name != "unknown-process" else "Host Triage",
            operator_brief="Conservative containment: contain what is known, preserve evidence, avoid broad disruption.",
            pre_approval_checklist=["Confirm event is not planned maintenance", "Capture process tree before containment", "Validate rollback steps available"],
        )

    return ContainmentPlan(
        proposed_action=f"Block source IP {source_ip_val} at edge and preserve host {host} for deeper review."
        if source_ip_val != "unknown-ip" else f"Require containment review for user {user} and isolate {host} if confirmed.",
        action_type="Network Blocking" if source_ip_val != "unknown-ip" else "Identity Containment",
        operator_brief="Response is human-gated; this case reflects a real inbound event with external reputation context.",
        pre_approval_checklist=["Verify alert origin against upstream system", "Confirm indicator is not internal scanner", "Retain original event payload for audit"],
    )


def source_ip(raw_alert: dict[str, Any]) -> str:
    return raw_alert.get("source_ip") or "unknown-ip"

