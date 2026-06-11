"""Tests for the deterministic fallback logic — all six canonical attack scenarios plus generic/generic catch-all."""

from __future__ import annotations

import pytest

from copilot_soc.pipeline.fallback import (
    fallback_containment,
    fallback_manager,
    fallback_triage,
)


def _make_alert(scenario_id: str, **overrides) -> dict:
    base = {
        "scenario_id": scenario_id,
        "source": "Wazuh",
        "rule_name": "Test Rule",
        "summary": "Test alert summary",
        "affected_user": "jsmith",
        "affected_host": "CORP-LAPTOP-42",
        "source_ip": "10.0.0.55",
        "process_name": "powershell.exe",
        "command_line": "powershell -enc test",
        "telemetry": ["event 1", "event 2"],
        "indicators": ["indicator-1"],
    }
    base.update(overrides)
    return base


# ── Manager Agent ──────────────────────────────────────────────────────────

class TestFallbackManager:
    def test_ransomware_routing(self):
        alert = _make_alert("ransomware_behavior")
        decision = fallback_manager(alert)
        assert decision.severity == "Critical"
        assert decision.risk_score == 98
        assert "encryption" in decision.routing_rationale.lower()

    def test_impossible_travel_routing(self):
        alert = _make_alert("impossible_travel")
        decision = fallback_manager(alert)
        assert decision.severity == "High"
        assert decision.risk_score == 86
        assert "takeover" in decision.routing_rationale.lower()

    def test_suspicious_powershell_routing(self):
        alert = _make_alert("suspicious_powershell")
        decision = fallback_manager(alert)
        assert decision.severity == "High"
        assert decision.risk_score == 84

    def test_data_exfiltration_routing(self):
        alert = _make_alert("data_exfiltration", data_volume="50GB")
        decision = fallback_manager(alert)
        assert decision.severity == "Critical"
        assert decision.risk_score == 94
        assert "outbound transfer" in decision.routing_rationale.lower()

    def test_privilege_escalation_routing(self):
        alert = _make_alert("privilege_escalation", group_name="Domain Admins")
        decision = fallback_manager(alert)
        assert decision.severity == "High"
        assert decision.risk_score == 81

    def test_brute_force_routing(self):
        alert = _make_alert("brute_force", failed_login_count=42)
        decision = fallback_manager(alert)
        assert decision.severity == "Medium"
        assert decision.risk_score == 68
        assert "42" in str(decision.notable_entities)

    def test_endpoint_detection_routing(self):
        alert = _make_alert("endpoint_detection", analyst_supplied_severity="High")
        decision = fallback_manager(alert)
        assert decision.severity == "High"
        assert decision.risk_score == 84

    def test_endpoint_sample_routing(self):
        alert = _make_alert("endpoint_sample", analyst_supplied_severity="Low")
        decision = fallback_manager(alert)
        assert decision.severity == "Low"
        assert decision.risk_score == 36

    def test_generic_external_detection(self):
        alert = _make_alert("external_detection", analyst_supplied_severity="High")
        decision = fallback_manager(alert)
        assert decision.risk_score == 83
        assert len(decision.triage_focus) >= 2

    def test_default_unknown_scenario(self):
        alert = _make_alert("some_unknown_threat")
        decision = fallback_manager(alert)
        assert decision.severity in ("Low", "Medium", "High", "Critical")
        assert 0 <= decision.risk_score <= 100


# ── Triage Agent ───────────────────────────────────────────────────────────

class TestFallbackTriage:
    def test_ransomware_triage(self):
        alert = _make_alert("ransomware_behavior")
        manager = fallback_manager(alert)
        finding = fallback_triage(alert, manager)
        assert finding.classification == "True Positive"
        assert finding.confidence_score == 96

    def test_impossible_travel_triage(self):
        alert = _make_alert("impossible_travel")
        manager = fallback_manager(alert)
        finding = fallback_triage(alert, manager)
        assert finding.classification == "True Positive"
        assert finding.confidence_score == 82

    def test_privilege_escalation_needs_more_data(self):
        alert = _make_alert("privilege_escalation")
        manager = fallback_manager(alert)
        finding = fallback_triage(alert, manager)
        assert finding.classification == "Needs More Data"
        assert finding.confidence_score == 77

    def test_generic_low_severity(self):
        alert = _make_alert("external_detection", analyst_supplied_severity="Low")
        manager = fallback_manager(alert)
        finding = fallback_triage(alert, manager)
        assert finding.confidence_score == 72

    def test_generic_high_severity(self):
        alert = _make_alert("external_detection", analyst_supplied_severity="Critical")
        manager = fallback_manager(alert)
        finding = fallback_triage(alert, manager)
        assert finding.confidence_score == 84

    def test_supporting_evidence_is_list(self):
        alert = _make_alert("ransomware_behavior")
        manager = fallback_manager(alert)
        finding = fallback_triage(alert, manager)
        assert isinstance(finding.supporting_evidence, list)
        assert len(finding.supporting_evidence) >= 2

    def test_investigation_summary_not_empty(self):
        alert = _make_alert("ransomware_behavior")
        manager = fallback_manager(alert)
        finding = fallback_triage(alert, manager)
        assert len(finding.investigation_summary) > 10


# ── Containment Agent ──────────────────────────────────────────────────────

class TestFallbackContainment:
    def test_ransomware_containment(self):
        alert = _make_alert("ransomware_behavior")
        manager = fallback_manager(alert)
        triage = fallback_triage(alert, manager)
        plan = fallback_containment(alert, manager, triage)
        assert plan.action_type == "Host Isolation"
        assert "isolate" in plan.proposed_action.lower()
        assert len(plan.pre_approval_checklist) >= 2

    def test_impossible_travel_containment(self):
        alert = _make_alert("impossible_travel")
        manager = fallback_manager(alert)
        triage = fallback_triage(alert, manager)
        plan = fallback_containment(alert, manager, triage)
        assert plan.action_type == "Identity Containment"
        assert "revoke" in plan.proposed_action.lower()

    def test_suspicious_powershell_containment(self):
        alert = _make_alert("suspicious_powershell", payload_domain="evil.com")
        manager = fallback_manager(alert)
        triage = fallback_triage(alert, manager)
        plan = fallback_containment(alert, manager, triage)
        assert plan.action_type == "Host Isolation"
        assert "block" in plan.proposed_action.lower()

    def test_data_exfiltration_containment(self):
        alert = _make_alert("data_exfiltration")
        manager = fallback_manager(alert)
        triage = fallback_triage(alert, manager)
        plan = fallback_containment(alert, manager, triage)
        assert plan.action_type == "Data Loss Containment"
        assert "quarantine" in plan.proposed_action.lower()

    def test_brute_force_containment(self):
        alert = _make_alert("brute_force")
        manager = fallback_manager(alert)
        triage = fallback_triage(alert, manager)
        plan = fallback_containment(alert, manager, triage)
        assert plan.action_type == "Network Blocking"
        assert "block" in plan.proposed_action.lower()

    def test_unknown_scenario_containment_has_ip(self):
        alert = _make_alert("external_detection")
        manager = fallback_manager(alert)
        triage = fallback_triage(alert, manager)
        plan = fallback_containment(alert, manager, triage)
        assert "block" in plan.proposed_action.lower() or "review" in plan.proposed_action.lower()

    def test_endpoint_detection_containment(self):
        alert = _make_alert("endpoint_detection")
        manager = fallback_manager(alert)
        triage = fallback_triage(alert, manager)
        plan = fallback_containment(alert, manager, triage)
        assert plan.action_type == "Process Containment"
        assert "powershell" in plan.proposed_action.lower()

    def test_unknown_host_containment(self):
        alert = _make_alert("endpoint_detection", affected_host=None, process_name=None)
        manager = fallback_manager(alert)
        triage = fallback_triage(alert, manager)
        plan = fallback_containment(alert, manager, triage)
        assert plan.action_type in ("Process Containment", "Host Triage")

    def test_pre_approval_checklist_is_list(self):
        alert = _make_alert("ransomware_behavior")
        manager = fallback_manager(alert)
        triage = fallback_triage(alert, manager)
        plan = fallback_containment(alert, manager, triage)
        assert isinstance(plan.pre_approval_checklist, list)
        assert len(plan.pre_approval_checklist) >= 2

    def test_operator_brief_is_short(self):
        alert = _make_alert("ransomware_behavior")
        manager = fallback_manager(alert)
        triage = fallback_triage(alert, manager)
        plan = fallback_containment(alert, manager, triage)
        assert 10 < len(plan.operator_brief) < 300
