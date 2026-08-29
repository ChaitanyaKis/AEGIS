"""Domain invariants: states the contracts must refuse to represent.

Every test here is a negative test. The point is not that pydantic works, it is that
each specific invalid state named in the AEGIS constitution is unrepresentable, so no
later component has to defend against it.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from aegis.core.domain import (
    Action,
    Agent,
    AgentLifecycleState,
    ApprovalRequirement,
    AuditEvent,
    BlastRadius,
    Capability,
    DataClassification,
    Evidence,
    EvidenceType,
    Incident,
    IncidentState,
    PolicyDecision,
    PolicyDecisionType,
    RiskLevel,
)
from tests.conftest import FIXED_TIME, LATER_TIME


def _agent_kwargs(**overrides: object) -> dict[str, object]:
    kwargs: dict[str, object] = {
        "agent_id": "diagnostic",
        "name": "Diagnostic Agent",
        "version": "1.0.0",
        "status": AgentLifecycleState.REGISTERED,
        "identity_reference": "aegis:identity:diagnostic",
    }
    kwargs.update(overrides)
    return kwargs


def _capability_kwargs(**overrides: object) -> dict[str, object]:
    kwargs: dict[str, object] = {
        "capability_id": "logs.read",
        "description": "Read service logs.",
        "risk_class": RiskLevel.LOW,
        "data_classification": DataClassification.INTERNAL,
        "reversible": True,
        "approval_requirement": ApprovalRequirement.NONE,
    }
    kwargs.update(overrides)
    return kwargs


def _incident_kwargs(**overrides: object) -> dict[str, object]:
    kwargs: dict[str, object] = {
        "incident_id": "INC-2026-0001",
        "source": "monitoring.alerting",
        "severity": RiskLevel.HIGH,
        "state": IncidentState.RECEIVED,
        "created_at": FIXED_TIME,
        "updated_at": FIXED_TIME,
    }
    kwargs.update(overrides)
    return kwargs


def _action_kwargs(**overrides: object) -> dict[str, object]:
    kwargs: dict[str, object] = {
        "action_id": "act-001",
        "incident_id": "INC-2026-0001",
        "requesting_agent": "remediation",
        "capability": "production.rollback",
        "target_resource": "service:payment-api",
    }
    kwargs.update(overrides)
    return kwargs


def _audit_kwargs(**overrides: object) -> dict[str, object]:
    kwargs: dict[str, object] = {
        "event_id": "evt-000001",
        "timestamp": FIXED_TIME,
        "actor": "system:policy-engine",
        "event_type": "policy.decision",
    }
    kwargs.update(overrides)
    return kwargs


# --- required identity --------------------------------------------------------------


def test_agent_requires_id() -> None:
    kwargs = _agent_kwargs()
    del kwargs["agent_id"]
    with pytest.raises(ValidationError):
        Agent(**kwargs)


def test_agent_requires_version() -> None:
    kwargs = _agent_kwargs()
    del kwargs["version"]
    with pytest.raises(ValidationError):
        Agent(**kwargs)


def test_agent_requires_identity_reference() -> None:
    with pytest.raises(ValidationError):
        Agent(**_agent_kwargs(identity_reference=""))


def test_capability_requires_id() -> None:
    kwargs = _capability_kwargs()
    del kwargs["capability_id"]
    with pytest.raises(ValidationError):
        Capability(**kwargs)


def test_incident_requires_id() -> None:
    kwargs = _incident_kwargs()
    del kwargs["incident_id"]
    with pytest.raises(ValidationError):
        Incident(**kwargs)


def test_action_requires_incident() -> None:
    kwargs = _action_kwargs()
    del kwargs["incident_id"]
    with pytest.raises(ValidationError):
        Action(**kwargs)


def test_action_requires_requesting_agent() -> None:
    kwargs = _action_kwargs()
    del kwargs["requesting_agent"]
    with pytest.raises(ValidationError):
        Action(**kwargs)


def test_audit_event_requires_event_id() -> None:
    kwargs = _audit_kwargs()
    del kwargs["event_id"]
    with pytest.raises(ValidationError):
        AuditEvent(**kwargs)


def test_audit_event_requires_timestamp() -> None:
    kwargs = _audit_kwargs()
    del kwargs["timestamp"]
    with pytest.raises(ValidationError):
        AuditEvent(**kwargs)


@pytest.mark.parametrize("missing", ["actor", "event_type"])
def test_audit_event_requires_actor_and_event_type(missing: str) -> None:
    kwargs = _audit_kwargs()
    del kwargs[missing]
    with pytest.raises(ValidationError):
        AuditEvent(**kwargs)


# --- empty and malformed identifiers ------------------------------------------------


@pytest.mark.parametrize("blank", ["", "   "])
def test_identifiers_may_not_be_blank(blank: str) -> None:
    with pytest.raises(ValidationError):
        Agent(**_agent_kwargs(agent_id=blank))
    with pytest.raises(ValidationError):
        Capability(**_capability_kwargs(capability_id=blank))
    with pytest.raises(ValidationError):
        Incident(**_incident_kwargs(incident_id=blank))
    with pytest.raises(ValidationError):
        Action(**_action_kwargs(action_id=blank))
    with pytest.raises(ValidationError):
        AuditEvent(**_audit_kwargs(event_id=blank))


@pytest.mark.parametrize("bad_id", ["has space", "-leading-hyphen", "semi;colon"])
def test_identifiers_reject_free_form_punctuation(bad_id: str) -> None:
    """Identifiers land in audit records and policy references; keep them narrow."""
    with pytest.raises(ValidationError):
        Agent(**_agent_kwargs(agent_id=bad_id))


def test_required_free_text_may_not_be_blank() -> None:
    with pytest.raises(ValidationError):
        Capability(**_capability_kwargs(description="  "))
    with pytest.raises(ValidationError):
        Action(**_action_kwargs(target_resource=""))


# --- policy decisions ---------------------------------------------------------------


@pytest.mark.parametrize("invalid", ["MAYBE", "allow", "ESCALATE", "UNKNOWN", ""])
def test_policy_decision_rejects_unauthoritative_decision(invalid: str) -> None:
    """ALLOW, DENY and REQUIRE_APPROVAL are the only decisions AEGIS recognises."""
    with pytest.raises(ValidationError):
        PolicyDecision(
            decision=invalid,
            reason="r",
            policy_reference="policy:x",
            evaluated_at=FIXED_TIME,
        )


def test_policy_decision_requires_reason_and_policy_reference() -> None:
    """A decision that cannot be explained or traced back to a rule is not auditable."""
    with pytest.raises(ValidationError):
        PolicyDecision(
            decision=PolicyDecisionType.DENY,
            reason="",
            policy_reference="policy:x",
            evaluated_at=FIXED_TIME,
        )
    with pytest.raises(ValidationError):
        PolicyDecision(
            decision=PolicyDecisionType.DENY,
            reason="not permitted",
            policy_reference="",
            evaluated_at=FIXED_TIME,
        )


def test_audit_event_rejects_unauthoritative_decision() -> None:
    with pytest.raises(ValidationError):
        AuditEvent(**_audit_kwargs(decision="MAYBE"))


# --- enum-typed fields --------------------------------------------------------------


def test_incident_rejects_unknown_state() -> None:
    with pytest.raises(ValidationError):
        Incident(**_incident_kwargs(state="TRIAGING"))


def test_agent_rejects_unknown_lifecycle_state() -> None:
    with pytest.raises(ValidationError):
        Agent(**_agent_kwargs(status="RUNNING"))


def test_risk_level_rejects_unknown_value() -> None:
    with pytest.raises(ValidationError):
        Capability(**_capability_kwargs(risk_class="SEVERE"))


# --- value ranges and ordering ------------------------------------------------------


@pytest.mark.parametrize("confidence", [-0.01, 1.01])
def test_evidence_confidence_must_be_a_probability(confidence: float) -> None:
    with pytest.raises(ValidationError):
        Evidence(
            evidence_id="ev-1",
            source="telemetry.payment-api",
            reference="metric:x",
            timestamp=FIXED_TIME,
            type=EvidenceType.TELEMETRY,
            confidence=confidence,
        )


def test_incident_rejects_updated_before_created() -> None:
    with pytest.raises(ValidationError):
        Incident(**_incident_kwargs(created_at=LATER_TIME, updated_at=FIXED_TIME))


def test_naive_timestamps_are_rejected() -> None:
    """Audit ordering is meaningless without an unambiguous instant."""
    naive = datetime(2026, 1, 1, 12, 0, 0)
    with pytest.raises(ValidationError):
        AuditEvent(**_audit_kwargs(timestamp=naive))


def test_blast_radius_requires_an_explicit_impact() -> None:
    """There is no safe default reach; the assessment must be stated."""
    with pytest.raises(ValidationError):
        BlastRadius(scope=("service:payment-api",))


# --- closed schemas -----------------------------------------------------------------


def test_unknown_fields_are_rejected() -> None:
    """Untrusted payloads must not be able to widen a contract."""
    with pytest.raises(ValidationError):
        Action(**_action_kwargs(approved=True))
    with pytest.raises(ValidationError):
        PolicyDecision(
            decision=PolicyDecisionType.ALLOW,
            reason="ok",
            policy_reference="policy:x",
            evaluated_at=datetime.now(UTC),
            override="ignore-deny",
        )
