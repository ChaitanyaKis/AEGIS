"""Valid construction of every domain contract."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from aegis.core.domain import (
    Action,
    Agent,
    AuditEvent,
    Capability,
    Evidence,
    Incident,
    IncidentState,
    PolicyDecision,
    PolicyDecisionType,
    RiskLevel,
    utc_now,
)
from tests.conftest import FIXED_TIME, LATER_TIME


def test_valid_evidence(evidence: Evidence) -> None:
    assert evidence.evidence_id == "ev-error-rate-001"
    assert evidence.confidence == 0.95
    assert evidence.timestamp == FIXED_TIME


def test_valid_capability(capability: Capability) -> None:
    assert capability.capability_id == "production.rollback"
    assert capability.risk_class is RiskLevel.HIGH
    assert capability.reversible is True
    assert capability.allowed_agents == ("remediation",)


def test_valid_agent(agent: Agent) -> None:
    assert agent.agent_id == "remediation"
    assert agent.version == "1.0.0"
    assert agent.capabilities == ("production.rollback",)
    assert agent.endpoint is not None
    assert agent.endpoint.kind == "local"


def test_valid_incident(incident: Incident, evidence: Evidence) -> None:
    assert incident.state is IncidentState.INVESTIGATING
    assert incident.evidence == (evidence,)
    assert incident.updated_at == LATER_TIME


def test_valid_action(action: Action) -> None:
    assert action.incident_id == "INC-2026-0001"
    assert action.requesting_agent == "remediation"
    assert action.blast_radius is not None
    assert action.blast_radius.impact is RiskLevel.HIGH


def test_valid_policy_decision(policy_decision: PolicyDecision) -> None:
    assert policy_decision.decision is PolicyDecisionType.REQUIRE_APPROVAL
    assert policy_decision.policy_reference


def test_valid_audit_event(audit_event: AuditEvent) -> None:
    assert audit_event.event_id == "evt-000001"
    assert audit_event.state_before is IncidentState.POLICY_CHECK
    assert audit_event.state_after is IncidentState.AWAITING_APPROVAL


def test_minimal_action_leaves_risk_and_blast_radius_unassessed() -> None:
    """A proposing agent is not allowed to assert its own risk.

    Risk and blast radius are outputs of deterministic engines. Their default is
    ``None`` — unassessed — and consumers must fail closed rather than read it as LOW.
    """
    action = Action(
        action_id="act-002",
        incident_id="INC-2026-0001",
        requesting_agent="diagnostic",
        capability="logs.read",
        target_resource="service:payment-api",
    )
    assert action.risk is None
    assert action.blast_radius is None
    assert action.arguments == {}
    assert action.evidence == ()


def test_minimal_audit_event_requires_only_when_who_and_what() -> None:
    event = AuditEvent(
        event_id="evt-000002",
        timestamp=FIXED_TIME,
        actor="system:control-plane",
        event_type="control-plane.started",
    )
    assert event.incident_id is None
    assert event.decision is None
    assert event.evidence == ()


def test_domain_models_are_immutable(incident: Incident) -> None:
    """Domain objects are values; a state change produces a new object.

    This is what makes ``state_before``/``state_after`` audit records honest.
    """
    with pytest.raises(ValidationError):
        incident.state = IncidentState.RESOLVED  # type: ignore[misc]

    advanced = incident.model_copy(update={"state": IncidentState.RESOLVED})
    assert incident.state is IncidentState.INVESTIGATING
    assert advanced.state is IncidentState.RESOLVED


def test_timestamps_are_normalised_to_utc() -> None:
    """A non-UTC aware timestamp is accepted and normalised, keeping audit order sane."""
    tokyo = timezone(timedelta(hours=9))
    evidence = Evidence(
        evidence_id="ev-tz",
        source="telemetry.payment-api",
        reference="metric:x",
        timestamp=datetime(2026, 1, 1, 21, 0, 0, tzinfo=tokyo),
        type="TELEMETRY",
        confidence=0.5,
    )
    assert evidence.timestamp == datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
    assert evidence.timestamp.tzinfo is UTC


def test_mapping_fields_are_normalised_to_sorted_order(agent: Agent) -> None:
    """Deterministic output does not depend on the caller's insertion order."""
    assert agent.endpoint is not None
    assert list(agent.endpoint.metadata) == ["adapter", "region"]

    action = Action(
        action_id="act-003",
        incident_id="INC-2026-0001",
        requesting_agent="remediation",
        capability="production.scale",
        target_resource="service:payment-api",
        arguments={"z": 1, "a": 2},
    )
    assert list(action.arguments) == ["a", "z"]


def test_utc_now_returns_an_aware_utc_instant() -> None:
    """The single clock helper never hands out a naive datetime."""
    now = utc_now()
    assert now.tzinfo is not None
    assert now.utcoffset() == timedelta(0)
