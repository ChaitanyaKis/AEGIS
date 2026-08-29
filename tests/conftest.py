"""Shared deterministic fixtures for the AEGIS domain tests.

Every value here is fixed. No clocks, no randomness, no I/O — a domain test that fails
must fail because the contract changed, not because the environment did.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from aegis.core.domain import (
    Action,
    Agent,
    AgentEndpoint,
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

FIXED_TIME = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
LATER_TIME = datetime(2026, 1, 1, 12, 5, 0, tzinfo=UTC)


@pytest.fixture
def evidence() -> Evidence:
    return Evidence(
        evidence_id="ev-error-rate-001",
        source="telemetry.payment-api",
        reference="metric:payment_api.error_rate@2026-01-01T12:00:00Z",
        timestamp=FIXED_TIME,
        type=EvidenceType.TELEMETRY,
        confidence=0.95,
    )


@pytest.fixture
def capability() -> Capability:
    return Capability(
        capability_id="production.rollback",
        description="Roll a service back to a previously deployed version.",
        risk_class=RiskLevel.HIGH,
        resource_scope=("service:payment-api",),
        data_classification=DataClassification.INTERNAL,
        reversible=True,
        approval_requirement=ApprovalRequirement.ALWAYS,
        allowed_agents=("remediation",),
    )


@pytest.fixture
def agent() -> Agent:
    return Agent(
        agent_id="remediation",
        name="Remediation Agent",
        version="1.0.0",
        status=AgentLifecycleState.ACTIVE,
        identity_reference="aegis:identity:remediation",
        capabilities=("production.rollback",),
        endpoint=AgentEndpoint(
            kind="local",
            reference="aegis.agents.remediation",
            metadata={"region": "local", "adapter": "in-process"},
        ),
    )


@pytest.fixture
def incident(evidence: Evidence) -> Incident:
    return Incident(
        incident_id="INC-2026-0001",
        source="monitoring.alerting",
        severity=RiskLevel.CRITICAL,
        state=IncidentState.INVESTIGATING,
        evidence=(evidence,),
        assigned_agents=("commander", "diagnostic"),
        proposed_actions=("act-rollback-001",),
        created_at=FIXED_TIME,
        updated_at=LATER_TIME,
    )


@pytest.fixture
def action(evidence: Evidence) -> Action:
    return Action(
        action_id="act-rollback-001",
        incident_id="INC-2026-0001",
        requesting_agent="remediation",
        capability="production.rollback",
        target_resource="service:payment-api",
        arguments={"target_version": "v4.7", "drain_seconds": 30},
        evidence=(evidence.evidence_id,),
        risk=RiskLevel.HIGH,
        blast_radius=BlastRadius(
            scope=("service:payment-api", "service:order-service"),
            impact=RiskLevel.HIGH,
        ),
    )


@pytest.fixture
def policy_decision(evidence: Evidence) -> PolicyDecision:
    return PolicyDecision(
        decision=PolicyDecisionType.REQUIRE_APPROVAL,
        reason="production.rollback is HIGH risk and always requires human approval.",
        policy_reference="policy:production-mutation/v1#rollback",
        evaluated_at=FIXED_TIME,
        evidence=(evidence.evidence_id,),
    )


@pytest.fixture
def audit_event(evidence: Evidence) -> AuditEvent:
    return AuditEvent(
        event_id="evt-000001",
        timestamp=FIXED_TIME,
        actor="system:policy-engine",
        agent_identity="aegis:identity:remediation",
        incident_id="INC-2026-0001",
        event_type="policy.decision",
        input_reference="act-rollback-001",
        decision=PolicyDecisionType.REQUIRE_APPROVAL,
        policy_reference="policy:production-mutation/v1#rollback",
        tool="production.rollback",
        result="awaiting-approval",
        state_before=IncidentState.POLICY_CHECK,
        state_after=IncidentState.AWAITING_APPROVAL,
        evidence=(evidence.evidence_id,),
    )
