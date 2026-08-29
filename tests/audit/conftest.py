"""Fixtures for the audit suite. Real engines throughout, injected clocks only."""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from aegis.core.approval import ApprovalEngine
from aegis.core.assessment import AssessmentPipeline
from aegis.core.audit import AuditRecorder, AuditStore
from aegis.core.capabilities import CapabilityRegistry
from aegis.core.domain import Action, AuditEvent
from aegis.core.incidents import IncidentStateMachine
from aegis.core.policy import PolicyEngine
from aegis.core.verification import VerificationEngine
from tests.fleet import (
    FIXED_EVALUATION_TIME,
    PAYMENT_API,
    build_action,
    build_graph,
    build_registry,
    fixed_clock,
)


class MovableClock:
    """A clock that only moves when a test moves it."""

    def __init__(self, start: datetime) -> None:
        self.now = start

    def __call__(self) -> datetime:
        return self.now

    def advance(self, delta: timedelta) -> None:
        self.now += delta


@pytest.fixture
def clock() -> MovableClock:
    return MovableClock(FIXED_EVALUATION_TIME)


@pytest.fixture
def store() -> AuditStore:
    return AuditStore()


@pytest.fixture
def recorder(store: AuditStore, clock: MovableClock) -> AuditRecorder:
    return AuditRecorder(store, clock=clock)


@pytest.fixture
def registry() -> CapabilityRegistry:
    return build_registry()


@pytest.fixture
def pipeline(registry: CapabilityRegistry) -> AssessmentPipeline:
    return AssessmentPipeline(registry, build_graph())


@pytest.fixture
def policy_engine(registry: CapabilityRegistry) -> PolicyEngine:
    return PolicyEngine(registry, clock=fixed_clock)


@pytest.fixture
def approval_engine(policy_engine: PolicyEngine, clock: MovableClock) -> ApprovalEngine:
    return ApprovalEngine(policy_engine, clock=clock)


@pytest.fixture
def verification_engine(clock: MovableClock) -> VerificationEngine:
    return VerificationEngine(clock=clock)


@pytest.fixture
def machine(clock: MovableClock) -> IncidentStateMachine:
    return IncidentStateMachine(clock=clock)


@pytest.fixture
def rollback_action(pipeline: AssessmentPipeline) -> Action:
    """The golden-incident rollback of payment-api, assessed."""
    return pipeline.assess(
        build_action(
            requesting_agent="remediation",
            capability="production.rollback",
            target_resource=PAYMENT_API,
        )
    ).require_assessed_action()


def make_event(
    *,
    event_id: str = "evt-000000",
    event_type: str = "policy.decision",
    incident_id: str | None = "INC-2026-0001",
    actor: str = "system:test",
    timestamp: datetime | None = None,
) -> AuditEvent:
    """A minimal hand-built event, for store mechanics that need no real artifact."""
    return AuditEvent(
        event_id=event_id,
        timestamp=timestamp or FIXED_EVALUATION_TIME,
        actor=actor,
        incident_id=incident_id,
        event_type=event_type,
    )
