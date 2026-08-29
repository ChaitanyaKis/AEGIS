"""Fixtures for the incident lifecycle suite."""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from aegis.core.approval import ApprovalEngine
from aegis.core.assessment import AssessmentPipeline
from aegis.core.capabilities import CapabilityRegistry
from aegis.core.incidents import IncidentStateMachine
from aegis.core.policy import PolicyEngine
from tests.fleet import FIXED_EVALUATION_TIME, build_graph, build_registry, fixed_clock


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
def machine(clock: MovableClock) -> IncidentStateMachine:
    return IncidentStateMachine(clock=clock)
