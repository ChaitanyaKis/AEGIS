"""Fixtures for the verification suite. Injected clocks only — no sleeps, no wall time."""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from aegis.core.assessment import AssessmentPipeline
from aegis.core.capabilities import CapabilityRegistry
from aegis.core.domain import Action
from aegis.core.incidents import IncidentStateMachine
from aegis.core.verification import VerificationEngine
from tests.fleet import (
    FIXED_EVALUATION_TIME,
    PAYMENT_API,
    build_action,
    build_graph,
    build_registry,
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
def registry() -> CapabilityRegistry:
    return build_registry()


@pytest.fixture
def pipeline(registry: CapabilityRegistry) -> AssessmentPipeline:
    return AssessmentPipeline(registry, build_graph())


@pytest.fixture
def engine(clock: MovableClock) -> VerificationEngine:
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
