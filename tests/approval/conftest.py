"""Fixtures for the approval suite.

The clock is a mutable holder so a test can move time forward deterministically without
ever touching wall time.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta

import pytest

from aegis.core.approval import ApprovalEngine
from aegis.core.assessment import AssessmentPipeline
from aegis.core.capabilities import CapabilityRegistry
from aegis.core.dependencies import DependencyGraph
from aegis.core.domain import Action
from aegis.core.policy import PolicyEngine
from tests.fleet import (
    FIXED_EVALUATION_TIME,
    PAYMENT_API,
    REMEDIATION,
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
def registry() -> CapabilityRegistry:
    return build_registry()


@pytest.fixture
def graph() -> DependencyGraph:
    return build_graph()


@pytest.fixture
def policy_engine(registry: CapabilityRegistry) -> PolicyEngine:
    return PolicyEngine(registry, clock=fixed_clock)


@pytest.fixture
def pipeline(registry: CapabilityRegistry, graph: DependencyGraph) -> AssessmentPipeline:
    return AssessmentPipeline(registry, graph)


@pytest.fixture
def approval_engine(policy_engine: PolicyEngine, clock: MovableClock) -> ApprovalEngine:
    return ApprovalEngine(policy_engine, clock=clock)


@pytest.fixture
def assess(pipeline: AssessmentPipeline) -> Callable[..., Action]:
    """Assess a proposal through the real pipeline, returning the assessed action."""

    def _assess(
        *,
        capability: str = "production.rollback",
        requesting_agent: str = "remediation",
        target_resource: str = PAYMENT_API,
        action_id: str = "act-001",
    ) -> Action:
        proposal = build_action(
            requesting_agent=requesting_agent,
            capability=capability,
            target_resource=target_resource,
            action_id=action_id,
        )
        return pipeline.assess(proposal).require_assessed_action()

    return _assess


@pytest.fixture
def rollback_action(assess: Callable[..., Action]) -> Action:
    """The golden-incident rollback, assessed: HIGH risk, REQUIRE_APPROVAL."""
    return assess()


@pytest.fixture
def remediation_agent():
    return REMEDIATION
