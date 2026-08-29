"""Fixtures for the simulated-enterprise suite. Injected clocks only, never wall time."""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from aegis.enterprise import (
    ActionExecutor,
    EnterpriseWorld,
    GoldenIncidentScenario,
    ObservationSource,
)
from tests.fleet import FIXED_EVALUATION_TIME, REMEDIATION, build_registry


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
def world() -> EnterpriseWorld:
    return EnterpriseWorld()


@pytest.fixture
def executor(world: EnterpriseWorld, clock: MovableClock) -> ActionExecutor:
    return ActionExecutor(world, clock=clock)


@pytest.fixture
def source(world: EnterpriseWorld) -> ObservationSource:
    return ObservationSource(world)


@pytest.fixture
def scenario(clock: MovableClock) -> GoldenIncidentScenario:
    return GoldenIncidentScenario(build_registry(), REMEDIATION, clock=clock)
