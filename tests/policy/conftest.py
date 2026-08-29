"""Fixtures for the policy suite.

The engine under test is given a fixed clock, so every decision it produces is
byte-reproducible and nothing in these tests depends on wall time.
"""

from __future__ import annotations

import pytest

from aegis.core.capabilities import CapabilityRegistry
from aegis.core.policy import PolicyEngine
from tests.fleet import build_registry, fixed_clock


@pytest.fixture
def registry() -> CapabilityRegistry:
    return build_registry()


@pytest.fixture
def engine(registry: CapabilityRegistry) -> PolicyEngine:
    return PolicyEngine(registry, clock=fixed_clock)
