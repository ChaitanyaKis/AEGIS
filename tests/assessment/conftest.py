"""Fixtures for the assessment suite.

Everything is built from the shared test fleet, so the blast-radius engine, risk engine,
pipeline and policy engine all reason about the same world. No mocks anywhere: the
integration tests exercise the real engines end to end.
"""

from __future__ import annotations

import pytest

from aegis.core.assessment import AssessmentPipeline, BlastRadiusEngine, RiskEngine
from aegis.core.capabilities import CapabilityRegistry
from aegis.core.dependencies import DependencyGraph
from aegis.core.policy import PolicyEngine
from tests.fleet import build_graph, build_registry, fixed_clock


@pytest.fixture
def registry() -> CapabilityRegistry:
    return build_registry()


@pytest.fixture
def graph() -> DependencyGraph:
    return build_graph()


@pytest.fixture
def blast_radius_engine(graph: DependencyGraph) -> BlastRadiusEngine:
    return BlastRadiusEngine(graph)


@pytest.fixture
def risk_engine() -> RiskEngine:
    return RiskEngine()


@pytest.fixture
def pipeline(registry: CapabilityRegistry, graph: DependencyGraph) -> AssessmentPipeline:
    return AssessmentPipeline(registry, graph)


@pytest.fixture
def policy_engine(registry: CapabilityRegistry) -> PolicyEngine:
    return PolicyEngine(registry, clock=fixed_clock)
