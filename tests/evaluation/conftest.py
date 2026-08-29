"""Fixtures for the evaluation suites.

The environment is built from the shared fleet so the benchmark measures the same
capability catalogue and agent roster the rest of the tests use. Everything is clock-
injected: a scenario run twice must produce the same bytes.
"""

from __future__ import annotations

import pytest

from aegis.enterprise import PAYMENT_API_RECOVERED
from aegis.evaluation import (
    AgentProfile,
    EvaluationEnvironment,
    EvaluationRunner,
    EvaluationSuiteRunner,
)
from tests.fleet import (
    BUSINESS_IMPACT,
    COMMANDER,
    DIAGNOSTIC,
    QUARANTINED_REMEDIATION,
    REGISTERED_REMEDIATION,
    REMEDIATION,
    RESTRICTED_REMEDIATION,
    RETIRED_REMEDIATION,
    SECURITY,
    UNREGISTERED,
    build_registry,
    fixed_clock,
)

AGENTS = {
    AgentProfile.COMMANDER: COMMANDER,
    AgentProfile.DIAGNOSTIC: DIAGNOSTIC,
    AgentProfile.SECURITY: SECURITY,
    AgentProfile.BUSINESS_IMPACT: BUSINESS_IMPACT,
    AgentProfile.REMEDIATION: REMEDIATION,
    AgentProfile.UNREGISTERED: UNREGISTERED,
    AgentProfile.RESTRICTED_REMEDIATION: RESTRICTED_REMEDIATION,
    AgentProfile.QUARANTINED_REMEDIATION: QUARANTINED_REMEDIATION,
    AgentProfile.RETIRED_REMEDIATION: RETIRED_REMEDIATION,
    AgentProfile.REGISTERED_REMEDIATION: REGISTERED_REMEDIATION,
}


def build_environment() -> EvaluationEnvironment:
    """The benchmark environment. A function, so each test can have its own."""
    return EvaluationEnvironment(
        build_registry(),
        dict(AGENTS),
        expected_state=PAYMENT_API_RECOVERED,
        clock=fixed_clock,
    )


@pytest.fixture
def environment() -> EvaluationEnvironment:
    return build_environment()


@pytest.fixture
def runner(environment: EvaluationEnvironment) -> EvaluationRunner:
    return EvaluationRunner(environment)


@pytest.fixture
def suite_runner(environment: EvaluationEnvironment) -> EvaluationSuiteRunner:
    return EvaluationSuiteRunner(environment)
