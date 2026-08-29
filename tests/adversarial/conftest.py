"""Fixtures for the adversarial suite. No credentials, no network, no live model.

The matrix in :mod:`aegis.evaluation.adversarial` performs the attacks and records what
happened; the assertions live here. That split is deliberate — a module that both attacked
and graded would be marking its own homework, and the whole point of the matrix is that its
verdict can be checked against artifacts it does not control.

Every attack runs once per session. They are deterministic (injected clock, simulated
enterprise, scripted models), so running them once and asserting over the results is the
same as running each one inside its own test, only faster.
"""

from __future__ import annotations

import pytest

from aegis.enterprise import PAYMENT_API_RECOVERED
from aegis.evaluation.adversarial import (
    AdversarialFixture,
    AttackClass,
    AttackResult,
    Containment,
    honest_baseline,
    run_matrix,
)
from tests.fleet import (
    BUSINESS_IMPACT,
    COMMANDER,
    DIAGNOSTIC,
    REMEDIATION,
    SECURITY,
    build_registry,
    fixed_clock,
)

__all__ = ["by_class", "one"]


@pytest.fixture(scope="session")
def fixture() -> AdversarialFixture:
    """The same fleet the benchmark and the unit suite measure.

    Reused rather than invented so that "AEGIS held" is a statement about the declared
    organizational configuration, not about one written to be easy to defend.
    """
    return AdversarialFixture(
        registry=build_registry(),
        agents={
            "commander": COMMANDER,
            "diagnostic": DIAGNOSTIC,
            "security": SECURITY,
            "business-impact": BUSINESS_IMPACT,
            "remediation": REMEDIATION,
        },
        expected_state=PAYMENT_API_RECOVERED,
        clock=fixed_clock,
    )


@pytest.fixture(scope="session")
def results(fixture: AdversarialFixture) -> tuple[AttackResult, ...]:
    return run_matrix(fixture)


@pytest.fixture(scope="session")
def baseline(fixture: AdversarialFixture):
    """The golden incident with no payload: the thing inert attacks are compared against."""
    return honest_baseline(fixture)


def one(results: tuple[AttackResult, ...], attack_id: str) -> AttackResult:
    """One attack by id, or a failure naming what is available.

    Raises rather than returning ``None`` so that a renamed attack fails the test that
    depended on it instead of silently asserting nothing.
    """
    for result in results:
        if result.attack_id == attack_id:
            return result
    raise AssertionError(
        f"no attack {attack_id!r}; available: {', '.join(r.attack_id for r in results)}"
    )


def by_class(
    results: tuple[AttackResult, ...], attack_class: AttackClass
) -> tuple[AttackResult, ...]:
    found = tuple(result for result in results if result.attack_class is attack_class)
    assert found, f"no attacks in class {attack_class}"
    return found


def refused(results: tuple[AttackResult, ...]) -> tuple[AttackResult, ...]:
    return tuple(r for r in results if r.containment is Containment.REFUSED)


def inert(results: tuple[AttackResult, ...]) -> tuple[AttackResult, ...]:
    return tuple(r for r in results if r.containment is Containment.INERT)
