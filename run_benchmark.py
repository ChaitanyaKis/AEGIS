"""Run the AEGIS deterministic governance benchmark and print the report.

    uv run python run_benchmark.py

The suite is deterministic: the clock is injected, the enterprise is simulated, and no
model, credential or network call is involved. Two runs produce the same report.

The capability catalogue and agent roster come from ``tests.fleet``. That is deliberate
rather than expedient — the benchmark measures a *declared organizational configuration*,
and reusing the one the rest of the test suite asserts against keeps the benchmark and the
unit tests describing the same fleet. :class:`EvaluationEnvironment` takes both as
arguments, so a different organization can be measured without editing this file.

Exit code is 0 when the suite passes and 1 when it does not, so CI can gate on it.
"""

from __future__ import annotations

import sys

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

from aegis.enterprise import PAYMENT_API_RECOVERED
from aegis.evaluation import (
    AgentProfile,
    EvaluationEnvironment,
    EvaluationSuiteRunner,
    SuiteStatus,
)
from aegis.evaluation.catalogue import BENCHMARK_SCENARIOS

BENCHMARK_FLEET = {
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
    """The environment the benchmark measures."""
    return EvaluationEnvironment(
        build_registry(),
        dict(BENCHMARK_FLEET),
        expected_state=PAYMENT_API_RECOVERED,
        clock=fixed_clock,
    )


def main() -> int:
    report = EvaluationSuiteRunner(build_environment()).run(BENCHMARK_SCENARIOS)
    print(report.render())
    return 0 if report.status is SuiteStatus.PASS else 1


if __name__ == "__main__":
    sys.exit(main())
