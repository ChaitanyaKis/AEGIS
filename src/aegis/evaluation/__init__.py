"""The AEGIS deterministic governance benchmark (``claude.md`` section 21).

Measures whether AEGIS makes the **correct** decision across a population of controlled
scenarios — including the many where the correct decision is to refuse. A benchmark
containing only successful incidents proves nothing about safety.

It is a governance and safety benchmark, not a measure of model quality. Every scenario
runs against deterministic test models, so results stay stable as providers change; a
live-model evaluation would be a separate exercise with different claims.

The evaluator has no authority. It reads the artifacts the control plane produced and
compares them with each scenario declared expectation. It never authorizes, never
re-derives risk, and never repairs what it finds.

The number that matters most::

    unauthorized_high_impact_actions == 0

Anything else fails the benchmark, however good the other metrics look.
"""

from aegis.evaluation.metrics import (
    EvaluationMetrics,
    EvaluationReport,
    MetricValue,
    SuiteStatus,
    build_metrics,
)
from aegis.evaluation.results import (
    CriticalViolation,
    EvaluationResult,
    Mismatch,
    MismatchSeverity,
    ObservedOutcome,
    ViolationType,
)
from aegis.evaluation.runner import (
    APPROVAL_RISK_LEVELS,
    EvaluationEnvironment,
    EvaluationRunner,
    EvaluationSuiteRunner,
)
from aegis.evaluation.scenario import (
    AgentProfile,
    ExpectedOutcome,
    ModelBehaviour,
    RoutingExpectation,
    Scenario,
    ScenarioCategory,
    SpecialistBehaviour,
)

__all__ = [
    "APPROVAL_RISK_LEVELS",
    "AgentProfile",
    "CriticalViolation",
    "EvaluationEnvironment",
    "EvaluationMetrics",
    "EvaluationReport",
    "EvaluationResult",
    "EvaluationRunner",
    "EvaluationSuiteRunner",
    "ExpectedOutcome",
    "MetricValue",
    "Mismatch",
    "MismatchSeverity",
    "ModelBehaviour",
    "ObservedOutcome",
    "RoutingExpectation",
    "Scenario",
    "ScenarioCategory",
    "SpecialistBehaviour",
    "SuiteStatus",
    "ViolationType",
    "build_metrics",
]
