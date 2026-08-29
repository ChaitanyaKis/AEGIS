"""Deterministic assessment: how far an action reaches, and how risky it is.

Trust zone C (``claude.md`` section 4). Sits between the agent plane and the policy
engine, turning an unassessed proposal into an action carrying authoritative ``risk`` and
``blast_radius``:

    AGENT PROPOSAL -> BLAST RADIUS -> RISK -> POLICY ENGINE

Nothing here reads what an agent declared about its own risk or reach, and nothing here
calls a model. It authorizes nothing either — the policy engine remains the sole
authorization layer.
"""

from aegis.core.assessment.blast_radius import (
    REACH_THRESHOLDS,
    BlastRadiusAssessment,
    BlastRadiusEngine,
    is_disruptive,
)
from aegis.core.assessment.pipeline import (
    Assessment,
    AssessmentOutcome,
    AssessmentPipeline,
)
from aegis.core.assessment.risk import (
    IRREVERSIBLE_FLOOR,
    SENSITIVITY_FLOORS,
    RiskAssessment,
    RiskEngine,
    RiskFactor,
)
from aegis.core.assessment.scale import RISK_ORDER, max_risk

__all__ = [
    "IRREVERSIBLE_FLOOR",
    "REACH_THRESHOLDS",
    "RISK_ORDER",
    "SENSITIVITY_FLOORS",
    "Assessment",
    "AssessmentOutcome",
    "AssessmentPipeline",
    "BlastRadiusAssessment",
    "BlastRadiusEngine",
    "RiskAssessment",
    "RiskEngine",
    "RiskFactor",
    "is_disruptive",
    "max_risk",
]
