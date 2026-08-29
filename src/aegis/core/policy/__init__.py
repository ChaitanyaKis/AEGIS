"""Deterministic policy engine — the authoritative authorization boundary.

Trust zone C (``claude.md`` sections 2, 5): an agent may *propose* an action; this
package independently decides whether it is permitted. Nothing here calls a model, and
no model output can widen what it permits.

Decisions are limited to the three authoritative outcomes with precedence
``DENY > REQUIRE_APPROVAL > ALLOW``, enforced structurally: hard-deny gates return
before approval or allow can be reached.
"""

from aegis.core.policy.engine import PolicyChecks, PolicyEngine, PolicyEvaluation
from aegis.core.policy.rules import (
    APPROVAL_RISK_LEVELS,
    OPERATIONAL_LIFECYCLE_STATES,
    PolicyRule,
    approval_is_required,
    is_privileged,
    lifecycle_is_operational,
    lifecycle_permits_capability,
    requires_risk_assessment,
)

__all__ = [
    "APPROVAL_RISK_LEVELS",
    "OPERATIONAL_LIFECYCLE_STATES",
    "PolicyChecks",
    "PolicyEngine",
    "PolicyEvaluation",
    "PolicyRule",
    "approval_is_required",
    "is_privileged",
    "lifecycle_is_operational",
    "lifecycle_permits_capability",
    "requires_risk_assessment",
]
