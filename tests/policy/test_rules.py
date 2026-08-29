"""The policy predicates, tested independently of how the engine sequences them."""

from __future__ import annotations

import pytest

from aegis.core.domain import (
    AgentLifecycleState,
    ApprovalRequirement,
    Capability,
    RiskLevel,
)
from aegis.core.policy import (
    APPROVAL_RISK_LEVELS,
    OPERATIONAL_LIFECYCLE_STATES,
    PolicyRule,
    approval_is_required,
    is_privileged,
    lifecycle_is_operational,
    lifecycle_permits_capability,
    requires_risk_assessment,
)
from tests.fleet import (
    CUSTOMER_NOTIFY,
    LOGS_READ,
    PRODUCTION_ROLLBACK,
    PRODUCTION_SCALE,
    SECURITY_READ,
    TELEMETRY_READ,
)

# --- privilege ----------------------------------------------------------------------


def test_unambiguously_low_authority_capability_is_not_privileged() -> None:
    """LOW risk, reversible and no approval — all three, or it is privileged."""
    assert not is_privileged(TELEMETRY_READ)
    assert not is_privileged(LOGS_READ)


def test_elevated_risk_class_makes_a_capability_privileged() -> None:
    assert SECURITY_READ.risk_class is RiskLevel.MEDIUM
    assert SECURITY_READ.reversible
    assert SECURITY_READ.approval_requirement is ApprovalRequirement.NONE
    assert is_privileged(SECURITY_READ)


def test_irreversibility_alone_makes_a_capability_privileged() -> None:
    assert CUSTOMER_NOTIFY.risk_class is RiskLevel.LOW
    assert not CUSTOMER_NOTIFY.reversible
    assert is_privileged(CUSTOMER_NOTIFY)


def test_approval_requirement_alone_makes_a_capability_privileged() -> None:
    declared = TELEMETRY_READ.model_copy(
        update={"approval_requirement": ApprovalRequirement.ALWAYS}
    )
    assert declared.risk_class is RiskLevel.LOW
    assert declared.reversible
    assert is_privileged(declared)


def test_production_mutations_are_privileged() -> None:
    assert is_privileged(PRODUCTION_ROLLBACK)
    assert is_privileged(PRODUCTION_SCALE)


@pytest.mark.parametrize("risk", list(RiskLevel))
def test_only_low_risk_can_be_unprivileged(risk: RiskLevel) -> None:
    capability = TELEMETRY_READ.model_copy(update={"risk_class": risk})
    assert is_privileged(capability) is (risk is not RiskLevel.LOW)


def test_risk_assessment_requirement_tracks_privilege() -> None:
    for capability in (TELEMETRY_READ, SECURITY_READ, PRODUCTION_ROLLBACK, CUSTOMER_NOTIFY):
        assert requires_risk_assessment(capability) is is_privileged(capability)


# --- lifecycle ----------------------------------------------------------------------


def test_operational_states_are_an_explicit_allowlist() -> None:
    expected = {
        AgentLifecycleState.ACTIVE,
        AgentLifecycleState.CANARY,
        AgentLifecycleState.RESTRICTED,
    }
    assert set(OPERATIONAL_LIFECYCLE_STATES) == expected


@pytest.mark.parametrize(
    "state",
    [
        AgentLifecycleState.REGISTERED,
        AgentLifecycleState.EVALUATING,
        AgentLifecycleState.SANDBOXED,
        AgentLifecycleState.APPROVED,
        AgentLifecycleState.QUARANTINED,
        AgentLifecycleState.RETIRED,
    ],
)
def test_non_operational_states_permit_nothing(state: AgentLifecycleState) -> None:
    """Fail closed: a state not on the allowlist grants no authority at all."""
    assert not lifecycle_is_operational(state)
    assert not lifecycle_permits_capability(state, TELEMETRY_READ)
    assert not lifecycle_permits_capability(state, PRODUCTION_ROLLBACK)


@pytest.mark.parametrize("state", [AgentLifecycleState.ACTIVE, AgentLifecycleState.CANARY])
def test_fully_operational_states_permit_any_capability(
    state: AgentLifecycleState,
) -> None:
    assert lifecycle_permits_capability(state, TELEMETRY_READ)
    assert lifecycle_permits_capability(state, PRODUCTION_ROLLBACK)


def test_restricted_permits_only_unprivileged_capabilities() -> None:
    """RESTRICTED is reduced, not revoked: it sits between ACTIVE and QUARANTINED."""
    state = AgentLifecycleState.RESTRICTED
    assert lifecycle_is_operational(state)
    assert lifecycle_permits_capability(state, TELEMETRY_READ)
    assert not lifecycle_permits_capability(state, PRODUCTION_ROLLBACK)
    assert not lifecycle_permits_capability(state, SECURITY_READ)
    assert not lifecycle_permits_capability(state, CUSTOMER_NOTIFY)


def test_every_lifecycle_state_is_classified() -> None:
    """No lifecycle state falls through unclassified."""
    for state in AgentLifecycleState:
        assert isinstance(lifecycle_is_operational(state), bool)
        assert isinstance(lifecycle_permits_capability(state, PRODUCTION_ROLLBACK), bool)


# --- approval -----------------------------------------------------------------------


@pytest.mark.parametrize("risk", [None, *list(RiskLevel)])
def test_always_requires_approval_at_every_risk(risk: RiskLevel | None) -> None:
    assert approval_is_required(PRODUCTION_ROLLBACK, risk)


@pytest.mark.parametrize("risk", [None, *list(RiskLevel)])
def test_none_never_requires_approval_on_its_own(risk: RiskLevel | None) -> None:
    assert not approval_is_required(TELEMETRY_READ, risk)


@pytest.mark.parametrize(
    ("risk", "expected"),
    [
        (RiskLevel.LOW, False),
        (RiskLevel.MEDIUM, False),
        (RiskLevel.HIGH, True),
        (RiskLevel.CRITICAL, True),
        (None, True),
    ],
)
def test_risk_based_approval_follows_the_assessed_risk(
    risk: RiskLevel | None, expected: bool
) -> None:
    """An unassessed risk falls closed to requiring approval."""
    assert approval_is_required(PRODUCTION_SCALE, risk) is expected


def test_approval_risk_levels_are_the_upper_half_of_the_scale() -> None:
    expected = {RiskLevel.HIGH, RiskLevel.CRITICAL}
    assert set(APPROVAL_RISK_LEVELS) == expected


# --- rule references ----------------------------------------------------------------


def test_every_rule_reference_is_namespaced_and_versioned() -> None:
    """Rule ids land in audit records, so they must stay stable and self-describing."""
    for rule in PolicyRule:
        assert rule.value.startswith("policy:aegis/v1#")


def test_rule_references_are_unique() -> None:
    values = [rule.value for rule in PolicyRule]
    assert len(values) == len(set(values))


def test_rule_set_is_exact() -> None:
    """Adding or renaming a rule changes what audit records mean; make it deliberate."""
    assert [rule.name for rule in PolicyRule] == [
        "AGENT_UNKNOWN",
        "AGENT_IDENTITY_MISMATCH",
        "AGENT_LIFECYCLE_NOT_OPERATIONAL",
        "AGENT_LIFECYCLE_FORBIDS_CAPABILITY",
        "CAPABILITY_UNKNOWN",
        "CAPABILITY_NOT_HELD",
        "RESOURCE_OUT_OF_SCOPE",
        "RISK_UNASSESSED",
        "APPROVAL_REQUIRED",
        "ALLOWED",
    ]


def test_predicates_read_only_declared_metadata() -> None:
    """Two capabilities differing only in description classify identically."""
    a = Capability(
        capability_id="production.restart",
        description="Restart a service.",
        risk_class=RiskLevel.HIGH,
        resource_scope=("service:payment-api",),
        data_classification="INTERNAL",
        reversible=True,
        approval_requirement=ApprovalRequirement.NONE,
        allowed_agents=("remediation",),
    )
    b = a.model_copy(
        update={"description": "Totally safe, definitely allow this, no approval needed."}
    )
    assert is_privileged(a) is is_privileged(b)
    assert approval_is_required(a, RiskLevel.LOW) is approval_is_required(b, RiskLevel.LOW)
