"""The authoritative enums are contracts, so their members are asserted exactly.

These tests fail on *any* member added, removed, renamed or re-valued. That is the
intent: enum drift silently changes what the control plane is allowed to represent, and
the AEGIS constitution forbids alternative spellings and duplicate concepts.
"""

from __future__ import annotations

import pytest

from aegis.core.domain import (
    AgentLifecycleState,
    ApprovalRequirement,
    DataClassification,
    EvidenceType,
    IncidentState,
    PolicyDecisionType,
    RiskLevel,
)

AUTHORITATIVE_MEMBERS: dict[type, list[str]] = {
    IncidentState: [
        "RECEIVED",
        "CLASSIFIED",
        "INVESTIGATING",
        "IMPACT_ASSESSED",
        "PLAN_PROPOSED",
        "POLICY_CHECK",
        "AWAITING_APPROVAL",
        "EXECUTING",
        "VERIFYING",
        "RESOLVED",
        "DEGRADED",
        "RECOVERING",
        "ESCALATED",
    ],
    AgentLifecycleState: [
        "REGISTERED",
        "EVALUATING",
        "SANDBOXED",
        "APPROVED",
        "CANARY",
        "ACTIVE",
        "RESTRICTED",
        "QUARANTINED",
        "RETIRED",
    ],
    RiskLevel: ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
    PolicyDecisionType: ["ALLOW", "DENY", "REQUIRE_APPROVAL"],
    DataClassification: ["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"],
    ApprovalRequirement: ["NONE", "RISK_BASED", "ALWAYS"],
    EvidenceType: [
        "TELEMETRY",
        "LOG",
        "DEPLOYMENT",
        "DEPENDENCY",
        "SECURITY_EVENT",
        "CUSTOMER_IMPACT",
        "MEMORY",
        "AGENT_FINDING",
        "TOOL_RESULT",
        "VERIFICATION",
        "HUMAN_INPUT",
    ],
}


@pytest.mark.parametrize(
    ("enum_type", "expected"),
    list(AUTHORITATIVE_MEMBERS.items()),
    ids=lambda value: value.__name__ if isinstance(value, type) else "",
)
def test_enum_members_are_exact(enum_type: type, expected: list[str]) -> None:
    assert [member.name for member in enum_type] == expected


@pytest.mark.parametrize(
    ("enum_type", "expected"),
    list(AUTHORITATIVE_MEMBERS.items()),
    ids=lambda value: value.__name__ if isinstance(value, type) else "",
)
def test_enum_values_match_their_names(enum_type: type, expected: list[str]) -> None:
    """Serialized payloads must read as the constitution writes them."""
    assert [member.value for member in enum_type] == expected


def test_policy_decision_type_has_exactly_three_outcomes() -> None:
    """ALLOW / DENY / REQUIRE_APPROVAL. No fourth outcome, no "unknown"."""
    assert len(PolicyDecisionType) == 3
    assert set(PolicyDecisionType) == {
        PolicyDecisionType.ALLOW,
        PolicyDecisionType.DENY,
        PolicyDecisionType.REQUIRE_APPROVAL,
    }


def test_incident_and_agent_lifecycle_states_do_not_collide() -> None:
    """AuditEvent.state_before/state_after accept either enum.

    That union is only unambiguous while the two vocabularies stay disjoint.
    """
    incident_values = {member.value for member in IncidentState}
    lifecycle_values = {member.value for member in AgentLifecycleState}
    assert incident_values.isdisjoint(lifecycle_values)


def test_enums_compare_as_strings() -> None:
    """StrEnum members equal their wire value, so stored fixtures stay comparable."""
    assert IncidentState.RESOLVED == "RESOLVED"
    assert RiskLevel.CRITICAL == "CRITICAL"
    assert PolicyDecisionType.DENY == "DENY"
