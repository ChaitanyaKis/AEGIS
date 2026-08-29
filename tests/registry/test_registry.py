from __future__ import annotations

from datetime import datetime

import pytest

from aegis.registry import (
    AgentAlreadyRegistered,
    AgentRegistry,
    AgentVersion,
    ApprovalStatus,
    IllegalRegistryTransition,
    RegistryRefusal,
    RegistryStatus,
    UnknownAgentVersion,
    UnknownRegisteredAgent,
)


from datetime import datetime, timezone

def _clock() -> datetime:
    return datetime(2026, 8, 29, 12, 0, 0, tzinfo=timezone.utc)


def test_registration_starts_at_draft_and_pending() -> None:
    registry = AgentRegistry(clock=_clock)
    record = registry.register(
        agent_id="remediation",
        version="1.0.0",
        name="Remediation",
        description="Fixes issues",
        owner="security",
        department="engineering",
        identity="service-account",
        capabilities=["production.rollback"],
    )

    assert record.status is RegistryStatus.DRAFT
    assert record.approval_status is ApprovalStatus.PENDING
    assert record.agent_id == "remediation"
    assert record.version == AgentVersion("1.0.0")


def test_cannot_register_duplicate_version() -> None:
    registry = AgentRegistry(clock=_clock)
    registry.register(
        agent_id="remediation",
        version="1.0.0",
        name="Remediation",
        description="Fixes issues",
        owner="security",
        department="engineering",
        identity="service-account",
    )

    with pytest.raises(AgentAlreadyRegistered):
        registry.register(
            agent_id="remediation",
            version="1.0.0",
            name="Remediation",
            description="Fixes issues",
            owner="security",
            department="engineering",
            identity="service-account",
        )


def test_lifecycle_transitions() -> None:
    registry = AgentRegistry(clock=_clock)
    registry.register(
        agent_id="remediation",
        version="1.0.0",
        name="Remediation",
        description="Fixes issues",
        owner="security",
        department="engineering",
        identity="service-account",
    )

    registry.publish("remediation", "1.0.0", actor="ops")
    assert registry.get("remediation", "1.0.0").status is RegistryStatus.PUBLISHED

    registry.approve("remediation", "1.0.0", approver="alice")
    record = registry.get("remediation", "1.0.0")
    assert record.status is RegistryStatus.APPROVED
    assert record.approval_status is ApprovalStatus.GRANTED

    registry.activate("remediation", "1.0.0", actor="ops")
    assert registry.get("remediation", "1.0.0").status is RegistryStatus.ACTIVE

    registry.suspend("remediation", "1.0.0", actor="ops", reason="investigating")
    assert registry.get("remediation", "1.0.0").status is RegistryStatus.SUSPENDED

    registry.activate("remediation", "1.0.0", actor="ops")
    assert registry.get("remediation", "1.0.0").status is RegistryStatus.ACTIVE

    registry.revoke("remediation", "1.0.0", actor="sec", reason="compromised")
    assert registry.get("remediation", "1.0.0").status is RegistryStatus.REVOKED


def test_cannot_activate_without_approval() -> None:
    registry = AgentRegistry(clock=_clock)
    registry.register(
        agent_id="remediation",
        version="1.0.0",
        name="Remediation",
        description="Fixes issues",
        owner="security",
        department="engineering",
        identity="service-account",
    )
    registry.publish("remediation", "1.0.0", actor="ops")

    with pytest.raises(IllegalRegistryTransition):
        registry.activate("remediation", "1.0.0", actor="ops")


def test_rejection_revokes_and_sets_status() -> None:
    registry = AgentRegistry(clock=_clock)
    registry.register(
        agent_id="remediation",
        version="1.0.0",
        name="Remediation",
        description="Fixes issues",
        owner="security",
        department="engineering",
        identity="service-account",
    )
    registry.publish("remediation", "1.0.0", actor="ops")

    record = registry.reject("remediation", "1.0.0", approver="alice", reason="unsafe")
    assert record.status is RegistryStatus.REVOKED
    assert record.approval_status is ApprovalStatus.REJECTED


def test_deterministic_version_selection() -> None:
    registry = AgentRegistry(clock=_clock)
    for v in ["1.0.0", "1.9.0", "1.10.0", "2.0.0"]:
        registry.register(
            agent_id="remediation",
            version=v,
            name="Remediation",
            description="Fixes",
            owner="security",
            department="engineering",
            identity="service",
        )
        registry.publish("remediation", v, actor="ops")
        registry.approve("remediation", v, approver="alice")
        registry.activate("remediation", v, actor="ops")

    # Suspend 2.0.0
    registry.suspend("remediation", "2.0.0", actor="ops", reason="bug")

    # Fallback should be 1.10.0, not 1.9.0
    selected = registry.select("remediation")
    assert selected is not None
    assert selected.version == AgentVersion("1.10.0")


def test_eligibility_verdict_invalid_version() -> None:
    registry = AgentRegistry(clock=_clock)
    registry.register(
        agent_id="remediation",
        version="1.0.0",
        name="Remediation",
        description="Fixes",
        owner="security",
        department="engineering",
        identity="service",
    )
    
    verdict = registry.eligibility("remediation", "invalid-version")
    assert not verdict.eligible
    assert verdict.refusal is RegistryRefusal.UNKNOWN_VERSION


def test_eligibility_verdict_unapproved() -> None:
    registry = AgentRegistry(clock=_clock)
    registry.register(
        agent_id="remediation",
        version="1.0.0",
        name="Remediation",
        description="Fixes",
        owner="security",
        department="engineering",
        identity="service",
    )
    registry.publish("remediation", "1.0.0", actor="ops")
    
    verdict = registry.eligibility("remediation", "1.0.0")
    assert not verdict.eligible
    assert verdict.refusal is RegistryRefusal.NOT_APPROVED


def test_eligibility_verdict_active() -> None:
    registry = AgentRegistry(clock=_clock)
    registry.register(
        agent_id="remediation",
        version="1.0.0",
        name="Remediation",
        description="Fixes",
        owner="security",
        department="engineering",
        identity="service",
        capabilities=["production.rollback"]
    )
    registry.publish("remediation", "1.0.0", actor="ops")
    registry.approve("remediation", "1.0.0", approver="alice")
    registry.activate("remediation", "1.0.0", actor="ops")
    
    verdict = registry.eligibility("remediation", "1.0.0")
    assert verdict.eligible
    assert verdict.refusal is RegistryRefusal.NONE

    # Test capability check
    verdict_cap = registry.eligibility("remediation", "1.0.0", capability="production.rollback")
    assert verdict_cap.eligible

    verdict_no_cap = registry.eligibility("remediation", "1.0.0", capability="unknown.cap")
    assert not verdict_no_cap.eligible
    assert verdict_no_cap.refusal is RegistryRefusal.CAPABILITY_NOT_DECLARED

    # Test identity check
    verdict_id = registry.eligibility("remediation", "1.0.0", identity="service")
    assert verdict_id.eligible

    verdict_no_id = registry.eligibility("remediation", "1.0.0", identity="wrong")
    assert not verdict_no_id.eligible
    assert verdict_no_id.refusal is RegistryRefusal.IDENTITY_MISMATCH
