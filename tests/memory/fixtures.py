"""Shared builders for the memory suites.

Everything here produces *real* control-plane artifacts — a real `Action`, a real
`VerificationResult` — rather than stand-ins. Admission's whole job is to check bindings
between genuine artifacts, so testing it against hand-rolled doubles would test the doubles.
"""

from __future__ import annotations

from datetime import timedelta

from aegis.core.approval import action_fingerprint
from aegis.core.domain import Action, RiskLevel
from aegis.core.verification import VerificationResult, VerificationStatus
from aegis.core.verification.results import CheckOutcome, Comparator, PredicateCheck
from aegis.memory import MemoryCandidate, MemoryType
from tests.fleet import FIXED_EVALUATION_TIME, PAYMENT_API, build_action

INCIDENT_A = "INC-2026-0001"
INCIDENT_B = "INC-2026-0002"
OBSERVATION_IDS = ("obs-telemetry-001", "obs-deployment-001")


def action(
    *,
    incident_id: str = INCIDENT_A,
    action_id: str = "act-001",
    target_resource: str = PAYMENT_API,
    capability: str = "production.rollback",
    risk: RiskLevel | None = RiskLevel.HIGH,
) -> Action:
    """A proposed and assessed rollback."""
    return build_action(
        requesting_agent="remediation",
        capability=capability,
        target_resource=target_resource,
        risk=risk,
        action_id=action_id,
        incident_id=incident_id,
    )


def verification(
    subject: Action,
    *,
    status: VerificationStatus = VerificationStatus.VERIFIED,
    verification_id: str = "ver-001",
    incident_id: str | None = None,
    action_id: str | None = None,
    fingerprint: str | None = None,
    resource: str | None = None,
    observations: tuple[str, ...] = OBSERVATION_IDS,
    age: timedelta = timedelta(0),
) -> VerificationResult:
    """A verification artifact for ``subject``, with every binding overridable.

    The overrides exist so a test can produce a *plausible but wrongly bound* artifact —
    right shape, wrong incident or wrong action — which is exactly what admission must
    refuse.
    """
    return VerificationResult(
        verification_id=verification_id,
        incident_id=incident_id if incident_id is not None else subject.incident_id,
        action_id=action_id if action_id is not None else subject.action_id,
        action_fingerprint=(
            fingerprint if fingerprint is not None else action_fingerprint(subject)
        ),
        resource=resource if resource is not None else subject.target_resource,
        status=status,
        checks=(
            PredicateCheck(
                attribute="deployment",
                comparator=Comparator.EQUALS,
                expected="v4.7",
                observed="v4.7",
                outcome=CheckOutcome.PASS,
                observation_ids=observations,
                detail="deployment EQUALS v4.7",
            ),
        ),
        observations_used=observations,
        evaluated_at=FIXED_EVALUATION_TIME - age,
        reason="the expected state was observed",
    )


def candidate(
    *,
    incident_id: str = INCIDENT_A,
    agent_id: str = "remediation",
    memory_type: MemoryType = MemoryType.REMEDIATION_OUTCOME,
    summary: str = "rolling payment-api back to v4.7 restored it",
    content: dict | None = None,
    supporting_evidence: tuple[str, ...] = (),
    verification_id: str | None = None,
    action_id: str | None = None,
) -> MemoryCandidate:
    """A memory proposal. Note it has no status field to set."""
    return MemoryCandidate(
        memory_type=memory_type,
        incident_id=incident_id,
        agent_id=agent_id,
        summary=summary,
        content=content if content is not None else {"capability": "production.rollback"},
        supporting_evidence=supporting_evidence,
        verification_id=verification_id,
        action_id=action_id,
    )
