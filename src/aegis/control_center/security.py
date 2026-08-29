"""What was detected, what was refused, and the difference between them.

Part 15, and the distinction it turns on:

    DETECTED  is not  BLOCKED

A detection is an observation. A refusal is something the deterministic control plane
actually did. An operator reading "prompt injection blocked" when all that happened was
"the Security agent noticed hostile text in an incident payload" has been told the system
stopped something it never stopped.

So :class:`SecurityEvent` has an ``outcome`` with three values -- ``DETECTED``, ``REFUSED``,
``CONTAINED`` -- and each is only used where an artifact supports it:

``DETECTED``
    Something noticed hostile content. Nothing was prevented by the noticing.
``REFUSED``
    A deterministic engine returned a refusal: a policy DENY, an A2A rejection, a gate
    rejection, an authentication failure.
``CONTAINED``
    A containment mechanism changed state: a breaker opened, an agent was quarantined, a
    key was revoked.

There is no ``BLOCKED``. The word is missing on purpose, because it is the one an operator
would read as "we are safe" and the one this package is least able to justify.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import Field

from aegis.control_center.capture import ControlCenterInput
from aegis.control_center.models import (
    Completeness,
    Provenance,
    ViewSource,
)
from aegis.core.audit.events import AuditEventType
from aegis.core.domain import DomainModel, Identifier, NonEmptyStr, Timestamp

__all__ = ["SecurityCategory", "SecurityEvent", "SecurityOutcome", "SecurityView", "build_security"]


class SecurityCategory(StrEnum):
    """What kind of security event this is. Closed, so nothing is filed as "other"."""

    MALICIOUS_INPUT = "MALICIOUS_INPUT"
    """Hostile content in an incident payload or a message payload. **Detection only.**"""

    UNAUTHORIZED_PROPOSAL = "UNAUTHORIZED_PROPOSAL"
    A2A_REFUSAL = "A2A_REFUSAL"
    REMOTE_AUTHENTICATION_FAILURE = "REMOTE_AUTHENTICATION_FAILURE"
    REPLAY_ATTEMPT = "REPLAY_ATTEMPT"
    TAMPERING = "TAMPERING"
    REVOKED_KEY_ATTEMPT = "REVOKED_KEY_ATTEMPT"
    WRONG_RECIPIENT = "WRONG_RECIPIENT"
    CROSS_INCIDENT_ATTEMPT = "CROSS_INCIDENT_ATTEMPT"
    AGENT_RESTRICTION = "AGENT_RESTRICTION"
    BREAKER_TRIP = "BREAKER_TRIP"
    KEY_REVOCATION = "KEY_REVOCATION"
    GOVERNANCE_ANOMALY = "GOVERNANCE_ANOMALY"


class SecurityOutcome(StrEnum):
    """What actually happened. Three values, and deliberately no ``BLOCKED``."""

    DETECTED = "DETECTED"
    """Noticed. Nothing was prevented by the noticing."""

    REFUSED = "REFUSED"
    """A deterministic engine returned a refusal. Something concrete did not happen."""

    CONTAINED = "CONTAINED"
    """A containment mechanism changed state: breaker opened, agent quarantined, key
    revoked."""


_A2A_REJECTION_CATEGORIES: dict[str, SecurityCategory] = {
    "ALREADY_CONSUMED": SecurityCategory.REPLAY_ATTEMPT,
    "REPLAY": SecurityCategory.REPLAY_ATTEMPT,
    "INTEGRITY_FAILURE": SecurityCategory.TAMPERING,
    "NOT_ISSUED": SecurityCategory.TAMPERING,
    "SENDER_MISMATCH": SecurityCategory.WRONG_RECIPIENT,
    "UNKNOWN_SENDER": SecurityCategory.WRONG_RECIPIENT,
    "UNKNOWN_RECIPIENT": SecurityCategory.WRONG_RECIPIENT,
    "NOT_PERMITTED": SecurityCategory.WRONG_RECIPIENT,
    "INCIDENT_MISMATCH": SecurityCategory.CROSS_INCIDENT_ATTEMPT,
    "CONVERSATION_MISMATCH": SecurityCategory.CROSS_INCIDENT_ATTEMPT,
    "PAYLOAD_TOO_LARGE": SecurityCategory.MALICIOUS_INPUT,
}
"""Which A2A rejection means which kind of security event.

A mapping rather than string matching, so a rejection code with no security meaning is
simply absent rather than being filed under whichever category its spelling resembles.
"""

_REMOTE_REJECTION_CATEGORIES: dict[str, SecurityCategory] = {
    "IDENTITY_REVOKED": SecurityCategory.REVOKED_KEY_ATTEMPT,
    "IDENTITY_EXPIRED": SecurityCategory.REVOKED_KEY_ATTEMPT,
    "SIGNATURE_INVALID": SecurityCategory.TAMPERING,
    "MALFORMED_FRAME": SecurityCategory.TAMPERING,
    "OVERSIZED_FRAME": SecurityCategory.MALICIOUS_INPUT,
    "ALREADY_CONSUMED": SecurityCategory.REPLAY_ATTEMPT,
    "REPLAY": SecurityCategory.REPLAY_ATTEMPT,
    "WRONG_RECIPIENT": SecurityCategory.WRONG_RECIPIENT,
    "SENDER_MISMATCH": SecurityCategory.WRONG_RECIPIENT,
    "UNKNOWN_KEY": SecurityCategory.REMOTE_AUTHENTICATION_FAILURE,
    "UNKNOWN_AGENT": SecurityCategory.REMOTE_AUTHENTICATION_FAILURE,
    "CROSS_INCIDENT": SecurityCategory.CROSS_INCIDENT_ATTEMPT,
    "CROSS_CONVERSATION": SecurityCategory.CROSS_INCIDENT_ATTEMPT,
}


class SecurityEvent(DomainModel):
    """One security-relevant thing that happened, with what actually followed from it."""

    at: Timestamp
    incident_id: Identifier
    actor: NonEmptyStr
    category: SecurityCategory
    outcome: SecurityOutcome
    detail: NonEmptyStr
    evidence_refs: tuple[NonEmptyStr, ...] = Field(default_factory=tuple)
    source: ViewSource = ViewSource.AUDIT

    def __repr__(self) -> str:
        return f"SecurityEvent({self.category}={self.outcome} @ {self.at.isoformat()})"


class SecurityView(DomainModel):
    """Every security event for one incident, grouped and counted.

    ``detections`` and ``refusals`` are counted separately and are never summed into a
    single "threats stopped" figure, because a detection stopped nothing.
    """

    events: tuple[SecurityEvent, ...] = Field(default_factory=tuple)
    detections: int = Field(default=0, ge=0)
    refusals: int = Field(default=0, ge=0)
    containments: int = Field(default=0, ge=0)
    provenance: Provenance

    def of_category(self, category: SecurityCategory) -> tuple[SecurityEvent, ...]:
        return tuple(event for event in self.events if event.category is category)

    def __repr__(self) -> str:
        return (
            f"SecurityView({self.detections} detected, {self.refusals} refused, "
            f"{self.containments} contained)"
        )


def build_security(data: ControlCenterInput) -> SecurityView:
    """Collect security events for this incident from the audit trail.

    Scoped to the incident first (Part 18), then classified. An event whose rejection code
    has no security meaning is left out rather than filed somewhere approximate -- a
    security view padded with routine refusals is a view nobody reads.
    """
    if not data.audit_available:
        return SecurityView(
            provenance=Provenance.unavailable(
                data.captured_at,
                "the audit store could not be read; no security events can be listed, which "
                "is not the same as none having occurred",
            )
        )

    events: list[SecurityEvent] = []
    for record in data.audit_records:
        if record.event.incident_id not in (None, data.incident_id):
            continue
        event = _classify(record, data.incident_id)
        if event is not None:
            events.append(event)

    events.sort(key=lambda event: (event.at, event.category.value, event.detail))
    return SecurityView(
        events=tuple(events),
        detections=sum(1 for e in events if e.outcome is SecurityOutcome.DETECTED),
        refusals=sum(1 for e in events if e.outcome is SecurityOutcome.REFUSED),
        containments=sum(1 for e in events if e.outcome is SecurityOutcome.CONTAINED),
        provenance=Provenance(
            source=ViewSource.AUDIT,
            as_of=data.captured_at,
            completeness=Completeness.COMPLETE,
        ),
    )


def _classify(record, incident_id: str) -> SecurityEvent | None:
    """One audit record as a security event, or ``None`` when it is not one."""
    event = record.event
    correlation = record.correlation
    at = event.timestamp
    where = event.incident_id or incident_id

    if event.event_type == AuditEventType.A2A_MESSAGE.value:
        rejection = correlation.get("rejection")
        category = _A2A_REJECTION_CATEGORIES.get(rejection or "")
        if category is None:
            return None
        return SecurityEvent(
            at=at,
            incident_id=where,
            actor=event.actor,
            category=category,
            # A transport refusal is something that concretely did not happen.
            outcome=SecurityOutcome.REFUSED,
            detail=f"A2A refused: {rejection}",
            evidence_refs=(event.event_id, correlation.get("message_id", "")),
        )

    if event.event_type == AuditEventType.REMOTE_AUTHENTICATION.value:
        if correlation.get("status") == "AUTHENTICATED":
            return None
        rejection = correlation.get("rejection", "")
        return SecurityEvent(
            at=at,
            incident_id=where,
            actor=event.actor,
            category=_REMOTE_REJECTION_CATEGORIES.get(
                rejection, SecurityCategory.REMOTE_AUTHENTICATION_FAILURE
            ),
            outcome=SecurityOutcome.REFUSED,
            detail=f"remote authentication refused: {rejection or 'unspecified'}",
            evidence_refs=(event.event_id, correlation.get("message_id", "")),
        )

    if event.event_type == AuditEventType.POLICY_DECISION.value:
        if str(event.decision or "") != "DENY":
            return None
        return SecurityEvent(
            at=at,
            incident_id=where,
            actor=event.actor,
            category=SecurityCategory.UNAUTHORIZED_PROPOSAL,
            outcome=SecurityOutcome.REFUSED,
            detail=f"policy denied: {event.result or event.policy_reference}",
            evidence_refs=(event.event_id, str(event.policy_reference or "")),
        )

    if event.event_type == AuditEventType.LIFECYCLE_GATE_REJECTED.value:
        return SecurityEvent(
            at=at,
            incident_id=where,
            actor=event.actor,
            category=SecurityCategory.GOVERNANCE_ANOMALY,
            outcome=SecurityOutcome.REFUSED,
            detail=f"lifecycle gate rejected: {event.result}",
            evidence_refs=(event.event_id, correlation.get("gate_id", "")),
        )

    if event.event_type == AuditEventType.CIRCUIT_OPENED.value:
        return SecurityEvent(
            at=at,
            incident_id=where,
            actor=event.actor,
            category=SecurityCategory.BREAKER_TRIP,
            outcome=SecurityOutcome.CONTAINED,
            detail=f"breaker opened for {correlation.get('scope_key', '?')}: {event.result}",
            evidence_refs=(event.event_id,),
        )

    if event.event_type == AuditEventType.AGENT_RESTRICTION_APPLIED.value:
        return SecurityEvent(
            at=at,
            incident_id=where,
            actor=event.actor,
            category=SecurityCategory.AGENT_RESTRICTION,
            outcome=SecurityOutcome.CONTAINED,
            detail=f"agent restricted: {event.result}",
            evidence_refs=(event.event_id,),
        )

    if event.event_type == AuditEventType.AGENT_RESTRICTION_REFUSED.value:
        return SecurityEvent(
            at=at,
            incident_id=where,
            actor=event.actor,
            category=SecurityCategory.AGENT_RESTRICTION,
            outcome=SecurityOutcome.REFUSED,
            detail=f"restricted agent refused participation: {event.result}",
            evidence_refs=(event.event_id,),
        )

    if event.event_type == AuditEventType.REMOTE_KEY_REVOKED.value:
        return SecurityEvent(
            at=at,
            incident_id=where,
            actor=event.actor,
            category=SecurityCategory.KEY_REVOCATION,
            outcome=SecurityOutcome.CONTAINED,
            detail=f"key revoked: {correlation.get('key_id', '?')}",
            evidence_refs=(event.event_id,),
        )

    if event.event_type == AuditEventType.MODEL_DECISION.value:
        # A model proposing something forbidden is a *detection*. What stopped it was
        # policy, and policy's refusal is recorded separately -- counting this as a
        # prevention would count the same defence twice and credit it to the wrong layer.
        capability = correlation.get("proposed_capability", "")
        if not capability or not correlation.get("failure_category"):
            return None
        return SecurityEvent(
            at=at,
            incident_id=where,
            actor=event.actor,
            category=SecurityCategory.MALICIOUS_INPUT,
            outcome=SecurityOutcome.DETECTED,
            detail=f"model output rejected at the boundary: {correlation['failure_category']}",
            evidence_refs=(event.event_id,),
        )

    return None
