"""Recorders — translating control-plane artifacts into audit events.

Every recorder here is a **translator**. It reads a decision that has already been made and
writes it down. None of them re-runs policy, recomputes risk, re-verifies anything or infers
an outcome the artifact does not state. That property is what makes the audit trail worth
trusting: if the log says DENY, it is because the policy engine returned DENY, not because
the recorder decided the situation looked like one.

Where an artifact carries an identifier, that identifier is recorded verbatim
(``action_id``, ``approval_id``, ``verification_id``, ``action_fingerprint``,
``policy_reference``). No parallel identity scheme is introduced and no second fingerprint
implementation exists.

Refusals
--------

A refused *approval creation* raises rather than producing an ``Approval``, so there is no
artifact to translate. It needs none: the refusal is caused by a policy decision, and that
decision is recorded by :meth:`AuditRecorder.record_policy_decision` as the DENY it is. The
material governance decision stays observable without fabricating an approval that never
existed.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import datetime

from aegis.core.approval import Approval, ApprovalStatus
from aegis.core.assessment import Assessment
from aegis.core.audit.events import AuditEventType
from aegis.core.audit.records import AuditRecord
from aegis.core.audit.store import AuditStore
from aegis.core.domain import Action, Agent, AuditEvent, utc_now
from aegis.core.incidents import StateTransition
from aegis.core.policy import PolicyEvaluation
from aegis.core.verification import VerificationResult

__all__ = ["APPROVAL_STATUS_EVENTS", "AuditRecorder"]

APPROVAL_STATUS_EVENTS: dict[ApprovalStatus, AuditEventType] = {
    ApprovalStatus.PENDING: AuditEventType.APPROVAL_REQUESTED,
    ApprovalStatus.APPROVED: AuditEventType.APPROVAL_GRANTED,
    ApprovalStatus.REJECTED: AuditEventType.APPROVAL_REJECTED,
    ApprovalStatus.EXPIRED: AuditEventType.APPROVAL_EXPIRED,
    ApprovalStatus.CONSUMED: AuditEventType.APPROVAL_CONSUMED,
}
"""Which event an approval's *actual* status emits.

Total over :class:`~aegis.core.approval.models.ApprovalStatus`, and driven entirely by the
artifact. A grant is never inferred from an approval merely existing, and consumption is
never inferred from an execution having happened.
"""

_APPROVAL_STATUS_TIMES: dict[ApprovalStatus, str] = {
    ApprovalStatus.PENDING: "created_at",
    ApprovalStatus.APPROVED: "decided_at",
    ApprovalStatus.REJECTED: "decided_at",
    ApprovalStatus.EXPIRED: "expires_at",
    ApprovalStatus.CONSUMED: "consumed_at",
}


class AuditRecorder:
    """Writes control-plane artifacts into an :class:`~aegis.core.audit.store.AuditStore`.

    Args:
        store: The log to append to.
        clock: Used only for artifacts that carry no timestamp of their own — currently
            just :class:`~aegis.core.assessment.pipeline.Assessment`. Every other recorder
            uses the artifact's own time, because when a thing happened is a property of
            the thing, not of when it was written down.

    Event ids are allocated from the store's length (``evt-000000``, ``evt-000001``, …),
    so they are deterministic, gap-free and unique within a store without a counter of the
    recorder's own to fall out of step.
    """

    def __init__(self, store: AuditStore, *, clock: Callable[[], datetime] = utc_now) -> None:
        self._store = store
        self._clock = clock

    @property
    def store(self) -> AuditStore:
        return self._store

    def _next_event_id(self) -> str:
        return f"evt-{len(self._store):06d}"

    def _append(self, event: AuditEvent, correlation: Mapping[str, str]) -> AuditRecord:
        return self._store.append(event, correlation={k: v for k, v in correlation.items() if v})

    # --- incident lifecycle ---------------------------------------------------------

    def record_state_transition(self, transition: StateTransition) -> AuditRecord:
        """Record an ``incident.state_changed`` event.

        Both states come from the transition artifact rather than from an ``Incident``
        object: the artifact already states what the move was, and re-deriving it from a
        mutable-looking incident would risk recording a different story than the one the
        state machine actually permitted.
        """
        event = AuditEvent(
            event_id=self._next_event_id(),
            timestamp=transition.occurred_at,
            actor=transition.actor,
            incident_id=transition.incident_id,
            event_type=AuditEventType.INCIDENT_STATE_CHANGED.value,
            input_reference=transition.approval_id or transition.verification_id,
            policy_reference=transition.policy_reference,
            result=transition.reason,
            state_before=transition.from_state,
            state_after=transition.to_state,
        )
        return self._append(
            event,
            {
                "guard": transition.guard.value,
                "approval_id": transition.approval_id or "",
                "verification_id": transition.verification_id or "",
                "action_fingerprint": transition.action_fingerprint or "",
            },
        )

    # --- assessment -----------------------------------------------------------------

    def record_assessment(
        self, assessment: Assessment, *, occurred_at: datetime | None = None
    ) -> AuditRecord:
        """Record an ``action.assessed`` event.

        Reads the computed risk and blast radius off the artifact. No risk is recalculated
        here, and a failed assessment is recorded as the failure it was — never as an
        absent or benign one.
        """
        proposal = assessment.proposal
        if assessment.ok and assessment.risk is not None and assessment.blast_radius is not None:
            deciding = ",".join(factor.name for factor in assessment.risk.deciding_factors)
            result = (
                f"{assessment.outcome} risk={assessment.risk.risk} "
                f"blast={assessment.blast_radius.blast_radius.impact}"
                f"({assessment.blast_radius.affected_count}) deciding={deciding}"
            )
        else:
            result = f"{assessment.outcome}: {assessment.failure_reason}"

        event = AuditEvent(
            event_id=self._next_event_id(),
            timestamp=occurred_at or self._clock(),
            actor="system:assessment-pipeline",
            incident_id=proposal.incident_id,
            event_type=AuditEventType.ACTION_ASSESSED.value,
            input_reference=proposal.action_id,
            tool=proposal.capability,
            result=result,
            evidence=proposal.evidence,
        )
        return self._append(
            event,
            {
                "action_id": proposal.action_id,
                "requesting_agent": proposal.requesting_agent,
                "target_resource": proposal.target_resource,
                "outcome": assessment.outcome.value,
                "risk": assessment.risk.risk.value if assessment.risk else "",
            },
        )

    # --- policy ---------------------------------------------------------------------

    def record_policy_decision(
        self,
        evaluation: PolicyEvaluation,
        action: Action,
        agent: Agent | None = None,
    ) -> AuditRecord:
        """Record a ``policy.decision`` event.

        The decision, its reason and its rule reference are copied verbatim from the
        evaluation. Policy is not re-run, so an audited DENY is the DENY that actually
        happened, whatever the registry looks like by the time this is read.
        """
        decision = evaluation.decision
        event = AuditEvent(
            event_id=self._next_event_id(),
            timestamp=decision.evaluated_at,
            actor="system:policy-engine",
            agent_identity=agent.identity_reference if agent else None,
            incident_id=action.incident_id,
            event_type=AuditEventType.POLICY_DECISION.value,
            input_reference=action.action_id,
            decision=decision.decision,
            policy_reference=decision.policy_reference,
            tool=action.capability,
            result=decision.reason,
            evidence=decision.evidence,
        )
        checks = evaluation.checks
        return self._append(
            event,
            {
                "action_id": action.action_id,
                "requesting_agent": action.requesting_agent,
                "target_resource": action.target_resource,
                "agent_known": _tri(checks.agent_known),
                "capability_held": _tri(checks.capability_held),
                "resource_in_scope": _tri(checks.resource_in_scope),
                "risk_assessed": _tri(checks.risk_assessed),
                "approval_required": _tri(checks.approval_required),
            },
        )

    # --- approval -------------------------------------------------------------------

    def record_approval(self, approval: Approval) -> AuditRecord:
        """Record the event matching the approval's *actual* status.

        One artifact, one event, chosen by :data:`APPROVAL_STATUS_EVENTS`. Recording an
        approval three times as it moves PENDING → APPROVED → CONSUMED produces three
        events, each stamped with the time that transition carries.
        """
        event_type = APPROVAL_STATUS_EVENTS[approval.status]
        timestamp = getattr(approval, _APPROVAL_STATUS_TIMES[approval.status])
        event = AuditEvent(
            event_id=self._next_event_id(),
            timestamp=timestamp,
            actor=approval.decided_by or "system:approval-engine",
            incident_id=approval.incident_id,
            event_type=event_type.value,
            input_reference=approval.approval_id,
            decision=approval.policy_decision.decision,
            policy_reference=approval.policy_decision.policy_reference,
            result=f"{approval.status} risk={approval.risk}",
            evidence=approval.policy_decision.evidence,
        )
        return self._append(
            event,
            {
                "approval_id": approval.approval_id,
                "action_id": approval.action_id,
                "action_fingerprint": approval.action_fingerprint,
                "requesting_agent": approval.requesting_agent,
                "status": approval.status.value,
                "decided_by": approval.decided_by or "",
            },
        )

    # --- verification ---------------------------------------------------------------

    def record_verification(self, result: VerificationResult) -> AuditRecord:
        """Record a ``verification.completed`` event, whatever the outcome.

        Emitted for failures as much as successes. The observations that contributed are
        recorded as evidence references, so the trail points at what established the state
        rather than copying it.
        """
        checks = ";".join(f"{check.attribute}={check.outcome}" for check in result.checks)
        event = AuditEvent(
            event_id=self._next_event_id(),
            timestamp=result.evaluated_at,
            actor="system:verification-engine",
            incident_id=result.incident_id,
            event_type=AuditEventType.VERIFICATION_COMPLETED.value,
            input_reference=result.verification_id,
            result=f"{result.status} {checks}",
            evidence=result.observations_used,
        )
        return self._append(
            event,
            {
                "verification_id": result.verification_id,
                "action_id": result.action_id,
                "action_fingerprint": result.action_fingerprint,
                "resource": result.resource,
                "status": result.status.value,
            },
        )

    # --- memory ---------------------------------------------------------------------

    def record_memory_admitted(
        self,
        *,
        memory_id: str,
        memory_type: str,
        incident_id: str,
        agent_id: str,
        verification_id: str,
        action_id: str,
        evidence: tuple[str, ...] = (),
        at: datetime | None = None,
    ) -> AuditRecord:
        """Record a ``memory.admitted`` event.

        Every parameter is a plain scalar rather than a memory object. That is deliberate:
        the audit package must not import :mod:`aegis.memory`, because an audit recorder
        that depended on memory would be a route from memory back into the control plane.
        The recorder is told what happened; it never inspects a memory record.

        Correlation carries ``memory_id``, ``verification_id`` and ``action_id`` together,
        so the trail joins what AEGIS came to believe to the artifact that established it.
        """
        event = AuditEvent(
            event_id=self._next_event_id(),
            timestamp=at if at is not None else self._clock(),
            actor="system:memory-admission",
            agent_identity=agent_id,
            incident_id=incident_id,
            event_type=AuditEventType.MEMORY_ADMITTED.value,
            input_reference=memory_id,
            result=f"AUTHORITATIVE {memory_type}",
            evidence=evidence,
        )
        return self._append(
            event,
            {
                "memory_id": memory_id,
                "memory_type": memory_type,
                "verification_id": verification_id,
                "action_id": action_id,
            },
        )

    def record_memory_revoked(
        self,
        *,
        memory_id: str,
        revoked_memory_id: str,
        incident_id: str,
        actor: str,
        reason: str,
        at: datetime | None = None,
    ) -> AuditRecord:
        """Record a ``memory.revoked`` event.

        ``memory_id`` is the revocation entry and ``revoked_memory_id`` is what it
        withdrew; both are recorded because the trail must show the withdrawal *and* what
        it applied to.
        """
        event = AuditEvent(
            event_id=self._next_event_id(),
            timestamp=at if at is not None else self._clock(),
            actor=actor,
            incident_id=incident_id,
            event_type=AuditEventType.MEMORY_REVOKED.value,
            input_reference=revoked_memory_id,
            result=f"REVOKED {reason}",
        )
        return self._append(
            event,
            {"memory_id": memory_id, "revoked_memory_id": revoked_memory_id},
        )

    # --- lifecycle and circuit breaker ------------------------------------------------

    def record_lifecycle_stop(
        self,
        *,
        incident_id: str,
        stop_reason: str,
        detail: str,
        counters: Mapping[str, str],
        limit_name: str | None = None,
        limit_value: int | None = None,
        at: datetime | None = None,
    ) -> AuditRecord:
        """Record a ``lifecycle.stopped`` event.

        Plain scalars rather than a :class:`~aegis.lifecycle.models.LifecycleRecord`, so
        the audit package does not import :mod:`aegis.lifecycle`. The recorder is told what
        happened; it never inspects a lifecycle object, and the dependency arrow stays
        pointing away from the control plane.

        The counters travel in correlation because "how many attempts were there" is the
        question an investigator asks immediately after "why did it stop".
        """
        event = AuditEvent(
            event_id=self._next_event_id(),
            timestamp=at if at is not None else self._clock(),
            actor="system:lifecycle-manager",
            incident_id=incident_id,
            event_type=AuditEventType.LIFECYCLE_STOPPED.value,
            result=f"{stop_reason} {detail}",
            policy_reference=limit_name,
        )
        correlation = {**dict(counters), "stop_reason": stop_reason}
        if limit_name:
            correlation["limit_name"] = limit_name
        if limit_value is not None:
            correlation["limit_value"] = str(limit_value)
        return self._append(event, correlation)

    def record_circuit_event(
        self,
        event_type: AuditEventType,
        *,
        scope_key: str,
        state: str,
        reason: str,
        incident_id: str | None = None,
        trip_class: str | None = None,
        at: datetime | None = None,
    ) -> AuditRecord:
        """Record a ``circuit.*`` event.

        One method for opened, probe and closed: the three differ only in which event type
        and state they carry, and three near-identical methods would drift apart.
        """
        event = AuditEvent(
            event_id=self._next_event_id(),
            timestamp=at if at is not None else self._clock(),
            actor="system:circuit-breaker",
            incident_id=incident_id,
            event_type=event_type.value,
            input_reference=scope_key,
            result=f"{state} {reason}",
        )
        return self._append(
            event,
            {"scope_key": scope_key, "circuit_state": state, "trip_class": trip_class or ""},
        )

    # --- lifecycle gate and agent restriction -----------------------------------------

    def record_gate_event(
        self,
        event_type: AuditEventType,
        *,
        gate_id: str,
        incident_id: str,
        action_id: str,
        action_fingerprint: str,
        lifecycle_scope: str,
        lifecycle_state: str,
        breaker_state: str,
        reason: str,
        at: datetime | None = None,
    ) -> AuditRecord:
        """Record a ``lifecycle.gate_*`` event.

        Plain scalars, so the audit package never imports :mod:`aegis.lifecycle`. One
        method for issued, consumed and rejected: they differ only in event type and
        reason, and three near-identical methods would drift apart.
        """
        event = AuditEvent(
            event_id=self._next_event_id(),
            timestamp=at if at is not None else self._clock(),
            actor="system:lifecycle-coordinator",
            incident_id=incident_id,
            event_type=event_type.value,
            input_reference=gate_id,
            result=reason,
        )
        return self._append(
            event,
            {
                "gate_id": gate_id,
                "action_id": action_id,
                "action_fingerprint": action_fingerprint,
                "lifecycle_scope": lifecycle_scope,
                "lifecycle_state": lifecycle_state,
                "breaker_state": breaker_state,
            },
        )

    def record_agent_restriction(
        self,
        event_type: AuditEventType,
        *,
        agent_id: str,
        scope_key: str,
        restriction: str,
        reason: str,
        incident_id: str | None = None,
        capability: str | None = None,
        resource: str | None = None,
        failure_class: str | None = None,
        action_fingerprint: str | None = None,
        counters: Mapping[str, str] | None = None,
        at: datetime | None = None,
    ) -> AuditRecord:
        """Record an ``agent.restriction_*`` event.

        ``agent_id`` must already be the authoritative accountable identity; this recorder
        has no way to check that and does not pretend to. The binding is enforced at the
        coordinator, which reads it from the registered agent record rather than from
        anything a model produced.
        """
        event = AuditEvent(
            event_id=self._next_event_id(),
            timestamp=at if at is not None else self._clock(),
            actor="system:agent-restriction",
            agent_identity=agent_id,
            incident_id=incident_id,
            event_type=event_type.value,
            input_reference=scope_key,
            result=f"{restriction} {reason}",
        )
        correlation = {
            "agent_id": agent_id,
            "scope_key": scope_key,
            "restriction": restriction,
            **{k: v for k, v in (dict(counters or {})).items()},
        }
        for name, value in (
            ("capability", capability),
            ("resource", resource),
            ("failure_class", failure_class),
            ("action_fingerprint", action_fingerprint),
        ):
            if value:
                correlation[name] = value
        return self._append(event, correlation)

    def record_model_decision(
        self,
        *,
        incident_id: str,
        agent_id: str,
        provider: str,
        step: int,
        decision_type: str | None = None,
        request_digest: str | None = None,
        response_digest: str | None = None,
        tool_id: str | None = None,
        delegate_to: str | None = None,
        proposed_capability: str | None = None,
        proposed_resource: str | None = None,
        failure_category: str | None = None,
        failure_type: str | None = None,
        at: datetime | None = None,
    ) -> AuditRecord:
        """Record a ``model.decision`` event: what the reasoning layer asked for.

        Plain scalars only, so the audit package imports nothing from the agent plane, the
        integrations package or any provider SDK. Every argument here is an identifier, a
        hex digest or an enum value — there is no parameter that can carry prompt text,
        response text or a credential.

        ``actor`` is the agent, not the provider: accountability belongs to the registered
        identity the decision was made under, and ``provider`` is recorded beside it as
        configuration rather than as an actor in its own right.

        Recording a proposal is not honouring one. Whatever appears in
        ``proposed_capability`` still had to pass assessment, policy, approval, the
        lifecycle gate and verification, each of which writes its own event.
        """
        event = AuditEvent(
            event_id=self._next_event_id(),
            timestamp=at if at is not None else self._clock(),
            actor=f"agent:{agent_id}",
            agent_identity=agent_id,
            incident_id=incident_id,
            event_type=AuditEventType.MODEL_DECISION.value,
            input_reference=request_digest,
            result=decision_type or f"MODEL_FAILURE:{failure_category or 'UNKNOWN'}",
        )
        correlation = {"provider": provider, "step": str(step)}
        for name, value in (
            ("decision_type", decision_type),
            ("response_digest", response_digest),
            ("tool_id", tool_id),
            ("delegate_to", delegate_to),
            ("proposed_capability", proposed_capability),
            ("proposed_resource", proposed_resource),
            ("failure_category", failure_category),
            ("failure_type", failure_type),
        ):
            if value:
                correlation[name] = value
        return self._append(event, correlation)

    def record_a2a_message(
        self,
        *,
        incident_id: str,
        message_id: str,
        conversation_id: str,
        sender_agent_id: str,
        recipient_agent_id: str,
        task_id: str,
        task_type: str,
        status: str,
        digest: str,
        sequence: int,
        target_resource: str | None = None,
        rejection: str | None = None,
        finding_id: str | None = None,
        at: datetime | None = None,
    ) -> AuditRecord:
        """Record an ``a2a.message`` event.

        Plain scalars only, so the audit package imports nothing from :mod:`aegis.a2a` and
        knows nothing about envelopes. Every argument is an identifier, an enum value, an
        integer or a hex digest — there is no parameter that can carry payload text, a
        prompt, a model response or a credential (Part 17).

        ``digest`` is the message seal, which identifies the exact message without
        reproducing a byte of what it contained.

        ``actor`` is the sending agent, because accountability for a message belongs to the
        agent that sent it. The transport is not an actor: it moved bytes and decided
        nothing.
        """
        event = AuditEvent(
            event_id=self._next_event_id(),
            timestamp=at if at is not None else self._clock(),
            actor=f"agent:{sender_agent_id}",
            agent_identity=sender_agent_id,
            incident_id=incident_id,
            event_type=AuditEventType.A2A_MESSAGE.value,
            input_reference=message_id,
            result=status if rejection is None else f"{status}:{rejection}",
        )
        correlation = {
            "message_id": message_id,
            "conversation_id": conversation_id,
            "sender_agent_id": sender_agent_id,
            "recipient_agent_id": recipient_agent_id,
            "task_id": task_id,
            "task_type": task_type,
            "status": status,
            "digest": digest,
            "sequence": str(sequence),
        }
        for name, value in (
            ("target_resource", target_resource),
            ("rejection", rejection),
            ("finding_id", finding_id),
        ):
            if value:
                correlation[name] = value
        return self._append(event, correlation)

    def record_remote_authentication(
        self,
        *,
        incident_id: str,
        message_id: str,
        conversation_id: str,
        claimed_agent_id: str,
        status: str,
        protocol_version: str,
        key_id: str | None = None,
        algorithm: str | None = None,
        authenticated_agent_id: str | None = None,
        digest: str | None = None,
        rejection: str | None = None,
        at: datetime | None = None,
    ) -> AuditRecord:
        """Record a ``remote.authentication`` event.

        Plain scalars only, so the audit package imports nothing from
        :mod:`aegis.a2a.remote` and knows nothing about envelopes, keys or signatures.
        There is no parameter here that can carry key material, a signature, payload text,
        a prompt or a credential (Part 19) -- not by convention, but because no such
        parameter exists.

        Two agent ids on purpose. ``claimed_agent_id`` is what the message said; the
        optional ``authenticated_agent_id`` is what the signature established, and it is
        absent on every refusal. A trail that recorded only one of them could not show the
        moment a claim and a fact disagreed, which is precisely the moment worth recording.

        ``actor`` is the *claimed* sender, because on a refusal there is no established one
        and an actor field cannot be left empty. The distinction between the two is in the
        correlation, where it can be read without being mistaken for an established identity.
        """
        event = AuditEvent(
            event_id=self._next_event_id(),
            timestamp=at if at is not None else self._clock(),
            actor=f"agent:{claimed_agent_id}",
            agent_identity=authenticated_agent_id or claimed_agent_id,
            incident_id=incident_id,
            event_type=AuditEventType.REMOTE_AUTHENTICATION.value,
            input_reference=message_id,
            result=status if rejection is None else f"{status}:{rejection}",
        )
        correlation = {
            "message_id": message_id,
            "conversation_id": conversation_id,
            "claimed_agent_id": claimed_agent_id,
            "status": status,
            "protocol_version": protocol_version,
        }
        for name, value in (
            ("key_id", key_id),
            ("algorithm", algorithm),
            ("authenticated_agent_id", authenticated_agent_id),
            ("digest", digest),
            ("rejection", rejection),
        ):
            if value:
                correlation[name] = value
        return self._append(event, correlation)

    def record_remote_key_revoked(
        self,
        *,
        incident_id: str,
        agent_id: str,
        key_id: str,
        algorithm: str,
        revoked_by: str,
        reason: str,
        at: datetime | None = None,
    ) -> AuditRecord:
        """Record a ``remote.key_revoked`` event.

        An operator action, so ``actor`` is the operator rather than the agent whose key it
        was. ``reason`` is free text supplied by whoever revoked it and is treated as text:
        it is never parsed, matched against, or allowed to influence anything.
        """
        event = AuditEvent(
            event_id=self._next_event_id(),
            timestamp=at if at is not None else self._clock(),
            actor=revoked_by,
            agent_identity=agent_id,
            incident_id=incident_id,
            event_type=AuditEventType.REMOTE_KEY_REVOKED.value,
            input_reference=key_id,
            result="REVOKED",
        )
        return self._append(
            event,
            {
                "agent_id": agent_id,
                "key_id": key_id,
                "algorithm": algorithm,
                "revoked_by": revoked_by,
                "reason": reason,
            },
        )

    def __repr__(self) -> str:
        return f"{type(self).__name__}(store={self._store!r})"


def _tri(value: bool | None) -> str:
    """Render a tri-state policy check. Empty means "not reached", and is dropped."""
    return "" if value is None else str(value).lower()
