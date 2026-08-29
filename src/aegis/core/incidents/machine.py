"""The deterministic incident state machine.

Owns lifecycle correctness: which states an incident may move between, and what a caller
must present to make a guarded move. It decides nothing about policy or approval — it
enforces that those decisions were made and are being carried.

Three structural guarantees fall out of the table in
:mod:`aegis.core.incidents.transitions`:

* **RESOLVED is reachable only from VERIFYING.** A tool returning success is not proof
  that an operation succeeded (``claude.md`` section 11), so execution cannot resolve an
  incident on its own say-so.
* **POLICY_CHECK cannot be skipped.** PLAN_PROPOSED leads nowhere except POLICY_CHECK,
  and every path to EXECUTING passes through it — including paths that detour through
  DEGRADED and RECOVERING.
* **AWAITING_APPROVAL cannot be walked out of.** Leaving it for EXECUTING requires an
  ``ExecutionAuthorization`` from a consumed approval.
* **RESOLVED requires proof.** Leaving VERIFYING for RESOLVED requires a VERIFIED
  ``VerificationResult`` *and* the action it verifies, so the machine can confirm the
  result covers the action that actually ran, on the resource it actually targeted. A
  tool returning success opens nothing.

Transitions produce a new frozen :class:`~aegis.core.domain.incident.Incident`. The
original is never mutated, so an incident's history is a chain of values rather than a
record that has been overwritten.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime

from aegis.core.approval import ExecutionAuthorization, action_fingerprint
from aegis.core.domain import (
    Action,
    DomainModel,
    Incident,
    IncidentRef,
    IncidentState,
    NonEmptyStr,
    PolicyDecision,
    PolicyDecisionType,
    Timestamp,
    utc_now,
)
from aegis.core.incidents.transitions import TERMINAL_STATES, TRANSITIONS, TransitionGuard
from aegis.core.verification import VerificationResult, VerificationStatus

__all__ = [
    "IncidentStateMachine",
    "IncidentTransitionResult",
    "InvalidIncidentTransition",
    "StateTransition",
]


class InvalidIncidentTransition(Exception):
    """A transition was refused.

    Never swallowed, never downgraded to a log line, and never answered by returning the
    original incident as though the move had happened.

    Attributes:
        incident_id: The incident the move was attempted on.
        from_state: Its current state.
        to_state: The state that was requested.
        reason: Machine-readable explanation.
    """

    def __init__(
        self,
        incident_id: str,
        from_state: IncidentState,
        to_state: IncidentState,
        reason: str,
    ) -> None:
        self.incident_id = incident_id
        self.from_state = from_state
        self.to_state = to_state
        self.reason = reason
        super().__init__(f"incident {incident_id!r}: {from_state} -> {to_state} refused: {reason}")


class StateTransition(DomainModel):
    """The record of one accepted transition.

    Everything a future audit store needs about the move, in the flat shape
    :class:`~aegis.core.domain.audit.AuditEvent` prefers. Produced only for transitions
    that actually happened — a refusal raises instead.
    """

    incident_id: IncidentRef
    from_state: IncidentState
    to_state: IncidentState
    reason: NonEmptyStr
    """Why the move was made, supplied by the caller. Required: no silent transitions."""

    actor: NonEmptyStr
    """What made the move, e.g. ``agent:commander`` or ``system:state-machine``."""

    occurred_at: Timestamp
    guard: TransitionGuard
    """Which guard the edge required, satisfied or NONE."""

    policy_reference: NonEmptyStr | None = None
    """Rule reference of the decision that justified a policy-guarded edge."""

    approval_id: NonEmptyStr | None = None
    """The approval spent on an EXECUTION_AUTHORIZATION-guarded edge."""

    action_fingerprint: str | None = None
    """Fingerprint of the action the authorisation or verification covered."""

    verification_id: NonEmptyStr | None = None
    """The verification result that justified a VERIFICATION-guarded edge."""


class IncidentTransitionResult(DomainModel):
    """A transitioned incident together with the record of how it got there."""

    incident: Incident
    transition: StateTransition


class IncidentStateMachine:
    """Applies the authoritative transition table to incidents.

    Args:
        clock: Source of the transition timestamp. Injectable so tests never depend on
            wall time. Time stamps the move; it never decides whether the move is legal.

    Stateless: the machine holds no incident state of its own, so the same incident,
    target state and guard artifacts always produce the same outcome.
    """

    def __init__(self, *, clock: Callable[[], datetime] = utc_now) -> None:
        self._clock = clock

    # --- queries --------------------------------------------------------------------

    @staticmethod
    def can_transition(from_state: IncidentState, to_state: IncidentState) -> bool:
        """Whether the edge exists at all.

        Says nothing about whether its guard is satisfied — a guarded edge answers
        ``True`` here and can still be refused by :meth:`transition`.
        """
        return to_state in TRANSITIONS[from_state]

    @staticmethod
    def guard_for(from_state: IncidentState, to_state: IncidentState) -> TransitionGuard:
        """The guard on an edge.

        Raises:
            KeyError: if the edge does not exist.
        """
        return TRANSITIONS[from_state][to_state]

    @staticmethod
    def allowed_transitions(from_state: IncidentState) -> tuple[IncidentState, ...]:
        """Every state reachable in one step, sorted by name."""
        return tuple(sorted(TRANSITIONS[from_state], key=lambda state: state.value))

    @staticmethod
    def is_terminal(state: IncidentState) -> bool:
        """Whether an incident in this state can never move again."""
        return state in TERMINAL_STATES

    # --- transition -----------------------------------------------------------------

    def transition(
        self,
        incident: Incident,
        to_state: IncidentState,
        *,
        reason: str,
        actor: str,
        policy_decision: PolicyDecision | None = None,
        authorization: ExecutionAuthorization | None = None,
        verification: VerificationResult | None = None,
        action: Action | None = None,
    ) -> Incident:
        """Move ``incident`` to ``to_state``, returning a new frozen incident.

        Args:
            incident: The incident to advance. Never mutated.
            to_state: The requested state.
            reason: Why. Required, so no transition is unexplained.
            actor: What made the move.
            policy_decision: Required for a policy-guarded edge, and must carry the
                decision the guard names.
            authorization: Required for an approval-guarded edge, and must belong to this
                incident.
            verification: Required for the verification-guarded edge, and must be
                VERIFIED and bound to this incident.
            action: Required alongside ``verification``. The action whose effect was
                verified, so the machine can check the result covers this exact action
                rather than another of the incident's proposals.

        Returns:
            A new :class:`~aegis.core.domain.incident.Incident` in ``to_state``, with
            ``updated_at`` restamped.

        Raises:
            InvalidIncidentTransition: if the edge does not exist, the current state is
                terminal, or the edge's guard is not satisfied.
        """
        return self.transition_detailed(
            incident,
            to_state,
            reason=reason,
            actor=actor,
            policy_decision=policy_decision,
            authorization=authorization,
            verification=verification,
            action=action,
        ).incident

    def transition_detailed(
        self,
        incident: Incident,
        to_state: IncidentState,
        *,
        reason: str,
        actor: str,
        policy_decision: PolicyDecision | None = None,
        authorization: ExecutionAuthorization | None = None,
        verification: VerificationResult | None = None,
        action: Action | None = None,
    ) -> IncidentTransitionResult:
        """Like :meth:`transition`, but also returns the :class:`StateTransition` record."""
        from_state = incident.state

        def refuse(detail: str) -> InvalidIncidentTransition:
            return InvalidIncidentTransition(incident.incident_id, from_state, to_state, detail)

        if from_state is to_state:
            raise refuse("a state cannot transition to itself")
        if self.is_terminal(from_state):
            raise refuse(f"{from_state} is terminal")
        if not self.can_transition(from_state, to_state):
            raise refuse("no such edge in the transition table")

        guard = self.guard_for(from_state, to_state)
        self._check_guard(
            guard, refuse, policy_decision, authorization, verification, action, incident
        )

        now = self._clock()
        moved = incident.model_copy(update={"state": to_state, "updated_at": now})
        record = StateTransition(
            incident_id=incident.incident_id,
            from_state=from_state,
            to_state=to_state,
            reason=reason,
            actor=actor,
            occurred_at=now,
            guard=guard,
            policy_reference=(
                policy_decision.policy_reference if policy_decision is not None else None
            ),
            approval_id=(authorization.approval.approval_id if authorization is not None else None),
            action_fingerprint=(
                authorization.action_fingerprint
                if authorization is not None
                else verification.action_fingerprint
                if verification is not None
                else None
            ),
            verification_id=(verification.verification_id if verification is not None else None),
        )
        return IncidentTransitionResult(incident=moved, transition=record)

    @staticmethod
    def _check_guard(
        guard: TransitionGuard,
        refuse: Callable[[str], InvalidIncidentTransition],
        policy_decision: PolicyDecision | None,
        authorization: ExecutionAuthorization | None,
        verification: VerificationResult | None,
        action: Action | None,
        incident: Incident,
    ) -> None:
        """Refuse unless the edge's guard is satisfied. Absence never satisfies a guard."""
        if guard is TransitionGuard.NONE:
            return

        if guard in {
            TransitionGuard.POLICY_ALLOW,
            TransitionGuard.POLICY_REQUIRE_APPROVAL,
        }:
            expected = (
                PolicyDecisionType.ALLOW
                if guard is TransitionGuard.POLICY_ALLOW
                else PolicyDecisionType.REQUIRE_APPROVAL
            )
            if policy_decision is None:
                raise refuse(f"edge requires a {expected} policy decision, none supplied")
            if policy_decision.decision is not expected:
                raise refuse(
                    f"edge requires a {expected} policy decision, got {policy_decision.decision}"
                )
            return

        if guard is TransitionGuard.EXECUTION_AUTHORIZATION:
            if authorization is None:
                raise refuse(
                    "edge requires an execution authorization from a consumed approval, "
                    "none supplied"
                )
            if authorization.incident_id != incident.incident_id:
                raise refuse(
                    f"execution authorization belongs to incident {authorization.incident_id!r}"
                )
            return

        if guard is TransitionGuard.VERIFICATION:
            if verification is None:
                raise refuse("edge requires a VERIFIED verification result, none supplied")
            if action is None:
                raise refuse("edge requires the action that was verified, none supplied")
            if verification.status is not VerificationStatus.VERIFIED:
                raise refuse(
                    f"verification {verification.verification_id!r} is "
                    f"{verification.status}, not VERIFIED"
                )
            if verification.incident_id != incident.incident_id:
                raise refuse(
                    f"verification {verification.verification_id!r} belongs to incident "
                    f"{verification.incident_id!r}"
                )
            if action.action_id not in incident.proposed_actions:
                raise refuse(
                    f"action {action.action_id!r} is not one of this incident's proposed actions"
                )
            if verification.action_id != action.action_id:
                raise refuse(
                    f"verification {verification.verification_id!r} verifies action "
                    f"{verification.action_id!r}, not {action.action_id!r}"
                )
            if verification.resource != action.target_resource:
                raise refuse(
                    f"verification {verification.verification_id!r} established the state "
                    f"of {verification.resource!r}, not {action.target_resource!r}"
                )
            if verification.action_fingerprint != action_fingerprint(action):
                raise refuse(
                    f"action {action.action_id!r} changed after verification "
                    f"{verification.verification_id!r} was produced"
                )
            return

        raise refuse(f"unsupported guard {guard}")  # pragma: no cover - table is closed

    def __repr__(self) -> str:
        return f"{type(self).__name__}()"
