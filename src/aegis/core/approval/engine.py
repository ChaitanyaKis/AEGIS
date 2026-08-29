"""The approval engine — human authority, bounded and checked.

    LLMs propose. Deterministic systems authorize. Humans approve what policy escalates.

This engine manages approval artifacts. It is emphatically **not** a second policy
engine: it cannot permit anything policy forbids, and it re-asks policy rather than
trusting a decision it was handed earlier.

Two boundaries do most of the work here.

Approval cannot manufacture authority
-------------------------------------

An artifact may only be raised from a live ``REQUIRE_APPROVAL`` decision. The caller's
decision is checked *and* policy is re-evaluated at request time, so a stale or forged
decision cannot open the door. A DENY can never become an approval request, so no amount
of human sign-off converts a denial into authorisation (``claude.md`` section 5).

An approval is not a permission grant
-------------------------------------

It authorises **one exact action** (fingerprint), **for a bounded time**
(``expires_at``), **under one policy context** (re-evaluated at consumption), **once**
(consumption ledger). Change the action, let it lapse, quarantine the agent, narrow the
capability's scope, or try it twice — and it stops working.

Nothing here executes anything: no tools, no network, no enterprise mutation. The
executor is a later milestone.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta

from aegis.core.approval.errors import (
    ApprovalConsumptionRefused,
    ApprovalCreationRefused,
    ApprovalRefusal,
)
from aegis.core.approval.fingerprint import action_fingerprint
from aegis.core.approval.models import (
    Approval,
    ApprovalStatus,
    ExecutionAuthorization,
)
from aegis.core.domain import (
    Action,
    Agent,
    PolicyDecision,
    PolicyDecisionType,
    utc_now,
)
from aegis.core.policy import PolicyEngine

__all__ = ["DEFAULT_APPROVAL_TTL", "ApprovalEngine"]

DEFAULT_APPROVAL_TTL = timedelta(minutes=15)
"""How long an approval stays usable unless the caller says otherwise.

Short on purpose: an approval is a statement about the state of the world when a human
looked at it, and that statement gets less true with every minute.
"""


class ApprovalEngine:
    """Creates, decides and consumes approval artifacts.

    Args:
        policy_engine: Used to re-evaluate policy at request time and again at
            consumption time. The engine never trusts a decision it was merely handed.
        clock: Source of timestamps. Injectable so tests never depend on wall time.
            Time is used only for expiry and stamping — never as an authorisation input
            in the policy sense.
        ttl: Default lifetime for new approvals.

    State: exactly one piece — a ledger of consumed approval ids, held so that
    single-use can be enforced. It has to live somewhere: approvals are immutable values,
    so a caller holding a pre-consumption copy could otherwise replay it forever. The
    ledger is the engine's only mutable state and is deliberately visible via
    :meth:`is_consumed`. A persistent store replaces it in a later milestone.
    """

    def __init__(
        self,
        policy_engine: PolicyEngine,
        *,
        clock: Callable[[], datetime] = utc_now,
        ttl: timedelta = DEFAULT_APPROVAL_TTL,
    ) -> None:
        if ttl <= timedelta(0):
            raise ValueError("ttl must be positive")
        self._policy = policy_engine
        self._clock = clock
        self._ttl = ttl
        self._consumed: set[str] = set()

    @property
    def policy_engine(self) -> PolicyEngine:
        return self._policy

    def is_consumed(self, approval_id: str) -> bool:
        """Whether this approval id has already authorised an execution."""
        return approval_id in self._consumed

    # --- creation -------------------------------------------------------------------

    def request(
        self,
        *,
        approval_id: str,
        action: Action,
        agent: Agent,
        decision: PolicyDecision,
        ttl: timedelta | None = None,
    ) -> Approval:
        """Raise a PENDING approval for ``action``.

        Args:
            approval_id: Identifier for the new artifact.
            action: The assessed action awaiting human authority.
            agent: The control-plane record for the requesting agent.
            decision: The REQUIRE_APPROVAL decision that escalated this action. Stored on
                the artifact, and cross-checked against a fresh evaluation.
            ttl: Lifetime override.

        Returns:
            A PENDING approval.

        Raises:
            ApprovalCreationRefused: if any authorisation context is missing or wrong —
                a decision that is not REQUIRE_APPROVAL, a mismatched agent or incident,
                an unassessed risk or blast radius, or a fresh evaluation that disagrees.
                A partially valid approval is never created.
        """
        if decision.decision is PolicyDecisionType.DENY:
            raise ApprovalCreationRefused(
                ApprovalRefusal.POLICY_DENIES,
                f"policy denies action {action.action_id!r}; no approval may be raised",
            )
        if decision.decision is not PolicyDecisionType.REQUIRE_APPROVAL:
            raise ApprovalCreationRefused(
                ApprovalRefusal.POLICY_DOES_NOT_REQUIRE_APPROVAL,
                f"decision is {decision.decision}, so no human artifact is needed",
            )
        if agent.agent_id != action.requesting_agent:
            raise ApprovalCreationRefused(
                ApprovalRefusal.AGENT_MISMATCH,
                f"agent {agent.agent_id!r} is not the requesting agent {action.requesting_agent!r}",
            )
        if action.risk is None:
            raise ApprovalCreationRefused(
                ApprovalRefusal.RISK_UNASSESSED,
                f"action {action.action_id!r} has not been risk-assessed",
            )
        if action.blast_radius is None:
            raise ApprovalCreationRefused(
                ApprovalRefusal.BLAST_RADIUS_UNASSESSED,
                f"action {action.action_id!r} has no assessed blast radius",
            )

        # The caller's decision is a claim. Ask policy again before acting on it.
        current = self._policy.evaluate(action, agent)
        if current.decision is not PolicyDecisionType.REQUIRE_APPROVAL:
            refusal = (
                ApprovalRefusal.POLICY_DENIES
                if current.decision is PolicyDecisionType.DENY
                else ApprovalRefusal.POLICY_DOES_NOT_REQUIRE_APPROVAL
            )
            raise ApprovalCreationRefused(
                refusal,
                f"current policy returns {current.decision} for action "
                f"{action.action_id!r} ({current.policy_reference})",
            )

        now = self._clock()
        return Approval(
            approval_id=approval_id,
            incident_id=action.incident_id,
            action_id=action.action_id,
            action_fingerprint=action_fingerprint(action),
            requesting_agent=action.requesting_agent,
            policy_decision=current,
            risk=action.risk,
            blast_radius=action.blast_radius,
            reason=current.reason,
            status=ApprovalStatus.PENDING,
            created_at=now,
            expires_at=now + (ttl if ttl is not None else self._ttl),
        )

    # --- human decisions ------------------------------------------------------------

    def approve(self, approval: Approval, *, by: str) -> Approval:
        """Record a human approval.

        Args:
            approval: The PENDING artifact.
            by: The human who approved, e.g. ``human:oncall``.

        Raises:
            ApprovalConsumptionRefused: if the approval was already decided, already
                consumed, or has lapsed. An expired approval is never silently renewed.
        """
        return self._decide(approval, ApprovalStatus.APPROVED, by)

    def reject(self, approval: Approval, *, by: str) -> Approval:
        """Record a human rejection. The artifact can never authorise execution again."""
        return self._decide(approval, ApprovalStatus.REJECTED, by)

    def expire(self, approval: Approval) -> Approval:
        """Mark a lapsed approval EXPIRED.

        A convenience for sweeping stale artifacts. Consumption does not depend on it
        having been called — expiry is always recomputed from the clock.
        """
        now = self._clock()
        if not approval.is_expired(now):
            raise ApprovalConsumptionRefused(
                ApprovalRefusal.NOT_APPROVED,
                f"approval {approval.approval_id!r} has not expired",
            )
        if approval.status is ApprovalStatus.CONSUMED:
            raise ApprovalConsumptionRefused(
                ApprovalRefusal.ALREADY_CONSUMED,
                f"approval {approval.approval_id!r} was already consumed",
            )
        return approval.model_copy(update={"status": ApprovalStatus.EXPIRED})

    def _decide(self, approval: Approval, status: ApprovalStatus, by: str) -> Approval:
        if self.is_consumed(approval.approval_id):
            raise ApprovalConsumptionRefused(
                ApprovalRefusal.ALREADY_CONSUMED,
                f"approval {approval.approval_id!r} was already consumed",
            )
        if approval.status is not ApprovalStatus.PENDING:
            raise ApprovalConsumptionRefused(
                ApprovalRefusal.ALREADY_DECIDED,
                f"approval {approval.approval_id!r} is already {approval.status}",
            )
        now = self._clock()
        if approval.is_expired(now):
            raise ApprovalConsumptionRefused(
                ApprovalRefusal.EXPIRED,
                f"approval {approval.approval_id!r} expired at {approval.expires_at}",
            )
        return approval.model_copy(update={"status": status, "decided_at": now, "decided_by": by})

    # --- consumption ----------------------------------------------------------------

    def consume_for_execution(
        self, approval: Approval, current_action: Action, current_agent: Agent | None
    ) -> ExecutionAuthorization:
        """Spend an approval to authorise one execution.

        Runs every check in order and refuses on the first failure: already consumed,
        not APPROVED, lapsed, action identity changed, action content changed, and
        finally a fresh policy evaluation against the *current* agent, capability
        definitions and registry contents.

        Args:
            approval: The APPROVED artifact.
            current_action: The action about to be executed, as it stands now.
            current_agent: The requesting agent's record as it stands now. ``None`` when
                the caller could not resolve one, which denies.

        Returns:
            An :class:`ExecutionAuthorization`. It records permission; it executes
            nothing.

        Raises:
            ApprovalConsumptionRefused: on any failed check. The approval is not marked
                consumed when consumption is refused, because nothing was authorised.
        """
        if self.is_consumed(approval.approval_id):
            raise ApprovalConsumptionRefused(
                ApprovalRefusal.ALREADY_CONSUMED,
                f"approval {approval.approval_id!r} has already authorised an execution",
            )
        if approval.status is not ApprovalStatus.APPROVED:
            raise ApprovalConsumptionRefused(
                ApprovalRefusal.NOT_APPROVED,
                f"approval {approval.approval_id!r} is {approval.status}, not APPROVED",
            )

        now = self._clock()
        if approval.is_expired(now):
            raise ApprovalConsumptionRefused(
                ApprovalRefusal.EXPIRED,
                f"approval {approval.approval_id!r} expired at {approval.expires_at}",
            )

        if current_action.action_id != approval.action_id:
            raise ApprovalConsumptionRefused(
                ApprovalRefusal.ACTION_IDENTITY_MISMATCH,
                f"approval {approval.approval_id!r} authorises action "
                f"{approval.action_id!r}, not {current_action.action_id!r}",
            )
        if current_action.incident_id != approval.incident_id:
            raise ApprovalConsumptionRefused(
                ApprovalRefusal.INCIDENT_MISMATCH,
                f"approval {approval.approval_id!r} belongs to incident "
                f"{approval.incident_id!r}, not {current_action.incident_id!r}",
            )
        if action_fingerprint(current_action) != approval.action_fingerprint:
            raise ApprovalConsumptionRefused(
                ApprovalRefusal.ACTION_FINGERPRINT_MISMATCH,
                f"action {current_action.action_id!r} changed after approval "
                f"{approval.approval_id!r} was granted",
            )

        # The world may have moved since a human looked at this.
        current = self._policy.evaluate(current_action, current_agent)
        if current.decision is not PolicyDecisionType.REQUIRE_APPROVAL:
            refusal = (
                ApprovalRefusal.POLICY_DENIES
                if current.decision is PolicyDecisionType.DENY
                else ApprovalRefusal.POLICY_NO_LONGER_REQUIRES_APPROVAL
            )
            raise ApprovalConsumptionRefused(
                refusal,
                f"policy now returns {current.decision} for action "
                f"{current_action.action_id!r} ({current.policy_reference}); approval "
                f"{approval.approval_id!r} no longer applies",
            )

        self._consumed.add(approval.approval_id)
        consumed = approval.model_copy(
            update={"status": ApprovalStatus.CONSUMED, "consumed_at": now}
        )
        return ExecutionAuthorization(
            approval=consumed,
            incident_id=approval.incident_id,
            action_id=approval.action_id,
            action_fingerprint=approval.action_fingerprint,
            agent_id=current_agent.agent_id if current_agent else approval.requesting_agent,
            policy_decision=current,
            authorized_at=now,
        )

    def __repr__(self) -> str:
        return f"{type(self).__name__}(consumed={len(self._consumed)})"
