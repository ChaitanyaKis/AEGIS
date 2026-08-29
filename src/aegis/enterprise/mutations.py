"""Applying an already-authorized action to the simulated world.

**CONTROLLED SIMULATION** (``claude.md`` sections 14, 17). Simulated mutations only —
nothing is deployed, restarted or rolled back anywhere real.

Where this sits
---------------

    CONTROL PLANE                         ENTERPRISE
    proposal -> assessment -> policy      authorized action
             -> approval -> authorization      -> simulated mutation
                                               -> changed world
                                               -> observations

The executor **never decides whether an action is permitted**. It does not call the policy
engine, and there is no import of it in this package. What it does do is refuse to act on
an action carrying no evidence of having been through the control plane: it requires an
:class:`~aegis.core.approval.models.ExecutionAuthorization` and checks that the artifact
binds to this exact action. Checking that a decision exists is not making one.

Execution success is not verification
-------------------------------------

:class:`ExecutionResult` says what the simulated operation reported. It says nothing about
whether the enterprise reached the desired state — that is the verification engine's job,
and it answers from observations, not from this. ``outcome is APPLIED`` must never be read
as ``VERIFIED`` (``claude.md`` section 11).
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from enum import StrEnum

from aegis.core.approval import ExecutionAuthorization, action_fingerprint
from aegis.core.dependencies import UnknownResourceError
from aegis.core.domain import Action, DomainModel, NonEmptyStr, Timestamp, utc_now
from aegis.enterprise.failures import FailureType
from aegis.enterprise.world import EnterpriseWorld, UnsupportedOperationError

__all__ = [
    "SUPPORTED_CAPABILITIES",
    "ActionExecutor",
    "ExecutionOutcome",
    "ExecutionResult",
    "UnauthorizedExecutionError",
]

SUPPORTED_CAPABILITIES: frozenset[str] = frozenset({"production.rollback"})
"""Capabilities the simulator knows how to carry out.

Deliberately small. A capability the simulator cannot perform is reported as
``UNSUPPORTED`` rather than quietly succeeding, so a scenario cannot appear to execute
something that never happened.
"""

_ROLLBACK_VERSION_ARGUMENT = "target_version"


class UnauthorizedExecutionError(Exception):
    """Execution was attempted without a valid authorization for this exact action.

    Raised rather than returned: an unauthorized execution attempt is a control-plane
    violation, not an outcome the simulation should report as one of its normal results.
    """


class ExecutionOutcome(StrEnum):
    """What the simulated operation reported. Not a statement about enterprise state."""

    APPLIED = "APPLIED"
    """The operation ran and the world changed. Still not evidence the goal was reached."""

    FAILED = "FAILED"
    """The operation ran and did not take. The world is unchanged."""

    UNSUPPORTED = "UNSUPPORTED"
    """The simulator does not model this capability, resource or argument."""

    BLOCKED = "BLOCKED"
    """An injected failure stopped the operation before it could act."""


class ExecutionResult(DomainModel):
    """The record of one simulated execution attempt.

    Named ``ExecutionResult``, never ``verification``: a successful execution is a report
    from the thing that did the work, and the thing that did the work is not a witness to
    whether it worked.
    """

    action_id: NonEmptyStr
    capability: NonEmptyStr
    target_resource: NonEmptyStr
    outcome: ExecutionOutcome
    world_changed: bool
    """Whether the world actually moved. ``False`` for every non-APPLIED outcome."""

    detail: NonEmptyStr
    executed_at: Timestamp

    @property
    def applied(self) -> bool:
        """Whether the operation reported success. Says nothing about verification."""
        return self.outcome is ExecutionOutcome.APPLIED


class ActionExecutor:
    """Applies authorized actions to the simulated world.

    Args:
        world: The world to act on.
        clock: Timestamp source for results. Injectable so scenarios control time.
    """

    def __init__(
        self,
        world: EnterpriseWorld,
        *,
        clock: Callable[[], datetime] = utc_now,
        gate_verifier=None,
    ) -> None:
        self._world = world
        self._clock = clock
        self._gate_verifier = gate_verifier
        """Verifies and consumes lifecycle gates. When present, a production mutation
        requires one — see :meth:`execute`.

        Typed loosely on purpose: the enterprise simulator must not import
        :mod:`aegis.lifecycle`, or the thing being governed would depend on the thing
        governing it. The executor calls one method and takes one answer.
        """

    @property
    def world(self) -> EnterpriseWorld:
        return self._world

    def execute(
        self,
        action: Action,
        authorization: ExecutionAuthorization,
        *,
        at: datetime | None = None,
        gate=None,
    ) -> ExecutionResult:
        """Carry out ``action`` against the simulated world.

        Two independent artifacts are required, from two independent origins:

        * ``authorization`` — the consumed approval. This is what a human granted, and it
          remains the actual authority.
        * ``gate`` — proof the lifecycle was crossed for this exact execution. Not
          authority: it grants nothing on its own, and an execution carrying only a gate
          is refused exactly as one carrying only an authorization is.

        Neither is sufficient and neither substitutes for the other. That is the point of
        having two: a caller who reaches this method directly has an authorization at best,
        and an authorization alone no longer executes anything.

        Args:
            action: The action to perform, as the control plane authorized it.
            authorization: The consumed approval that permits it, bound to this action.
            at: Execution instant. Defaults to the injected clock.
            gate: The lifecycle gate. Required when a verifier is configured.

        Returns:
            An :class:`ExecutionResult` describing what the operation reported.

        Raises:
            UnauthorizedExecutionError: if the authorization is missing or mis-bound.
            LifecycleGateRejected: if the gate is missing, forged, stale, consumed, or
                bound to a different execution.
        """
        self._require_authorization(action, authorization)
        self._require_gate(action, gate)
        now = at if at is not None else self._clock()

        def result(
            outcome: ExecutionOutcome, detail: str, *, changed: bool = False
        ) -> ExecutionResult:
            return ExecutionResult(
                action_id=action.action_id,
                capability=action.capability,
                target_resource=action.target_resource,
                outcome=outcome,
                world_changed=changed,
                detail=detail,
                executed_at=now,
            )

        if action.capability not in SUPPORTED_CAPABILITIES:
            return result(
                ExecutionOutcome.UNSUPPORTED,
                f"the simulator does not model capability {action.capability!r}",
            )
        if not self._world.contains(action.target_resource):
            return result(
                ExecutionOutcome.UNSUPPORTED,
                f"resource {action.target_resource!r} is not declared in this world",
            )

        version = action.arguments.get(_ROLLBACK_VERSION_ARGUMENT)
        if not isinstance(version, str) or not version:
            return result(
                ExecutionOutcome.UNSUPPORTED,
                f"rollback requires a {_ROLLBACK_VERSION_ARGUMENT!r} string argument",
            )

        # Injected failures act before the world moves, so a blocked or failed operation
        # leaves the enterprise exactly as it was.
        if self._world.is_failing(FailureType.TOOL_TIMEOUT):
            return result(
                ExecutionOutcome.BLOCKED,
                "simulated tool timeout: the operation did not complete",
            )
        if self._world.is_failing(FailureType.TOOL_500):
            return result(
                ExecutionOutcome.BLOCKED,
                "simulated tool error 500: the operation was rejected by the endpoint",
            )
        if self._world.is_failing(FailureType.ROLLBACK_FAILURE):
            return result(
                ExecutionOutcome.FAILED,
                f"simulated rollback failure: {action.target_resource} did not move to {version}",
            )

        try:
            state = self._world.rollback(action.target_resource, version)
        except (UnsupportedOperationError, UnknownResourceError) as error:
            return result(ExecutionOutcome.UNSUPPORTED, str(error))

        return result(
            ExecutionOutcome.APPLIED,
            f"{action.target_resource} rolled back to {state.deployment}",
            changed=True,
        )

    def _require_gate(self, action: Action, gate) -> None:
        """Refuse to act without a lifecycle gate the coordinator actually issued.

        The check is delegated wholesale to the verifier. The executor deliberately does
        not re-implement any binding: duplicating them here would create a second, drifting
        opinion about what a valid gate is, and the whole value of the gate is that exactly
        one component decides.

        Consumption happens here rather than at issue, so a gate is spent by the execution
        it authorised the lifecycle *for* — which is what makes replay impossible rather
        than merely unlikely.
        """
        if self._gate_verifier is None:
            return
        if gate is None:
            from aegis.lifecycle.errors import LifecycleGateRejected
            from aegis.lifecycle.gate import GateRejection

            raise LifecycleGateRejected(
                GateRejection(
                    gate_id="<absent>",
                    check="presence",
                    reason=(
                        f"action {action.action_id!r} arrived without a lifecycle gate; "
                        f"production mutation requires one"
                    ),
                )
            )
        self._gate_verifier.consume(gate, action)

    @staticmethod
    def _require_authorization(
        action: Action, authorization: ExecutionAuthorization | None
    ) -> None:
        """Refuse to act without an authorization that binds to this exact action."""
        if authorization is None:
            raise UnauthorizedExecutionError(
                f"action {action.action_id!r} has no execution authorization"
            )
        if authorization.action_id != action.action_id:
            raise UnauthorizedExecutionError(
                f"authorization covers action {authorization.action_id!r}, not {action.action_id!r}"
            )
        if authorization.incident_id != action.incident_id:
            raise UnauthorizedExecutionError(
                f"authorization belongs to incident {authorization.incident_id!r}, not "
                f"{action.incident_id!r}"
            )
        if authorization.action_fingerprint != action_fingerprint(action):
            raise UnauthorizedExecutionError(
                f"action {action.action_id!r} changed after it was authorized"
            )

    def __repr__(self) -> str:
        return f"{type(self).__name__}(world={self._world!r})"
