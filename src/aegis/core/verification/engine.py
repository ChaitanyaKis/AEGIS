"""The verification engine — establishing what actually happened.

    PROPOSE -> AUTHORIZE -> EXECUTE -> VERIFY -> ESTABLISH ACTUAL STATE

This is the "verify" stage (``claude.md`` section 11). It compares a declared expected
state against independent observations and returns a
:class:`~aegis.core.verification.results.VerificationResult`. It asks no model whether
something *looks* healthy, makes no probabilistic judgement, reads no tool return value
and touches no network.

How an observation becomes usable
---------------------------------

Every observation passes four filters before it can contribute, and each is a hard gate:

1. **Resource** — it must be about the action's target. Observations of dependent services
   are context, never a substitute (section 11).
2. **Evidence type** — it must be a type that can establish enterprise state. Tool results
   and agent findings are excluded by construction.
3. **Source** — it must come from a source the expectation explicitly accepts.
4. **Freshness** — it must be no older than the expectation's window.

What is left is then compared, attribute by attribute. Anything that survives none of
these leaves the corresponding predicate unestablished, and an unestablished predicate is
never a pass.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from datetime import datetime

from aegis.core.approval import action_fingerprint
from aegis.core.domain import Action, utc_now
from aegis.core.verification.expectation import Comparator, ExpectedState, Predicate
from aegis.core.verification.observation import Observation, ObservedValue
from aegis.core.verification.results import (
    STATUS_PRECEDENCE,
    CheckOutcome,
    PredicateCheck,
    VerificationResult,
    VerificationStatus,
)

__all__ = ["VerificationEngine", "VerificationRequestError"]


class VerificationRequestError(ValueError):
    """The verification was wired up wrongly and could not be attempted.

    Distinct from a failed verification: this means the caller asked an incoherent
    question — such as checking an expectation for one resource against an action
    targeting another — not that the enterprise is in the wrong state. Raising keeps a
    wiring bug loud instead of letting it read as an ordinary non-verification.
    """


_OUTCOME_TO_STATUS = {
    CheckOutcome.MISSING: VerificationStatus.INSUFFICIENT_EVIDENCE,
    CheckOutcome.STALE: VerificationStatus.STALE,
    CheckOutcome.CONFLICT: VerificationStatus.MISMATCH,
    CheckOutcome.FAIL: VerificationStatus.FAILED,
}


def _compare(predicate: Predicate, observed: ObservedValue) -> bool:
    """Evaluate one predicate against one value. Closed, total, and never parses text."""
    match predicate.comparator:
        case Comparator.EQUALS:
            return observed == predicate.value
        case Comparator.AT_MOST | Comparator.AT_LEAST:
            # A categorical value cannot satisfy an ordered comparison. That is a failed
            # expectation, not an error: the resource is not in the state that was asked for.
            if isinstance(observed, str) or isinstance(predicate.value, str):
                return False
            if predicate.comparator is Comparator.AT_MOST:
                return observed <= predicate.value
            return observed >= predicate.value
    return False  # pragma: no cover - Comparator is closed


class VerificationEngine:
    """Compares expected enterprise state against observed enterprise state.

    Args:
        clock: Source of the evaluation instant, used only for freshness. Injectable so
            tests never depend on wall time.

    Stateless and pure given its inputs and evaluation time: the same action, expectation
    and observations always produce an equal result.
    """

    def __init__(self, *, clock: Callable[[], datetime] = utc_now) -> None:
        self._clock = clock

    def verify(
        self,
        action: Action,
        expected_state: ExpectedState,
        observations: Iterable[Observation],
        *,
        verification_id: str,
        evaluated_at: datetime | None = None,
    ) -> VerificationResult:
        """Establish whether ``action`` achieved ``expected_state``.

        Args:
            action: The executed action being verified. Supplies the incident, action and
                resource bindings the result is stamped with.
            expected_state: What success means, and how fresh and trusted the evidence
                must be. Its ``resource`` must be the action's target.
            observations: Candidate observations. Ones that fail any filter are simply not
                used; passing irrelevant observations is harmless and never helps.
            verification_id: Identifier for the result.
            evaluated_at: Evaluation instant. Defaults to the injected clock.

        Returns:
            A :class:`VerificationResult`. Only ``VERIFIED`` establishes the expected
            state; the other four statuses each say something different about why nothing
            was established.

        Raises:
            VerificationRequestError: if the expectation is for a different resource than
                the action targets.
        """
        if expected_state.resource != action.target_resource:
            raise VerificationRequestError(
                f"expectation describes {expected_state.resource!r} but action "
                f"{action.action_id!r} targets {action.target_resource!r}"
            )

        now = evaluated_at if evaluated_at is not None else self._clock()
        usable = self._usable_observations(action, expected_state, observations, now)
        stale_attributes = self._stale_attributes(action, expected_state, observations, now)

        checks = tuple(
            self._check(predicate, usable, stale_attributes)
            for predicate in expected_state.predicates
        )
        status = self._status(checks)
        contributing = sorted(
            {observation_id for check in checks for observation_id in check.observation_ids}
        )

        return VerificationResult(
            verification_id=verification_id,
            incident_id=action.incident_id,
            action_id=action.action_id,
            action_fingerprint=action_fingerprint(action),
            resource=action.target_resource,
            status=status,
            checks=checks,
            observations_used=tuple(contributing),
            evaluated_at=now,
            reason=self._reason(status, checks),
        )

    # --- filtering ------------------------------------------------------------------

    @staticmethod
    def _admissible(
        action: Action, expected_state: ExpectedState, observation: Observation
    ) -> bool:
        """Resource, evidence type and source gates. Freshness is applied separately."""
        return (
            observation.resource == action.target_resource
            and observation.is_observable
            and observation.source in expected_state.accepted_sources
        )

    def _usable_observations(
        self,
        action: Action,
        expected_state: ExpectedState,
        observations: Iterable[Observation],
        now: datetime,
    ) -> tuple[Observation, ...]:
        """Observations that pass every gate, including freshness."""
        return tuple(
            observation
            for observation in observations
            if self._admissible(action, expected_state, observation)
            and now - observation.observed_at <= expected_state.max_observation_age
        )

    def _stale_attributes(
        self,
        action: Action,
        expected_state: ExpectedState,
        observations: Iterable[Observation],
        now: datetime,
    ) -> frozenset[str]:
        """Attributes that were observed by an admissible source, but only too long ago.

        Tracked so that "nobody is watching this" and "the data has gone cold" stay
        distinguishable — they call for different responses.
        """
        return frozenset(
            attribute
            for observation in observations
            if self._admissible(action, expected_state, observation)
            and now - observation.observed_at > expected_state.max_observation_age
            for attribute in observation.values
        )

    # --- evaluation -----------------------------------------------------------------

    @staticmethod
    def _check(
        predicate: Predicate,
        usable: Sequence[Observation],
        stale_attributes: frozenset[str],
    ) -> PredicateCheck:
        """Evaluate one predicate against every usable observation carrying its attribute."""
        carrying = [
            observation for observation in usable if predicate.attribute in observation.values
        ]
        observation_ids = tuple(sorted(observation.observation_id for observation in carrying))

        if not carrying:
            stale = predicate.attribute in stale_attributes
            outcome = CheckOutcome.STALE if stale else CheckOutcome.MISSING
            detail = (
                f"{predicate.describe()}: only stale observations available"
                if stale
                else f"{predicate.describe()}: no usable observation carried this attribute"
            )
            return PredicateCheck(
                attribute=predicate.attribute,
                comparator=predicate.comparator,
                expected=predicate.value,
                outcome=outcome,
                detail=detail,
            )

        distinct = {observation.values[predicate.attribute] for observation in carrying}
        if len(distinct) > 1:
            # Contradictory evidence establishes nothing, whether or not each value would
            # individually pass. The engine never picks a winner.
            return PredicateCheck(
                attribute=predicate.attribute,
                comparator=predicate.comparator,
                expected=predicate.value,
                outcome=CheckOutcome.CONFLICT,
                observation_ids=observation_ids,
                detail=(
                    f"{predicate.describe()}: sources disagree "
                    f"({', '.join(sorted(str(value) for value in distinct))})"
                ),
            )

        observed = next(iter(distinct))
        passed = _compare(predicate, observed)
        return PredicateCheck(
            attribute=predicate.attribute,
            comparator=predicate.comparator,
            expected=predicate.value,
            observed=observed,
            outcome=CheckOutcome.PASS if passed else CheckOutcome.FAIL,
            observation_ids=observation_ids,
            detail=(
                f"{predicate.describe()}: observed {observed} -> {'PASS' if passed else 'FAIL'}"
            ),
        )

    @staticmethod
    def _status(checks: Sequence[PredicateCheck]) -> VerificationStatus:
        """Reduce per-predicate outcomes to one status.

        Every predicate must pass. Otherwise the most severe failure wins, per
        :data:`~aegis.core.verification.results.STATUS_PRECEDENCE`.
        """
        outcomes = {check.outcome for check in checks}
        if outcomes == {CheckOutcome.PASS}:
            return VerificationStatus.VERIFIED
        for status in STATUS_PRECEDENCE:
            if any(_OUTCOME_TO_STATUS.get(outcome) is status for outcome in outcomes):
                return status
        return VerificationStatus.INSUFFICIENT_EVIDENCE  # pragma: no cover

    @staticmethod
    def _reason(status: VerificationStatus, checks: Sequence[PredicateCheck]) -> str:
        if status is VerificationStatus.VERIFIED:
            return f"all {len(checks)} predicate(s) satisfied by fresh, accepted observations"
        offending = [check.attribute for check in checks if check.outcome is not CheckOutcome.PASS]
        return f"{status} on: {', '.join(offending)}"

    def __repr__(self) -> str:
        return f"{type(self).__name__}()"
