"""Failure classification, and the line between a decision and an anomaly.

The distinction this module exists to hold (Part 13):

    A policy DENY is the control plane **working**. It must never open the breaker.

    A governance anomaly is the control plane producing a state that should be
    unreachable. One occurrence is already the strongest signal available.

Getting this backwards in either direction is a serious failure mode. Treating DENY as an
anomaly means a correctly-governed system disables itself the first time it refuses
something — a denial-of-service built out of the safety mechanism. Treating an anomaly as
ordinary means execution without authorization gets averaged in with flaky telemetry.

Classification is deterministic and total: every input maps to exactly one class, and the
functions here read recorded artifacts without asking any engine to re-decide anything.
"""

from __future__ import annotations

from enum import StrEnum

from aegis.core.domain import DomainModel, NonEmptyStr, PolicyDecisionType

__all__ = [
    "GOVERNANCE_ANOMALIES",
    "FailureClass",
    "FailureSignal",
    "classify_execution",
    "classify_verification",
    "detect_governance_anomaly",
    "is_governance_anomaly",
]


class FailureClass(StrEnum):
    """What kind of trouble a lifecycle step produced.

    Separate members rather than a single ``FAILED`` because the breaker thresholds them
    independently and because a human reading the trail needs to know which pipeline broke.
    """

    NONE = "NONE"
    """Nothing went wrong. Recorded explicitly so success is a value, not an absence."""

    EXECUTION_FAILURE = "EXECUTION_FAILURE"
    """The enterprise refused or failed to carry out the action."""

    VERIFICATION_FAILURE = "VERIFICATION_FAILURE"
    """Verification ran and established the expected state was not reached."""

    STALE_VERIFICATION = "STALE_VERIFICATION"
    """Evidence was too old to establish anything. The observation pipeline is unhealthy;
    this says nothing about whether the remediation worked."""

    VERIFICATION_MISMATCH = "VERIFICATION_MISMATCH"
    """Sources disagreed. The picture of the enterprise is not trustworthy."""

    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    """Nothing usable was observed at all. Counted with stale verification, since both
    mean the same thing operationally: verification could not see."""

    GOVERNANCE_ANOMALY = "GOVERNANCE_ANOMALY"
    """A state the control plane should not be able to reach. See
    :data:`GOVERNANCE_ANOMALIES`."""


GOVERNANCE_ANOMALIES: tuple[str, ...] = (
    "execution_without_authorization",
    "execution_without_policy_evaluation",
    "execution_after_deny",
    "authorization_for_different_action",
    "verification_for_different_action",
    "audit_chain_invalid",
)
"""Every condition that counts as an anomaly, named and closed.

A closed vocabulary rather than a predicate over free text: an anomaly type that could be
invented at a call site is one no test covers. Note what is *absent* — there is no member
for a denial, a rejection, an unsupported capability or a failed tool, because none of
those is anomalous. They are the system saying no, which it is supposed to be able to do.
"""


class FailureSignal(DomainModel):
    """One classified outcome, ready for the breaker to count.

    Carries the class and a human-readable reason. Deliberately not the artifacts
    themselves: the breaker must not be able to re-interpret a verification or second-guess
    a policy decision, so it is handed a classification and nothing to re-derive it from.
    """

    failure_class: FailureClass
    reason: NonEmptyStr
    scope_key: NonEmptyStr
    """Which breaker this signal belongs to. Computed by the caller from the action."""

    @property
    def is_failure(self) -> bool:
        return self.failure_class is not FailureClass.NONE


def classify_execution(outcome: object) -> FailureClass:
    """Classify what the enterprise reported about an execution.

    ``APPLIED`` is the only non-failure. ``FAILED``, ``BLOCKED`` and ``UNSUPPORTED`` all
    count as execution failures: from the lifecycle's point of view the distinction is
    diagnostic, and none of them is a reason to keep trying indefinitely.

    Note what this does *not* do — it does not consult the world, re-run the action, or
    treat a missing result as success. An unrecognisable outcome is a failure, because
    failing closed is the only safe reading of "I cannot tell what happened".
    """
    name = _name(outcome)
    if name == "APPLIED":
        return FailureClass.NONE
    return FailureClass.EXECUTION_FAILURE


def classify_verification(status: object) -> FailureClass:
    """Classify a verification status into its own failure class.

    Each status keeps its identity (Part 21). ``VERIFIED`` is the only success, and an
    unrecognisable status is treated as a verification failure rather than as success —
    the same fail-closed reading as everywhere else in AEGIS.
    """
    name = _name(status)
    if name == "VERIFIED":
        return FailureClass.NONE
    if name == "STALE":
        return FailureClass.STALE_VERIFICATION
    if name == "MISMATCH":
        return FailureClass.VERIFICATION_MISMATCH
    if name == "INSUFFICIENT_EVIDENCE":
        return FailureClass.INSUFFICIENT_EVIDENCE
    return FailureClass.VERIFICATION_FAILURE


def is_governance_anomaly(policy_decision: object) -> bool:
    """Whether a policy decision is itself anomalous. **Always false.**

    A function that exists to be called and return ``False``, because the alternative is a
    call site that quietly forgets the rule. ALLOW, DENY and REQUIRE_APPROVAL are all the
    policy engine working; none of them is evidence that anything is wrong.
    """
    return False


def detect_governance_anomaly(
    *,
    executed: bool,
    authorization_present: bool,
    policy_decision: PolicyDecisionType | None,
    action_id: str | None,
    authorized_action_id: str | None,
    verified_action_id: str | None,
    audit_valid: bool,
) -> tuple[str, ...]:
    """Find every anomaly in one completed remediation, by name.

    Each check compares two recorded artifacts against each other and asks whether the
    record of permission exists — never whether permission was *deserved*, which is the
    policy engine's question and is not re-asked here.

    Returns the names of the anomalies found, in the fixed order above, so the same inputs
    always produce the same tuple.
    """
    found: list[str] = []

    if executed and not authorization_present:
        found.append("execution_without_authorization")
    if executed and policy_decision is None:
        found.append("execution_without_policy_evaluation")
    if executed and policy_decision is PolicyDecisionType.DENY:
        found.append("execution_after_deny")
    if (
        authorization_present
        and authorized_action_id is not None
        and action_id is not None
        and authorized_action_id != action_id
    ):
        found.append("authorization_for_different_action")
    if verified_action_id is not None and action_id is not None and verified_action_id != action_id:
        found.append("verification_for_different_action")
    if not audit_valid:
        found.append("audit_chain_invalid")

    return tuple(found)


def _name(value: object) -> str:
    """A StrEnum member's value, a plain string, or a token that matches nothing.

    An unreadable value must never compare equal to a success name, so anything that is
    not a string becomes a sentinel rather than its ``repr`` — a repr can be crafted.
    """
    resolved = getattr(value, "value", value)
    return resolved if isinstance(resolved, str) else "<unrecognised>"
