"""The incident transition table and the state machine that applies it.

Most of this file is negative. A state machine's value is entirely in what it refuses,
and the AEGIS lifecycle has three refusals that matter more than the rest: you cannot
resolve without verifying, you cannot execute without a policy check, and you cannot
leave a terminal state.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from aegis.core.approval import action_fingerprint
from aegis.core.domain import (
    Incident,
    IncidentState,
    PolicyDecision,
    PolicyDecisionType,
    to_json,
)
from aegis.core.incidents import (
    TERMINAL_STATES,
    TRANSITIONS,
    IncidentStateMachine,
    InvalidIncidentTransition,
    TransitionGuard,
)
from aegis.core.verification import (
    CheckOutcome,
    Comparator,
    PredicateCheck,
    VerificationResult,
    VerificationStatus,
)
from tests.fleet import (
    FIXED_EVALUATION_TIME,
    INCIDENT_CREATED_AT,
    PAYMENT_API,
    build_action,
    build_incident,
)

ALLOW = PolicyDecision(
    decision=PolicyDecisionType.ALLOW,
    reason="permitted",
    policy_reference="policy:aegis/v1#allowed",
    evaluated_at=FIXED_EVALUATION_TIME,
)
REQUIRE_APPROVAL = PolicyDecision(
    decision=PolicyDecisionType.REQUIRE_APPROVAL,
    reason="needs sign-off",
    policy_reference="policy:aegis/v1#approval-required",
    evaluated_at=FIXED_EVALUATION_TIME,
)
DENY = PolicyDecision(
    decision=PolicyDecisionType.DENY,
    reason="not permitted",
    policy_reference="policy:aegis/v1#capability-not-held",
    evaluated_at=FIXED_EVALUATION_TIME,
)


RESOLUTION_ACTION = build_action(
    requesting_agent="remediation",
    capability="production.rollback",
    target_resource=PAYMENT_API,
)
"""The action the fleet incident lists in ``proposed_actions``."""


def _verification(
    *, status: VerificationStatus = VerificationStatus.VERIFIED
) -> VerificationResult:
    """A verification result bound to :data:`RESOLUTION_ACTION`."""
    return VerificationResult(
        verification_id="ver-001",
        incident_id="INC-2026-0001",
        action_id=RESOLUTION_ACTION.action_id,
        action_fingerprint=action_fingerprint(RESOLUTION_ACTION),
        resource=RESOLUTION_ACTION.target_resource,
        status=status,
        checks=(
            PredicateCheck(
                attribute="health",
                comparator=Comparator.EQUALS,
                expected="healthy",
                observed="healthy",
                outcome=CheckOutcome.PASS,
                observation_ids=("obs-health",),
                detail="health EQUALS healthy: observed healthy -> PASS",
            ),
        ),
        observations_used=("obs-health",),
        evaluated_at=FIXED_EVALUATION_TIME,
        reason="all 1 predicate(s) satisfied by fresh, accepted observations",
    )


VERIFIED = _verification()


def _move(
    machine: IncidentStateMachine,
    from_state: IncidentState,
    to_state: IncidentState,
    **kwargs: object,
) -> Incident:
    return machine.transition(
        build_incident(state=from_state),
        to_state,
        reason="test",
        actor="system:test",
        **kwargs,  # type: ignore[arg-type]
    )


# --- table shape --------------------------------------------------------------------


def test_every_incident_state_has_defined_behaviour() -> None:
    """No enum member may be left out; an undefined state is an undefined boundary."""
    assert set(TRANSITIONS) == set(IncidentState)


def test_terminal_states_are_exactly_resolved_and_escalated() -> None:
    expected = {IncidentState.RESOLVED, IncidentState.ESCALATED}
    assert set(TERMINAL_STATES) == expected


def test_terminal_states_have_no_outgoing_edges() -> None:
    for state in TERMINAL_STATES:
        assert TRANSITIONS[state] == {}


def test_no_state_transitions_to_itself() -> None:
    for state, edges in TRANSITIONS.items():
        assert state not in edges


def test_table_is_read_only() -> None:
    with pytest.raises(TypeError):
        TRANSITIONS[IncidentState.PLAN_PROPOSED][IncidentState.EXECUTING] = (  # type: ignore[index]
            TransitionGuard.NONE
        )


def test_transitivity_is_not_implied() -> None:
    """A -> B and B -> C must not create A -> C."""
    machine = IncidentStateMachine()
    assert machine.can_transition(IncidentState.RECEIVED, IncidentState.CLASSIFIED)
    assert machine.can_transition(IncidentState.CLASSIFIED, IncidentState.INVESTIGATING)
    assert not machine.can_transition(IncidentState.RECEIVED, IncidentState.INVESTIGATING)


# --- the normal path ----------------------------------------------------------------


NORMAL_PATH = [
    (IncidentState.RECEIVED, IncidentState.CLASSIFIED, {}),
    (IncidentState.CLASSIFIED, IncidentState.INVESTIGATING, {}),
    (IncidentState.INVESTIGATING, IncidentState.IMPACT_ASSESSED, {}),
    (IncidentState.IMPACT_ASSESSED, IncidentState.PLAN_PROPOSED, {}),
    (IncidentState.PLAN_PROPOSED, IncidentState.POLICY_CHECK, {}),
    (
        IncidentState.POLICY_CHECK,
        IncidentState.AWAITING_APPROVAL,
        {"policy_decision": REQUIRE_APPROVAL},
    ),
    (IncidentState.EXECUTING, IncidentState.VERIFYING, {}),
    (
        IncidentState.VERIFYING,
        IncidentState.RESOLVED,
        {"verification": VERIFIED, "action": RESOLUTION_ACTION},
    ),
]


@pytest.mark.parametrize(
    ("from_state", "to_state", "kwargs"),
    NORMAL_PATH,
    ids=[f"{a.value}->{b.value}" for a, b, _ in NORMAL_PATH],
)
def test_normal_path_edges_are_permitted(
    from_state: IncidentState, to_state: IncidentState, kwargs: dict
) -> None:
    machine = IncidentStateMachine(clock=lambda: FIXED_EVALUATION_TIME)
    assert _move(machine, from_state, to_state, **kwargs).state is to_state


def test_policy_check_to_executing_needs_an_allow() -> None:
    """The no-approval branch: ALLOW goes straight to execution."""
    machine = IncidentStateMachine(clock=lambda: FIXED_EVALUATION_TIME)
    moved = _move(
        machine,
        IncidentState.POLICY_CHECK,
        IncidentState.EXECUTING,
        policy_decision=ALLOW,
    )
    assert moved.state is IncidentState.EXECUTING


# --- RESOLVED is reachable only from VERIFYING --------------------------------------


@pytest.mark.parametrize(
    "from_state",
    [
        state
        for state in IncidentState
        if state not in {IncidentState.VERIFYING, IncidentState.RESOLVED}
    ],
    ids=lambda state: state.value,
)
def test_resolved_is_unreachable_except_from_verifying(
    from_state: IncidentState,
) -> None:
    """Execution is not proof of success (claude.md section 11)."""
    machine = IncidentStateMachine(clock=lambda: FIXED_EVALUATION_TIME)
    assert not machine.can_transition(from_state, IncidentState.RESOLVED)
    with pytest.raises(InvalidIncidentTransition):
        _move(machine, from_state, IncidentState.RESOLVED)


def test_only_verifying_leads_to_resolved_in_the_table() -> None:
    sources = [state for state, edges in TRANSITIONS.items() if IncidentState.RESOLVED in edges]
    assert sources == [IncidentState.VERIFYING]


# --- POLICY_CHECK cannot be skipped -------------------------------------------------


def test_plan_proposed_cannot_jump_to_executing() -> None:
    machine = IncidentStateMachine(clock=lambda: FIXED_EVALUATION_TIME)
    with pytest.raises(InvalidIncidentTransition) as excinfo:
        _move(
            machine,
            IncidentState.PLAN_PROPOSED,
            IncidentState.EXECUTING,
            policy_decision=ALLOW,
        )
    assert excinfo.value.from_state is IncidentState.PLAN_PROPOSED
    assert excinfo.value.to_state is IncidentState.EXECUTING


def test_plan_proposed_cannot_jump_to_awaiting_approval() -> None:
    machine = IncidentStateMachine(clock=lambda: FIXED_EVALUATION_TIME)
    with pytest.raises(InvalidIncidentTransition):
        _move(
            machine,
            IncidentState.PLAN_PROPOSED,
            IncidentState.AWAITING_APPROVAL,
            policy_decision=REQUIRE_APPROVAL,
        )


def test_plan_proposed_leads_only_to_policy_check_degraded_or_escalated() -> None:
    machine = IncidentStateMachine()
    assert machine.allowed_transitions(IncidentState.PLAN_PROPOSED) == (
        IncidentState.DEGRADED,
        IncidentState.ESCALATED,
        IncidentState.POLICY_CHECK,
    )


def _sources(target: IncidentState) -> list[IncidentState]:
    """Every state with an edge into ``target``, sorted by name."""
    return sorted(
        (state for state, edges in TRANSITIONS.items() if target in edges),
        key=lambda state: state.value,
    )


def test_every_edge_into_executing_is_guarded() -> None:
    """There are exactly two ways to execute, and neither is unguarded."""
    assert _sources(IncidentState.EXECUTING) == [
        IncidentState.AWAITING_APPROVAL,
        IncidentState.POLICY_CHECK,
    ]
    assert (
        TRANSITIONS[IncidentState.POLICY_CHECK][IncidentState.EXECUTING]
        is TransitionGuard.POLICY_ALLOW
    )
    assert (
        TRANSITIONS[IncidentState.AWAITING_APPROVAL][IncidentState.EXECUTING]
        is TransitionGuard.EXECUTION_AUTHORIZATION
    )


def test_awaiting_approval_is_only_reachable_through_policy_check() -> None:
    """The approval branch is not a separate door into execution."""
    assert _sources(IncidentState.AWAITING_APPROVAL) == [IncidentState.POLICY_CHECK]


def test_executing_is_unreachable_from_intake_without_policy_check() -> None:
    """Remove the gate from the graph and execution becomes unreachable.

    Breadth-first from RECEIVED, the only state an incident enters at. Covers every
    detour, including the DEGRADED and RECOVERING recovery loops.
    """
    seen = {IncidentState.RECEIVED}
    frontier = [IncidentState.RECEIVED]
    while frontier:
        current = frontier.pop()
        if current is IncidentState.POLICY_CHECK:
            continue  # the gate is removed from the graph
        for nxt in TRANSITIONS[current]:
            if nxt not in seen:
                seen.add(nxt)
                frontier.append(nxt)

    assert IncidentState.EXECUTING not in seen
    assert IncidentState.AWAITING_APPROVAL not in seen
    assert IncidentState.RESOLVED not in seen


def test_intake_reaches_execution_once_the_gate_is_restored() -> None:
    """The complement: with POLICY_CHECK in place the lifecycle is actually traversable."""
    seen = {IncidentState.RECEIVED}
    frontier = [IncidentState.RECEIVED]
    while frontier:
        current = frontier.pop()
        for nxt in TRANSITIONS[current]:
            if nxt not in seen:
                seen.add(nxt)
                frontier.append(nxt)
    assert seen == set(IncidentState)


def test_recovery_re_enters_at_investigating_only() -> None:
    """A degradation detour is not a shortcut past the policy gate."""
    machine = IncidentStateMachine()
    assert machine.allowed_transitions(IncidentState.RECOVERING) == (
        IncidentState.DEGRADED,
        IncidentState.ESCALATED,
        IncidentState.INVESTIGATING,
    )


# --- guards -------------------------------------------------------------------------


def test_awaiting_approval_cannot_be_walked_out_of() -> None:
    """No artifact, no execution."""
    machine = IncidentStateMachine(clock=lambda: FIXED_EVALUATION_TIME)
    with pytest.raises(InvalidIncidentTransition, match="execution authorization"):
        _move(machine, IncidentState.AWAITING_APPROVAL, IncidentState.EXECUTING)


def test_a_policy_decision_does_not_satisfy_the_approval_guard() -> None:
    machine = IncidentStateMachine(clock=lambda: FIXED_EVALUATION_TIME)
    with pytest.raises(InvalidIncidentTransition):
        _move(
            machine,
            IncidentState.AWAITING_APPROVAL,
            IncidentState.EXECUTING,
            policy_decision=ALLOW,
        )


@pytest.mark.parametrize(
    ("to_state", "decision"),
    [
        (IncidentState.EXECUTING, DENY),
        (IncidentState.EXECUTING, REQUIRE_APPROVAL),
        (IncidentState.AWAITING_APPROVAL, DENY),
        (IncidentState.AWAITING_APPROVAL, ALLOW),
    ],
    ids=["execute-on-deny", "execute-on-approval", "await-on-deny", "await-on-allow"],
)
def test_policy_guards_require_the_matching_decision(
    to_state: IncidentState, decision: PolicyDecision
) -> None:
    machine = IncidentStateMachine(clock=lambda: FIXED_EVALUATION_TIME)
    with pytest.raises(InvalidIncidentTransition, match="requires a"):
        _move(machine, IncidentState.POLICY_CHECK, to_state, policy_decision=decision)


@pytest.mark.parametrize("to_state", [IncidentState.EXECUTING, IncidentState.AWAITING_APPROVAL])
def test_a_missing_policy_decision_never_satisfies_a_guard(
    to_state: IncidentState,
) -> None:
    """Absence is not permission."""
    machine = IncidentStateMachine(clock=lambda: FIXED_EVALUATION_TIME)
    with pytest.raises(InvalidIncidentTransition, match="none supplied"):
        _move(machine, IncidentState.POLICY_CHECK, to_state)


def test_a_denied_plan_can_only_re_plan_degrade_or_escalate() -> None:
    """POLICY_CHECK + DENY reaches neither AWAITING_APPROVAL nor EXECUTING."""
    machine = IncidentStateMachine(clock=lambda: FIXED_EVALUATION_TIME)
    for to_state in (IncidentState.AWAITING_APPROVAL, IncidentState.EXECUTING):
        with pytest.raises(InvalidIncidentTransition):
            _move(machine, IncidentState.POLICY_CHECK, to_state, policy_decision=DENY)

    for to_state in (
        IncidentState.PLAN_PROPOSED,
        IncidentState.DEGRADED,
        IncidentState.ESCALATED,
    ):
        assert _move(machine, IncidentState.POLICY_CHECK, to_state).state is to_state


def test_guard_for_reports_the_edges_requirement() -> None:
    machine = IncidentStateMachine()
    assert machine.guard_for(IncidentState.RECEIVED, IncidentState.CLASSIFIED) is (
        TransitionGuard.NONE
    )
    assert (
        machine.guard_for(IncidentState.POLICY_CHECK, IncidentState.AWAITING_APPROVAL)
        is TransitionGuard.POLICY_REQUIRE_APPROVAL
    )
    assert (
        machine.guard_for(IncidentState.AWAITING_APPROVAL, IncidentState.EXECUTING)
        is TransitionGuard.EXECUTION_AUTHORIZATION
    )


# --- terminal states ----------------------------------------------------------------


@pytest.mark.parametrize("terminal", sorted(TERMINAL_STATES, key=lambda s: s.value))
@pytest.mark.parametrize(
    "to_state",
    [
        IncidentState.INVESTIGATING,
        IncidentState.EXECUTING,
        IncidentState.PLAN_PROPOSED,
        IncidentState.DEGRADED,
    ],
    ids=lambda state: state.value,
)
def test_terminal_states_never_re_enter_processing(
    terminal: IncidentState, to_state: IncidentState
) -> None:
    machine = IncidentStateMachine(clock=lambda: FIXED_EVALUATION_TIME)
    with pytest.raises(InvalidIncidentTransition, match="terminal"):
        _move(machine, terminal, to_state, policy_decision=ALLOW)


def test_resolved_cannot_reopen_into_executing() -> None:
    machine = IncidentStateMachine(clock=lambda: FIXED_EVALUATION_TIME)
    with pytest.raises(InvalidIncidentTransition):
        _move(machine, IncidentState.RESOLVED, IncidentState.EXECUTING)


def test_escalated_cannot_resume() -> None:
    machine = IncidentStateMachine(clock=lambda: FIXED_EVALUATION_TIME)
    with pytest.raises(InvalidIncidentTransition):
        _move(machine, IncidentState.ESCALATED, IncidentState.EXECUTING)


# --- degraded / recovering ----------------------------------------------------------


@pytest.mark.parametrize(
    "state",
    [
        state
        for state in IncidentState
        if state not in TERMINAL_STATES and state is not IncidentState.DEGRADED
    ],
    ids=lambda state: state.value,
)
def test_every_active_state_can_degrade(state: IncidentState) -> None:
    """claude.md section 8: any state may degrade."""
    machine = IncidentStateMachine(clock=lambda: FIXED_EVALUATION_TIME)
    assert _move(machine, state, IncidentState.DEGRADED).state is IncidentState.DEGRADED


def test_terminal_states_cannot_degrade() -> None:
    machine = IncidentStateMachine(clock=lambda: FIXED_EVALUATION_TIME)
    for terminal in TERMINAL_STATES:
        with pytest.raises(InvalidIncidentTransition):
            _move(machine, terminal, IncidentState.DEGRADED)


def test_degraded_recovers_or_escalates() -> None:
    machine = IncidentStateMachine()
    assert machine.allowed_transitions(IncidentState.DEGRADED) == (
        IncidentState.ESCALATED,
        IncidentState.RECOVERING,
    )


# --- immutability and records -------------------------------------------------------


def test_transition_returns_a_new_incident_and_leaves_the_original() -> None:
    machine = IncidentStateMachine(clock=lambda: FIXED_EVALUATION_TIME)
    original = build_incident(state=IncidentState.RECEIVED)
    before = to_json(original)

    moved = machine.transition(
        original, IncidentState.CLASSIFIED, reason="triaged", actor="agent:commander"
    )

    assert to_json(original) == before
    assert original.state is IncidentState.RECEIVED
    assert moved is not original
    assert moved.state is IncidentState.CLASSIFIED


def test_transition_restamps_updated_at_only() -> None:
    machine = IncidentStateMachine(clock=lambda: FIXED_EVALUATION_TIME)
    original = build_incident(state=IncidentState.RECEIVED)
    moved = machine.transition(
        original, IncidentState.CLASSIFIED, reason="triaged", actor="agent:commander"
    )
    assert moved.updated_at == FIXED_EVALUATION_TIME
    assert moved.created_at == INCIDENT_CREATED_AT
    for field in Incident.model_fields:
        if field in {"state", "updated_at"}:
            continue
        assert getattr(moved, field) == getattr(original, field), field


def test_transition_record_carries_what_audit_will_need() -> None:
    machine = IncidentStateMachine(clock=lambda: FIXED_EVALUATION_TIME)
    result = machine.transition_detailed(
        build_incident(state=IncidentState.POLICY_CHECK),
        IncidentState.AWAITING_APPROVAL,
        reason="rollback requires human sign-off",
        actor="system:policy-engine",
        policy_decision=REQUIRE_APPROVAL,
    )
    record = result.transition
    assert record.incident_id == "INC-2026-0001"
    assert record.from_state is IncidentState.POLICY_CHECK
    assert record.to_state is IncidentState.AWAITING_APPROVAL
    assert record.reason
    assert record.actor == "system:policy-engine"
    assert record.occurred_at == FIXED_EVALUATION_TIME
    assert record.guard is TransitionGuard.POLICY_REQUIRE_APPROVAL
    assert record.policy_reference == REQUIRE_APPROVAL.policy_reference


def test_reason_and_actor_are_required() -> None:
    machine = IncidentStateMachine(clock=lambda: FIXED_EVALUATION_TIME)
    incident = build_incident(state=IncidentState.RECEIVED)
    for kwargs in ({"reason": "", "actor": "x"}, {"reason": "x", "actor": "  "}):
        with pytest.raises(ValidationError):
            machine.transition_detailed(incident, IncidentState.CLASSIFIED, **kwargs)


def test_refusal_carries_machine_readable_context() -> None:
    machine = IncidentStateMachine(clock=lambda: FIXED_EVALUATION_TIME)
    with pytest.raises(InvalidIncidentTransition) as excinfo:
        _move(machine, IncidentState.EXECUTING, IncidentState.RESOLVED)
    error = excinfo.value
    assert error.incident_id == "INC-2026-0001"
    assert error.from_state is IncidentState.EXECUTING
    assert error.to_state is IncidentState.RESOLVED
    assert error.reason


def test_self_transition_is_refused() -> None:
    machine = IncidentStateMachine(clock=lambda: FIXED_EVALUATION_TIME)
    with pytest.raises(InvalidIncidentTransition, match="itself"):
        _move(machine, IncidentState.INVESTIGATING, IncidentState.INVESTIGATING)


# --- determinism --------------------------------------------------------------------


def test_repeated_transitions_are_byte_identical() -> None:
    machine = IncidentStateMachine(clock=lambda: FIXED_EVALUATION_TIME)
    incident = build_incident(state=IncidentState.RECEIVED)
    first = machine.transition_detailed(
        incident, IncidentState.CLASSIFIED, reason="triaged", actor="agent:commander"
    )
    second = machine.transition_detailed(
        incident, IncidentState.CLASSIFIED, reason="triaged", actor="agent:commander"
    )
    assert to_json(first) == to_json(second)


def test_the_machine_holds_no_state() -> None:
    machine = IncidentStateMachine(clock=lambda: FIXED_EVALUATION_TIME)
    incident = build_incident(state=IncidentState.RECEIVED)
    first = machine.transition(incident, IncidentState.CLASSIFIED, reason="a", actor="system:test")
    machine.transition(
        build_incident(state=IncidentState.EXECUTING),
        IncidentState.VERIFYING,
        reason="b",
        actor="system:test",
    )
    second = machine.transition(incident, IncidentState.CLASSIFIED, reason="a", actor="system:test")
    assert to_json(first) == to_json(second)
