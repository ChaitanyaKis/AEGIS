"""The simulated world: initial state, topology, controlled mutation and the executor."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from aegis.core.approval import ExecutionAuthorization, action_fingerprint
from aegis.core.dependencies import UnknownResourceError
from aegis.core.domain import Action, PolicyDecision, PolicyDecisionType, to_json
from aegis.enterprise import (
    ORDER_SERVICE,
    PAYMENT_API,
    PAYMENT_API_FAULTY_VERSION,
    PAYMENT_API_GOOD_VERSION,
    SUPPORTED_CAPABILITIES,
    ActionExecutor,
    DeploymentProfile,
    EnterpriseWorld,
    ExecutionOutcome,
    FailureType,
    ResourceDefinition,
    ResourceState,
    ServiceHealth,
    UnauthorizedExecutionError,
    UnsupportedOperationError,
    WorldSnapshot,
    build_dependency_graph,
    dependency_nodes,
)
from tests.enterprise.conftest import MovableClock
from tests.fleet import FIXED_EVALUATION_TIME

ACTION_ID = "act-001"
INCIDENT_ID = "INC-2026-0001"


def _action(
    *,
    capability: str = "production.rollback",
    target: str = PAYMENT_API,
    arguments: dict | None = None,
    action_id: str = ACTION_ID,
) -> Action:
    return Action(
        action_id=action_id,
        incident_id=INCIDENT_ID,
        requesting_agent="remediation",
        capability=capability,
        target_resource=target,
        arguments={"target_version": PAYMENT_API_GOOD_VERSION} if arguments is None else arguments,
    )


def _authorization(action: Action) -> ExecutionAuthorization:
    """A stand-in authorization. The real approval flow is exercised by the scenario."""
    from datetime import timedelta

    from aegis.core.approval import Approval, ApprovalStatus

    decision = PolicyDecision(
        decision=PolicyDecisionType.REQUIRE_APPROVAL,
        reason="rollback needs sign-off",
        policy_reference="policy:aegis/v1#approval-required",
        evaluated_at=FIXED_EVALUATION_TIME,
    )
    approval = Approval(
        approval_id="apr-001",
        incident_id=action.incident_id,
        action_id=action.action_id,
        action_fingerprint=action_fingerprint(action),
        requesting_agent=action.requesting_agent,
        policy_decision=decision,
        risk="HIGH",
        blast_radius={"scope": (PAYMENT_API,), "impact": "HIGH"},
        reason="rollback needs sign-off",
        status=ApprovalStatus.CONSUMED,
        created_at=FIXED_EVALUATION_TIME,
        expires_at=FIXED_EVALUATION_TIME + timedelta(minutes=15),
        decided_at=FIXED_EVALUATION_TIME,
        decided_by="human:oncall",
        consumed_at=FIXED_EVALUATION_TIME,
    )
    return ExecutionAuthorization(
        approval=approval,
        incident_id=action.incident_id,
        action_id=action.action_id,
        action_fingerprint=action_fingerprint(action),
        agent_id=action.requesting_agent,
        policy_decision=decision,
        authorized_at=FIXED_EVALUATION_TIME,
    )


# --- initial state ------------------------------------------------------------------


def test_the_golden_incident_starting_condition(world: EnterpriseWorld) -> None:
    """claude.md section 16: payment-api on v4.8 at 37% error rate, unhealthy."""
    state = world.state(PAYMENT_API)
    assert state.deployment == PAYMENT_API_FAULTY_VERSION == "v4.8"
    assert state.error_rate == 37.0
    assert state.health is ServiceHealth.UNHEALTHY
    assert not state.healthy


def test_every_other_resource_starts_healthy(world: EnterpriseWorld) -> None:
    for resource_id in world.resources():
        if resource_id == PAYMENT_API:
            continue
        assert world.state(resource_id).health is ServiceHealth.HEALTHY


def test_two_worlds_start_identical() -> None:
    """No randomness anywhere, so nothing to seed and nothing to drift."""
    assert to_json(EnterpriseWorld().snapshot()) == to_json(EnterpriseWorld().snapshot())


def test_an_unknown_resource_has_no_state(world: EnterpriseWorld) -> None:
    assert not world.contains("service:totally-unknown")
    with pytest.raises(UnknownResourceError):
        world.state("service:totally-unknown")


@pytest.mark.parametrize("near_miss", ["payment-api", "service:payment", "SERVICE:PAYMENT-API"])
def test_resource_lookup_is_exact(world: EnterpriseWorld, near_miss: str) -> None:
    assert not world.contains(near_miss)


# --- snapshots are immutable --------------------------------------------------------


def test_snapshots_are_frozen_and_ordered(world: EnterpriseWorld) -> None:
    snapshot = world.snapshot()
    ids = [resource.resource_id for resource in snapshot.resources]
    assert ids == sorted(ids)
    with pytest.raises(ValidationError):
        snapshot.resources[0].error_rate = 0.0  # type: ignore[misc]


def test_an_unordered_snapshot_is_rejected() -> None:
    """The ordering guarantee is enforced, not merely produced."""
    with pytest.raises(ValidationError, match="sorted"):
        WorldSnapshot(
            resources=(
                ResourceState(
                    resource_id="service:z",
                    deployment="v1",
                    error_rate=0.0,
                    health=ServiceHealth.HEALTHY,
                ),
                ResourceState(
                    resource_id="service:a",
                    deployment="v1",
                    error_rate=0.0,
                    health=ServiceHealth.HEALTHY,
                ),
            )
        )


def test_a_snapshot_does_not_track_later_changes(world: EnterpriseWorld) -> None:
    """A snapshot is a photograph, not a window."""
    before = world.snapshot()
    world.rollback(PAYMENT_API, PAYMENT_API_GOOD_VERSION)
    assert before.resource(PAYMENT_API).deployment == PAYMENT_API_FAULTY_VERSION
    assert world.snapshot().resource(PAYMENT_API).deployment == PAYMENT_API_GOOD_VERSION


def test_deriving_a_modified_state_leaves_the_world_untouched(
    world: EnterpriseWorld,
) -> None:
    world.state(PAYMENT_API).model_copy(update={"health": ServiceHealth.HEALTHY})
    assert world.state(PAYMENT_API).health is ServiceHealth.UNHEALTHY


def test_the_world_exposes_no_mutable_internals(world: EnterpriseWorld) -> None:
    surface = {name for name in dir(EnterpriseWorld) if not name.startswith("_")}
    assert "states" not in surface
    assert "failures" not in surface
    assert isinstance(world.active_failures(), frozenset)
    assert isinstance(world.resources(), tuple)


# --- topology -----------------------------------------------------------------------


def test_the_topology_matches_the_control_planes_dependency_semantics() -> None:
    graph = build_dependency_graph()
    assert graph.dependencies(ORDER_SERVICE) == ("db:order", PAYMENT_API)
    assert graph.dependents(PAYMENT_API) == ("service:api-gateway", ORDER_SERVICE)
    assert len(graph) == 8


def test_there_is_only_one_topology_definition() -> None:
    """tests/fleet.py sources its nodes from the enterprise, it does not restate them."""
    from tests.fleet import BASE_TOPOLOGY

    assert dependency_nodes() == BASE_TOPOLOGY


def test_graph_construction_is_deterministic() -> None:
    first, second = build_dependency_graph(), build_dependency_graph()
    for resource in first.resources():
        assert first.dependents(resource) == second.dependents(resource)
        assert first.criticality(resource) == second.criticality(resource)


def test_a_resource_cannot_declare_an_unknown_initial_version() -> None:
    with pytest.raises(ValidationError, match="not a declared version"):
        ResourceDefinition(
            resource_id="service:a",
            criticality="LOW",
            deployments=(
                DeploymentProfile(version="v1", error_rate=0.0, health=ServiceHealth.HEALTHY),
            ),
            initial_deployment="v2",
        )


def test_duplicate_resources_are_rejected() -> None:
    definition = ResourceDefinition(
        resource_id="service:a",
        criticality="LOW",
        deployments=(
            DeploymentProfile(version="v1", error_rate=0.0, health=ServiceHealth.HEALTHY),
        ),
        initial_deployment="v1",
    )
    with pytest.raises(ValueError, match="duplicate resource"):
        EnterpriseWorld([definition, definition])


# --- controlled mutation ------------------------------------------------------------


def test_rollback_moves_the_deployment_and_its_declared_behaviour(
    world: EnterpriseWorld,
) -> None:
    state = world.rollback(PAYMENT_API, PAYMENT_API_GOOD_VERSION)
    assert state.deployment == PAYMENT_API_GOOD_VERSION == "v4.7"
    assert state.error_rate == 0.7
    assert state.health is ServiceHealth.HEALTHY


def test_a_deployment_cannot_claim_an_undeclared_outcome(world: EnterpriseWorld) -> None:
    """Behaviour comes from the version's profile, never from the caller."""
    world.deploy(PAYMENT_API, PAYMENT_API_GOOD_VERSION)
    assert world.state(PAYMENT_API).error_rate == 0.7
    world.deploy(PAYMENT_API, PAYMENT_API_FAULTY_VERSION)
    assert world.state(PAYMENT_API).error_rate == 37.0
    assert world.state(PAYMENT_API).health is ServiceHealth.UNHEALTHY


def test_an_undeclared_version_is_unsupported(world: EnterpriseWorld) -> None:
    with pytest.raises(UnsupportedOperationError, match="no declared version"):
        world.rollback(PAYMENT_API, "v9.9")


def test_rolling_back_to_the_current_version_is_unsupported(
    world: EnterpriseWorld,
) -> None:
    with pytest.raises(UnsupportedOperationError, match="already running"):
        world.rollback(PAYMENT_API, PAYMENT_API_FAULTY_VERSION)


def test_mutating_an_unknown_resource_is_rejected(world: EnterpriseWorld) -> None:
    for operation in (
        lambda: world.rollback("service:nope", "v1"),
        lambda: world.set_error_rate("service:nope", 1.0),
        lambda: world.set_health("service:nope", ServiceHealth.HEALTHY),
    ):
        with pytest.raises(UnknownResourceError):
            operation()


def test_scenario_overrides_are_available(world: EnterpriseWorld) -> None:
    assert world.set_error_rate(PAYMENT_API, 12.5).error_rate == 12.5
    assert world.set_health(PAYMENT_API, ServiceHealth.DEGRADED).health is (ServiceHealth.DEGRADED)


def test_an_impossible_error_rate_is_rejected(world: EnterpriseWorld) -> None:
    with pytest.raises(ValidationError):
        world.set_error_rate(PAYMENT_API, 101.0)


# --- the execution boundary ---------------------------------------------------------


def test_an_authorized_rollback_is_applied(
    executor: ActionExecutor, world: EnterpriseWorld, clock: MovableClock
) -> None:
    action = _action()
    result = executor.execute(action, _authorization(action))
    assert result.outcome is ExecutionOutcome.APPLIED
    assert result.applied
    assert result.world_changed
    assert result.executed_at == clock.now
    assert world.state(PAYMENT_API).deployment == PAYMENT_API_GOOD_VERSION


def test_execution_without_authorization_is_refused(executor: ActionExecutor) -> None:
    """The simulator will not act on an action carrying no control-plane evidence."""
    with pytest.raises(UnauthorizedExecutionError, match="no execution authorization"):
        executor.execute(_action(), None)  # type: ignore[arg-type]


def test_an_authorization_for_another_action_is_refused(
    executor: ActionExecutor,
) -> None:
    other = _action(action_id="act-999")
    with pytest.raises(UnauthorizedExecutionError, match="covers action"):
        executor.execute(_action(), _authorization(other))


def test_an_action_edited_after_authorization_is_refused(
    executor: ActionExecutor, world: EnterpriseWorld
) -> None:
    action = _action()
    authorization = _authorization(action)
    tampered = action.model_copy(update={"target_resource": ORDER_SERVICE})
    with pytest.raises(UnauthorizedExecutionError, match="changed after"):
        executor.execute(tampered, authorization)
    assert world.state(PAYMENT_API).deployment == PAYMENT_API_FAULTY_VERSION


def test_an_unsupported_capability_is_reported_not_performed(
    executor: ActionExecutor, world: EnterpriseWorld
) -> None:
    action = _action(capability="production.scale")
    result = executor.execute(action, _authorization(action))
    assert result.outcome is ExecutionOutcome.UNSUPPORTED
    assert not result.world_changed
    assert to_json(world.snapshot()) == to_json(EnterpriseWorld().snapshot())


def test_only_rollback_is_modelled() -> None:
    assert {"production.rollback"} == SUPPORTED_CAPABILITIES


def test_an_unknown_target_resource_is_unsupported(executor: ActionExecutor) -> None:
    action = _action(target="service:totally-unknown")
    result = executor.execute(action, _authorization(action))
    assert result.outcome is ExecutionOutcome.UNSUPPORTED
    assert "not declared" in result.detail


@pytest.mark.parametrize(
    "arguments", [{}, {"target_version": ""}, {"target_version": 47}, {"version": "v4.7"}]
)
def test_a_malformed_action_is_rejected(
    executor: ActionExecutor, world: EnterpriseWorld, arguments: dict
) -> None:
    action = _action(arguments=arguments)
    result = executor.execute(action, _authorization(action))
    assert result.outcome is ExecutionOutcome.UNSUPPORTED
    assert world.state(PAYMENT_API).deployment == PAYMENT_API_FAULTY_VERSION


def test_an_undeclared_target_version_is_unsupported(
    executor: ActionExecutor, world: EnterpriseWorld
) -> None:
    action = _action(arguments={"target_version": "v9.9"})
    result = executor.execute(action, _authorization(action))
    assert result.outcome is ExecutionOutcome.UNSUPPORTED
    assert world.state(PAYMENT_API).deployment == PAYMENT_API_FAULTY_VERSION


def test_the_simulator_never_decides_authorization() -> None:
    """No policy import exists in the enterprise package's execution path."""
    import pathlib

    import aegis.enterprise as enterprise

    package = pathlib.Path(enterprise.__path__[0])
    executor_source = (package / "mutations.py").read_text(encoding="utf-8")
    world_source = (package / "world.py").read_text(encoding="utf-8")
    for source in (executor_source, world_source):
        assert "aegis.core.policy" not in source
        assert "PolicyEngine" not in source


def test_execution_success_is_not_verification(executor: ActionExecutor) -> None:
    """An ExecutionResult carries no verification status, by construction."""
    action = _action()
    result = executor.execute(action, _authorization(action))
    assert result.applied
    assert not hasattr(result, "verified")
    assert not hasattr(result, "status")
    assert "VERIFIED" not in to_json(result)


def test_execution_is_deterministic(clock: MovableClock) -> None:
    def run() -> str:
        world = EnterpriseWorld()
        action = _action()
        return to_json(ActionExecutor(world, clock=clock).execute(action, _authorization(action)))

    assert run() == run()


# --- failure injection at the execution layer ---------------------------------------


@pytest.mark.parametrize(
    ("failure", "expected"),
    [
        (FailureType.TOOL_TIMEOUT, ExecutionOutcome.BLOCKED),
        (FailureType.TOOL_500, ExecutionOutcome.BLOCKED),
        (FailureType.ROLLBACK_FAILURE, ExecutionOutcome.FAILED),
    ],
    ids=lambda value: str(value),
)
def test_execution_failures_leave_the_world_untouched(
    executor: ActionExecutor,
    world: EnterpriseWorld,
    failure: FailureType,
    expected: ExecutionOutcome,
) -> None:
    world.inject_failure(failure)
    action = _action()
    result = executor.execute(action, _authorization(action))

    assert result.outcome is expected
    assert not result.world_changed
    assert world.state(PAYMENT_API).deployment == PAYMENT_API_FAULTY_VERSION
    assert world.state(PAYMENT_API).health is ServiceHealth.UNHEALTHY


def test_the_three_execution_failures_stay_distinguishable(
    executor: ActionExecutor, world: EnterpriseWorld
) -> None:
    details = {}
    for failure in (
        FailureType.TOOL_TIMEOUT,
        FailureType.TOOL_500,
        FailureType.ROLLBACK_FAILURE,
    ):
        world.clear_failures()
        world.inject_failure(failure)
        action = _action()
        details[failure] = executor.execute(action, _authorization(action)).detail
    assert len(set(details.values())) == 3


def test_failures_can_be_injected_and_cleared(world: EnterpriseWorld) -> None:
    assert world.active_failures() == frozenset()
    world.inject_failure(FailureType.TOOL_500)
    assert world.is_failing(FailureType.TOOL_500)
    assert world.snapshot().active_failures == ("tool_500",)
    world.clear_failure(FailureType.TOOL_500)
    assert not world.is_failing(FailureType.TOOL_500)
    world.clear_failure(FailureType.TOOL_500)  # clearing twice is harmless
    assert world.active_failures() == frozenset()


def test_clearing_an_unheld_failure_is_a_noop(world: EnterpriseWorld) -> None:
    world.clear_failures()
    assert world.active_failures() == frozenset()
