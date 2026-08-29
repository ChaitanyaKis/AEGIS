"""The circuit breaker: states, thresholds, probes, and everything it must refuse.

The breaker is a gate that can only say no. Most of these tests are about the ways it
must *not* be able to say yes.
"""

from __future__ import annotations

import ast
import pathlib

import pytest
from pydantic import ValidationError

from aegis.core.domain import PolicyDecisionType
from aegis.lifecycle import (
    GOVERNANCE_ANOMALIES,
    BreakerScope,
    CircuitBreaker,
    CircuitBreakerConfig,
    CircuitState,
    FailureClass,
    ProbeAlreadyInFlight,
    classify_execution,
    classify_verification,
    detect_governance_anomaly,
    is_governance_anomaly,
    scope_key,
)
from tests.fleet import fixed_clock

ROLLBACK = "production.rollback"
PAYMENT = "service:payment-api"


@pytest.fixture
def breaker() -> CircuitBreaker:
    return CircuitBreaker(clock=fixed_clock)


def key(breaker: CircuitBreaker, capability: str = ROLLBACK, resource: str = PAYMENT) -> str:
    return breaker.key_for(capability=capability, resource=resource, incident_id="INC-1")


def trip(breaker: CircuitBreaker, k: str, times: int = 3) -> None:
    for _ in range(times):
        breaker.record(k, FailureClass.EXECUTION_FAILURE, reason="the rollback failed")


class TestClosedIsTheStartingState:
    def test_an_unseen_scope_is_closed(self, breaker) -> None:
        assert breaker.state_of(key(breaker)) is CircuitState.CLOSED

    def test_a_closed_breaker_allows(self, breaker) -> None:
        decision = breaker.check(key(breaker))
        assert decision.allowed
        assert decision.state is CircuitState.CLOSED
        assert not decision.is_probe

    def test_allowing_is_not_permission(self, breaker) -> None:
        # There is no method that returns authority, and the decision carries none.
        decision = breaker.check(key(breaker))
        assert set(type(decision).model_fields) == {
            "allowed",
            "state",
            "scope_key",
            "reason",
            "is_probe",
        }
        assert "authorization" not in str(type(decision).model_fields)


class TestOpeningOnThresholds:
    def test_failures_below_the_threshold_do_not_open(self, breaker) -> None:
        k = key(breaker)
        trip(breaker, k, times=2)
        assert breaker.state_of(k) is CircuitState.CLOSED
        assert breaker.check(k).allowed

    def test_the_threshold_opens_the_breaker(self, breaker) -> None:
        k = key(breaker)
        trip(breaker, k, times=3)
        assert breaker.state_of(k) is CircuitState.OPEN

    def test_a_higher_threshold_needs_more_failures(self) -> None:
        breaker = CircuitBreaker(
            CircuitBreakerConfig(execution_failure_threshold=5), clock=fixed_clock
        )
        k = key(breaker)
        trip(breaker, k, times=4)
        assert breaker.state_of(k) is CircuitState.CLOSED
        trip(breaker, k, times=1)
        assert breaker.state_of(k) is CircuitState.OPEN

    def test_the_snapshot_names_which_class_tripped_it(self, breaker) -> None:
        k = key(breaker)
        trip(breaker, k)
        snapshot = breaker.snapshot(k)
        assert snapshot.trip_class is FailureClass.EXECUTION_FAILURE
        assert "threshold of 3" in snapshot.opened_reason
        assert snapshot.opened_at is not None

    def test_failure_classes_are_counted_separately(self, breaker) -> None:
        # Two execution failures and two verification failures are not four of anything.
        k = key(breaker)
        breaker.record(k, FailureClass.EXECUTION_FAILURE, reason="x")
        breaker.record(k, FailureClass.EXECUTION_FAILURE, reason="x")
        breaker.record(k, FailureClass.VERIFICATION_FAILURE, reason="y")
        breaker.record(k, FailureClass.VERIFICATION_FAILURE, reason="y")
        assert breaker.state_of(k) is CircuitState.CLOSED
        assert breaker.snapshot(k).counts == {"EXECUTION_FAILURE": 2, "VERIFICATION_FAILURE": 2}

    def test_a_mismatch_has_a_tighter_threshold(self, breaker) -> None:
        k = key(breaker)
        breaker.record(k, FailureClass.VERIFICATION_MISMATCH, reason="sources disagreed")
        assert breaker.state_of(k) is CircuitState.CLOSED
        breaker.record(k, FailureClass.VERIFICATION_MISMATCH, reason="sources disagreed")
        assert breaker.state_of(k) is CircuitState.OPEN

    def test_a_governance_anomaly_opens_immediately(self, breaker) -> None:
        k = key(breaker)
        breaker.record(k, FailureClass.GOVERNANCE_ANOMALY, reason="execution without auth")
        assert breaker.state_of(k) is CircuitState.OPEN

    def test_a_verified_success_clears_the_counters(self, breaker) -> None:
        k = key(breaker)
        trip(breaker, k, times=2)
        breaker.record(k, FailureClass.NONE, reason="verified")
        assert breaker.snapshot(k).counts == {}
        trip(breaker, k, times=2)
        assert breaker.state_of(k) is CircuitState.CLOSED


class TestOpenBlocks:
    def test_open_refuses(self, breaker) -> None:
        k = key(breaker)
        trip(breaker, k)
        decision = breaker.check(k)
        assert not decision.allowed
        assert decision.state is CircuitState.OPEN

    def test_open_keeps_refusing(self, breaker) -> None:
        # No amount of asking changes the answer, and asking does not decay the state.
        k = key(breaker)
        trip(breaker, k)
        for _ in range(10):
            assert not breaker.check(k).allowed
        assert breaker.state_of(k) is CircuitState.OPEN

    def test_more_failures_while_open_do_not_reopen_or_close(self, breaker) -> None:
        k = key(breaker)
        trip(breaker, k)
        opened_at = breaker.snapshot(k).opened_at
        trip(breaker, k, times=5)
        assert breaker.state_of(k) is CircuitState.OPEN
        assert breaker.snapshot(k).opened_at == opened_at

    def test_the_snapshot_reports_that_execution_is_blocked(self, breaker) -> None:
        k = key(breaker)
        trip(breaker, k)
        assert breaker.snapshot(k).blocks_execution

    def test_a_closed_breaker_does_not_block(self, breaker) -> None:
        assert not breaker.snapshot(key(breaker)).blocks_execution


class TestHalfOpenAllowsExactlyOneProbe:
    def test_allow_probe_moves_open_to_half_open(self, breaker) -> None:
        k = key(breaker)
        trip(breaker, k)
        breaker.allow_probe(k)
        assert breaker.state_of(k) is CircuitState.HALF_OPEN

    def test_the_first_probe_is_permitted(self, breaker) -> None:
        k = key(breaker)
        trip(breaker, k)
        breaker.allow_probe(k)
        decision = breaker.check(k)
        assert decision.allowed
        assert decision.is_probe

    def test_a_second_probe_is_refused(self, breaker) -> None:
        k = key(breaker)
        trip(breaker, k)
        breaker.allow_probe(k)
        breaker.check(k)
        second = breaker.check(k)
        assert not second.allowed
        assert "already in flight" in second.reason

    def test_permit_probe_raises_on_a_second_request(self, breaker) -> None:
        k = key(breaker)
        trip(breaker, k)
        breaker.allow_probe(k)
        breaker.permit_probe(k)
        with pytest.raises(ProbeAlreadyInFlight):
            breaker.permit_probe(k)

    def test_allow_probe_on_a_closed_breaker_changes_nothing(self, breaker) -> None:
        k = key(breaker)
        breaker.allow_probe(k)
        assert breaker.state_of(k) is CircuitState.CLOSED

    def test_a_successful_probe_closes_the_breaker(self, breaker) -> None:
        k = key(breaker)
        trip(breaker, k)
        breaker.allow_probe(k)
        breaker.check(k)
        snapshot = breaker.record_probe_success(k)
        assert snapshot.state is CircuitState.CLOSED
        assert snapshot.counts == {}
        assert breaker.check(k).allowed

    def test_a_failed_probe_reopens_the_breaker(self, breaker) -> None:
        k = key(breaker)
        trip(breaker, k)
        breaker.allow_probe(k)
        breaker.check(k)
        snapshot = breaker.record_probe_failure(k, reason="still failing")
        assert snapshot.state is CircuitState.OPEN
        assert not breaker.check(k).allowed

    def test_a_failed_probe_never_closes_the_breaker(self, breaker) -> None:
        # The mutation "close after a failed probe" must have somewhere to fail.
        k = key(breaker)
        trip(breaker, k)
        for attempt in range(3):
            breaker.allow_probe(k)
            breaker.check(k)
            breaker.record_probe_failure(k, reason=f"attempt {attempt}")
            assert breaker.state_of(k) is CircuitState.OPEN

    def test_repeated_probe_failures_are_counted(self, breaker) -> None:
        k = key(breaker)
        trip(breaker, k)
        for _ in range(2):
            breaker.allow_probe(k)
            breaker.check(k)
            breaker.record_probe_failure(k, reason="still failing")
        assert breaker.snapshot(k).consecutive_probe_failures == 2

    def test_a_probe_can_be_retried_after_it_fails(self, breaker) -> None:
        # Failing clears the in-flight flag, or the breaker would deadlock half-open.
        k = key(breaker)
        trip(breaker, k)
        breaker.allow_probe(k)
        breaker.check(k)
        breaker.record_probe_failure(k, reason="failed")
        breaker.allow_probe(k)
        assert breaker.check(k).allowed


class TestThereIsNoBlindReset:
    def test_the_breaker_exposes_no_reset_method(self, breaker) -> None:
        for forbidden in ("reset", "close", "clear", "force_close", "open"):
            assert not hasattr(breaker, forbidden), f"CircuitBreaker.{forbidden} must not exist"

    def test_the_only_route_to_closed_is_a_successful_probe(self, breaker) -> None:
        k = key(breaker)
        trip(breaker, k)
        # Every public method except record_probe_success, tried against an open breaker.
        breaker.check(k)
        breaker.snapshot(k)
        breaker.state_of(k)
        breaker.record(k, FailureClass.NONE, reason="a success elsewhere")
        assert breaker.state_of(k) is CircuitState.OPEN
        breaker.allow_probe(k)
        assert breaker.state_of(k) is CircuitState.HALF_OPEN
        breaker.record_probe_success(k)
        assert breaker.state_of(k) is CircuitState.CLOSED

    def test_a_snapshot_cannot_change_the_breaker(self, breaker) -> None:
        k = key(breaker)
        trip(breaker, k)
        snapshot = breaker.snapshot(k)
        with pytest.raises(ValidationError):
            snapshot.state = CircuitState.CLOSED  # type: ignore[misc]
        assert breaker.state_of(k) is CircuitState.OPEN

    def test_a_snapshot_holds_no_route_back_to_the_breaker(self, breaker) -> None:
        snapshot = breaker.snapshot(key(breaker))
        for forbidden in ("record", "check", "allow_probe", "record_probe_success"):
            assert not hasattr(snapshot, forbidden)


class TestScoping:
    def test_the_default_scope_separates_capability_and_resource(self, breaker) -> None:
        rollback_payment = key(breaker)
        rollback_orders = key(breaker, resource="service:order-service")
        scale_payment = key(breaker, capability="production.scale")
        trip(breaker, rollback_payment)
        assert breaker.state_of(rollback_payment) is CircuitState.OPEN
        assert breaker.state_of(rollback_orders) is CircuitState.CLOSED
        assert breaker.state_of(scale_payment) is CircuitState.CLOSED

    def test_one_bad_incident_does_not_disable_unrelated_automation(self, breaker) -> None:
        trip(breaker, key(breaker))
        assert breaker.check(key(breaker, resource="service:order-service")).allowed

    def test_failures_accumulate_across_incidents_in_the_same_scope(self) -> None:
        # Three incidents each failing once against the same capability and resource is
        # exactly the pattern a per-incident scope would miss.
        breaker = CircuitBreaker(clock=fixed_clock)
        for incident in ("INC-1", "INC-2", "INC-3"):
            k = breaker.key_for(capability=ROLLBACK, resource=PAYMENT, incident_id=incident)
            breaker.record(k, FailureClass.EXECUTION_FAILURE, reason="failed")
        assert breaker.state_of(key(breaker)) is CircuitState.OPEN

    def test_an_incident_scope_cannot_accumulate_across_incidents(self) -> None:
        breaker = CircuitBreaker(
            CircuitBreakerConfig(scope=BreakerScope.INCIDENT), clock=fixed_clock
        )
        for incident in ("INC-1", "INC-2", "INC-3"):
            k = breaker.key_for(capability=ROLLBACK, resource=PAYMENT, incident_id=incident)
            breaker.record(k, FailureClass.EXECUTION_FAILURE, reason="failed")
            assert breaker.state_of(k) is CircuitState.CLOSED

    @pytest.mark.parametrize(
        ("scope", "expected"),
        [
            (BreakerScope.CAPABILITY_RESOURCE, "production.rollback@service:payment-api"),
            (BreakerScope.CAPABILITY, "production.rollback"),
            (BreakerScope.RESOURCE, "service:payment-api"),
            (BreakerScope.INCIDENT, "INC-1"),
            (BreakerScope.GLOBAL, "global"),
        ],
    )
    def test_each_scope_produces_its_declared_key(self, scope, expected) -> None:
        assert (
            scope_key(scope, capability=ROLLBACK, resource=PAYMENT, incident_id="INC-1") == expected
        )

    def test_a_missing_component_still_lands_in_a_stable_bucket(self) -> None:
        # Failing open here would mean unattributable failures accumulate nowhere.
        assert scope_key(BreakerScope.CAPABILITY_RESOURCE, capability=ROLLBACK) == (f"{ROLLBACK}@*")


class TestFailureClassification:
    @pytest.mark.parametrize("outcome", ["FAILED", "BLOCKED", "UNSUPPORTED"])
    def test_every_non_applied_execution_is_a_failure(self, outcome) -> None:
        assert classify_execution(outcome) is FailureClass.EXECUTION_FAILURE

    def test_applied_is_the_only_execution_success(self) -> None:
        assert classify_execution("APPLIED") is FailureClass.NONE

    def test_verification_statuses_keep_their_identity(self) -> None:
        assert classify_verification("VERIFIED") is FailureClass.NONE
        assert classify_verification("FAILED") is FailureClass.VERIFICATION_FAILURE
        assert classify_verification("STALE") is FailureClass.STALE_VERIFICATION
        assert classify_verification("MISMATCH") is FailureClass.VERIFICATION_MISMATCH
        assert classify_verification("INSUFFICIENT_EVIDENCE") is FailureClass.INSUFFICIENT_EVIDENCE

    def test_the_real_enums_classify_the_same_way(self) -> None:
        from aegis.core.verification import VerificationStatus
        from aegis.enterprise import ExecutionOutcome

        assert classify_execution(ExecutionOutcome.APPLIED) is FailureClass.NONE
        assert classify_execution(ExecutionOutcome.FAILED) is FailureClass.EXECUTION_FAILURE
        assert classify_verification(VerificationStatus.VERIFIED) is FailureClass.NONE
        assert classify_verification(VerificationStatus.STALE) is FailureClass.STALE_VERIFICATION

    def test_an_unreadable_outcome_fails_closed(self) -> None:
        # A repr can be crafted; failing closed is the only safe reading of "cannot tell".
        crafted = type("X", (), {"__repr__": lambda self: "APPLIED"})()
        assert classify_execution(crafted) is FailureClass.EXECUTION_FAILURE
        assert classify_verification(crafted) is FailureClass.VERIFICATION_FAILURE

    def test_a_tool_failure_never_becomes_a_success(self) -> None:
        for value in ("UNAVAILABLE", "TIMEOUT", "ERROR", "DENIED", None, 0, ""):
            assert classify_execution(value) is FailureClass.EXECUTION_FAILURE


class TestGovernanceAnomalyIsNotADeny:
    @pytest.mark.parametrize(
        "decision",
        [PolicyDecisionType.ALLOW, PolicyDecisionType.DENY, PolicyDecisionType.REQUIRE_APPROVAL],
    )
    def test_no_policy_decision_is_an_anomaly(self, decision) -> None:
        assert is_governance_anomaly(decision) is False

    def test_a_deny_with_nothing_executed_produces_no_anomaly(self) -> None:
        # The critical case. A breaker that opened here would turn correct governance into
        # a self-inflicted outage the first time AEGIS said no.
        assert (
            detect_governance_anomaly(
                executed=False,
                authorization_present=False,
                policy_decision=PolicyDecisionType.DENY,
                action_id="act-1",
                authorized_action_id=None,
                verified_action_id=None,
                audit_valid=True,
            )
            == ()
        )

    def test_a_clean_approved_execution_produces_no_anomaly(self) -> None:
        assert (
            detect_governance_anomaly(
                executed=True,
                authorization_present=True,
                policy_decision=PolicyDecisionType.REQUIRE_APPROVAL,
                action_id="act-1",
                authorized_action_id="act-1",
                verified_action_id="act-1",
                audit_valid=True,
            )
            == ()
        )

    def test_execution_without_authorization_is_an_anomaly(self) -> None:
        found = detect_governance_anomaly(
            executed=True,
            authorization_present=False,
            policy_decision=PolicyDecisionType.REQUIRE_APPROVAL,
            action_id="act-1",
            authorized_action_id=None,
            verified_action_id="act-1",
            audit_valid=True,
        )
        assert "execution_without_authorization" in found

    def test_execution_after_deny_is_an_anomaly(self) -> None:
        found = detect_governance_anomaly(
            executed=True,
            authorization_present=True,
            policy_decision=PolicyDecisionType.DENY,
            action_id="act-1",
            authorized_action_id="act-1",
            verified_action_id="act-1",
            audit_valid=True,
        )
        assert "execution_after_deny" in found

    def test_an_authorization_for_a_different_action_is_an_anomaly(self) -> None:
        found = detect_governance_anomaly(
            executed=True,
            authorization_present=True,
            policy_decision=PolicyDecisionType.REQUIRE_APPROVAL,
            action_id="act-1",
            authorized_action_id="act-999",
            verified_action_id="act-1",
            audit_valid=True,
        )
        assert "authorization_for_different_action" in found

    def test_a_verification_of_a_different_action_is_an_anomaly(self) -> None:
        found = detect_governance_anomaly(
            executed=True,
            authorization_present=True,
            policy_decision=PolicyDecisionType.REQUIRE_APPROVAL,
            action_id="act-1",
            authorized_action_id="act-1",
            verified_action_id="act-999",
            audit_valid=True,
        )
        assert "verification_for_different_action" in found

    def test_a_broken_audit_chain_is_an_anomaly(self) -> None:
        found = detect_governance_anomaly(
            executed=False,
            authorization_present=False,
            policy_decision=None,
            action_id="act-1",
            authorized_action_id=None,
            verified_action_id=None,
            audit_valid=False,
        )
        assert found == ("audit_chain_invalid",)

    def test_the_anomaly_vocabulary_is_closed_and_names_no_refusal(self) -> None:
        for name in GOVERNANCE_ANOMALIES:
            assert "deny" not in name or name == "execution_after_deny"
            assert "reject" not in name
            assert "unsupported" not in name


class TestStructuralBoundaries:
    def test_the_breaker_imports_no_governance_engine(self) -> None:
        # It is handed a classification and cannot re-derive one, because it is never
        # given the artifacts.
        source = pathlib.Path("src/aegis/lifecycle/circuit_breaker.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported |= {a.name for a in node.names}
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module)
        for forbidden in (
            "aegis.core.policy",
            "aegis.core.approval",
            "aegis.core.verification",
            "aegis.core.incidents",
            "aegis.enterprise",
            "aegis.memory",
            "aegis.agents",
        ):
            assert not any(m.startswith(forbidden) for m in imported), forbidden

    def test_the_lifecycle_package_uses_no_dynamic_dispatch(self) -> None:
        found: list[tuple[str, str]] = []
        for path in sorted(pathlib.Path("src/aegis/lifecycle").rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                    and node.func.id in {"eval", "exec", "__import__", "compile"}
                ):
                    found.append((path.name, node.func.id))
        assert not found

    def test_the_lifecycle_package_reaches_no_network_or_shell(self) -> None:
        forbidden = {
            "subprocess",
            "socket",
            "requests",
            "httpx",
            "urllib",
            "http",
            "importlib",
            "google",
            "openai",
            "anthropic",
        }
        found: list[tuple[str, str]] = []
        for path in sorted(pathlib.Path("src/aegis/lifecycle").rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    found += [
                        (path.name, a.name) for a in node.names if a.name.split(".")[0] in forbidden
                    ]
                elif (
                    isinstance(node, ast.ImportFrom)
                    and node.module
                    and node.module.split(".")[0] in forbidden
                ):
                    found.append((path.name, node.module))
        assert not found

    def test_no_os_system_or_shell_true(self) -> None:
        for path in sorted(pathlib.Path("src/aegis/lifecycle").rglob("*.py")):
            source = path.read_text(encoding="utf-8")
            assert "os.system" not in source
            assert "shell=True" not in source


class TestDeterminism:
    def test_the_same_failure_sequence_produces_the_same_snapshot(self) -> None:
        from aegis.core.domain import to_json

        def build() -> CircuitBreaker:
            breaker = CircuitBreaker(clock=fixed_clock)
            k = key(breaker)
            breaker.record(k, FailureClass.EXECUTION_FAILURE, reason="a")
            breaker.record(k, FailureClass.VERIFICATION_FAILURE, reason="b")
            breaker.record(k, FailureClass.EXECUTION_FAILURE, reason="c")
            return breaker

        first, second = build(), build()
        assert to_json(first.snapshot(key(first))) == to_json(second.snapshot(key(second)))

    def test_counts_are_reported_in_sorted_order(self, breaker) -> None:
        k = key(breaker)
        breaker.record(k, FailureClass.VERIFICATION_FAILURE, reason="b")
        breaker.record(k, FailureClass.EXECUTION_FAILURE, reason="a")
        assert list(breaker.snapshot(k).counts) == sorted(breaker.snapshot(k).counts)
