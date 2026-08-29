"""Tamper evidence for lifecycle state, and the rule that a valid chain is not enough.

Two distinct properties are tested here, and conflating them is the mistake this file
exists to prevent.

**Integrity** — the chain detects modification, insertion, deletion and reordering. Every
mutation listed in the milestone gets its own test.

**Legality** — a chain can be cryptographically perfect and still describe a history that
could not have happened. Appending an old ``CLOSED`` snapshot after an ``OPEN`` one, with a
correctly recomputed digest, is a blind reset smuggled in through storage. Integrity alone
would wave it through, which is why every transition is checked as a legal edge.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from aegis.lifecycle import (
    LIFECYCLE_GENESIS_DIGEST,
    BreakerTransition,
    CircuitBreaker,
    CircuitBreakerConfig,
    CircuitState,
    FailureClass,
    InMemoryLifecycleState,
    LifecycleStateCorrupt,
    LifecycleStateRecord,
    StateRecordKind,
    legal_transition,
    state_digest,
    verify_state_chain,
)

ROLLBACK = "production.rollback"
PAYMENT = "service:payment-api"
START = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)


def clock():
    return START


@pytest.fixture
def store() -> InMemoryLifecycleState:
    """A store holding a full open-then-probe history, so every record kind is present."""
    state = InMemoryLifecycleState()
    breaker = CircuitBreaker(
        CircuitBreakerConfig(probe_cooldown_seconds=None), clock=clock, persistence=state
    )
    key = breaker.key_for(capability=ROLLBACK, resource=PAYMENT)
    for _ in range(3):
        breaker.record(key, FailureClass.EXECUTION_FAILURE, reason="the rollback failed")
    breaker.allow_probe(key)
    return state


def records(store) -> list[LifecycleStateRecord]:
    return list(store.load())


def tamper(store, index: int, **updates) -> None:
    """Rewrite one stored record in place, as an in-process attacker would."""
    store._records[index] = store._records[index].model_copy(update=updates)


def reseal(record: LifecycleStateRecord, **updates) -> LifecycleStateRecord:
    """Rewrite a record *and* recompute its digest — a tamper that hides itself.

    The interesting attacker. Anyone who can edit the store can also run the digest
    function, so tests that only flip a field without resealing prove less than they look.
    """
    changed = record.model_copy(update=updates)
    return changed.model_copy(update={"digest": state_digest(changed)})


class TestModificationIsDetected:
    def test_an_unmodified_chain_verifies(self, store) -> None:
        report = verify_state_chain(records(store))
        assert report.valid
        assert report.checked == 4

    def test_flipping_open_to_closed_is_detected(self, store) -> None:
        tamper(store, 2, circuit_state=CircuitState.CLOSED)
        report = verify_state_chain(records(store))
        assert not report.valid
        assert report.first_invalid_index == 2

    def test_a_modified_failure_count_is_detected(self, store) -> None:
        tamper(store, 1, failure_counts={"EXECUTION_FAILURE": 0})
        assert not verify_state_chain(records(store)).valid

    def test_a_modified_scope_is_detected(self, store) -> None:
        tamper(store, 1, scope_key="production.rollback@service:order-service")
        assert not verify_state_chain(records(store)).valid

    def test_a_modified_failure_class_is_detected(self, store) -> None:
        tamper(store, 2, trip_class=FailureClass.STALE_VERIFICATION)
        assert not verify_state_chain(records(store)).valid

    def test_a_modified_sequence_is_detected(self, store) -> None:
        tamper(store, 1, sequence=7)
        report = verify_state_chain(records(store))
        assert not report.valid
        assert "sequence" in report.reason

    def test_a_modified_previous_digest_is_detected(self, store) -> None:
        tamper(store, 2, previous_digest="c" * 64)
        assert not verify_state_chain(records(store)).valid

    def test_a_corrupted_digest_is_detected(self, store) -> None:
        tamper(store, 0, digest="d" * 64)
        report = verify_state_chain(records(store))
        assert not report.valid
        assert report.first_invalid_index == 0

    def test_a_modified_probe_flag_is_detected(self, store) -> None:
        tamper(store, 3, probe_in_flight=True)
        assert not verify_state_chain(records(store)).valid

    def test_a_modified_transition_is_detected(self, store) -> None:
        tamper(store, 2, transition=BreakerTransition.FAILURE_RECORDED)
        assert not verify_state_chain(records(store)).valid

    def test_modified_counters_are_detected(self) -> None:
        from aegis.lifecycle import LifecycleCounters, LifecycleLimits, LifecycleManager

        state = InMemoryLifecycleState()
        manager = LifecycleManager(
            limits=LifecycleLimits(),
            breaker=CircuitBreaker(clock=clock, persistence=state),
            clock=clock,
        )
        manager.begin("INC-1")
        manager.record_step()
        state._records[0] = state._records[0].model_copy(
            update={"counters": LifecycleCounters(steps_used=0)}
        )
        assert not verify_state_chain(state.load()).valid


class TestStructuralTamperingIsDetected:
    def test_removing_a_middle_record_is_detected(self, store) -> None:
        del store._records[1]
        report = verify_state_chain(records(store))
        assert not report.valid
        assert report.first_invalid_index == 1

    def test_removing_the_head_record_is_detected(self, store) -> None:
        del store._records[0]
        report = verify_state_chain(records(store))
        assert not report.valid
        assert report.first_invalid_index == 0

    def test_inserting_a_forged_record_is_detected(self, store) -> None:
        forged = records(store)[0].model_copy(update={"scope_key": "smuggled@in"})
        store._records.insert(1, forged)
        assert not verify_state_chain(records(store)).valid

    def test_reordering_records_is_detected(self, store) -> None:
        chain = store._records
        chain[1], chain[2] = chain[2], chain[1]
        assert not verify_state_chain(records(store)).valid

    def test_appending_a_forged_record_is_detected(self, store) -> None:
        last = records(store)[-1]
        forged = LifecycleStateRecord(
            sequence=len(records(store)),
            kind=StateRecordKind.BREAKER,
            recorded_at=START,
            scope_key=last.scope_key,
            transition=BreakerTransition.PROBE_SUCCEEDED,
            circuit_state=CircuitState.CLOSED,
            previous_digest="0" * 64,  # does not link
            digest="0" * 64,
        )
        store._records.append(forged)
        assert not verify_state_chain(records(store)).valid

    def test_the_report_names_where_the_damage_starts(self, store) -> None:
        tamper(store, 2, circuit_state=CircuitState.CLOSED)
        report = verify_state_chain(records(store))
        assert report.first_invalid_index == 2
        assert report.trusted_prefix == 2
        assert report.reason

    def test_an_empty_chain_verifies(self) -> None:
        assert verify_state_chain(()).valid

    def test_the_first_record_links_to_the_genesis_digest(self, store) -> None:
        assert records(store)[0].previous_digest == LIFECYCLE_GENESIS_DIGEST


class TestAValidChainCanStillBeIllegal:
    """§3. A resealed tamper defeats the digest but not the transition table."""

    def test_a_resealed_flip_from_open_to_closed_is_still_refused(self, store) -> None:
        # The attack the digest alone cannot stop: edit the record *and* recompute its
        # digest. The chain verifies perfectly and the history is still impossible.
        store._records[2] = reseal(records(store)[2], circuit_state=CircuitState.CLOSED)
        # Relink everything after it so the chain is genuinely intact.
        _relink(store, from_index=3)
        report = verify_state_chain(records(store))
        assert not report.valid
        assert "not a legal edge" in report.reason

    def test_replaying_an_old_closed_record_cannot_close_an_open_breaker(self, store) -> None:
        # The blind reset smuggled in through storage.
        earlier_closed = records(store)[0]
        appended = reseal(
            earlier_closed,
            sequence=len(records(store)),
            previous_digest=records(store)[-1].digest,
        )
        store._records.append(appended)

        report = verify_state_chain(records(store))
        assert not report.valid, "an old CLOSED snapshot must not be replayable"

        with pytest.raises(LifecycleStateCorrupt):
            CircuitBreaker(clock=clock, persistence=store)

    def test_closing_requires_a_probe_success(self, store) -> None:
        # Every transition that can result in CLOSED from a non-closed state.
        closing = [
            transition
            for transition in BreakerTransition
            if legal_transition(
                transition, previous=CircuitState.OPEN, resulting=CircuitState.CLOSED
            )
            or legal_transition(
                transition, previous=CircuitState.HALF_OPEN, resulting=CircuitState.CLOSED
            )
        ]
        assert closing == [BreakerTransition.PROBE_SUCCEEDED]

    def test_a_failure_can_never_result_in_closed_from_open(self) -> None:
        assert not legal_transition(
            BreakerTransition.FAILURE_RECORDED,
            previous=CircuitState.OPEN,
            resulting=CircuitState.CLOSED,
        )

    def test_a_probe_cannot_be_permitted_from_closed(self) -> None:
        assert not legal_transition(
            BreakerTransition.PROBE_PERMITTED,
            previous=CircuitState.CLOSED,
            resulting=CircuitState.HALF_OPEN,
        )

    def test_an_unknown_transition_is_refused(self) -> None:
        assert not legal_transition(
            BreakerTransition.COUNTERS_UPDATED,
            previous=CircuitState.OPEN,
            resulting=CircuitState.CLOSED,
        )

    def test_a_breaker_never_exposes_a_reset(self, store) -> None:
        breaker = CircuitBreaker(clock=clock, persistence=store)
        for forbidden in ("reset", "close", "clear", "force_close", "open", "set_state"):
            assert not hasattr(breaker, forbidden)

    def test_persistence_added_no_route_to_closed(self, store) -> None:
        # Writing directly to the store is the only new surface, and it is covered above.
        breaker = CircuitBreaker(clock=clock, persistence=store)
        key = breaker.key_for(capability=ROLLBACK, resource=PAYMENT)
        assert breaker.state_of(key) is CircuitState.HALF_OPEN
        breaker.record(key, FailureClass.NONE, reason="a success elsewhere")
        assert breaker.state_of(key) is not CircuitState.CLOSED


def _relink(store, *, from_index: int) -> None:
    """Recompute links and digests from an index onward, producing an intact chain."""
    chain = store._records
    for index in range(from_index, len(chain)):
        previous = chain[index - 1].digest if index else LIFECYCLE_GENESIS_DIGEST
        chain[index] = reseal(chain[index], previous_digest=previous)


class TestDigestCoverage:
    def test_every_record_field_is_covered_by_the_digest(self) -> None:
        # If a field is added to the record and not to the payload, this fails — rather
        # than the omission being discovered by someone exploiting it.
        from aegis.lifecycle.state import _DigestPayload

        covered = set(_DigestPayload.model_fields)
        record_fields = set(LifecycleStateRecord.model_fields) - {"digest"}
        assert record_fields <= covered, f"uncovered: {record_fields - covered}"

    def test_a_digest_is_64_lowercase_hex_characters(self, store) -> None:
        digest = records(store)[0].digest
        assert len(digest) == 64
        assert digest == digest.lower()
        int(digest, 16)

    def test_the_digest_is_stable_across_recomputation(self, store) -> None:
        for record in records(store):
            assert record.digest == state_digest(record)

    def test_failure_counts_are_covered_regardless_of_key_order(self, store) -> None:
        record = records(store)[2]
        reordered = record.model_copy(
            update={"failure_counts": dict(reversed(list(record.failure_counts.items())))}
        )
        assert state_digest(reordered) == record.digest

    def test_a_changed_count_changes_the_digest(self, store) -> None:
        record = records(store)[2]
        assert state_digest(record.model_copy(update={"failure_counts": {"X": 1}})) != (
            record.digest
        )


class TestTheVerifierReportsRatherThanRepairs:
    def test_verification_does_not_modify_the_chain(self, store) -> None:
        from aegis.core.domain import to_json

        before = [to_json(r) for r in records(store)]
        verify_state_chain(records(store))
        assert [to_json(r) for r in records(store)] == before

    def test_a_damaged_chain_stays_damaged(self, store) -> None:
        tamper(store, 1, failure_counts={})
        assert not verify_state_chain(records(store)).valid
        assert not verify_state_chain(records(store)).valid

    def test_the_report_exposes_the_declared_fields(self, store) -> None:
        tamper(store, 1, sequence=99)
        report = verify_state_chain(records(store))
        assert set(type(report).model_fields) == {
            "valid",
            "checked",
            "first_invalid_index",
            "reason",
        }
        assert report.trusted_prefix == 1

    def test_a_valid_report_has_no_first_invalid_index(self, store) -> None:
        report = verify_state_chain(records(store))
        assert report.first_invalid_index is None
        assert report.trusted_prefix == report.checked


class TestBreakerIntegrityReporting:
    def test_the_breaker_reports_its_chain(self, store) -> None:
        breaker = CircuitBreaker(clock=clock, persistence=store)
        assert breaker.verify_integrity().valid

    def test_a_breaker_without_persistence_reports_an_empty_valid_chain(self) -> None:
        breaker = CircuitBreaker(clock=clock)
        report = breaker.verify_integrity()
        assert report.valid
        assert report.checked == 0

    def test_a_damaged_chain_is_reported_by_the_breaker(self, store) -> None:
        breaker = CircuitBreaker(clock=clock, persistence=store)
        tamper(store, 1, failure_counts={})
        assert not breaker.verify_integrity().valid

    def test_a_timedelta_import_is_not_needed_for_a_none_cooldown(self, store) -> None:
        # A None cooldown means never automatically eligible; nothing computes a deadline.
        breaker = CircuitBreaker(
            CircuitBreakerConfig(probe_cooldown_seconds=None), clock=clock, persistence=store
        )
        key = breaker.key_for(capability=ROLLBACK, resource=PAYMENT)
        assert breaker.snapshot(key).probe_eligible_at is None


class TestDiscriminatingCoverageFoundByMutation:
    """Tests added because a weakening survived the suite as first written.

    Each one isolates a guarantee that another check happened to cover, so removing the
    guarantee alone now fails something.
    """

    def test_a_changed_circuit_state_changes_the_digest(self, store) -> None:
        # `test_flipping_open_to_closed_is_detected` passed even when the digest stopped
        # covering circuit_state, because transition legality caught the flip. This pins
        # the digest's own coverage of the field.
        record = records(store)[2]
        flipped = record.model_copy(update={"circuit_state": CircuitState.HALF_OPEN})
        assert state_digest(flipped) != record.digest

    def test_a_changed_probe_flag_changes_the_digest(self, store) -> None:
        record = records(store)[3]
        assert state_digest(record.model_copy(update={"probe_in_flight": True})) != record.digest

    def test_a_changed_recorded_at_changes_the_digest(self, store) -> None:
        from datetime import timedelta

        record = records(store)[0]
        later = record.model_copy(update={"recorded_at": START + timedelta(hours=1)})
        assert state_digest(later) != record.digest

    def test_a_resealed_probe_success_straight_from_open_is_refused(self, store) -> None:
        # The subtler replay: not an old snapshot, but a *forged transition* claiming the
        # breaker was closed by a probe that never went half-open. Only the explicit edge
        # (PROBE_SUCCEEDED, HALF_OPEN, CLOSED) permits closing, and this is not it.
        chain = store._records
        del chain[3]  # drop the PROBE_PERMITTED record, leaving the scope OPEN
        forged = reseal(
            records(store)[2],
            sequence=3,
            transition=BreakerTransition.PROBE_SUCCEEDED,
            circuit_state=CircuitState.CLOSED,
            previous_digest=records(store)[2].digest,
        )
        chain.append(forged)

        report = verify_state_chain(records(store))
        assert not report.valid
        assert "not a legal edge" in report.reason

    def test_closing_from_open_is_not_a_legal_edge_under_any_transition(self) -> None:
        for transition in BreakerTransition:
            assert not legal_transition(
                transition, previous=CircuitState.OPEN, resulting=CircuitState.CLOSED
            ), transition
