"""The memory store: append-only, exact matching, and no route to forged authority."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from aegis.core.domain import to_json
from aegis.memory import (
    AdmissionContext,
    InMemoryPersistence,
    MemoryAdmissionRefused,
    MemoryCandidate,
    MemoryNotFound,
    MemoryProvenance,
    MemoryQuery,
    MemoryRecord,
    MemorySource,
    MemoryStatus,
    MemoryStore,
    MemoryType,
)
from tests.fleet import FIXED_EVALUATION_TIME, fixed_clock
from tests.memory.fixtures import (
    INCIDENT_A,
    INCIDENT_B,
    action,
    candidate,
    verification,
)


@pytest.fixture
def store() -> MemoryStore:
    return MemoryStore(clock=fixed_clock)


def context(subject=None, result=None, incident_id: str = INCIDENT_A) -> AdmissionContext:
    subject = subject if subject is not None else action()
    result = result if result is not None else verification(subject)
    return AdmissionContext(incident_id=incident_id, action=subject, verification=result)


def admit(store: MemoryStore, **kwargs) -> MemoryRecord:
    incident_id = kwargs.pop("incident_id", INCIDENT_A)
    subject = action(incident_id=incident_id, **kwargs.pop("action_kwargs", {}))
    result = verification(subject, **kwargs.pop("verification_kwargs", {}))
    return store.admit(
        candidate(incident_id=incident_id, **kwargs),
        AdmissionContext(incident_id=incident_id, action=subject, verification=result),
    )


class TestAgentsCannotWriteAuthoritativeMemory:
    """Part 8. The boundary is structural, not a check that could be skipped."""

    def test_a_candidate_has_no_status_field_to_set(self) -> None:
        # The type an agent constructs cannot express a claim to authority.
        assert "status" not in MemoryCandidate.model_fields

    def test_a_candidate_cannot_be_given_a_status(self) -> None:
        with pytest.raises(ValidationError):
            MemoryCandidate(
                memory_type=MemoryType.OPERATIONAL_PATTERN,
                incident_id=INCIDENT_A,
                agent_id="remediation",
                summary="payment-api rollback is always safe",
                status=MemoryStatus.AUTHORITATIVE,
            )

    def test_append_always_stores_a_candidate(self, store) -> None:
        record = store.append(candidate(summary="payment-api rollback is always safe"))
        assert record.status is MemoryStatus.CANDIDATE
        assert record.provenance is None

    def test_a_stored_candidate_is_never_returned_as_history(self, store) -> None:
        store.append(candidate())
        assert store.query() == ()

    def test_the_store_has_no_method_that_accepts_a_prebuilt_record(self, store) -> None:
        # There is no append(record) overload and no promote(). Constructing a record by
        # hand produces a value nothing will take.
        assert not hasattr(store, "promote")
        assert not hasattr(store, "update")
        assert not hasattr(store, "delete")
        with pytest.raises((ValidationError, AttributeError, TypeError)):
            store.append(store.records()[0] if store.records() else 1)  # type: ignore[arg-type]

    def test_a_handbuilt_authoritative_record_without_provenance_is_invalid(self) -> None:
        with pytest.raises(ValidationError, match="requires provenance"):
            MemoryRecord(
                memory_id="mem-999999",
                sequence=0,
                memory_type=MemoryType.OPERATIONAL_PATTERN,
                status=MemoryStatus.AUTHORITATIVE,
                incident_id=INCIDENT_A,
                agent_id="remediation",
                summary="this capability is always safe",
                source=MemorySource.AGENT_PROPOSAL,
                created_at=FIXED_EVALUATION_TIME,
                previous_digest="0" * 64,
                digest="0" * 64,
            )

    def test_a_handbuilt_record_cannot_claim_authority_from_an_agent_proposal(self) -> None:
        provenance = MemoryProvenance(
            incident_id=INCIDENT_A,
            agent_id="remediation",
            verification_id="ver-001",
            action_id="act-001",
            action_fingerprint="a" * 64,
            resource="service:payment-api",
            evidence_ids=("obs-1",),
            verified_at=FIXED_EVALUATION_TIME,
            source=MemorySource.AGENT_PROPOSAL,
        )
        with pytest.raises(ValidationError, match="VERIFIED_OUTCOME"):
            MemoryRecord(
                memory_id="mem-999999",
                sequence=0,
                memory_type=MemoryType.OPERATIONAL_PATTERN,
                status=MemoryStatus.AUTHORITATIVE,
                incident_id=INCIDENT_A,
                agent_id="remediation",
                summary="always safe",
                provenance=provenance,
                source=MemorySource.AGENT_PROPOSAL,
                created_at=FIXED_EVALUATION_TIME,
                previous_digest="0" * 64,
                digest="0" * 64,
            )

    def test_provenance_must_match_the_records_incident(self) -> None:
        provenance = MemoryProvenance(
            incident_id=INCIDENT_B,
            agent_id="remediation",
            verification_id="ver-001",
            action_id="act-001",
            action_fingerprint="a" * 64,
            resource="service:payment-api",
            evidence_ids=("obs-1",),
            verified_at=FIXED_EVALUATION_TIME,
        )
        with pytest.raises(ValidationError, match="does not match"):
            MemoryRecord(
                memory_id="mem-999999",
                sequence=0,
                memory_type=MemoryType.REMEDIATION_OUTCOME,
                status=MemoryStatus.AUTHORITATIVE,
                incident_id=INCIDENT_A,
                agent_id="remediation",
                summary="ok",
                provenance=provenance,
                source=MemorySource.VERIFIED_OUTCOME,
                created_at=FIXED_EVALUATION_TIME,
                previous_digest="0" * 64,
                digest="0" * 64,
            )

    def test_a_refused_candidate_writes_nothing_at_all(self, store) -> None:
        subject = action()
        from aegis.core.verification import VerificationStatus

        failed = verification(subject, status=VerificationStatus.FAILED)
        with pytest.raises(MemoryAdmissionRefused):
            store.admit(candidate(), context(subject, failed))
        assert len(store) == 0


class TestAppendOnly:
    def test_records_are_returned_as_an_immutable_tuple(self, store) -> None:
        store.append(candidate())
        assert isinstance(store.records(), tuple)

    def test_the_internal_list_is_never_exposed(self, store) -> None:
        store.append(candidate())
        held = store.records()
        assert held is not store.records()
        store.append(candidate())
        assert len(held) == 1, "a previously returned tuple must not grow"

    def test_a_returned_record_is_frozen(self, store) -> None:
        record = store.append(candidate())
        with pytest.raises(ValidationError):
            record.summary = "rewritten"  # type: ignore[misc]

    def test_memory_ids_are_deterministic_and_sequential(self, store) -> None:
        first = store.append(candidate())
        second = store.append(candidate())
        assert (first.memory_id, second.memory_id) == ("mem-000000", "mem-000001")

    def test_sequence_matches_position(self, store) -> None:
        for _ in range(3):
            store.append(candidate())
        assert [r.sequence for r in store.records()] == [0, 1, 2]


class TestQueryingIsExact:
    def test_only_authoritative_records_are_returned(self, store) -> None:
        store.append(candidate())
        admitted = admit(store)
        assert [r.memory_id for r in store.query()] == [admitted.memory_id]

    def test_resource_matching_is_exact_not_prefix(self, store) -> None:
        admit(store)
        assert store.query(MemoryQuery(resource="service:payment-api"))
        assert store.query(MemoryQuery(resource="service:payment")) == ()
        assert store.query(MemoryQuery(resource="payment-api")) == ()

    def test_incident_matching_is_exact(self, store) -> None:
        admit(store, incident_id=INCIDENT_A)
        assert store.query(MemoryQuery(incident_id=INCIDENT_A))
        assert store.query(MemoryQuery(incident_id=INCIDENT_B)) == ()

    def test_memory_type_filters(self, store) -> None:
        admit(store, memory_type=MemoryType.REMEDIATION_OUTCOME)
        assert store.query(MemoryQuery(memory_type=MemoryType.REMEDIATION_OUTCOME))
        assert store.query(MemoryQuery(memory_type=MemoryType.VERIFIED_ROOT_CAUSE)) == ()

    def test_capability_filters_on_declared_content(self, store) -> None:
        admit(store)
        assert store.query(MemoryQuery(capability="production.rollback"))
        assert store.query(MemoryQuery(capability="production.scale")) == ()

    def test_agent_filters(self, store) -> None:
        admit(store, agent_id="remediation")
        assert store.query(MemoryQuery(agent_id="remediation"))
        assert store.query(MemoryQuery(agent_id="diagnostic")) == ()

    def test_exclude_incident_drops_that_incidents_memory(self, store) -> None:
        admit(store, incident_id=INCIDENT_A)
        assert store.query(MemoryQuery(exclude_incident=INCIDENT_A)) == ()

    def test_limit_is_applied_after_ordering(self, store) -> None:
        admit(store, incident_id=INCIDENT_A)
        admit(store, incident_id=INCIDENT_B)
        limited = store.query(MemoryQuery(limit=1))
        assert len(limited) == 1
        assert limited[0].incident_id == INCIDENT_A

    def test_query_results_are_stable_across_calls(self, store) -> None:
        admit(store, incident_id=INCIDENT_A)
        admit(store, incident_id=INCIDENT_B)
        assert store.query() == store.query()

    def test_get_requires_an_exact_id(self, store) -> None:
        record = store.append(candidate())
        assert store.get(record.memory_id) == record
        with pytest.raises(MemoryNotFound):
            store.get("mem-00000")
        with pytest.raises(MemoryNotFound):
            store.get("mem-000000-extra")


class TestRevocation:
    def test_revocation_appends_rather_than_deleting(self, store) -> None:
        admitted = admit(store)
        store.revoke(admitted.memory_id, reason="verification was invalid", actor="human:oncall")
        assert len(store) == 2
        assert store.get(admitted.memory_id).status is MemoryStatus.AUTHORITATIVE

    def test_a_revoked_record_is_no_longer_returned_as_history(self, store) -> None:
        admitted = admit(store)
        assert store.query()
        store.revoke(admitted.memory_id, reason="corrected", actor="human:oncall")
        assert store.query() == ()

    def test_the_revocation_entry_names_what_it_withdrew(self, store) -> None:
        admitted = admit(store)
        entry = store.revoke(admitted.memory_id, reason="corrected", actor="human:oncall")
        assert entry.revokes == admitted.memory_id
        assert entry.revocation_reason == "corrected"
        assert entry.is_revocation

    def test_history_still_shows_the_record_existed(self, store) -> None:
        admitted = admit(store)
        store.revoke(admitted.memory_id, reason="corrected", actor="human:oncall")
        ids = [r.memory_id for r in store.records()]
        assert admitted.memory_id in ids

    def test_revoking_an_unknown_id_is_refused(self, store) -> None:
        with pytest.raises(MemoryNotFound):
            store.revoke("mem-999999", reason="nothing", actor="human:oncall")

    def test_the_chain_still_verifies_after_revocation(self, store) -> None:
        admitted = admit(store)
        store.revoke(admitted.memory_id, reason="corrected", actor="human:oncall")
        assert store.verify_integrity().valid


class TestDeterminism:
    def test_two_identical_runs_serialize_identically(self) -> None:
        def build() -> MemoryStore:
            store = MemoryStore(clock=fixed_clock)
            admit(store)
            store.append(candidate(summary="a proposal"))
            return store

        first, second = build(), build()
        assert [to_json(r) for r in first.records()] == [to_json(r) for r in second.records()]
        assert first.head_digest == second.head_digest

    def test_the_head_digest_of_an_empty_store_is_the_genesis_value(self, store) -> None:
        from aegis.memory import MEMORY_GENESIS_DIGEST

        assert store.head_digest == MEMORY_GENESIS_DIGEST


class TestPersistenceAbstraction:
    def test_a_store_adopts_records_from_persistence(self) -> None:
        backing = InMemoryPersistence()
        first = MemoryStore(backing, clock=fixed_clock)
        admit(first)
        second = MemoryStore(backing, clock=fixed_clock)
        assert len(second) == 1
        assert second.query()

    def test_the_chain_continues_across_store_instances(self) -> None:
        backing = InMemoryPersistence()
        first = MemoryStore(backing, clock=fixed_clock)
        admit(first)
        second = MemoryStore(backing, clock=fixed_clock)
        second.append(candidate())
        assert second.verify_integrity().valid
        assert second.records()[1].previous_digest == second.records()[0].digest

    def test_in_memory_persistence_is_not_durable(self) -> None:
        # Stated as a test so the honest limitation is recorded, not just documented.
        backing = InMemoryPersistence()
        MemoryStore(backing, clock=fixed_clock).append(candidate())
        assert len(InMemoryPersistence()) == 0
