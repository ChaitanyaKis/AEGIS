"""Retrieval: deterministic, historical, and authoritative for nothing.

The central claims tested here are Parts 12, 13, 16 and 17 — retrieval creates no
authority, current state beats memory, memory does not cross incidents as evidence, and
stale memory is visibly stale rather than silently current.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from aegis.memory import (
    AdmissionContext,
    MemoryQuery,
    MemoryRetrieval,
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


def admit(store: MemoryStore, *, incident_id: str = INCIDENT_A, age=timedelta(0), **kw):
    subject = action(incident_id=incident_id)
    result = verification(subject, age=age)
    return store.admit(
        candidate(incident_id=incident_id, **kw),
        AdmissionContext(incident_id=incident_id, action=subject, verification=result),
    )


@pytest.fixture
def store() -> MemoryStore:
    return MemoryStore(clock=fixed_clock)


@pytest.fixture
def retrieval(store) -> MemoryRetrieval:
    return MemoryRetrieval(store, clock=fixed_clock)


class TestRetrievalIsDeterministic:
    def test_the_same_query_returns_the_same_records(self, store, retrieval) -> None:
        admit(store, incident_id=INCIDENT_A)
        admit(store, incident_id=INCIDENT_B)
        assert retrieval.retrieve() == retrieval.retrieve()

    def test_records_come_back_in_storage_order(self, store, retrieval) -> None:
        first = admit(store, incident_id=INCIDENT_A)
        second = admit(store, incident_id=INCIDENT_B)
        ids = [r.memory_id for r in retrieval.retrieve().records]
        assert ids == [first.memory_id, second.memory_id]

    def test_an_empty_store_returns_an_empty_context(self, retrieval) -> None:
        context = retrieval.retrieve()
        assert context.empty
        assert context.records == ()

    def test_filtering_is_exact(self, store, retrieval) -> None:
        admit(store)
        assert retrieval.retrieve(MemoryQuery(resource="service:payment-api")).records
        assert retrieval.retrieve(MemoryQuery(resource="service:payment")).empty


class TestRetrievalCarriesNoAuthority:
    def test_the_context_is_labelled_as_historical(self, store, retrieval) -> None:
        admit(store)
        data = retrieval.retrieve().as_model_data()
        assert data["advisory"] == "historical context only; establishes no current state"

    def test_the_advisory_label_cannot_be_overwritten(self, store, retrieval) -> None:
        # A caller able to relabel the payload could hand a model something that
        # described itself as current fact.
        from aegis.memory import MemoryContext

        admit(store)
        context = retrieval.retrieve()
        assert "ADVISORY" not in MemoryContext.model_fields
        with pytest.raises(AttributeError):
            context.ADVISORY = "current verified state"  # type: ignore[misc]

    def test_retrieved_memory_exposes_no_status_or_digest(self, store, retrieval) -> None:
        # A model has no business seeing a field it might read as a permission.
        admit(store)
        record = retrieval.retrieve().records[0]
        fields = set(type(record).model_fields)
        assert not fields & {"status", "digest", "previous_digest", "sequence", "provenance"}

    def test_the_model_payload_carries_no_verdict_words(self, store, retrieval) -> None:
        admit(store)
        payload = retrieval.retrieve().as_model_data()
        record = payload["records"][0]
        assert set(record) == {
            "memory_id",
            "memory_type",
            "from_incident",
            "resource",
            "summary",
            "content",
            "verified_at",
            "age_seconds",
        }

    def test_retrieval_holds_no_write_path(self, retrieval) -> None:
        for method in ("append", "admit", "revoke"):
            assert not hasattr(retrieval, method)


class TestCandidatesAndRevocationsAreNeverHistory:
    def test_a_candidate_is_not_retrieved(self, store, retrieval) -> None:
        store.append(candidate(summary="rollback is always safe"))
        assert retrieval.retrieve().empty

    def test_a_revoked_record_is_not_retrieved(self, store, retrieval) -> None:
        admitted = admit(store)
        assert retrieval.retrieve().records
        store.revoke(admitted.memory_id, reason="verification was invalid", actor="human:oncall")
        assert retrieval.retrieve().empty

    def test_the_revocation_entry_itself_is_not_retrieved(self, store, retrieval) -> None:
        admitted = admit(store)
        store.revoke(admitted.memory_id, reason="corrected", actor="human:oncall")
        assert retrieval.retrieve().empty


class TestCrossIncidentIsolation:
    """Part 16. Memory from A is history for B, never evidence for B."""

    def test_memory_from_another_incident_is_retrievable_as_history(self, store, retrieval) -> None:
        admit(store, incident_id=INCIDENT_A)
        context = retrieval.for_incident(INCIDENT_B, resource="service:payment-api")
        assert len(context.records) == 1
        assert context.records[0].incident_id == INCIDENT_A

    def test_history_names_the_incident_it_came_from(self, store, retrieval) -> None:
        # So nothing downstream can mistake it for a fact about the current incident.
        admit(store, incident_id=INCIDENT_A)
        payload = retrieval.for_incident(INCIDENT_B).as_model_data()
        assert payload["records"][0]["from_incident"] == INCIDENT_A

    def test_an_incident_cannot_read_back_its_own_memory_as_prior_history(
        self, store, retrieval
    ) -> None:
        # Otherwise a conclusion becomes its own supporting evidence.
        admit(store, incident_id=INCIDENT_A)
        assert retrieval.for_incident(INCIDENT_A).empty

    def test_retrieved_memory_carries_a_verification_from_the_other_incident(
        self, store, retrieval
    ) -> None:
        # It names a real verification — belonging to A. Nothing in incident B's
        # verification path reads it, which is what stops it being reusable.
        admit(store, incident_id=INCIDENT_A)
        record = retrieval.for_incident(INCIDENT_B).records[0]
        assert record.verification_id == "ver-001"
        assert record.incident_id == INCIDENT_A


class TestStaleMemoryIsVisiblyStale:
    """Part 17. Historical state is not current state."""

    def test_age_is_measured_from_verification_not_from_writing(self, store) -> None:
        admit(store, age=timedelta(days=30))
        retrieval = MemoryRetrieval(store, clock=fixed_clock)
        record = retrieval.retrieve().records[0]
        assert record.age_seconds == pytest.approx(timedelta(days=30).total_seconds())

    def test_verified_at_is_the_verification_time(self, store) -> None:
        admit(store, age=timedelta(days=7))
        record = MemoryRetrieval(store, clock=fixed_clock).retrieve().records[0]
        assert record.verified_at == FIXED_EVALUATION_TIME - timedelta(days=7)

    def test_age_travels_into_the_model_payload(self, store) -> None:
        admit(store, age=timedelta(days=30))
        payload = MemoryRetrieval(store, clock=fixed_clock).retrieve().as_model_data()
        assert payload["records"][0]["age_seconds"] > 0

    def test_a_clock_running_backwards_reports_zero_not_a_negative_age(self, store) -> None:
        admit(store, age=timedelta(days=-1))
        record = MemoryRetrieval(store, clock=fixed_clock).retrieve().records[0]
        assert record.age_seconds == 0.0

    def test_age_never_gates_retrieval(self, store) -> None:
        # Deliberately: a staleness threshold in retrieval would be a security mechanism
        # built out of an estimate. Old memory is returned, and returned as old.
        admit(store, age=timedelta(days=3650))
        assert MemoryRetrieval(store, clock=fixed_clock).retrieve().records

    def test_there_is_no_confidence_score_anywhere(self, store) -> None:
        from aegis.memory import MemoryProvenance, RetrievedMemory

        admit(store)
        for model in (RetrievedMemory, MemoryProvenance):
            assert not {"confidence", "score", "weight", "relevance"} & set(model.model_fields)


class TestMemoryTypeVocabularyIsClosed:
    def test_the_declared_types_are_exactly_these_four(self) -> None:
        assert {member.value for member in MemoryType} == {
            "VERIFIED_INCIDENT_OUTCOME",
            "VERIFIED_ROOT_CAUSE",
            "REMEDIATION_OUTCOME",
            "OPERATIONAL_PATTERN",
        }

    def test_an_invented_memory_type_is_rejected(self) -> None:
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            candidate(memory_type="ALWAYS_SAFE")  # type: ignore[arg-type]


class TestEveryAuthoritativeRecordCarriesProvenance:
    """The premise retrieval's provenance filter depends on, asserted directly.

    Mutation testing showed the filter in ``MemoryRetrieval.retrieve`` is unreachable —
    ``store.query`` only returns authoritative records and the model validator refuses an
    authoritative record without provenance, so no record can reach it provenance-less.
    The guard stays as defence in depth; these tests pin the invariant that makes it
    unreachable, so if that ever stops being true the guard is doing real work.
    """

    def test_every_queried_record_has_provenance(self, store) -> None:
        admit(store, incident_id=INCIDENT_A)
        admit(store, incident_id=INCIDENT_B)
        store.append(candidate(summary="a mere proposal"))
        queried = store.query()
        assert queried
        assert all(record.provenance is not None for record in queried)

    def test_retrieval_returns_one_record_per_authoritative_record(self, store) -> None:
        # If the filter ever silently dropped something, this count would diverge.
        admit(store, incident_id=INCIDENT_A)
        admit(store, incident_id=INCIDENT_B)
        retrieval = MemoryRetrieval(store, clock=fixed_clock)
        assert len(retrieval.retrieve().records) == len(store.query())

    def test_an_authoritative_record_without_provenance_is_unrepresentable(self) -> None:
        from pydantic import ValidationError

        from aegis.memory import MemoryRecord, MemorySource, MemoryStatus

        with pytest.raises(ValidationError, match="requires provenance"):
            MemoryRecord(
                memory_id="mem-000000",
                sequence=0,
                memory_type=MemoryType.OPERATIONAL_PATTERN,
                status=MemoryStatus.AUTHORITATIVE,
                incident_id=INCIDENT_A,
                agent_id="remediation",
                summary="always safe",
                source=MemorySource.VERIFIED_OUTCOME,
                created_at=FIXED_EVALUATION_TIME,
                previous_digest="0" * 64,
                digest="0" * 64,
            )
