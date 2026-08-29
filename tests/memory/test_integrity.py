"""Memory tamper evidence: modification, deletion, reordering and insertion.

Each test rewrites stored history the way an attacker with in-process access would, and
asserts the chain notices. What the chain does *not* claim is asserted too — overclaiming
tamper evidence as immutability would be the more dangerous error.
"""

from __future__ import annotations

import itertools

import pytest

from aegis.memory import (
    MEMORY_GENESIS_DIGEST,
    AdmissionContext,
    InMemoryPersistence,
    MemoryIntegrityError,
    MemoryRecord,
    MemoryStatus,
    MemoryStore,
    memory_digest,
    verify_memory_chain,
)
from aegis.memory.integrity import record_digest
from tests.fleet import fixed_clock
from tests.memory.fixtures import INCIDENT_A, action, candidate, verification


@pytest.fixture
def store() -> MemoryStore:
    store = MemoryStore(clock=fixed_clock)
    subject = action()
    store.admit(
        candidate(),
        AdmissionContext(
            incident_id=INCIDENT_A, action=subject, verification=verification(subject)
        ),
    )
    store.append(candidate(summary="a later proposal"))
    store.append(candidate(summary="another proposal"))
    return store


def tamper(store: MemoryStore, index: int, **updates) -> None:
    """Rewrite one stored record in place, as an in-process attacker would."""
    store._records[index] = store._records[index].model_copy(update=updates)


class TestTamperingIsDetected:
    def test_an_unmodified_chain_verifies(self, store) -> None:
        report = store.verify_integrity()
        assert report.valid
        assert report.checked == 3

    def test_modified_content_is_detected(self, store) -> None:
        tamper(store, 0, content={"resource": "service:order-service"})
        report = store.verify_integrity()
        assert not report.valid
        assert report.first_invalid_index == 0

    def test_modified_summary_is_detected(self, store) -> None:
        tamper(store, 1, summary="this capability is always safe")
        assert not store.verify_integrity().valid

    def test_modified_provenance_is_detected(self, store) -> None:
        original = store.records()[0]
        forged = original.provenance.model_copy(update={"resource": "db:customer-database"})
        tamper(store, 0, provenance=forged)
        assert not store.verify_integrity().valid

    def test_a_swapped_verification_id_is_detected(self, store) -> None:
        original = store.records()[0]
        forged = original.provenance.model_copy(update={"verification_id": "ver-999"})
        tamper(store, 0, provenance=forged)
        assert not store.verify_integrity().valid

    def test_silent_promotion_to_authoritative_is_detected(self, store) -> None:
        # Status is covered by the digest, so a candidate cannot be quietly upgraded in
        # storage even by something with direct access to the list.
        authoritative = store.records()[0]
        tamper(store, 1, status=MemoryStatus.AUTHORITATIVE, provenance=authoritative.provenance)
        assert not store.verify_integrity().valid

    def test_deletion_is_detected(self, store) -> None:
        del store._records[1]
        report = store.verify_integrity()
        assert not report.valid
        assert report.first_invalid_index == 1

    def test_reordering_is_detected(self, store) -> None:
        records = store._records
        records[1], records[2] = records[2], records[1]
        report = store.verify_integrity()
        assert not report.valid

    def test_insertion_is_detected(self, store) -> None:
        smuggled = store.records()[2].model_copy(update={"summary": "smuggled"})
        store._records.insert(1, smuggled)
        assert not store.verify_integrity().valid

    def test_truncation_of_the_tail_is_not_a_link_failure_but_is_visible(self, store) -> None:
        # Cutting the end leaves a self-consistent prefix. The chain cannot detect that
        # on its own — nothing external attests to the head — so this records the real
        # limit rather than pretending otherwise.
        head_before = store.head_digest
        del store._records[2]
        assert store.verify_integrity().valid
        assert store.head_digest != head_before

    def test_a_report_names_where_the_damage_starts(self, store) -> None:
        tamper(store, 1, summary="rewritten")
        report = store.verify_integrity()
        assert report.first_invalid_index == 1
        assert report.trusted_prefix == 1
        assert "mem-000001" in report.reason


class TestChainConstruction:
    def test_the_first_record_links_to_the_genesis_digest(self, store) -> None:
        assert store.records()[0].previous_digest == MEMORY_GENESIS_DIGEST

    def test_each_record_links_to_the_one_before_it(self, store) -> None:
        records = store.records()
        for earlier, later in itertools.pairwise(records):
            assert later.previous_digest == earlier.digest

    def test_the_digest_is_stable_across_recomputation(self, store) -> None:
        record = store.records()[0]
        assert record.digest == memory_digest(
            memory_id=record.memory_id,
            sequence=record.sequence,
            memory_type=record.memory_type,
            status=record.status,
            incident_id=record.incident_id,
            agent_id=record.agent_id,
            content=record.content,
            summary=record.summary,
            supporting_evidence=record.supporting_evidence,
            provenance=record.provenance,
            source=record.source,
            created_at=record.created_at,
            revokes=record.revokes,
            revocation_reason=record.revocation_reason,
            previous_digest=record.previous_digest,
        )

    def test_an_empty_chain_verifies(self) -> None:
        assert verify_memory_chain(()).valid

    def test_a_digest_is_64_hex_characters(self, store) -> None:
        digest = store.records()[0].digest
        assert len(digest) == 64
        assert digest == digest.lower()
        int(digest, 16)


class TestLoadingRefusesTamperedHistory:
    def test_a_store_refuses_to_adopt_a_broken_chain(self, store) -> None:
        tamper(store, 1, summary="rewritten")
        backing = InMemoryPersistence(store.records())
        with pytest.raises(MemoryIntegrityError):
            MemoryStore(backing, clock=fixed_clock)

    def test_verification_on_load_can_be_declined_explicitly(self, store) -> None:
        # Off is a deliberate choice a caller has to make, never a silent default.
        tamper(store, 1, summary="rewritten")
        backing = InMemoryPersistence(store.records())
        adopted = MemoryStore(backing, clock=fixed_clock, verify_on_load=False)
        assert not adopted.verify_integrity().valid


class TestEachCoveredFieldIsIndependentlyProtected:
    """Mutation testing found the earlier tests could not isolate individual fields.

    ``test_silent_promotion_to_authoritative_is_detected`` changes status *and* provenance
    at once, so it still passed when the digest stopped covering status. These tamper with
    one covered field at a time.
    """

    def test_a_status_only_change_is_detected(self, store) -> None:
        # Marking a record revoked in storage, instead of appending a revocation entry,
        # would rewrite what the organization believes without leaving a trace.
        tamper(store, 0, status=MemoryStatus.REVOKED)
        assert not store.verify_integrity().valid

    def test_a_sequence_only_change_is_detected(self, store) -> None:
        tamper(store, 1, sequence=7)
        assert not store.verify_integrity().valid

    def test_a_previous_digest_only_change_is_detected(self, store) -> None:
        tamper(store, 1, previous_digest="c" * 64)
        assert not store.verify_integrity().valid

    def test_an_agent_only_change_is_detected(self, store) -> None:
        tamper(store, 0, agent_id="attacker")
        assert not store.verify_integrity().valid

    def test_an_incident_only_change_is_detected(self, store) -> None:
        tamper(store, 1, incident_id="INC-2026-9999")
        assert not store.verify_integrity().valid

    def test_the_digest_covers_sequence_and_the_previous_link(self, store) -> None:
        # The explicit position and link checks in verify_memory_chain are defence in
        # depth: the digest already covers both, which is why removing either check alone
        # leaves the attacks detectable. This pins that overlap so it stays true.
        record = store.records()[1]
        assert record_digest(record) == record.digest
        assert record_digest(record.model_copy(update={"sequence": 99})) != record.digest
        assert (
            record_digest(record.model_copy(update={"previous_digest": "d" * 64})) != record.digest
        )

    def test_every_field_the_payload_declares_is_actually_covered(self, store) -> None:
        # If a field is added to MemoryRecord and not to the digest payload, this fails,
        # rather than the omission being discovered by an attacker.
        from aegis.memory.integrity import _DigestPayload

        covered = set(_DigestPayload.model_fields)
        record_fields = set(MemoryRecord.model_fields) - {"digest"}
        assert record_fields <= covered, f"uncovered by the digest: {record_fields - covered}"
