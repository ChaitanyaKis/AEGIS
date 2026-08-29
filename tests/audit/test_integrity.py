"""The hash chain: digest formula, linkage and tamper detection.

Each test below plays an attacker with write access to the stored records and checks that
:func:`verify_chain` notices. What that proves and what it does not is stated explicitly in
the module docstring of ``aegis.core.audit.records``: this is tamper *evidence*, not
immutability.
"""

from __future__ import annotations

import hashlib
from itertools import pairwise

import pytest

from aegis.core.audit import (
    GENESIS_DIGEST,
    AuditRecord,
    AuditStore,
    record_digest,
    verify_chain,
)
from aegis.core.domain import to_json
from tests.audit.conftest import make_event


def _filled(store: AuditStore, count: int = 4) -> AuditStore:
    for index in range(count):
        store.append(
            make_event(event_id=f"evt-{index:06d}", incident_id="INC-1"),
            correlation={"action_id": f"act-{index:03d}"},
        )
    return store


# --- the digest formula -------------------------------------------------------------


def test_genesis_is_a_fixed_documented_value() -> None:
    assert GENESIS_DIGEST == "0" * 64
    assert AuditStore().head_digest == GENESIS_DIGEST


def test_the_first_record_links_to_genesis(store: AuditStore) -> None:
    record = store.append(make_event())
    assert record.previous_digest == GENESIS_DIGEST


def test_each_record_links_to_its_predecessor(store: AuditStore) -> None:
    records = _filled(store).records()
    for previous, current in pairwise(records):
        assert current.previous_digest == previous.digest


def test_the_digest_formula_is_sha256_over_the_canonical_document() -> None:
    """Pinned exactly: the hashed document is canonical JSON, not concatenated strings."""
    event = make_event()
    correlation = {"action_id": "act-001"}
    expected_document = (
        '{"correlation":{"action_id":"act-001"},'
        f'"event":{to_json(event)},'
        f'"previous_digest":"{GENESIS_DIGEST}",'
        '"sequence":0}'
    )
    expected = hashlib.sha256(expected_document.encode("utf-8")).hexdigest()
    assert (
        record_digest(
            sequence=0,
            event=event,
            correlation=correlation,
            previous_digest=GENESIS_DIGEST,
        )
        == expected
    )


def test_digests_are_hex_and_deterministic() -> None:
    event = make_event()
    first = record_digest(sequence=0, event=event, correlation={}, previous_digest=GENESIS_DIGEST)
    second = record_digest(sequence=0, event=event, correlation={}, previous_digest=GENESIS_DIGEST)
    assert first == second
    assert len(first) == 64
    assert all(character in "0123456789abcdef" for character in first)


def test_correlation_key_order_does_not_change_the_digest() -> None:
    event = make_event()
    forward = record_digest(
        sequence=0,
        event=event,
        correlation={"action_id": "act-001", "approval_id": "apr-001"},
        previous_digest=GENESIS_DIGEST,
    )
    reversed_order = record_digest(
        sequence=0,
        event=event,
        correlation={"approval_id": "apr-001", "action_id": "act-001"},
        previous_digest=GENESIS_DIGEST,
    )
    assert forward == reversed_order


@pytest.mark.parametrize(
    "change",
    ["sequence", "event", "correlation", "previous_digest"],
)
def test_every_covered_field_changes_the_digest(change: str) -> None:
    """No field is a free variable an attacker could edit without breaking the chain."""
    base = dict(
        sequence=0,
        event=make_event(),
        correlation={"action_id": "act-001"},
        previous_digest=GENESIS_DIGEST,
    )
    baseline = record_digest(**base)  # type: ignore[arg-type]
    altered = {
        "sequence": {"sequence": 1},
        "event": {"event": make_event(actor="system:impostor")},
        "correlation": {"correlation": {"action_id": "act-002"}},
        "previous_digest": {"previous_digest": "f" * 64},
    }[change]
    assert record_digest(**{**base, **altered}) != baseline  # type: ignore[arg-type]


def test_two_equal_histories_serialize_identically() -> None:
    first = _filled(AuditStore())
    second = _filled(AuditStore())
    assert [to_json(record) for record in first.records()] == [
        to_json(record) for record in second.records()
    ]
    assert first.head_digest == second.head_digest


def test_the_head_digest_commits_to_the_whole_history(store: AuditStore) -> None:
    _filled(store)
    head = store.head_digest
    store.append(make_event(event_id="evt-999999"))
    assert store.head_digest != head


# --- an untampered chain ------------------------------------------------------------


def test_an_intact_chain_verifies(store: AuditStore) -> None:
    report = _filled(store).verify_integrity()
    assert report.valid
    assert report.checked == 4
    assert report.first_invalid_index is None
    assert report.reason is None
    assert report.trusted_prefix == 4


def test_verification_is_repeatable(store: AuditStore) -> None:
    _filled(store)
    assert to_json(store.verify_integrity()) == to_json(store.verify_integrity())


# --- tampering ----------------------------------------------------------------------


def test_event_replacement_is_detected(store: AuditStore) -> None:
    """Swap a record's event for another perfectly valid one."""
    records = list(_filled(store).records())
    records[2] = records[2].model_copy(
        update={"event": make_event(event_id="evt-000002", actor="system:impostor")}
    )
    report = verify_chain(records)
    assert not report.valid
    assert report.first_invalid_index == 2
    assert report.trusted_prefix == 2


def test_event_mutation_is_detected(store: AuditStore) -> None:
    """Change one field of one event."""
    records = list(_filled(store).records())
    tampered_event = records[1].event.model_copy(update={"result": "looked fine to me"})
    records[1] = records[1].model_copy(update={"event": tampered_event})
    report = verify_chain(records)
    assert not report.valid
    assert report.first_invalid_index == 1


def test_correlation_mutation_is_detected(store: AuditStore) -> None:
    records = list(_filled(store).records())
    records[1] = records[1].model_copy(update={"correlation": {"action_id": "act-999"}})
    assert not verify_chain(records).valid


def test_reordering_is_detected(store: AuditStore) -> None:
    records = list(_filled(store).records())
    records[1], records[2] = records[2], records[1]
    report = verify_chain(records)
    assert not report.valid
    assert report.first_invalid_index == 1


def test_deletion_is_detected(store: AuditStore) -> None:
    records = list(_filled(store).records())
    del records[2]
    report = verify_chain(records)
    assert not report.valid
    assert report.first_invalid_index == 2


def test_head_deletion_is_detected(store: AuditStore) -> None:
    """Truncating the oldest record still breaks the sequence numbering."""
    records = list(_filled(store).records())
    del records[0]
    report = verify_chain(records)
    assert not report.valid
    assert report.first_invalid_index == 0
    assert "sequence" in report.reason


def test_a_records_position_is_checked_independently_of_its_links(
    store: AuditStore,
) -> None:
    """Sequence is checked in its own right, not only via the digest it feeds.

    Deleting the oldest record leaves every remaining link internally consistent with the
    record before it; what gives it away first is that record 1 is now sitting at index 0.
    """
    records = list(_filled(store).records())
    del records[0]
    assert records[0].sequence == 1
    report = verify_chain(records)
    assert not report.valid
    assert "claims sequence 1" in report.reason


def test_insertion_is_detected(store: AuditStore) -> None:
    """A fabricated record spliced into the middle of history."""
    records = list(_filled(store).records())
    forged = AuditRecord(
        sequence=2,
        event=make_event(event_id="evt-forged", actor="system:impostor"),
        correlation={},
        previous_digest=records[1].digest,
        digest=record_digest(
            sequence=2,
            event=make_event(event_id="evt-forged", actor="system:impostor"),
            correlation={},
            previous_digest=records[1].digest,
        ),
    )
    records.insert(2, forged)
    report = verify_chain(records)
    assert not report.valid
    assert report.first_invalid_index == 3


def test_appending_a_forged_record_at_the_end_is_detected(store: AuditStore) -> None:
    """Even a correctly-linked forgery fails, because its own digest must recompute."""
    records = list(_filled(store).records())
    records.append(
        AuditRecord(
            sequence=4,
            event=make_event(event_id="evt-forged"),
            correlation={},
            previous_digest=records[-1].digest,
            digest="f" * 64,
        )
    )
    report = verify_chain(records)
    assert not report.valid
    assert report.first_invalid_index == 4


def test_digest_modification_is_detected(store: AuditStore) -> None:
    records = list(_filled(store).records())
    records[1] = records[1].model_copy(update={"digest": "f" * 64})
    report = verify_chain(records)
    assert not report.valid
    assert report.first_invalid_index == 1


def test_previous_digest_modification_is_detected(store: AuditStore) -> None:
    records = list(_filled(store).records())
    records[2] = records[2].model_copy(update={"previous_digest": "f" * 64})
    report = verify_chain(records)
    assert not report.valid
    assert report.first_invalid_index == 2


def test_sequence_modification_is_detected(store: AuditStore) -> None:
    records = list(_filled(store).records())
    records[2] = records[2].model_copy(update={"sequence": 7})
    assert not verify_chain(records).valid


def test_a_consistently_rewritten_chain_still_needs_the_whole_tail(
    store: AuditStore,
) -> None:
    """Editing one event forces recomputing every later digest, not just its own.

    The point of the chain: a partial rewrite cannot be made to verify.
    """
    records = list(_filled(store).records())
    tampered_event = records[1].event.model_copy(update={"actor": "system:impostor"})
    records[1] = records[1].model_copy(
        update={
            "event": tampered_event,
            "digest": record_digest(
                sequence=1,
                event=tampered_event,
                correlation=records[1].correlation,
                previous_digest=records[1].previous_digest,
            ),
        }
    )
    report = verify_chain(records)
    assert not report.valid
    assert report.first_invalid_index == 2  # the untouched successor no longer links


def test_verification_reports_and_never_repairs(store: AuditStore) -> None:
    _filled(store)
    records = list(store.records())
    records[1] = records[1].model_copy(update={"digest": "f" * 64})
    first = verify_chain(records)
    second = verify_chain(records)
    assert not first.valid
    assert to_json(first) == to_json(second)
    assert records[1].digest == "f" * 64


def test_the_stores_own_verification_catches_tampering(store: AuditStore) -> None:
    """An attacker reaching into the store's private list is still detected."""
    _filled(store)
    assert store.verify_integrity().valid
    store._records[1] = store._records[1].model_copy(  # simulated attacker with memory access
        update={"event": make_event(event_id="evt-000001", actor="system:impostor")}
    )
    report = store.verify_integrity()
    assert not report.valid
    assert report.first_invalid_index == 1
    assert report.reason
