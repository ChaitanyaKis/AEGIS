"""Store mechanics: append-only behaviour, identity, ordering and incident queries."""

from __future__ import annotations

from datetime import timedelta

import pytest
from pydantic import ValidationError

from aegis.core.audit import (
    EVENT_VOCABULARY_VERSION,
    AuditEventType,
    AuditStore,
    DuplicateAuditEventError,
)
from aegis.core.domain import to_json
from tests.audit.conftest import make_event
from tests.fleet import FIXED_EVALUATION_TIME

# --- vocabulary ---------------------------------------------------------------------


def test_event_vocabulary_is_exact() -> None:
    """Renaming or removing a member changes what historical records mean."""
    assert [event_type.value for event_type in AuditEventType] == [
        "incident.state_changed",
        "action.assessed",
        "policy.decision",
        "approval.requested",
        "approval.granted",
        "approval.rejected",
        "approval.expired",
        "approval.consumed",
        "verification.completed",
        "memory.admitted",
        "memory.revoked",
        "lifecycle.stopped",
        "circuit.opened",
        "circuit.probe",
        "circuit.closed",
        "lifecycle.gate_issued",
        "lifecycle.gate_consumed",
        "lifecycle.gate_rejected",
        "agent.restriction_applied",
        "agent.restriction_refused",
        "a2a.message",
        "model.decision",
        "remote.authentication",
        "remote.key_revoked",
    ]


def test_event_vocabulary_is_versioned() -> None:
    # Unchanged by the memory milestone: this module's own rule is that *adding* a member
    # is compatible, because no historical record changes meaning. Only a rename or a
    # removal would force a version bump.
    assert EVENT_VOCABULARY_VERSION == "aegis.audit/v1"


def test_event_types_are_namespaced_and_unique() -> None:
    values = [event_type.value for event_type in AuditEventType]
    assert len(values) == len(set(values))
    assert all("." in value for value in values)


# --- append -------------------------------------------------------------------------


def test_append_returns_a_record_and_grows_the_log(store: AuditStore) -> None:
    record = store.append(make_event())
    assert record.sequence == 0
    assert len(store) == 1
    assert store.records() == (record,)


def test_append_preserves_insertion_order(store: AuditStore) -> None:
    for index in range(5):
        store.append(make_event(event_id=f"evt-{index:06d}"))
    assert [event.event_id for event in store.events()] == [
        f"evt-{index:06d}" for index in range(5)
    ]
    assert [record.sequence for record in store.records()] == [0, 1, 2, 3, 4]


def test_append_order_is_kept_even_when_timestamps_go_backwards(
    store: AuditStore,
) -> None:
    """Append order is when AEGIS recorded it; the timestamp is when it happened.

    An event recorded out of order relative to its own timestamp is evidence, not
    something to tidy away by sorting.
    """
    store.append(make_event(event_id="evt-000000", timestamp=FIXED_EVALUATION_TIME))
    store.append(
        make_event(
            event_id="evt-000001",
            timestamp=FIXED_EVALUATION_TIME - timedelta(hours=1),
        )
    )
    assert [event.event_id for event in store.events()] == ["evt-000000", "evt-000001"]


def test_equal_timestamps_keep_append_order(store: AuditStore) -> None:
    for index in range(3):
        store.append(make_event(event_id=f"evt-{index:06d}", timestamp=FIXED_EVALUATION_TIME))
    assert [event.event_id for event in store.events()] == [
        "evt-000000",
        "evt-000001",
        "evt-000002",
    ]


def test_an_empty_store_is_empty(store: AuditStore) -> None:
    assert len(store) == 0
    assert store.records() == ()
    assert store.events() == ()
    assert store.verify_integrity().valid


# --- identity -----------------------------------------------------------------------


def test_a_duplicate_event_id_is_rejected(store: AuditStore) -> None:
    store.append(make_event(event_id="evt-000000"))
    with pytest.raises(DuplicateAuditEventError) as excinfo:
        store.append(make_event(event_id="evt-000000", actor="system:impostor"))
    assert excinfo.value.event_id == "evt-000000"


def test_a_rejected_duplicate_does_not_alter_history(store: AuditStore) -> None:
    """A refused append leaves the log exactly as it was."""
    store.append(make_event(event_id="evt-000000", actor="system:original"))
    before = [to_json(record) for record in store.records()]
    head = store.head_digest

    with pytest.raises(DuplicateAuditEventError):
        store.append(make_event(event_id="evt-000000", actor="system:impostor"))

    assert [to_json(record) for record in store.records()] == before
    assert store.head_digest == head
    assert store.events()[0].actor == "system:original"
    assert len(store) == 1


def test_membership_is_by_event_id(store: AuditStore) -> None:
    store.append(make_event(event_id="evt-000000"))
    assert "evt-000000" in store
    assert "evt-000001" not in store


def test_record_for_event_matches_exactly(store: AuditStore) -> None:
    store.append(make_event(event_id="evt-000000"))
    assert store.record_for_event("evt-000000") is not None
    assert store.record_for_event("evt-0000") is None
    assert store.record_for_event("evt-000000x") is None


# --- immutability -------------------------------------------------------------------


def test_the_store_exposes_no_mutable_internal_state(store: AuditStore) -> None:
    store.append(make_event(event_id="evt-000000"))
    records = store.records()
    events = store.events()
    assert isinstance(records, tuple)
    assert isinstance(events, tuple)

    # Discarding what you were handed cannot reach stored history.
    mutable = list(records)
    mutable.clear()
    mutable.append(records[0])
    assert len(store) == 1
    assert store.records() == records


def test_stored_records_and_events_are_frozen(store: AuditStore) -> None:
    record = store.append(make_event(event_id="evt-000000"))
    with pytest.raises(ValidationError):
        record.digest = "0" * 64  # type: ignore[misc]
    with pytest.raises(ValidationError):
        record.event.actor = "system:impostor"  # type: ignore[misc]


def test_deriving_a_modified_copy_leaves_the_store_untouched(store: AuditStore) -> None:
    store.append(make_event(event_id="evt-000000", actor="system:original"))
    original = store.records()[0]
    original.model_copy(update={"digest": "f" * 64})
    original.event.model_copy(update={"actor": "system:impostor"})

    assert store.records()[0].event.actor == "system:original"
    assert store.verify_integrity().valid


def test_repeated_reads_return_equivalent_history(store: AuditStore) -> None:
    for index in range(3):
        store.append(make_event(event_id=f"evt-{index:06d}"))
    assert [to_json(record) for record in store.records()] == [
        to_json(record) for record in store.records()
    ]


def test_the_store_offers_no_update_or_delete() -> None:
    """Append-only is structural: there is no method to call."""
    surface = {name for name in dir(AuditStore) if not name.startswith("_")}
    assert not surface & {
        "update",
        "delete",
        "remove",
        "pop",
        "clear",
        "insert",
        "replace",
        "truncate",
    }


# --- incident queries ---------------------------------------------------------------


def test_incident_query_returns_only_that_incident(store: AuditStore) -> None:
    store.append(make_event(event_id="evt-000000", incident_id="INC-1"))
    store.append(make_event(event_id="evt-000001", incident_id="INC-2"))
    store.append(make_event(event_id="evt-000002", incident_id="INC-1"))

    assert [event.event_id for event in store.events_for_incident("INC-1")] == [
        "evt-000000",
        "evt-000002",
    ]


def test_incident_query_preserves_global_order(store: AuditStore) -> None:
    for index in range(6):
        store.append(
            make_event(
                event_id=f"evt-{index:06d}",
                incident_id="INC-1" if index % 2 == 0 else "INC-2",
            )
        )
    records = store.records_for_incident("INC-1")
    assert [record.sequence for record in records] == [0, 2, 4]


@pytest.mark.parametrize("query", ["INC-1", "INC-10", "INC-100"])
def test_incident_query_is_exact_and_never_leaks_a_neighbour(store: AuditStore, query: str) -> None:
    """``INC-10`` must not return ``INC-100``'s history."""
    for index, incident_id in enumerate(["INC-1", "INC-10", "INC-100", "INC-101"]):
        store.append(make_event(event_id=f"evt-{index:06d}", incident_id=incident_id))

    matched = store.events_for_incident(query)
    assert len(matched) == 1
    assert matched[0].incident_id == query


def test_an_unknown_incident_returns_nothing(store: AuditStore) -> None:
    store.append(make_event(event_id="evt-000000", incident_id="INC-1"))
    assert store.events_for_incident("INC-9999") == ()
    assert store.events_for_incident("") == ()


def test_events_without_an_incident_match_no_incident_query(store: AuditStore) -> None:
    store.append(make_event(event_id="evt-000000", incident_id=None))
    assert store.events_for_incident("INC-1") == ()
    assert len(store.events()) == 1


def test_repr_is_informative(store: AuditStore) -> None:
    store.append(make_event(event_id="evt-000000"))
    assert repr(store) == "AuditStore(1 records)"
