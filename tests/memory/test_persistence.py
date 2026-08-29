"""File-backed persistence: durability across processes, and its honest limits."""

from __future__ import annotations

import pytest

from aegis.memory import (
    AdmissionContext,
    JsonlMemoryPersistence,
    MemoryIntegrityError,
    MemoryStore,
)
from tests.fleet import fixed_clock
from tests.memory.fixtures import INCIDENT_A, action, candidate, verification


def admit(store: MemoryStore, *, incident_id: str = INCIDENT_A, **kw):
    subject = action(incident_id=incident_id)
    return store.admit(
        candidate(incident_id=incident_id, **kw),
        AdmissionContext(
            incident_id=incident_id, action=subject, verification=verification(subject)
        ),
    )


@pytest.fixture
def log(tmp_path):
    return JsonlMemoryPersistence(tmp_path / "memory.jsonl")


class TestRecordsSurviveANewStore:
    def test_a_missing_file_reads_as_an_empty_log(self, log) -> None:
        assert MemoryStore(log, clock=fixed_clock).records() == ()

    def test_records_are_read_back_by_a_fresh_store(self, log) -> None:
        written = admit(MemoryStore(log, clock=fixed_clock))
        reopened = MemoryStore(log, clock=fixed_clock)
        assert [r.memory_id for r in reopened.records()] == [written.memory_id]

    def test_a_reopened_record_is_byte_identical(self, log) -> None:
        from aegis.core.domain import to_json

        written = admit(MemoryStore(log, clock=fixed_clock))
        reopened = MemoryStore(log, clock=fixed_clock).records()[0]
        assert to_json(reopened) == to_json(written)

    def test_the_chain_continues_after_reopening(self, log) -> None:
        admit(MemoryStore(log, clock=fixed_clock))
        second = MemoryStore(log, clock=fixed_clock)
        second.append(candidate(summary="written after reopening"))
        assert second.verify_integrity().valid
        assert len(MemoryStore(log, clock=fixed_clock)) == 2

    def test_authoritative_memory_is_still_authoritative_after_reopening(self, log) -> None:
        admit(MemoryStore(log, clock=fixed_clock))
        assert MemoryStore(log, clock=fixed_clock).query()

    def test_revocation_survives_reopening(self, log) -> None:
        first = MemoryStore(log, clock=fixed_clock)
        written = admit(first)
        first.revoke(written.memory_id, reason="corrected", actor="human:oncall")
        assert MemoryStore(log, clock=fixed_clock).query() == ()

    def test_one_line_per_record(self, log) -> None:
        store = MemoryStore(log, clock=fixed_clock)
        admit(store)
        store.append(candidate())
        assert len(log.path.read_text(encoding="utf-8").strip().splitlines()) == 2


class TestOutOfProcessTamperingIsDetected:
    def test_an_edited_line_is_detected_on_load(self, log) -> None:
        admit(MemoryStore(log, clock=fixed_clock))
        text = log.path.read_text(encoding="utf-8")
        log.path.write_text(text.replace("payment-api", "order-service"), encoding="utf-8")
        with pytest.raises(MemoryIntegrityError):
            MemoryStore(log, clock=fixed_clock)

    def test_a_deleted_line_is_detected_on_load(self, log) -> None:
        store = MemoryStore(log, clock=fixed_clock)
        admit(store)
        store.append(candidate())
        store.append(candidate(summary="third"))
        lines = log.path.read_text(encoding="utf-8").splitlines()
        log.path.write_text("\n".join(lines[:1] + lines[2:]) + "\n", encoding="utf-8")
        with pytest.raises(MemoryIntegrityError):
            MemoryStore(log, clock=fixed_clock)

    def test_a_reordered_file_is_detected_on_load(self, log) -> None:
        store = MemoryStore(log, clock=fixed_clock)
        admit(store)
        store.append(candidate())
        lines = log.path.read_text(encoding="utf-8").splitlines()
        log.path.write_text("\n".join(reversed(lines)) + "\n", encoding="utf-8")
        with pytest.raises(MemoryIntegrityError):
            MemoryStore(log, clock=fixed_clock)

    def test_a_corrupt_line_is_reported_not_silently_skipped(self, log) -> None:
        admit(MemoryStore(log, clock=fixed_clock))
        with log.path.open("a", encoding="utf-8") as handle:
            handle.write('{"memory_id": "mem-000001"\n')  # truncated mid-append
        with pytest.raises(MemoryIntegrityError, match="damaged"):
            MemoryStore(log, clock=fixed_clock)

    def test_an_appended_forged_record_is_detected(self, log) -> None:
        # A record forged with a plausible body but no valid link into the chain.
        store = MemoryStore(log, clock=fixed_clock)
        written = admit(store)
        forged = written.model_copy(
            update={"memory_id": "mem-000001", "sequence": 1, "summary": "always safe"}
        )
        from aegis.core.domain import to_json

        with log.path.open("a", encoding="utf-8") as handle:
            handle.write(to_json(forged) + "\n")
        with pytest.raises(MemoryIntegrityError):
            MemoryStore(log, clock=fixed_clock)


class TestDurabilityIsNotOverclaimed:
    def test_persistence_holds_no_update_or_delete_method(self, log) -> None:
        # The interface offers no way to rewrite history, so no backend can offer the
        # store one.
        from aegis.memory import MemoryPersistence

        assert set(MemoryPersistence.__protocol_attrs__) == {"load", "append"}
        for method in ("update", "delete", "truncate", "write"):
            assert not hasattr(log, method)

    def test_the_file_is_appended_never_rewritten(self, log) -> None:
        store = MemoryStore(log, clock=fixed_clock)
        admit(store)
        first = log.path.read_text(encoding="utf-8")
        store.append(candidate())
        assert log.path.read_text(encoding="utf-8").startswith(first)

    def test_nothing_prevents_an_operator_with_write_access_from_editing_the_file(
        self, log
    ) -> None:
        # Recorded as a test because it is a real limitation, not a hypothetical one.
        # The chain makes the edit *detectable*; it does not make it impossible.
        admit(MemoryStore(log, clock=fixed_clock))
        log.path.write_text("", encoding="utf-8")
        assert MemoryStore(log, clock=fixed_clock).records() == ()
