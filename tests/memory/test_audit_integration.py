"""Memory operations in the audit trail (Part 19).

Two new event types were added rather than reusing an existing one. The justification is
in :class:`~aegis.core.audit.AuditEventType`: ``verification.completed`` says a
verification ran, and ``memory.admitted`` says organizational belief changed as a result.
Collapsing them would make it impossible to audit what AEGIS came to believe as distinct
from what it observed.

No domain contract changed. ``AuditEvent.event_type`` is an open string by design and
``AuditEventType`` lives in the audit package, so adding members is a compatible change
under that module's own stated rule.
"""

from __future__ import annotations

import ast
import pathlib

from aegis.core.audit import AuditEventType, AuditRecorder, AuditStore
from aegis.core.audit.events import EVENT_VOCABULARY_VERSION
from tests.fleet import FIXED_EVALUATION_TIME, fixed_clock


def build_recorder() -> AuditRecorder:
    return AuditRecorder(AuditStore(), clock=fixed_clock)


class TestMemoryAdmissionIsAudited:
    def test_an_admission_is_recorded(self) -> None:
        recorder = build_recorder()
        record = recorder.record_memory_admitted(
            memory_id="mem-000000",
            memory_type="REMEDIATION_OUTCOME",
            incident_id="INC-2026-0001",
            agent_id="remediation",
            verification_id="ver-001",
            action_id="act-001",
            evidence=("obs-telemetry-001",),
        )
        assert record.event.event_type == AuditEventType.MEMORY_ADMITTED.value
        assert record.event.actor == "system:memory-admission"
        assert record.event.incident_id == "INC-2026-0001"

    def test_correlation_joins_memory_to_the_artifact_that_established_it(self) -> None:
        # The whole point of the correlation block: a reader can trace organizational
        # belief back to the verification and action behind it.
        recorder = build_recorder()
        record = recorder.record_memory_admitted(
            memory_id="mem-000000",
            memory_type="VERIFIED_ROOT_CAUSE",
            incident_id="INC-2026-0001",
            agent_id="remediation",
            verification_id="ver-001",
            action_id="act-001",
        )
        assert record.correlation == {
            "action_id": "act-001",
            "memory_id": "mem-000000",
            "memory_type": "VERIFIED_ROOT_CAUSE",
            "verification_id": "ver-001",
        }

    def test_the_supporting_observations_are_recorded_as_evidence(self) -> None:
        recorder = build_recorder()
        record = recorder.record_memory_admitted(
            memory_id="mem-000000",
            memory_type="REMEDIATION_OUTCOME",
            incident_id="INC-2026-0001",
            agent_id="remediation",
            verification_id="ver-001",
            action_id="act-001",
            evidence=("obs-a", "obs-b"),
        )
        assert record.event.evidence == ("obs-a", "obs-b")

    def test_an_admission_event_is_covered_by_the_audit_chain(self) -> None:
        recorder = build_recorder()
        recorder.record_memory_admitted(
            memory_id="mem-000000",
            memory_type="REMEDIATION_OUTCOME",
            incident_id="INC-2026-0001",
            agent_id="remediation",
            verification_id="ver-001",
            action_id="act-001",
        )
        assert recorder.store.verify_integrity().valid


class TestMemoryRevocationIsAudited:
    def test_a_revocation_is_recorded_with_its_actor_and_reason(self) -> None:
        recorder = build_recorder()
        record = recorder.record_memory_revoked(
            memory_id="mem-000001",
            revoked_memory_id="mem-000000",
            incident_id="INC-2026-0001",
            actor="human:oncall",
            reason="the underlying verification was invalid",
        )
        assert record.event.event_type == AuditEventType.MEMORY_REVOKED.value
        assert record.event.actor == "human:oncall"
        assert "the underlying verification was invalid" in record.event.result

    def test_both_the_entry_and_what_it_withdrew_are_recorded(self) -> None:
        recorder = build_recorder()
        record = recorder.record_memory_revoked(
            memory_id="mem-000001",
            revoked_memory_id="mem-000000",
            incident_id="INC-2026-0001",
            actor="human:oncall",
            reason="corrected",
        )
        assert record.correlation == {
            "memory_id": "mem-000001",
            "revoked_memory_id": "mem-000000",
        }
        assert record.event.input_reference == "mem-000000"

    def test_a_revocation_never_removes_the_admission_event(self) -> None:
        recorder = build_recorder()
        recorder.record_memory_admitted(
            memory_id="mem-000000",
            memory_type="REMEDIATION_OUTCOME",
            incident_id="INC-2026-0001",
            agent_id="remediation",
            verification_id="ver-001",
            action_id="act-001",
        )
        recorder.record_memory_revoked(
            memory_id="mem-000001",
            revoked_memory_id="mem-000000",
            incident_id="INC-2026-0001",
            actor="human:oncall",
            reason="corrected",
        )
        types = [r.event.event_type for r in recorder.store.records()]
        assert types == [
            AuditEventType.MEMORY_ADMITTED.value,
            AuditEventType.MEMORY_REVOKED.value,
        ]
        assert recorder.store.verify_integrity().valid


class TestTheVocabularyChangeWasMinimal:
    def test_exactly_two_memory_event_types_exist(self) -> None:
        memory_events = [e.value for e in AuditEventType if e.value.startswith("memory.")]
        assert sorted(memory_events) == ["memory.admitted", "memory.revoked"]

    def test_the_vocabulary_version_did_not_change(self) -> None:
        # Adding a member is compatible under the audit module's own rule: no historical
        # record changes meaning. Only a rename or removal would force a bump.
        assert EVENT_VOCABULARY_VERSION == "aegis.audit/v1"

    def test_the_domain_contract_was_not_touched(self) -> None:
        # AuditEvent.event_type is an open string. Memory needed no field, no widening
        # and no new domain model.
        from aegis.core.domain import AuditEvent

        assert set(AuditEvent.model_fields) == {
            "event_id",
            "timestamp",
            "actor",
            "agent_identity",
            "incident_id",
            "event_type",
            "input_reference",
            "decision",
            "policy_reference",
            "tool",
            "result",
            "state_before",
            "state_after",
            "evidence",
        }

    def test_the_audit_package_does_not_import_memory(self) -> None:
        # The recorder takes plain scalars precisely so this stays true: an audit
        # recorder that depended on memory would be a route from memory back into the
        # control plane.
        offenders: list[str] = []
        for path in sorted(pathlib.Path("src/aegis/core/audit").rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                module = None
                if isinstance(node, ast.Import):
                    module = ",".join(a.name for a in node.names)
                elif isinstance(node, ast.ImportFrom):
                    module = node.module
                if module and "aegis.memory" in module:
                    offenders.append(str(path))
        assert not offenders

    def test_memory_events_are_namespaced_like_every_other(self) -> None:
        for event in AuditEventType:
            assert "." in event.value
            assert event.value == event.value.lower()

    def test_timestamps_come_from_the_injected_clock(self) -> None:
        recorder = build_recorder()
        record = recorder.record_memory_revoked(
            memory_id="mem-000001",
            revoked_memory_id="mem-000000",
            incident_id="INC-2026-0001",
            actor="human:oncall",
            reason="corrected",
        )
        assert record.event.timestamp == FIXED_EVALUATION_TIME
