"""What did *not* happen — the half the suite was missing.

Written after a mutation campaign left thirteen survivors. Every one of them broke a
property that only shows up when the honest answer is ``FALSE`` or *absent*: escalation on a
run that resolved, a phase that never occurred, an approval with no binding, a memory that
was revoked, a search that should return nothing.

The suite had tested what happened. A read model that answered ``TRUE`` to everything would
have passed almost all of it, which is exactly the failure this file exists to make
impossible.

Each class below names the mutation it closes.
"""

from __future__ import annotations

import json

import pytest

from aegis.control_center import (
    FORBIDDEN_CONTENT,
    HISTORICAL_CONTEXT_LABEL,
    IncidentQuery,
    Phase,
    ProjectionStatus,
    SecurityCategory,
    SecurityOutcome,
    Tri,
    export_incident,
    export_json,
    project_incident,
    search,
)
from aegis.core.audit import AuditEventType
from aegis.core.domain import IncidentState
from aegis.enterprise import PAYMENT_API, PAYMENT_API_FAULTY_VERSION
from aegis.evaluation.control_center_stage import projection_discrepancies
from aegis.memory.models import MemoryProvenance, MemoryRecord
from aegis.memory.types import MemorySource, MemoryStatus, MemoryType

from .conftest import capture, truncate


def _without_requests(orchestrator):
    """The trail with every delegation *request* removed, leaving findings orphaned.

    What a partially-lost trail looks like: the answers survived and the questions did not.
    """
    return tuple(
        record
        for record in orchestrator.audit.records()
        if not (
            record.event.event_type == AuditEventType.A2A_MESSAGE.value
            and record.correlation.get("status") == "ISSUED"
        )
    )


def _drop_one_request(orchestrator):
    """The trail with exactly *one* delegation request removed.

    Sharper than removing all of them. With every request gone there is nothing left for a
    join to reach for, so a chain builder that guessed would guess ``None`` and look
    correct. Leave the other requests in place and a guess has somewhere wrong to land.

    Returns the records and the ``task_id`` whose request was dropped.
    """
    records = list(orchestrator.audit.records())
    for index, record in enumerate(records):
        if (
            record.event.event_type == AuditEventType.A2A_MESSAGE.value
            and record.correlation.get("status") == "ISSUED"
            and record.correlation.get("task_id")
        ):
            return tuple(records[:index] + records[index + 1 :]), record.correlation["task_id"]
    raise AssertionError("the run recorded no delegation request to drop")


def _tasks_by_message(orchestrator) -> dict[str, str]:
    """Which task each A2A message belonged to, straight off the trail.

    The chain's joins are checked against this rather than against the chain's own edges --
    an edge that says it joined on ``task_id`` has to be checkable against the task the
    messages actually carried.
    """
    return {
        record.correlation["message_id"]: record.correlation["task_id"]
        for record in orchestrator.audit.records()
        if record.event.event_type == AuditEventType.A2A_MESSAGE.value
        and record.correlation.get("message_id")
        and record.correlation.get("task_id")
    }


def _foreign(orchestrator):
    """This incident's records, re-stamped as another incident's. Nothing else changed.

    Deliberately identical in every other respect, so a filter that keys off anything but
    ``incident_id`` -- a timestamp, an event id, an actor -- lets them through.
    """
    return tuple(
        record.model_copy(
            update={"event": record.event.model_copy(update={"incident_id": "INC-ELSEWHERE"})}
        )
        for record in orchestrator.audit.records()
    )


class TestEscalationIsNotHidden:
    """Closes C4: ``escalated`` hard-wired to ``FALSE``.

    Every earlier test used a run that resolved, where ``FALSE`` is the right answer -- so a
    view that always said ``FALSE`` was indistinguishable from one that looked.
    """

    def test_an_escalated_incident_is_shown_escalated(self, escalated) -> None:
        orchestrator, run = escalated
        projection = project_incident(capture(orchestrator, run))
        assert run.incident.state is IncidentState.ESCALATED
        assert projection.summary.escalated is Tri.TRUE

    def test_a_resolved_incident_is_not(self, projection) -> None:
        """The other half, so the pair discriminates rather than either alone."""
        assert projection.summary.escalated is Tri.FALSE

    def test_the_timeline_records_the_escalation(self, escalated) -> None:
        orchestrator, run = escalated
        projection = project_incident(capture(orchestrator, run))
        assert projection.timeline.occurred(Phase.ESCALATION) is Tri.TRUE
        assert projection.timeline.occurred(Phase.RESOLUTION) is Tri.FALSE


class TestExecutionThatDidNotHappen:
    """Closes C8: ``executed`` hard-wired to ``TRUE``.

    The crashed-run test asserted ``UNKNOWN``, which a constant ``TRUE`` fails -- but that
    path returns early and never reaches the field the mutation touched. What was missing
    was a *completed* run in which nothing executed.
    """

    def test_a_denied_run_shows_no_execution(self, denied) -> None:
        orchestrator, run = denied
        projection = project_incident(capture(orchestrator, run))
        assert run.execution is None
        assert projection.summary.executed is Tri.FALSE
        assert projection.verification.executed is Tri.FALSE

    def test_and_the_world_agrees(self, denied) -> None:
        """Read from the enterprise world, which the projection cannot see -- so the two
        agreeing means something."""
        orchestrator, _ = denied
        assert orchestrator.world.state(PAYMENT_API).deployment == PAYMENT_API_FAULTY_VERSION

    def test_the_execution_phase_is_false_not_unknown(self, denied) -> None:
        """A completed run that executed nothing genuinely did not execute. ``UNKNOWN``
        here would be under-claiming, which is its own kind of unhelpful."""
        orchestrator, run = denied
        projection = project_incident(capture(orchestrator, run))
        assert projection.timeline.occurred(Phase.EXECUTION) is Tri.FALSE


class TestAPhaseThatNeverOccurredIsFalse:
    """Closes C15: an absent phase reported as having happened.

    Over a *complete, trusted* trail, absence is evidence. Every earlier test asserted the
    phases that did occur, so a view that answered ``TRUE`` for all of them passed.
    """

    def test_a_denied_run_never_reached_the_gate(self, denied) -> None:
        orchestrator, run = denied
        projection = project_incident(capture(orchestrator, run))
        assert projection.timeline.occurred(Phase.GATE) is Tri.FALSE
        assert projection.timeline.occurred(Phase.VERIFICATION) is Tri.FALSE

    def test_a_clean_run_had_no_recovery_and_no_escalation(self, projection) -> None:
        assert projection.timeline.occurred(Phase.RECOVERY) is Tri.FALSE
        assert projection.timeline.occurred(Phase.ESCALATION) is Tri.FALSE

    def test_a_clean_run_had_no_security_events(self, projection) -> None:
        assert projection.timeline.occurred(Phase.SECURITY) is Tri.FALSE

    def test_absence_stops_being_evidence_once_the_trail_is_doubted(self, data) -> None:
        """The pair that makes ``FALSE`` meaningful: the same absent phases become
        ``UNKNOWN`` the moment the source cannot be vouched for."""
        docked = project_incident(truncate(data))
        assert docked.timeline.occurred(Phase.SECURITY) is Tri.UNKNOWN


class TestTheTimelineFiltersByIncident:
    """Closes C6: the incident filter removed from the timeline.

    The isolation suite checked A2A, security and approvals. The timeline check compared
    strings that foreign records happen to share, so it never fired.
    """

    def test_foreign_records_add_no_entries(self, resolved) -> None:
        orchestrator, run = resolved
        alone = project_incident(capture(orchestrator, run))
        merged = capture(orchestrator, run).model_copy(
            update={"audit_records": (*orchestrator.audit.records(), *_foreign(orchestrator))}
        )
        assert len(project_incident(merged).timeline) == len(alone.timeline)

    def test_and_the_entries_are_identical(self, resolved) -> None:
        """Counting alone would pass if the filter dropped this incident's entries and kept
        the foreign ones."""
        orchestrator, run = resolved
        alone = project_incident(capture(orchestrator, run))
        merged = capture(orchestrator, run).model_copy(
            update={"audit_records": (*orchestrator.audit.records(), *_foreign(orchestrator))}
        )
        assert project_incident(merged).timeline.entries == alone.timeline.entries


class TestSearchFiltersByIncident:
    """Closes C21: the ``incident_id`` filter ignored."""

    def test_filtering_by_id_returns_only_that_incident(self, projection) -> None:
        other = projection.model_copy(update={"incident_id": "INC-ELSEWHERE"})
        found = search((projection, other), IncidentQuery(incident_id=projection.incident_id))
        assert [match.incident_id for match in found] == [projection.incident_id]

    def test_filtering_by_an_absent_id_returns_nothing(self, projection) -> None:
        assert search((projection,), IncidentQuery(incident_id="INC-NOT-HERE")) == ()


class TestResolutionIsReadNotDerived:
    """Closes C29: ``resolved`` computed from verification instead of from the state.

    On a clean run the two agree, so nothing distinguished them. The discriminating case is
    a run that verified and did **not** resolve -- which the state machine would not produce
    on its own, so it is constructed.
    """

    @pytest.fixture
    def verified_but_escalated(self, resolved):
        orchestrator, run = resolved
        return orchestrator, run.model_copy(
            update={"incident": run.incident.model_copy(update={"state": IncidentState.ESCALATED})}
        )

    def test_a_verified_run_that_did_not_resolve_shows_resolved_false(
        self, verified_but_escalated
    ) -> None:
        projection = project_incident(capture(*verified_but_escalated))
        assert projection.verification.verified is Tri.TRUE
        assert projection.verification.resolved is Tri.FALSE
        assert projection.summary.resolved is Tri.FALSE

    def test_the_resolution_source_names_the_state(self, verified_but_escalated) -> None:
        projection = project_incident(capture(*verified_but_escalated))
        assert projection.verification.resolution_source.value == "ESCALATED"


class TestAnApprovalWithoutItsBindingIsNotShown:
    """Closes C27: an approval displayed with a substituted fingerprint.

    Part 11 says an approval is shown with its exact action or not at all. Every earlier
    test used approvals that had one, so dropping the rule changed nothing.
    """

    @staticmethod
    def _unbound(orchestrator):
        return tuple(
            record.model_copy(
                update={
                    "correlation": {
                        key: value
                        for key, value in record.correlation.items()
                        if key != "action_fingerprint"
                    }
                }
            )
            if record.event.event_type.startswith("approval.")
            else record
            for record in orchestrator.audit.records()
        )

    def test_an_approval_event_with_no_fingerprint_is_dropped(self, resolved) -> None:
        orchestrator, run = resolved
        data = capture(orchestrator, None, incident_id=run.incident.incident_id).model_copy(
            update={"audit_records": self._unbound(orchestrator)}
        )
        assert project_incident(data).approvals == ()

    def test_the_same_events_with_a_fingerprint_are_shown(self, resolved) -> None:
        """The control. Without it the test above would pass over a view that showed no
        approvals at all."""
        orchestrator, run = resolved
        data = capture(orchestrator, None, incident_id=run.incident.incident_id)
        assert project_incident(data).approvals

    def test_a_displayed_approval_carries_a_real_fingerprint(self, projection, resolved) -> None:
        _, run = resolved
        assert projection.approvals[0].action_fingerprint == run.authorization.action_fingerprint
        assert projection.approvals[0].action_fingerprint != "0" * 64


class TestTheMemoryRules:
    """Closes C22 and C23: revoked and unverified memory shown as authoritative.

    No control-center projection held memory records, so both rules were unexercised at the
    view level. These build the records the store would produce.
    """

    @pytest.fixture
    def with_memory(self, resolved):
        orchestrator, run = resolved
        provenance = MemoryProvenance(
            incident_id=run.incident.incident_id,
            agent_id="commander",
            verification_id=run.verification.verification_id,
            action_id=run.action.action_id,
            action_fingerprint=run.verification.action_fingerprint,
            resource=run.verification.resource,
            evidence_ids=tuple(run.verification.observations_used),
            verified_at=run.verification.evaluated_at,
        )
        authoritative = MemoryRecord(
            memory_id="mem-verified",
            sequence=0,
            memory_type=MemoryType.REMEDIATION_OUTCOME,
            status=MemoryStatus.AUTHORITATIVE,
            incident_id=run.incident.incident_id,
            agent_id="commander",
            summary="rolling payment-api back resolved the incident",
            provenance=provenance,
            source=MemorySource.VERIFIED_OUTCOME,
            created_at=run.incident.created_at,
            previous_digest="0" * 64,
            digest="a" * 64,
        )
        unverified = MemoryRecord(
            memory_id="mem-unverified",
            sequence=1,
            memory_type=MemoryType.OPERATIONAL_PATTERN,
            status=MemoryStatus.CANDIDATE,
            incident_id=run.incident.incident_id,
            agent_id="commander",
            summary="a conclusion nothing established",
            source=MemorySource.AGENT_PROPOSAL,
            created_at=run.incident.created_at,
            previous_digest="a" * 64,
            digest="b" * 64,
        )
        revocation = MemoryRecord(
            memory_id="mem-revocation",
            sequence=2,
            memory_type=MemoryType.REMEDIATION_OUTCOME,
            status=MemoryStatus.REVOKED,
            incident_id=run.incident.incident_id,
            agent_id="commander",
            summary="withdrawing the verified conclusion",
            source=MemorySource.VERIFIED_OUTCOME,
            created_at=run.incident.updated_at,
            revokes="mem-verified",
            revocation_reason="the deployment was rolled forward again",
            previous_digest="b" * 64,
            digest="c" * 64,
        )
        data = capture(orchestrator, run, memory_records=(authoritative, unverified, revocation))
        return project_incident(data)

    def test_a_revoked_memory_is_not_authoritative(self, with_memory) -> None:
        entry = next(e for e in with_memory.memory.entries if e.memory_id == "mem-verified")
        assert entry.revoked is Tri.TRUE
        assert entry.authoritative is Tri.FALSE
        assert entry not in with_memory.memory.authoritative()

    def test_the_revocation_names_what_withdrew_it(self, with_memory) -> None:
        entry = next(e for e in with_memory.memory.entries if e.memory_id == "mem-verified")
        assert entry.revoked_by.value == "mem-revocation"
        assert entry.revocation_reason.known

    def test_an_unverified_memory_is_not_authoritative(self, with_memory) -> None:
        entry = next(e for e in with_memory.memory.entries if e.memory_id == "mem-unverified")
        assert not entry.verification_id.known
        assert entry.authoritative is Tri.FALSE

    def test_the_authoritative_filter_returns_nothing_here(self, with_memory) -> None:
        """One record was authoritative and has been withdrawn; the other never was."""
        assert with_memory.memory.authoritative() == ()
        assert with_memory.memory.authoritative_count == 0
        assert with_memory.memory.revoked_count == 1
        assert with_memory.memory.unverified_count == 1

    def test_every_entry_still_carries_the_historical_label(self, with_memory) -> None:
        assert with_memory.memory.entries
        for entry in with_memory.memory.entries:
            assert entry.label == HISTORICAL_CONTEXT_LABEL

    def test_the_revocation_is_folded_rather_than_listed(self, with_memory) -> None:
        """An operator asking what we know should see one withdrawn conclusion, not a
        conclusion plus a separate note saying to ignore it."""
        assert {entry.memory_id for entry in with_memory.memory.entries} == {
            "mem-verified",
            "mem-unverified",
        }

    def test_an_unverified_record_shown_as_authoritative_would_be_caught(
        self, with_memory, resolved
    ) -> None:
        """The oracle's rule, exercised through a real projection rather than a hand-built
        entry."""
        orchestrator, run = resolved
        lying = with_memory.model_copy(
            update={
                "memory": with_memory.memory.model_copy(
                    update={
                        "entries": tuple(
                            entry.model_copy(update={"authoritative": Tri.TRUE})
                            for entry in with_memory.memory.entries
                        )
                    }
                )
            }
        )
        assert projection_discrepancies(orchestrator, run, lying) != ()

    def test_and_the_honest_projection_is_not(self, with_memory, resolved) -> None:
        orchestrator, run = resolved
        assert projection_discrepancies(orchestrator, run, with_memory) == ()


class TestSecurityDetectionIsNotContainment:
    """Closes C32: a detection reported as a containment.

    The ``model.decision`` path was unexercised, so the one place the distinction is
    actually made had no test behind it.
    """

    @pytest.fixture
    def with_model_failure(self, resolved):
        orchestrator, run = resolved
        orchestrator.recorder.record_model_decision(
            incident_id=run.incident.incident_id,
            agent_id="commander",
            provider="deterministic-test-model",
            step=1,
            request_digest="d" * 64,
            failure_category="SCHEMA_VIOLATION",
            proposed_capability="production.rollback",
        )
        return project_incident(capture(orchestrator, run))

    def test_a_rejected_model_output_is_a_detection(self, with_model_failure) -> None:
        events = with_model_failure.security.of_category(SecurityCategory.MALICIOUS_INPUT)
        assert events
        assert all(event.outcome is SecurityOutcome.DETECTED for event in events)

    def test_it_is_counted_as_a_detection_not_a_containment(self, with_model_failure) -> None:
        assert with_model_failure.security.detections >= 1
        assert with_model_failure.security.containments == 0

    def test_detection_and_prevention_are_never_summed(self, with_model_failure) -> None:
        """What stopped the action was policy, whose refusal is recorded separately.
        Counting both would credit the same defence twice, to the wrong layer."""
        view = with_model_failure.security
        assert view.detections + view.refusals + view.containments == len(view.events)

    def test_the_timeline_files_it_as_reasoning_rather_than_as_a_phase(
        self, with_model_failure
    ) -> None:
        """The two views answer different questions about the same event, and neither is
        the other's summary. The timeline asks *when the incident did what*, and a model
        decision happened while investigating. The security view asks *what the defences
        caught*, and a rejected model output is a detection."""
        assert with_model_failure.timeline.occurred(Phase.INVESTIGATING) is Tri.TRUE
        assert with_model_failure.security.detections >= 1


class TestTheExportIsFaithful:
    """Closes C18 and C19: an export that altered a value, and a forbidden list that could
    quietly shrink."""

    def test_the_export_copies_the_audit_verdict_exactly(self, projection) -> None:
        """Not recomputed and not softened. An export that adjusted the verdict would be
        editing the one thing an investigator reads it for."""
        export = export_incident(projection)
        assert export.audit == projection.audit
        assert export.audit.trusted_prefix == projection.audit.trusted_prefix

    def test_every_section_is_copied_unchanged(self, projection) -> None:
        export = export_incident(projection)
        for section in (
            "summary",
            "timeline",
            "causal_chain",
            "governance",
            "lifecycle",
            "breakers",
            "agents",
            "memory",
            "a2a",
            "security",
            "sources",
        ):
            assert getattr(export, section) == getattr(projection, section), section

    def test_the_fingerprint_survives_the_export(self, projection, resolved) -> None:
        _, run = resolved
        document = json.loads(export_json(projection))
        assert (
            document["governance"]["fingerprint"]["value"] == run.authorization.action_fingerprint
        )

    def test_the_forbidden_list_is_pinned(self) -> None:
        """The list is both the guard and the parameter source for the sweep, so shrinking
        it would shrink the test. Pinning its contents is what stops that."""
        pinned = frozenset(
            {
                "private_key",
                "secret",
                "api_key",
                "credential",
                "password",
                "token",
                "signature",
                "hmac",
                "verification_key",
                "system_prompt",
                "prompt_text",
                "response_text",
            }
        )
        assert pinned == FORBIDDEN_CONTENT


class TestACausalEdgeNeedsASharedIdentifier:
    """Closes C30: an edge invented when no identifier joined two artifacts."""

    def test_a_finding_with_no_recorded_request_gets_no_edge(self, resolved) -> None:
        """The request events are removed, leaving findings whose task nothing recorded.
        The findings are still listed -- they happened -- and no edge is invented for them."""
        orchestrator, run = resolved
        data = capture(orchestrator, run).model_copy(
            update={"audit_records": _without_requests(orchestrator)}
        )
        chain = project_incident(data).causal_chain
        findings = [node for node in chain.nodes if node.node_type.value == "FINDING"]
        assert findings
        for finding in findings:
            assert not [edge for edge in chain.edges if edge.target_id == finding.node_id]

    def test_and_no_edge_dangles(self, resolved) -> None:
        orchestrator, run = resolved
        data = capture(orchestrator, run).model_copy(
            update={"audit_records": _without_requests(orchestrator)}
        )
        chain = project_incident(data).causal_chain
        node_ids = {node.node_id for node in chain.nodes}
        for edge in chain.edges:
            assert edge.source_id in node_ids and edge.target_id in node_ids, edge

    def test_the_intact_trail_does_join_them(self, projection) -> None:
        """The control: with the requests present, every finding is joined on ``task_id``."""
        chain = projection.causal_chain
        findings = [node for node in chain.nodes if node.node_type.value == "FINDING"]
        assert findings
        for finding in findings:
            joined = [edge for edge in chain.edges if edge.target_id == finding.node_id]
            assert joined
            assert all(edge.joined_on == "task_id" for edge in joined)

    def test_one_orphaned_finding_is_left_orphaned(self, resolved) -> None:
        """The discriminating case. One request is dropped and the others are left, so a
        builder that reached for *some* request rather than *the* request has somewhere
        wrong to land -- and the finding it would land on is named here."""
        orchestrator, run = resolved
        records, orphaned_task = _drop_one_request(orchestrator)
        data = capture(orchestrator, run).model_copy(update={"audit_records": records})
        chain = project_incident(data).causal_chain

        tasks = _tasks_by_message(orchestrator)
        orphans = [
            node
            for node in chain.nodes
            if node.node_type.value == "FINDING"
            and any(tasks.get(reference) == orphaned_task for reference in node.evidence_refs)
        ]
        assert orphans, f"no finding belonged to the dropped task {orphaned_task}"
        for orphan in orphans:
            assert not [edge for edge in chain.edges if edge.target_id == orphan.node_id]

    def test_every_task_join_names_the_task_both_ends_actually_carried(self, resolved) -> None:
        """An edge claiming ``joined_on="task_id"`` is checked against the task the messages
        really carried -- read from the trail, not from the chain. An edge whose source
        belonged to a different task is a fabricated link however plausible it looks."""
        orchestrator, run = resolved
        chain = project_incident(capture(orchestrator, run)).causal_chain
        tasks = _tasks_by_message(orchestrator)

        joins = [edge for edge in chain.edges if edge.joined_on == "task_id"]
        assert joins
        for edge in joins:
            assert tasks[edge.source_id] == edge.value, edge


class TestTheDeniedRunProjectsHonestly:
    """A whole-projection negative case, since most of the survivors lived in one."""

    def test_the_status_is_partial_because_the_chain_stops_at_the_denial(self, denied) -> None:
        orchestrator, run = denied
        projection = project_incident(capture(orchestrator, run))
        assert projection.status is ProjectionStatus.PARTIAL

    def test_nothing_downstream_of_the_denial_is_claimed(self, denied) -> None:
        orchestrator, run = denied
        projection = project_incident(capture(orchestrator, run))
        assert projection.governance.gate_consumed is not Tri.TRUE
        assert projection.summary.executed is Tri.FALSE
        assert projection.summary.resolved is Tri.FALSE
        assert projection.summary.verified is Tri.UNKNOWN

    def test_the_approval_status_is_unknown_rather_than_denied(self, denied) -> None:
        """No approval was ever requested, so there is no approval status -- which is not
        the same as an approval that was refused."""
        orchestrator, run = denied
        projection = project_incident(capture(orchestrator, run))
        assert not projection.summary.approval_status.known
        assert projection.approvals == ()

    def test_the_export_of_a_denial_is_still_deterministic(self, denied) -> None:
        orchestrator, run = denied
        projection = project_incident(capture(orchestrator, run))
        assert export_json(projection) == export_json(projection)
