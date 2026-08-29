"""Part 18: one incident's view never carries another incident's artifacts.

Two incidents in one process share a resource, a fleet, a capability catalogue and often an
audit store. What they must not share is a *view*. An operator reading incident A must not
see B's approval, B's findings, B's messages or B's denial -- not because the numbers would
be wrong, but because they would be attributed to the wrong incident, which is worse than
being absent.

Every view filters by incident id **before** reading anything, so the filtering is a
property of how the data is gathered rather than a step somebody could forget after
assembling it.
"""

from __future__ import annotations

import pytest

from aegis.control_center import ControlCenter, Tri, UnknownIncident, project_incident
from aegis.enterprise import PAYMENT_API, EnterpriseWorld
from tests.fleet import DIAGNOSTIC
from tests.orchestration.conftest import build_incident, build_orchestrator

from .conftest import capture


@pytest.fixture
def two_incidents():
    """Two genuine runs sharing one audit store, one fleet and one resource.

    Deliberately the *hardest* arrangement for isolation: same resource, same agents, same
    capability. If the views were going to bleed, this is where they would.
    """
    world = EnterpriseWorld()
    first = build_orchestrator(world=world)
    first_run = first.run(build_incident(), affected_resource=PAYMENT_API)

    second = build_orchestrator(world=EnterpriseWorld(), remediation_agent=DIAGNOSTIC)
    second_run = second.run(build_incident(), affected_resource=PAYMENT_API)

    # One store holding both histories, which is what a shared deployment looks like.
    merged = tuple(first.audit.records()) + tuple(
        record.model_copy(
            update={
                "event": record.event.model_copy(update={"incident_id": "INC-SECOND"}),
            }
        )
        for record in second.audit.records()
    )
    combined = capture(first, first_run).model_copy(update={"audit_records": merged})
    return project_incident(combined), first_run, second_run


class TestForeignRecordsAppearNowhere:
    def test_no_timeline_entry_belongs_to_another_incident(self, two_incidents) -> None:
        projection, _, _ = two_incidents
        for entry in projection.timeline.entries:
            assert entry.event_id is None or "SECOND" not in str(entry.evidence_refs)

    def test_no_a2a_message_belongs_to_another_incident(self, two_incidents) -> None:
        projection, _, _ = two_incidents
        for message in projection.a2a.messages:
            assert message.incident_id == projection.incident_id

    def test_no_security_event_belongs_to_another_incident(self, two_incidents) -> None:
        projection, _, _ = two_incidents
        for event in projection.security.events:
            assert event.incident_id == projection.incident_id

    def test_no_approval_belongs_to_another_incident(self, two_incidents) -> None:
        projection, first_run, _ = two_incidents
        for approval in projection.approvals:
            assert approval.incident_id == first_run.incident.incident_id

    def test_the_foreign_denial_does_not_appear(self, two_incidents) -> None:
        """The second run was denied. A leak would show this incident a denial it never
        had -- and a denial is exactly the kind of thing an operator acts on."""
        projection, _, second_run = two_incidents
        assert second_run.evaluation.decision.decision.value == "DENY"
        assert projection.governance.policy_decision.value == "REQUIRE_APPROVAL"

    def test_the_causal_chain_holds_only_this_incident(self, two_incidents) -> None:
        projection, first_run, _ = two_incidents
        incident_id = first_run.incident.incident_id
        for edge in projection.causal_chain.edges:
            if edge.joined_on == "incident_id":
                assert edge.value == incident_id

    def test_agent_activity_counts_only_this_incident(self, two_incidents) -> None:
        """Otherwise one incident's failures would explain another's restriction."""
        projection, _, _ = two_incidents
        diagnostic = projection.agent("diagnostic")
        assert diagnostic is not None
        assert diagnostic.activity.findings_returned <= 1

    def test_adding_a_foreign_history_changes_nothing(self, resolved, two_incidents) -> None:
        """The strongest form: the projection with the foreign records is the same as the
        one without them."""
        orchestrator, run = resolved
        alone = project_incident(capture(orchestrator, run))
        merged, _, _ = two_incidents
        assert merged.summary == alone.summary
        assert merged.a2a.messages == alone.a2a.messages
        assert merged.governance.policy_decision == alone.governance.policy_decision


class TestTheSameThingInTwoIncidents:
    def test_same_resource_different_incident(self, two_incidents) -> None:
        projection, first_run, second_run = two_incidents
        # Both runs targeted the same resource -- the hardest arrangement for isolation.
        assert first_run.action.target_resource == second_run.action.target_resource
        assert projection.summary.resource.value == "service:payment-api"
        assert projection.incident_id == first_run.incident.incident_id

    def test_same_agent_different_incident(self, two_incidents) -> None:
        """``diagnostic`` participated in both. Its activity here counts only this one."""
        projection, _, _ = two_incidents
        assert projection.agent("diagnostic") is not None

    def test_same_action_different_incident(self, two_incidents) -> None:
        """Both proposed a rollback on the same resource. The fingerprints are the same
        bytes, and the approvals still belong to one incident each."""
        projection, first_run, _ = two_incidents
        assert projection.governance.fingerprint.value == first_run.authorization.action_fingerprint


class TestTheControlCenterScopesByIncident:
    def test_an_unknown_incident_raises_rather_than_answering(self, projection) -> None:
        """Returning an empty projection would let a typo render as an incident where
        nothing happened -- a fabricated state, and the one thing this package must not
        produce."""
        center = ControlCenter([projection])
        with pytest.raises(UnknownIncident) as error:
            center.incident("INC-DOES-NOT-EXIST")
        assert projection.incident_id in error.value.available

    def test_it_holds_exactly_what_it_was_given(self, projection) -> None:
        center = ControlCenter([projection])
        assert center.incident_ids() == (projection.incident_id,)
        assert len(center) == 1

    def test_incidents_are_returned_in_a_stable_order(self, projection, two_incidents) -> None:
        other, _, _ = two_incidents
        center = ControlCenter([other, projection])
        ids = [incident.incident_id for incident in center.incidents()]
        assert ids == sorted(ids)


class TestIsolationSurvivesBrokenSources:
    def test_a_corrupted_chain_does_not_relax_the_filter(self, two_incidents, data) -> None:
        """A view that stopped filtering when it stopped trusting would leak precisely when
        an operator is least able to notice."""
        from .conftest import corrupt

        projection, _, _ = two_incidents
        damaged = project_incident(corrupt(data))
        for message in damaged.a2a.messages:
            assert message.incident_id == damaged.incident_id
        assert projection.incident_id == damaged.incident_id

    def test_an_unreadable_source_does_not_widen_anything(self, resolved) -> None:
        orchestrator, run = resolved
        blind = project_incident(capture(orchestrator, run, audit_available=False))
        assert blind.security.events == ()
        assert all(message.incident_id == blind.incident_id for message in blind.a2a.messages)

    def test_unknown_is_still_unknown_not_borrowed(self, two_incidents) -> None:
        """A leak would be one way to fill an UNKNOWN. The restriction state stays unknown
        rather than being answered from the other incident's registry."""
        projection, _, _ = two_incidents
        assert projection.summary.agents_restricted is Tri.UNKNOWN
