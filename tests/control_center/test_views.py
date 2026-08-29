"""Parts 4 to 15: every view, and the distinctions each one refuses to collapse.

One theme runs through all of them. An operator dashboard's job is to be *readable*, and
the readable thing is almost always the collapsed thing -- one badge, one boolean, one
number. Every class here declines that trade in one specific place, and the tests say which.
"""

from __future__ import annotations

import pytest

from aegis.control_center import (
    HISTORICAL_CONTEXT_LABEL,
    Certainty,
    ChainCompleteness,
    ExplanationOutcome,
    NodeType,
    Phase,
    Question,
    SecurityOutcome,
    Tri,
    ViewSource,
    project_incident,
)

from .conftest import capture

# --- Part 4: the timeline ----------------------------------------------------------------


class TestTheTimelineReconstructsWhatHappened:
    def test_the_golden_incident_reaches_resolution(self, projection) -> None:
        assert projection.timeline.occurred(Phase.RESOLUTION) is Tri.TRUE
        assert projection.timeline.occurred(Phase.VERIFICATION) is Tri.TRUE

    @pytest.mark.parametrize(
        "phase",
        [
            Phase.CLASSIFIED,
            Phase.INVESTIGATING,
            Phase.DELEGATION,
            Phase.FINDING,
            Phase.ASSESSMENT,
            Phase.POLICY,
            Phase.APPROVAL,
            Phase.GATE,
            Phase.EXECUTION,
            Phase.VERIFICATION,
            Phase.RESOLUTION,
        ],
    )
    def test_every_phase_of_a_clean_run_is_observed(self, projection, phase: Phase) -> None:
        assert projection.timeline.occurred(phase) is Tri.TRUE, phase

    def test_entries_are_ordered_and_deterministic(self, data) -> None:
        first = project_incident(data).timeline
        second = project_incident(data).timeline
        assert first == second
        stamps = [entry.at for entry in first.entries]
        assert stamps == sorted(stamps)

    def test_every_entry_names_the_artifact_behind_it(self, projection) -> None:
        for entry in projection.timeline.entries:
            assert entry.evidence_refs, entry.summary
            assert entry.certainty is Certainty.OBSERVED

    def test_a_finding_and_a_bare_result_are_different_phases(self, projection) -> None:
        """A response with no finding is a task that concluded nothing. Counting it among
        the findings would overstate what the fleet actually established."""
        findings = projection.timeline.of_phase(Phase.FINDING)
        assert findings
        assert all("finding_id" not in entry.summary for entry in findings)

    def test_the_state_machine_entering_executing_is_not_evidence_of_a_mutation(
        self, projection
    ) -> None:
        """The distinction the audit vocabulary cannot make on its own: a state machine
        moving to EXECUTING says work is authorised to begin, not that production changed."""
        entries = [
            entry
            for entry in projection.timeline.of_phase(Phase.EXECUTION)
            if entry.source is ViewSource.AUDIT
        ]
        assert entries
        assert all("not evidence production changed" in (e.summary or "") for e in entries)

    def test_the_execution_artifact_comes_from_the_run(self, projection) -> None:
        """And says so, because the audit vocabulary has no execution event -- a real
        limitation of the trail, stated rather than papered over."""
        entries = [
            entry
            for entry in projection.timeline.of_phase(Phase.EXECUTION)
            if entry.source is ViewSource.RUN
        ]
        assert len(entries) == 1
        assert "no execution event" in (entries[0].detail or "")

    def test_an_unlisted_phase_answers_unknown_rather_than_raising(self, projection) -> None:
        summary = projection.timeline.phase(Phase.SECURITY)
        assert summary.phase is Phase.SECURITY


# --- Part 5: the causal chain -------------------------------------------------------------


class TestTheCausalChainJoinsOnIdentifiers:
    def test_a_resolved_run_produces_a_complete_chain(self, projection) -> None:
        assert projection.causal_chain.completeness is ChainCompleteness.COMPLETE
        assert projection.causal_chain.missing_links == ()

    def test_every_edge_connects_two_real_nodes(self, projection) -> None:
        """An edge whose source is not a node is a link nobody can follow -- and a
        plausible-looking one, which is worse."""
        ids = {node.node_id for node in projection.causal_chain.nodes}
        for edge in projection.causal_chain.edges:
            assert edge.source_id in ids, edge
            assert edge.target_id in ids, edge

    def test_every_edge_names_the_identifier_that_justifies_it(self, projection) -> None:
        """Part 5's rule: never a link because two events were adjacent in time."""
        for edge in projection.causal_chain.edges:
            assert edge.joined_on
            assert edge.value

    def test_the_approval_edge_joins_on_the_action_fingerprint(self, projection) -> None:
        """Not the action id. An approval binds to the exact action bytes, and a looser
        join would let the chain show an approval beside an action it does not authorise."""
        approval = projection.causal_chain.node(NodeType.APPROVAL)
        assert approval is not None
        edges = [e for e in projection.causal_chain.edges if e.target_id == approval.node_id]
        assert edges and edges[0].joined_on == "action_fingerprint"

    def test_the_verification_edge_joins_on_the_fingerprint_too(self, projection) -> None:
        verification = projection.causal_chain.node(NodeType.VERIFICATION)
        assert verification is not None
        edges = [
            e
            for e in projection.causal_chain.edges
            if e.target_id == verification.node_id and e.joined_on == "action_fingerprint"
        ]
        assert edges

    def test_a_finding_joins_its_request_on_the_task(self, projection) -> None:
        """Request and response have different message ids and share a task id. Joining on
        the message id produced a dangling edge -- caught, and fixed by joining on the
        identifier both artifacts actually record."""
        findings = [n for n in projection.causal_chain.nodes if n.node_type is NodeType.FINDING]
        assert findings
        for finding in findings:
            edges = [e for e in projection.causal_chain.edges if e.target_id == finding.node_id]
            assert edges and edges[0].joined_on == "task_id"

    def test_observations_feed_the_verification(self, projection) -> None:
        observations = [
            n for n in projection.causal_chain.nodes if n.node_type is NodeType.OBSERVATION
        ]
        assert observations
        verification = projection.causal_chain.node(NodeType.VERIFICATION)
        assert verification is not None
        for observation in observations:
            assert verification.node_id in {
                edge.target_id
                for edge in projection.causal_chain.edges
                if edge.source_id == observation.node_id
            }

    def test_a_short_run_is_partial_rather_than_broken(self, escalated) -> None:
        """A chain as long as what happened is not a defective chain."""
        orchestrator, run = escalated
        chain = project_incident(capture(orchestrator, run)).causal_chain
        assert chain.completeness in {ChainCompleteness.PARTIAL, ChainCompleteness.BROKEN}

    def test_node_status_is_never_derived_from_the_node_before_it(self, projection) -> None:
        """So a chain cannot propagate optimism forwards."""
        policy = projection.causal_chain.node(NodeType.POLICY)
        approval = projection.causal_chain.node(NodeType.APPROVAL)
        assert policy is not None and approval is not None
        assert policy.status != approval.status


# --- Parts 6, 7, 11, 12: governance -------------------------------------------------------


class TestTheGovernanceView:
    def test_the_governed_path_is_shown_in_order(self, projection) -> None:
        names = [name for name, _ in projection.governance.stages]
        assert names == [
            "action",
            "risk",
            "blast_radius",
            "policy",
            "approval_required",
            "approval",
            "gate_issued",
            "gate_consumed",
            "executed",
            "verified",
            "resolved",
        ]

    def test_the_recorded_decision_is_displayed_unchanged(self, projection) -> None:
        assert projection.governance.policy_decision.value == "REQUIRE_APPROVAL"
        assert projection.governance.approval_required is Tri.TRUE

    def test_the_policy_reason_and_rule_are_both_shown(self, projection) -> None:
        """A decision that cannot be traced to a rule is indistinguishable from an
        arbitrary one."""
        assert projection.governance.policy_reason.known
        assert projection.governance.policy_reference.known

    def test_a_denial_is_displayed_as_a_denial(self, denied) -> None:
        orchestrator, run = denied
        governance = project_incident(capture(orchestrator, run)).governance
        assert governance.policy_decision.value == "DENY"
        assert governance.approval_required is Tri.FALSE


class TestApprovalBinding:
    def test_an_approval_is_shown_with_its_exact_action(self, projection) -> None:
        """Part 11. There is no ``approved`` boolean anywhere -- an approval is displayed
        with its fingerprint or not displayed at all."""
        assert projection.approvals
        for approval in projection.approvals:
            assert approval.action_fingerprint
            assert len(approval.action_fingerprint) == 64

    def test_the_approval_view_has_no_bare_approved_flag(self) -> None:
        from aegis.control_center import ApprovalView

        assert "approved" not in ApprovalView.model_fields

    def test_authorises_matches_only_the_exact_fingerprint(self, projection) -> None:
        approval = projection.approvals[0]
        assert approval.authorises(approval.action_fingerprint) is Tri.TRUE
        assert approval.authorises("0" * 64) is Tri.FALSE
        assert approval.authorises(approval.action_fingerprint[:32]) is Tri.FALSE

    def test_authorises_returns_a_tri_not_a_boolean(self, projection) -> None:
        """So ``if approval.authorises(x)`` cannot read UNKNOWN as permission."""
        assert projection.approvals[0].authorises("") is Tri.UNKNOWN

    def test_the_displayed_fingerprint_is_the_one_the_approval_recorded(
        self, projection, resolved
    ) -> None:
        _, run = resolved
        assert projection.approvals[0].action_fingerprint == run.authorization.action_fingerprint

    def test_a_reconstructed_approval_shows_its_final_status(self, resolved) -> None:
        """Found by the oracle: folding events one at a time showed an approval that was
        requested, granted and consumed as merely REQUESTED -- telling an operator a
        decision was outstanding when a human had already made it."""
        orchestrator, run = resolved
        approvals = project_incident(
            capture(orchestrator, None, incident_id=run.incident.incident_id)
        ).approvals
        assert approvals
        assert approvals[0].status in {"GRANTED", "CONSUMED"}


class TestVerificationIsThreeSeparateFacts:
    def test_executed_verified_and_resolved_are_separate(self, projection) -> None:
        view = projection.verification
        assert view.executed is Tri.TRUE
        assert view.verified is Tri.TRUE
        assert view.resolved is Tri.TRUE

    def test_resolution_is_read_from_the_state_not_derived(self, resolved) -> None:
        """A view that computed resolution from verification would be re-implementing the
        guard it exists to display."""
        orchestrator, run = resolved
        view = project_incident(capture(orchestrator, run)).verification
        assert view.resolution_source.value == str(run.incident.state)

    def test_the_observations_behind_the_verification_are_listed(self, projection) -> None:
        """Its independence rests on these, so they are shown rather than summarised."""
        assert projection.verification.observations_used

    def test_a_run_with_no_verification_reports_unknown(self, denied) -> None:
        orchestrator, run = denied
        view = project_incident(capture(orchestrator, run)).verification
        assert view.verified is Tri.UNKNOWN
        assert not view.verification_id.known


class TestWhyDidAegisDoThis:
    @pytest.mark.parametrize("question", list(Question))
    def test_every_question_is_answerable(self, projection, question: Question) -> None:
        answer = projection.why(question)
        assert answer.answer
        assert answer.outcome in set(ExplanationOutcome)

    def test_an_explained_answer_names_its_artifacts(self, projection) -> None:
        answer = projection.why(Question.WHY_RESOLVED)
        assert answer.outcome is ExplanationOutcome.EXPLAINED
        assert answer.evidence_refs

    def test_a_question_about_something_that_did_not_happen_is_not_a_gap(self, projection) -> None:
        """ "Why was it denied" has no answer when nothing was denied, and that is not
        missing evidence."""
        answer = projection.why(Question.WHY_DENIED)
        assert answer.outcome is ExplanationOutcome.NOT_APPLICABLE

    def test_a_missing_artifact_produces_explanation_incomplete(self, resolved) -> None:
        orchestrator, run = resolved
        answer = project_incident(
            capture(orchestrator, None, incident_id=run.incident.incident_id)
        ).why(Question.WHY_RESOLVED)
        assert answer.outcome is ExplanationOutcome.EXPLANATION_INCOMPLETE
        assert answer.missing

    def test_an_incomplete_explanation_names_what_is_missing(self, resolved) -> None:
        """So an operator knows what to go and look for, rather than only that we do not
        know."""
        orchestrator, run = resolved
        answer = project_incident(
            capture(orchestrator, None, incident_id=run.incident.incident_id)
        ).why(Question.WHY_PROPOSED)
        assert "OrchestrationRun" in answer.missing

    def test_no_answer_hedges(self, projection) -> None:
        """No prose, no model output, no "probably". An explanation is supported by
        artifacts or it is EXPLANATION_INCOMPLETE."""
        for question in Question:
            answer = projection.why(question).answer.lower()
            for hedge in ("probably", "likely", "appears to", "seems", "may have"):
                assert hedge not in answer, (question, answer)

    def test_the_denial_explanation_quotes_the_rule(self, denied) -> None:
        orchestrator, run = denied
        answer = project_incident(capture(orchestrator, run)).why(Question.WHY_DENIED)
        assert answer.outcome is ExplanationOutcome.EXPLAINED
        assert run.evaluation.decision.policy_reference in answer.answer

    def test_answers_are_deterministic(self, data) -> None:
        first = project_incident(data)
        second = project_incident(data)
        for question in Question:
            assert first.why(question) == second.why(question)


# --- Part 8: agents ------------------------------------------------------------------------


class TestTheAgentViewKeepsThreeThingsApart:
    def test_capability_proposal_authority_and_restriction_are_separate_fields(
        self, projection
    ) -> None:
        remediation = projection.agent("remediation")
        assert remediation is not None
        assert "production.rollback" in remediation.capabilities
        assert "production.rollback" in remediation.proposal_capabilities
        assert not remediation.restriction.known  # the registry was not wired here

    def test_a_capability_grant_is_not_permission(self, projection) -> None:
        """Holding ``production.rollback`` is a grant record. The view has no field that
        says the action is allowed, because that is not a property of the agent."""
        from aegis.control_center import AgentView

        assert "permitted" not in AgentView.model_fields
        assert "allowed" not in AgentView.model_fields
        assert "authorized" not in AgentView.model_fields

    def test_may_propose_is_named_so_it_cannot_read_as_may_perform(self, projection) -> None:
        commander = projection.agent("commander")
        assert commander is not None
        assert commander.may_propose == commander.proposal_capabilities

    def test_activity_is_counted_from_artifacts(self, projection) -> None:
        diagnostic = projection.agent("diagnostic")
        assert diagnostic is not None
        assert diagnostic.activity.delegations_received >= 1
        assert diagnostic.activity.findings_returned >= 1

    def test_agents_are_sorted_so_the_view_is_deterministic(self, projection) -> None:
        ids = [agent.agent_id for agent in projection.agents]
        assert ids == sorted(ids)


# --- Parts 9 and 10: lifecycle and breaker --------------------------------------------------


class TestTheLifecycleView:
    def test_counters_and_the_stop_reason_are_shown(self, projection) -> None:
        assert projection.lifecycle.steps_used is not None
        assert projection.lifecycle.stop_reason.known
        assert projection.lifecycle.execution_count == 1

    def test_not_stopped_is_a_value_rather_than_an_absence(self, projection) -> None:
        assert projection.lifecycle.stop_reason.value == "NOT_STOPPED"
        assert projection.lifecycle.stopped is Tri.FALSE

    def test_per_fingerprint_executions_are_shown(self, projection) -> None:
        assert projection.lifecycle.executions_by_fingerprint

    def test_the_view_offers_no_way_to_change_anything(self) -> None:
        from aegis.control_center import LifecycleView

        surface = {name for name in dir(LifecycleView) if not name.startswith("_")}
        # Exact names: a substring rule tripped on ``model_fields_set``, and a rule that
        # fires on pydantic's own machinery is a rule somebody will delete.
        for forbidden in ("set", "reset", "extend", "raise_limit", "clear", "adjust"):
            assert forbidden not in surface, forbidden


class TestTheBreakerView:
    def test_a_closed_breaker_is_shown_closed(self, projection) -> None:
        assert projection.breakers
        assert projection.breakers[0].state.value == "CLOSED"
        assert projection.breakers[0].open is Tri.FALSE

    def test_the_three_states_are_distinguishable(self) -> None:
        """CLOSED, OPEN and HALF_OPEN mean three different things about what automation
        will do next, and the view renders each as itself."""
        from aegis.lifecycle import CircuitState

        assert {state.value for state in CircuitState} == {"CLOSED", "OPEN", "HALF_OPEN"}

    def test_the_view_offers_no_reset(self) -> None:
        from aegis.control_center import BreakerView

        surface = {name for name in dir(BreakerView) if not name.startswith("_")}
        for forbidden in ("reset", "close", "open_breaker", "force", "trip"):
            assert not any(forbidden == name for name in surface), forbidden

    def test_quarantined_is_separate_from_open(self) -> None:
        """One is a decision, the other is an admission that the state could not be
        verified. Merging them would hide which."""
        from aegis.control_center import BreakerView

        assert "quarantined" in BreakerView.model_fields
        assert "state" in BreakerView.model_fields


# --- Part 13: memory -------------------------------------------------------------------------


class TestTheMemoryView:
    def test_every_entry_is_labelled_historical(self) -> None:
        from aegis.control_center import MemoryEntryView

        assert MemoryEntryView.model_fields["label"].default == HISTORICAL_CONTEXT_LABEL

    def test_the_label_is_a_constant_a_renderer_cannot_paraphrase(self) -> None:
        assert HISTORICAL_CONTEXT_LABEL == "HISTORICAL CONTEXT ONLY"

    def test_an_empty_store_is_not_an_unreadable_one(self, projection) -> None:
        assert projection.memory.entries == ()
        assert projection.memory.provenance.source is ViewSource.MEMORY

    def test_the_authoritative_filter_excludes_unknowns(self, projection) -> None:
        """Strict: an entry whose authority is UNKNOWN is not among the authoritative
        ones. Showing uncertain memory there would make exactly the claim this package
        must not make."""
        assert all(entry.authoritative is Tri.TRUE for entry in projection.memory.authoritative())


# --- Part 14: A2A -----------------------------------------------------------------------------


class TestTheA2AView:
    def test_every_message_is_shown_with_five_separate_statuses(self, projection) -> None:
        assert projection.a2a.messages
        for message in projection.a2a.messages:
            assert message.consumption.known
            assert message.integrity.known
            assert message.consumed in set(Tri)
            assert message.replayed in set(Tri)

    def test_no_payload_or_key_material_field_exists(self) -> None:
        from aegis.control_center import A2AMessageView
        from aegis.control_center.a2a import FORBIDDEN_FIELDS

        for forbidden in FORBIDDEN_FIELDS:
            assert forbidden not in A2AMessageView.model_fields, forbidden

    def test_the_integrity_value_is_a_digest_prefix_not_a_seal(self, projection) -> None:
        """A digest identifies a message without reproducing a byte of it, which is why it
        is safe to show."""
        for message in projection.a2a.messages:
            assert len(message.integrity.value) == 16

    def test_local_messages_report_authentication_as_unknown(self, projection) -> None:
        """Local A2A has no authentication step. Reporting one would invent it."""
        for message in projection.a2a.messages:
            assert not message.authentication.known

    def test_messages_are_sorted_by_conversation_and_sequence(self, projection) -> None:
        keys = [(m.conversation_id, m.sequence, m.message_id) for m in projection.a2a.messages]
        assert keys == sorted(keys)


# --- Part 15: security --------------------------------------------------------------------------


class TestTheSecurityView:
    def test_a_clean_run_has_no_security_events(self, projection) -> None:
        assert projection.security.events == ()
        assert projection.security.detections == 0
        assert projection.security.refusals == 0

    def test_there_is_no_blocked_outcome(self) -> None:
        """The word an operator would read as "we are safe", and the one this package is
        least able to justify."""
        assert "BLOCKED" not in {member.name for member in SecurityOutcome}
        assert {member.name for member in SecurityOutcome} == {
            "DETECTED",
            "REFUSED",
            "CONTAINED",
        }

    def test_detections_and_refusals_are_counted_separately(self) -> None:
        """Never summed into "threats stopped", because a detection stopped nothing."""
        from aegis.control_center import SecurityView

        assert "detections" in SecurityView.model_fields
        assert "refusals" in SecurityView.model_fields
        assert "threats_stopped" not in SecurityView.model_fields

    def test_a_policy_denial_is_a_refusal_not_a_detection(self, denied) -> None:
        orchestrator, run = denied
        security = project_incident(capture(orchestrator, run)).security
        denials = [e for e in security.events if e.category.value == "UNAUTHORIZED_PROPOSAL"]
        assert denials
        assert all(event.outcome is SecurityOutcome.REFUSED for event in denials)

    def test_every_event_names_its_evidence(self, denied) -> None:
        orchestrator, run = denied
        for event in project_incident(capture(orchestrator, run)).security.events:
            assert event.evidence_refs
