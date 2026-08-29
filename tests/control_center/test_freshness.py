"""Parts 1, 16 and 17: missing evidence is UNKNOWN, and corruption is surfaced.

The most important file in this suite. Every test here is a variant of one question:

    when the control center does not know, does it say so?

The failure mode it guards against is specific and dangerous. AEGIS is built to fail
closed, so an unreadable source produces *silence* -- and silence rendered as ``FALSE``
looks exactly like a system with nothing wrong. A dashboard that turned *unavailable* into
*safe* would invert the property the whole project rests on.
"""

from __future__ import annotations

import pytest

from aegis.control_center import (
    AuditTrust,
    Certainty,
    Completeness,
    Fact,
    ProjectionStatus,
    Provenance,
    Tri,
    ViewSource,
    project_incident,
)

from .conftest import capture, corrupt, truncate


class TestTheVocabularyMakesUnknownRepresentable:
    def test_tri_has_three_values(self) -> None:
        assert {member.name for member in Tri} == {"TRUE", "FALSE", "UNKNOWN"}

    def test_none_becomes_unknown_not_false(self) -> None:
        """The conversion lives in one place precisely so it cannot be done wrong in
        several."""
        assert Tri.of(None) is Tri.UNKNOWN
        assert Tri.of(False) is Tri.FALSE
        assert Tri.of(True) is Tri.TRUE

    def test_unknown_is_not_true_and_not_false(self) -> None:
        assert not Tri.UNKNOWN.is_true
        assert not Tri.UNKNOWN.known
        assert Tri.UNKNOWN is not Tri.FALSE

    def test_a_stated_fact_must_have_a_value(self) -> None:
        """A fact with nothing behind it is what this package exists not to produce."""
        with pytest.raises(ValueError, match="must have a value"):
            Fact(certainty=Certainty.OBSERVED)

    def test_an_unavailable_fact_must_not_carry_one(self) -> None:
        with pytest.raises(ValueError, match="must not carry a value"):
            Fact(value="RESOLVED", certainty=Certainty.UNAVAILABLE)

    def test_an_unknown_fact_is_not_known(self) -> None:
        assert not Fact.unknown().known
        assert Fact.unknown().value is None

    def test_observed_and_derived_are_different_claims(self) -> None:
        assert Fact.observed("x").certainty is Certainty.OBSERVED
        assert Fact.derived("x").certainty is Certainty.DERIVED

    def test_there_is_no_source_meaning_computed(self) -> None:
        """Every member of ``ViewSource`` names something that exists. A fact with no
        artifact behind it is not a fact this package may state."""
        assert "COMPUTED" not in {member.name for member in ViewSource}
        assert "SYSTEM" not in {member.name for member in ViewSource}


class TestEveryViewDeclaresItsProvenance:
    def test_the_projection_keeps_sources_separate(self, projection) -> None:
        """Part 16: two views captured from different sources are two observations, and
        flattening them would assert a "current state" that was never true all at once."""
        assert len(projection.sources) >= 6
        assert {source.source for source in projection.sources} >= {
            ViewSource.AUDIT,
            ViewSource.RUN,
            ViewSource.MEMORY,
            ViewSource.A2A_LEDGER,
        }

    def test_every_view_carries_an_as_of(self, projection) -> None:
        for source in projection.sources:
            assert source.as_of == projection.captured_at

    def test_an_unavailable_source_is_never_marked_complete(self) -> None:
        provenance = Provenance.unavailable(
            __import__("datetime").datetime.now(__import__("datetime").UTC), "unreadable"
        )
        assert provenance.completeness is Completeness.UNKNOWN
        assert provenance.source is ViewSource.NONE
        assert not provenance.trustworthy


class TestAnUnreadableAuditStoreIsUnknownNotEmpty:
    @pytest.fixture
    def blind(self, resolved):
        orchestrator, run = resolved
        return project_incident(capture(orchestrator, run, audit_available=False))

    def test_the_trust_is_unavailable_not_untrusted(self, blind) -> None:
        """Two different failures. One is a missing source, the other is evidence of
        tampering, and an operator needs to tell them apart."""
        assert blind.audit.trust is AuditTrust.UNAVAILABLE

    def test_the_timeline_is_unknown_rather_than_empty(self, blind) -> None:
        assert blind.timeline.provenance.completeness is Completeness.UNKNOWN
        assert "could not be read" in (blind.timeline.provenance.detail or "")

    def test_no_phase_is_reported_as_false(self, blind) -> None:
        """The headline. Every phase is UNKNOWN, because a store nobody could read says
        nothing about what did or did not happen."""
        from aegis.control_center import Phase

        for phase in Phase:
            assert blind.timeline.occurred(phase) is not Tri.FALSE, phase

    def test_the_security_view_says_so_rather_than_showing_none(self, blind) -> None:
        assert blind.security.events == ()
        assert "not the same as none having occurred" in (blind.security.provenance.detail or "")


class TestACorruptedChainIsSurfacedNotRepaired:
    @pytest.fixture
    def tampered(self, data):
        return project_incident(corrupt(data))

    def test_the_trust_is_untrusted(self, tampered) -> None:
        assert tampered.audit.trust is AuditTrust.UNTRUSTED
        assert tampered.status is ProjectionStatus.AUDIT_UNTRUSTED

    def test_the_failing_index_and_reason_are_shown(self, tampered) -> None:
        """Part 17 requires all three. An operator has to be able to see how much of the
        history still stands."""
        assert tampered.audit.first_invalid_index is not None
        assert tampered.audit.reason
        assert tampered.audit.trusted_prefix == tampered.audit.first_invalid_index

    def test_nothing_is_repaired(self, data) -> None:
        """The damaged records are still damaged after projecting. A projection that
        quietly fixed a chain would destroy the evidence it exists to show."""
        damaged = corrupt(data)
        project_incident(damaged)
        assert not damaged.audit_integrity.valid

    def test_entries_are_still_shown_but_not_vouched_for(self, tampered) -> None:
        """Hiding them helps nobody. Withdrawing the claim about them is the honest move."""
        assert len(tampered.timeline) > 0
        assert tampered.timeline.provenance.completeness is Completeness.UNKNOWN

    def test_no_audit_sourced_phase_is_true_over_an_untrusted_chain(self, tampered) -> None:
        """Every phase the *trail* would answer is withdrawn.

        ``EXECUTION`` is the exception, and correctly so: it is answered by the run's own
        ``ExecutionResult``, which a corrupted audit chain does not touch. A rule that
        withdrew it too would be saying a damaged trail invalidates a separate artifact,
        which is not true and would cost an operator a fact they still have.
        """
        from aegis.control_center import Phase

        for phase in Phase:
            if phase is Phase.EXECUTION:
                continue
            assert tampered.timeline.occurred(phase) is not Tri.TRUE, phase

    def test_the_execution_phase_still_stands_on_the_run(self, tampered) -> None:
        """The other half, stated rather than left as an exception in a loop."""
        from aegis.control_center import Phase, ViewSource

        assert tampered.timeline.occurred(Phase.EXECUTION) is Tri.TRUE
        assert any(
            entry.source is ViewSource.RUN for entry in tampered.timeline.of_phase(Phase.EXECUTION)
        )


class TestATruncatedTrailIsDetected:
    """The subtle one: a truncated prefix verifies perfectly.

    A valid chain proves no *tampering*. It says nothing about *completeness*, and a docked
    trail looks exactly like a shorter history. The store's own head digest is the only
    thing that can tell them apart.
    """

    @pytest.fixture
    def docked(self, data):
        return project_incident(truncate(data))

    def test_the_chain_still_verifies(self, docked) -> None:
        assert docked.audit.trust is AuditTrust.TRUSTED

    def test_and_truncation_is_reported_anyway(self, docked) -> None:
        assert docked.audit.truncated is Tri.TRUE
        assert not docked.audit.complete

    def test_the_projection_is_downgraded(self, docked) -> None:
        assert docked.status is ProjectionStatus.PARTIAL
        assert docked.timeline.provenance.completeness is Completeness.UNKNOWN

    def test_absence_is_no_longer_evidence(self, docked) -> None:
        """The reason detection matters. Over a whole trail an absent phase is FALSE; over
        a docked one it must be UNKNOWN, because the evidence may simply be past the cut."""
        from aegis.control_center import Phase

        for phase in Phase:
            assert docked.timeline.occurred(phase) is not Tri.FALSE, phase

    def test_an_intact_trail_is_not_reported_as_truncated(self, projection) -> None:
        """The control. Without it, "truncated" could be hard-coded true and every test
        above would still pass."""
        assert projection.audit.truncated is Tri.FALSE
        assert projection.audit.complete

    def test_truncation_is_unknown_when_the_head_cannot_be_read(self, data) -> None:
        without_head = data.model_copy(update={"audit_head_digest": None})
        assert project_incident(without_head).audit.truncated is Tri.UNKNOWN


class TestACrashedRunIsUnknownNotFalse:
    @pytest.fixture
    def crashed(self, resolved):
        orchestrator, run = resolved
        return project_incident(capture(orchestrator, None, incident_id=run.incident.incident_id))

    def test_execution_is_unknown(self, crashed) -> None:
        """The single most dangerous thing to get wrong. "executed=FALSE" over a crashed
        run tells an operator production is untouched when nobody knows."""
        assert crashed.summary.executed is Tri.UNKNOWN
        assert crashed.verification.executed is Tri.UNKNOWN

    def test_verification_and_resolution_are_unknown(self, crashed) -> None:
        assert crashed.summary.verified is Tri.UNKNOWN
        assert crashed.summary.resolved is Tri.UNKNOWN

    def test_the_timeline_execution_phase_is_unknown(self, crashed) -> None:
        from aegis.control_center import Phase

        assert crashed.timeline.occurred(Phase.EXECUTION) is Tri.UNKNOWN

    def test_the_lifecycle_counters_are_none_not_zero(self, crashed) -> None:
        """A zero is a claim. A crashed run used steps nobody counted."""
        assert crashed.lifecycle.steps_used is None
        assert crashed.lifecycle.execution_count is None
        assert not crashed.lifecycle.stop_reason.known

    def test_the_causal_chain_is_broken_and_says_what_is_missing(self, crashed) -> None:
        from aegis.control_center import ChainCompleteness

        assert crashed.causal_chain.completeness is ChainCompleteness.BROKEN
        assert "OrchestrationRun" in crashed.causal_chain.missing_links


class TestAnUnreadableLifecycleIsUnknownNotClosed:
    @pytest.fixture
    def blind(self, resolved):
        orchestrator, run = resolved
        return project_incident(capture(orchestrator, run, lifecycle_available=False))

    def test_the_breaker_is_unknown_not_closed(self, blind) -> None:
        """The most dangerous default in the package. A breaker nobody can read is
        emphatically not a closed one."""
        assert blind.summary.breaker_open is Tri.UNKNOWN
        assert blind.breakers == ()

    def test_an_empty_breaker_list_is_not_read_as_no_breakers(self, blind, projection) -> None:
        """``build_breakers`` returns an empty tuple for both "none" and "unreadable". The
        availability flag, not the tuple's length, decides which -- and the summary honours
        the difference."""
        assert blind.breakers == ()
        assert blind.summary.breaker_open is Tri.UNKNOWN
        assert projection.summary.breaker_open is Tri.FALSE

    def test_the_lifecycle_view_is_unavailable(self, blind) -> None:
        assert blind.lifecycle.provenance.source is ViewSource.NONE
        assert blind.lifecycle.stopped is Tri.UNKNOWN


class TestAnUnreadableRestrictionRegistryIsUnknownNotActive:
    def test_restriction_is_unknown_when_the_registry_is_unreadable(self, resolved) -> None:
        """An unreadable containment mechanism is not one reporting that every agent is
        fine."""
        orchestrator, run = resolved
        projected = project_incident(capture(orchestrator, run))
        for agent in projected.agents:
            assert not agent.restriction.known
            assert agent.quarantined is Tri.UNKNOWN
        assert projected.summary.agents_restricted is Tri.UNKNOWN


class TestAnUnreadableMemoryStoreIsUnknownNotEmpty:
    def test_the_view_says_unreadable(self, resolved) -> None:
        orchestrator, run = resolved
        projected = project_incident(capture(orchestrator, run, memory_available=False))
        assert projected.memory.entries == ()
        assert projected.memory.provenance.source is ViewSource.NONE
        assert "could not be read" in (projected.memory.provenance.detail or "")


class TestProjectionStatusIsTheWorstOfItsSources:
    def test_everything_intact_is_complete(self, projection) -> None:
        assert projection.status is ProjectionStatus.COMPLETE

    def test_one_broken_source_makes_it_partial(self, resolved) -> None:
        orchestrator, run = resolved
        assert (
            project_incident(capture(orchestrator, run, memory_available=False)).status
            is ProjectionStatus.PARTIAL
        )

    def test_a_broken_chain_beats_a_broken_source(self, data) -> None:
        """An untrusted chain is the worst thing a projection can report, so it wins."""
        assert project_incident(corrupt(data)).status is ProjectionStatus.AUDIT_UNTRUSTED

    def test_nothing_readable_is_unknown(self, resolved) -> None:
        orchestrator, run = resolved
        blind = capture(
            orchestrator,
            None,
            incident_id=run.incident.incident_id,
            audit_available=False,
            memory_available=False,
        ).model_copy(update={"a2a_available": False})
        assert project_incident(blind).status is ProjectionStatus.UNKNOWN
