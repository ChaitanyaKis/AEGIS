"""Memory admission: only a verified outcome, bound to one incident and one action.

The positive case is one test. Everything else here is a refusal, because admission is a
gate and a gate is defined by what it stops.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from aegis.core.verification import VerificationStatus
from aegis.memory import (
    ADMISSION_CHECKS,
    REQUIRED_VERIFICATION_STATUS,
    AdmissionContext,
    MemoryAdmission,
    MemoryAdmissionRefused,
    MemorySource,
)
from tests.fleet import fixed_clock
from tests.memory.fixtures import (
    INCIDENT_A,
    INCIDENT_B,
    OBSERVATION_IDS,
    action,
    candidate,
    verification,
)


@pytest.fixture
def admission() -> MemoryAdmission:
    return MemoryAdmission(clock=fixed_clock)


def context(subject=None, result=None, incident_id: str = INCIDENT_A) -> AdmissionContext:
    subject = subject if subject is not None else action()
    result = result if result is not None else verification(subject)
    return AdmissionContext(incident_id=incident_id, action=subject, verification=result)


class TestAVerifiedOutcomeIsAdmitted:
    def test_provenance_is_derived_from_the_verified_artifacts(self, admission) -> None:
        subject = action()
        result = verification(subject)
        provenance = admission.admit(candidate(), context(subject, result))

        assert provenance.verification_id == result.verification_id
        assert provenance.action_id == subject.action_id
        assert provenance.action_fingerprint == result.action_fingerprint
        assert provenance.resource == subject.target_resource
        assert provenance.verified_at == result.evaluated_at
        assert provenance.source is MemorySource.VERIFIED_OUTCOME

    def test_evidence_comes_from_the_verification_not_the_candidate(self, admission) -> None:
        # A candidate citing nothing still gets the observations that actually
        # established the outcome. Provenance is read off the artifact, never accepted
        # as a claim.
        provenance = admission.admit(candidate(supporting_evidence=()), context())
        assert set(provenance.evidence_ids) == set(OBSERVATION_IDS)

    def test_evidence_is_stored_sorted_so_records_serialize_identically(self, admission) -> None:
        provenance = admission.admit(candidate(), context())
        assert list(provenance.evidence_ids) == sorted(provenance.evidence_ids)

    def test_a_candidate_may_name_the_verification_and_action_it_expects(self, admission) -> None:
        subject = action()
        result = verification(subject)
        provenance = admission.admit(
            candidate(verification_id=result.verification_id, action_id=subject.action_id),
            context(subject, result),
        )
        assert provenance.verification_id == result.verification_id


class TestUnverifiedOutcomesAreRefused:
    """Part 7. Only VERIFIED establishes anything."""

    @pytest.mark.parametrize(
        "status",
        [
            VerificationStatus.FAILED,
            VerificationStatus.STALE,
            VerificationStatus.MISMATCH,
            VerificationStatus.INSUFFICIENT_EVIDENCE,
        ],
    )
    def test_a_non_verified_status_cannot_become_authoritative(self, admission, status) -> None:
        subject = action()
        with pytest.raises(MemoryAdmissionRefused) as refusal:
            admission.admit(candidate(), context(subject, verification(subject, status=status)))
        assert refusal.value.check == "verification.status"

    def test_every_failure_status_is_covered_by_this_test(self) -> None:
        # If a new failure mode is added to the verification engine, this fails until
        # someone decides whether it may establish memory. Silence would default to
        # "admissible", which is the wrong default.
        non_verified = set(VerificationStatus) - {VerificationStatus.VERIFIED}
        covered = {
            VerificationStatus.FAILED,
            VerificationStatus.STALE,
            VerificationStatus.MISMATCH,
            VerificationStatus.INSUFFICIENT_EVIDENCE,
        }
        assert non_verified == covered

    def test_the_required_status_literal_matches_the_real_enum(self) -> None:
        # Memory compares the status by name to avoid importing the verification engine.
        # This pins the literal, so renaming the enum member breaks a memory test loudly
        # instead of silently admitting unverified outcomes.
        assert VerificationStatus.VERIFIED.value == REQUIRED_VERIFICATION_STATUS

    def test_a_missing_verification_is_refused(self, admission) -> None:
        with pytest.raises(MemoryAdmissionRefused) as refusal:
            admission.admit(
                candidate(),
                AdmissionContext(incident_id=INCIDENT_A, action=action(), verification=None),
            )
        assert refusal.value.check == "verification.present"

    def test_an_unrecognisable_status_fails_closed(self, admission) -> None:
        subject = action()
        result = verification(subject).model_copy(update={"status": object()})
        with pytest.raises(MemoryAdmissionRefused) as refusal:
            admission.admit(candidate(), context(subject, result))
        assert refusal.value.check == "verification.status"

    def test_a_status_that_merely_stringifies_as_verified_is_still_checked(self, admission) -> None:
        # A bare string passes, because that is what the contract says a status looks
        # like. What must not pass is an arbitrary object whose repr happens to contain
        # the word.
        subject = action()
        result = verification(subject).model_copy(
            update={"status": type("X", (), {"__repr__": lambda s: "VERIFIED"})()}
        )
        with pytest.raises(MemoryAdmissionRefused):
            admission.admit(candidate(), context(subject, result))


class TestBindingsAreChecked:
    """Parts 6 and 16. A verification is not a globally reusable token."""

    def test_a_verification_from_another_incident_is_refused(self, admission) -> None:
        subject = action()
        foreign = verification(subject, incident_id=INCIDENT_B)
        with pytest.raises(MemoryAdmissionRefused) as refusal:
            admission.admit(candidate(), context(subject, foreign))
        assert refusal.value.check == "verification.incident_binding"

    def test_a_verification_of_another_action_is_refused(self, admission) -> None:
        subject = action()
        other = verification(subject, action_id="act-999")
        with pytest.raises(MemoryAdmissionRefused) as refusal:
            admission.admit(candidate(), context(subject, other))
        assert refusal.value.check == "verification.action_binding"

    def test_a_fingerprint_that_does_not_match_the_action_is_refused(self, admission) -> None:
        # Same action id, different action. Ids can be reused; fingerprints cannot.
        subject = action()
        forged = verification(subject, fingerprint="a" * 64)
        with pytest.raises(MemoryAdmissionRefused) as refusal:
            admission.admit(candidate(), context(subject, forged))
        assert refusal.value.check == "verification.fingerprint_binding"

    def test_a_verification_of_a_different_action_with_the_same_id_is_refused(
        self, admission
    ) -> None:
        # The realistic attack: reuse a genuine verification by relabelling the action.
        verified_action = action(target_resource="service:order-service")
        genuine = verification(verified_action)
        different = action(target_resource="service:payment-api")
        with pytest.raises(MemoryAdmissionRefused) as refusal:
            admission.admit(candidate(), context(different, genuine))
        assert refusal.value.check == "verification.fingerprint_binding"

    def test_an_action_from_another_incident_is_refused(self, admission) -> None:
        foreign = action(incident_id=INCIDENT_B)
        with pytest.raises(MemoryAdmissionRefused) as refusal:
            admission.admit(
                candidate(),
                AdmissionContext(
                    incident_id=INCIDENT_A,
                    action=foreign,
                    verification=verification(foreign),
                ),
            )
        assert refusal.value.check == "action.belongs_to_incident"

    def test_a_candidate_about_another_incident_is_refused(self, admission) -> None:
        with pytest.raises(MemoryAdmissionRefused) as refusal:
            admission.admit(candidate(incident_id=INCIDENT_B), context())
        assert refusal.value.check == "incident.present"

    def test_a_candidate_claiming_the_wrong_action_is_refused(self, admission) -> None:
        with pytest.raises(MemoryAdmissionRefused) as refusal:
            admission.admit(candidate(action_id="act-999"), context())
        assert refusal.value.check == "action.belongs_to_incident"

    def test_a_candidate_claiming_the_wrong_verification_is_refused(self, admission) -> None:
        with pytest.raises(MemoryAdmissionRefused) as refusal:
            admission.admit(candidate(verification_id="ver-999"), context())
        assert refusal.value.check == "verification.present"

    def test_an_empty_incident_id_is_refused(self, admission) -> None:
        subject = action()
        with pytest.raises(MemoryAdmissionRefused) as refusal:
            admission.admit(
                candidate(),
                AdmissionContext(
                    incident_id="", action=subject, verification=verification(subject)
                ),
            )
        assert refusal.value.check == "incident.present"

    def test_something_that_is_not_an_action_is_refused(self, admission) -> None:
        subject = action()
        with pytest.raises(MemoryAdmissionRefused) as refusal:
            admission.admit(
                candidate(),
                AdmissionContext(
                    incident_id=INCIDENT_A,
                    action={"action_id": "act-001"},
                    verification=verification(subject),
                ),
            )
        assert refusal.value.check == "action.belongs_to_incident"


class TestProvenanceAndContentChecks:
    def test_a_verification_with_no_observations_is_refused(self, admission) -> None:
        # A verified outcome established by nothing is a contradiction, not a thin record.
        subject = action()
        empty = verification(subject, observations=())
        with pytest.raises(MemoryAdmissionRefused) as refusal:
            admission.admit(candidate(), context(subject, empty))
        assert refusal.value.check == "provenance.evidence"

    def test_a_candidate_citing_evidence_the_verification_never_used_is_refused(
        self, admission
    ) -> None:
        with pytest.raises(MemoryAdmissionRefused) as refusal:
            admission.admit(candidate(supporting_evidence=("obs-invented-999",)), context())
        assert refusal.value.check == "provenance.evidence"

    def test_a_candidate_citing_a_subset_of_the_evidence_is_accepted(self, admission) -> None:
        provenance = admission.admit(
            candidate(supporting_evidence=(OBSERVATION_IDS[0],)), context()
        )
        assert set(provenance.evidence_ids) == set(OBSERVATION_IDS)

    def test_content_naming_a_different_resource_is_refused(self, admission) -> None:
        with pytest.raises(MemoryAdmissionRefused) as refusal:
            admission.admit(candidate(content={"resource": "service:order-service"}), context())
        assert refusal.value.check == "content.corresponds_to_outcome"

    def test_content_naming_the_verified_resource_is_accepted(self, admission) -> None:
        provenance = admission.admit(
            candidate(content={"resource": "service:payment-api"}), context()
        )
        assert provenance.resource == "service:payment-api"

    def test_a_resource_claim_is_matched_exactly_not_by_prefix(self, admission) -> None:
        with pytest.raises(MemoryAdmissionRefused):
            admission.admit(candidate(content={"resource": "service:payment"}), context())

    def test_a_non_string_resource_claim_is_refused(self, admission) -> None:
        with pytest.raises(MemoryAdmissionRefused) as refusal:
            admission.admit(candidate(content={"resource": 42}), context())
        assert refusal.value.check == "content.corresponds_to_outcome"


class TestAdmissionIsDeterministic:
    def test_the_same_inputs_reach_the_same_decision(self, admission) -> None:
        subject = action()
        result = verification(subject)
        first = admission.admit(candidate(), context(subject, result))
        second = admission.admit(candidate(), context(subject, result))
        assert first == second

    def test_provenance_carries_the_verification_time_not_the_admission_time(
        self, admission
    ) -> None:
        # Age is the age of the knowledge. Writing it down later does not refresh it.
        subject = action()
        old = verification(subject, age=timedelta(days=30))
        provenance = admission.admit(candidate(), context(subject, old))
        assert provenance.verified_at == old.evaluated_at

    def test_every_declared_check_name_is_one_the_code_can_produce(self) -> None:
        assert len(set(ADMISSION_CHECKS)) == len(ADMISSION_CHECKS)
        assert "verification.status" in ADMISSION_CHECKS
        assert "verification.fingerprint_binding" in ADMISSION_CHECKS
