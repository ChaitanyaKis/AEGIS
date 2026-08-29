"""The memory stage of a benchmark scenario: seed before, admit after.

Kept in its own module so the runner's incident logic stays about incidents. Two jobs:

**Seeding.** Turn a scenario's declared :class:`~aegis.evaluation.scenario.MemorySeed`
entries into real stored memory, by putting each one through the *real* admission path
against genuine artifacts. A seed cannot become authoritative by being written into a
fixture — even the benchmark's own setup has to satisfy the gate it is measuring, which is
why a seed declaring a non-VERIFIED status simply fails to become authoritative rather than
being special-cased.

**Post-run admission.** Take the scenario's declared
:class:`~aegis.evaluation.scenario.MemoryWriteAttempt` and try to admit it against whatever
the run *actually* produced — its real action and its real verification. This is what makes
the memory metrics measurements rather than assertions about fixtures: nothing here decides
whether a memory should be admissible, it only reports what admission said.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta

from aegis.core.approval import action_fingerprint
from aegis.core.domain import Action, RiskLevel
from aegis.core.verification import VerificationResult
from aegis.core.verification.results import CheckOutcome, Comparator, PredicateCheck
from aegis.evaluation.scenario import MemorySeed, MemoryWriteAttempt, Scenario
from aegis.memory import (
    AdmissionContext,
    MemoryAdmissionRefused,
    MemoryCandidate,
    MemoryRetrieval,
    MemoryStore,
)

__all__ = ["MemoryOutcome", "attempt_write", "seed_memory"]


class MemoryOutcome:
    """What the memory stage observed. A plain value, assembled by the runner."""

    __slots__ = (
        "admitted",
        "authoritative_count",
        "head_digest",
        "integrity_valid",
        "poisoned_seeded",
        "refusal_check",
        "shown_to_model",
    )

    def __init__(
        self,
        *,
        admitted: bool = False,
        refusal_check: str | None = None,
        authoritative_count: int = 0,
        integrity_valid: bool = True,
        shown_to_model: bool = False,
        poisoned_seeded: bool = False,
        head_digest: str | None = None,
    ) -> None:
        self.admitted = admitted
        self.refusal_check = refusal_check
        self.authoritative_count = authoritative_count
        self.integrity_valid = integrity_valid
        self.shown_to_model = shown_to_model
        self.poisoned_seeded = poisoned_seeded
        self.head_digest = head_digest


def _synthetic_action(seed: MemorySeed) -> Action:
    """A past action for a seeded memory. Deterministic, from the seed's own fields."""
    return Action(
        action_id=f"act-{seed.incident_id}-historical",
        incident_id=seed.incident_id,
        requesting_agent="remediation",
        capability="production.rollback",
        target_resource=seed.resource,
        risk=RiskLevel.HIGH,
    )


def _synthetic_verification(seed: MemorySeed, subject: Action, now: datetime) -> VerificationResult:
    """The verification that established a seeded memory, at the seed's declared age."""
    return VerificationResult(
        verification_id=f"ver-{seed.incident_id}-historical",
        incident_id=seed.incident_id,
        action_id=subject.action_id,
        action_fingerprint=action_fingerprint(subject),
        resource=seed.resource,
        status=seed.verification_status,
        checks=(
            PredicateCheck(
                attribute="deployment",
                comparator=Comparator.EQUALS,
                expected="v4.7",
                observed="v4.7",
                outcome=CheckOutcome.PASS,
                observation_ids=("obs-historical-001",),
                detail="deployment EQUALS v4.7",
            ),
        ),
        observations_used=("obs-historical-001",),
        evaluated_at=now - timedelta(days=seed.age_days),
        reason="the expected state was observed",
    )


def seed_memory(
    scenario: Scenario, *, clock: Callable[[], datetime]
) -> tuple[MemoryStore, dict, bool]:
    """Build a store holding the scenario's declared history.

    Returns the store, the JSON payload to show the model, and whether any seed was
    deliberately poisoned. Seeds that cannot be admitted are recorded as candidates, so a
    scenario declaring an unverified seed still exercises "this never became history".
    """
    store = MemoryStore(clock=clock)
    poisoned = False
    now = clock()

    for seed in scenario.seeded_memory:
        poisoned = poisoned or seed.poisoned
        subject = _synthetic_action(seed)
        result = _synthetic_verification(seed, subject, now)
        candidate = MemoryCandidate(
            memory_type=seed.memory_type,
            incident_id=seed.incident_id,
            agent_id="remediation",
            summary=seed.summary,
            content={"resource": seed.resource, "capability": "production.rollback"},
        )
        try:
            record = store.admit(
                candidate,
                AdmissionContext(incident_id=seed.incident_id, action=subject, verification=result),
            )
        except MemoryAdmissionRefused:
            # The seed did not qualify. It is kept as a candidate so the scenario can
            # assert that it exists and yet is never returned as history.
            store.append(candidate)
            continue
        if seed.revoked:
            store.revoke(
                record.memory_id, reason="scenario declares this revoked", actor="human:oncall"
            )

    if scenario.tamper_memory and len(store):
        # Deliberate corruption, reaching past the store's own API the way an in-process
        # attacker would. The scenario declares this, and expects the chain to say so.
        records = store._records
        records[0] = records[0].model_copy(update={"summary": "tampered in storage"})

    payload = (
        MemoryRetrieval(store, clock=clock)
        .for_incident(f"INC-{scenario.scenario_id}", requesting_agent="commander")
        .as_model_data()
    )
    return store, payload, poisoned


def attempt_write(
    attempt: MemoryWriteAttempt,
    store: MemoryStore,
    run,
    *,
    incident_id: str,
) -> tuple[bool, str | None]:
    """Try to admit a memory against what the run actually produced.

    Returns ``(admitted, refusal_check)``. A run with no action or no verification cannot
    support memory at all, which is reported as a refusal rather than an exception — that
    is a real and expected outcome for a scenario that never got that far.
    """
    if run is None or run.action is None or run.verification is None:
        return False, "verification.present"

    subject = run.action
    verification = run.verification
    if attempt.forge_fingerprint:
        verification = verification.model_copy(update={"action_fingerprint": "f" * 64})
    if attempt.forge_verification_incident is not None:
        verification = verification.model_copy(
            update={"incident_id": attempt.forge_verification_incident}
        )
    if attempt.claim_resource is not None:
        content = {"resource": attempt.claim_resource}
    else:
        content = {"capability": subject.capability}

    candidate = MemoryCandidate(
        memory_type=attempt.memory_type,
        incident_id=attempt.claim_incident or incident_id,
        agent_id=attempt.agent_id,
        summary=attempt.summary,
        content=content,
        action_id=attempt.claim_action,
        verification_id=attempt.claim_verification,
    )
    try:
        store.admit(
            candidate,
            AdmissionContext(incident_id=incident_id, action=subject, verification=verification),
        )
    except MemoryAdmissionRefused as refusal:
        return False, refusal.check
    return True, None
