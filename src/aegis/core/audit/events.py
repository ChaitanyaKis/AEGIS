"""The authoritative audit event vocabulary.

``AuditEvent.event_type`` is a plain string in the domain contract, left deliberately open
in the first milestone because the components that emit events did not exist yet. They
exist now, so the vocabulary is pinned here instead — in the audit package, where the
emitters live — rather than by narrowing the domain field. Keeping the field a string
preserves the serialization semantics of every event already written, while this enum is
what any AEGIS component must use to write a new one.

The vocabulary is versioned. Adding a member is a compatible change; renaming or removing
one changes what historical records mean, so both are breaking and both are pinned by test.
"""

from __future__ import annotations

from enum import StrEnum

__all__ = ["EVENT_VOCABULARY_VERSION", "AuditEventType"]

EVENT_VOCABULARY_VERSION = "aegis.audit/v1"
"""Version of the event-type vocabulary defined in this module."""


class AuditEventType(StrEnum):
    """Every event type AEGIS currently emits.

    Names are namespaced ``subject.happening`` and read as statements of fact about
    something that already occurred — never as intentions or requests.
    """

    INCIDENT_STATE_CHANGED = "incident.state_changed"
    """An incident moved between states, via an edge the state machine permitted."""

    ACTION_ASSESSED = "action.assessed"
    """The assessment pipeline computed (or could not compute) risk and blast radius."""

    POLICY_DECISION = "policy.decision"
    """The policy engine returned ALLOW, DENY or REQUIRE_APPROVAL."""

    APPROVAL_REQUESTED = "approval.requested"
    """A human-approval artifact was raised from a live REQUIRE_APPROVAL decision."""

    APPROVAL_GRANTED = "approval.granted"
    APPROVAL_REJECTED = "approval.rejected"
    APPROVAL_EXPIRED = "approval.expired"
    APPROVAL_CONSUMED = "approval.consumed"
    """An approval was spent to authorise exactly one execution."""

    VERIFICATION_COMPLETED = "verification.completed"
    """The verification engine established — or failed to establish — enterprise state.

    Emitted for every outcome, not only VERIFIED. A verification that could not establish
    the expected state is exactly the kind of thing an audit trail must show.
    """

    MEMORY_ADMITTED = "memory.admitted"
    """A memory record was admitted as authoritative against a verified outcome.

    A new member rather than a reuse of ``verification.completed``: that event says a
    verification ran, and this one says organizational memory changed as a result. They
    have different actors, different artifacts and different consequences, and collapsing
    them would make it impossible to audit what AEGIS came to believe as distinct from what
    it observed. Adding a member is a compatible change under this module's own rule, so
    ``EVENT_VOCABULARY_VERSION`` is unchanged.
    """

    MEMORY_REVOKED = "memory.revoked"
    """An authoritative memory record was withdrawn.

    Distinct from admission because the trail must show that something believed was later
    unbelieved, and by whom. Revocation is append-only: this event accompanies a new record
    and never erases the original.
    """

    LIFECYCLE_STOPPED = "lifecycle.stopped"
    """Automated handling ended because a lifecycle limit applied.

    Not expressible through the existing vocabulary. ``incident.state_changed`` records
    that an incident escalated but not *which budget was exhausted*, and the counters that
    justify the stop belong to no other event. Reusing it would leave "why did automation
    stop" answerable only by inference from the absence of further events.
    """

    CIRCUIT_OPENED = "circuit.opened"
    """The breaker opened for one scope after repeated classified failures.

    Deliberately distinct from ``policy.decision``: a DENY is the control plane refusing
    one action, and this is automation being stopped for a whole scope across incidents.
    Collapsing them would make a correct refusal and an emergency stop indistinguishable in
    the trail — the exact confusion section 13 of this milestone exists to prevent.
    """

    CIRCUIT_PROBE = "circuit.probe"
    """A half-open probe was permitted, and how it turned out."""

    CIRCUIT_CLOSED = "circuit.closed"
    """A probe verified and the breaker returned to normal operation."""

    LIFECYCLE_GATE_ISSUED = "lifecycle.gate_issued"
    """A lifecycle gate was minted for one exact execution.

    Not expressible through the existing vocabulary. ``policy.decision`` says an action was
    permitted and ``approval.consumed`` says a human agreed; neither says the lifecycle was
    crossed, which is a third, independent condition of executing. Without its own event
    the trail could not distinguish "governance ran" from "governance was skipped and
    nothing noticed".
    """

    LIFECYCLE_GATE_CONSUMED = "lifecycle.gate_consumed"
    """A gate was spent by the execution it was issued for. Single-use, so this appears at
    most once per gate and a second occurrence would itself be the alarm."""

    LIFECYCLE_GATE_REJECTED = "lifecycle.gate_rejected"
    """A gate was refused, naming the binding that failed.

    Distinct from ``policy.decision``: a DENY is the control plane refusing an action on
    its merits, and this is an execution arriving without valid proof that governance
    happened. Collapsing them would hide attempted bypasses among ordinary refusals.
    """

    AGENT_RESTRICTION_APPLIED = "agent.restriction_applied"
    """An accountable agent was quarantined after repeated attributed failures.

    Deliberately not an ``incident.state_changed``: quarantine is a property of an agent
    across incidents, not of the incident that happened to trip it.
    """

    AGENT_RESTRICTION_REFUSED = "agent.restriction_refused"
    """A quarantined agent attempted to participate and was refused.

    The other half of the story. Without it the trail shows a restriction being applied and
    then silence, and silence is indistinguishable from the restriction not working.
    """

    A2A_MESSAGE = "a2a.message"
    """One agent-to-agent message reached a status: issued, accepted, rejected, completed.

    Not expressible through the existing vocabulary. ``model.decision`` records that the
    Commander decided to delegate, and the specialist's finding records what came back;
    neither records the *message* — its identity, its digest, its position in a
    conversation, or whether the transport admitted it at all. Without that, a refused
    delegation and a delegation that was never attempted look identical in the trail, and a
    replay leaves no evidence of having been tried.

    Deliberately **one** member with a status scalar rather than four members. Unlike the
    gate events, which describe three different things happening to different artifacts,
    these describe one message moving through one lifecycle; four types would be four names
    for the same fact and would drift apart. Adding a member is a compatible change under
    this module's own rule, so ``EVENT_VOCABULARY_VERSION`` is unchanged.

    Carries identifiers, a status and a digest — never payload text, never a prompt, never a
    model response (Part 17).
    """

    MODEL_DECISION = "model.decision"
    """The reasoning layer produced one output — or failed to.

    The one genuinely missing fact (Prompt 14, Part 12). Every existing member records what
    the *control plane* did: ``policy.decision`` says an action was permitted,
    ``approval.granted`` says a human agreed, ``action.assessed`` says risk was computed.
    None of them records what the model *asked for*, so a trail could not distinguish
    "the model proposed a rollback and policy allowed it" from "the model proposed
    exporting the customer database and policy denied it, then proposed a rollback". Those
    are very different runs and they must not look alike.

    Recorded for failures too, with no decision type and a failure category instead. A model
    that timed out is a fact about the run; leaving it out would make an aborted run
    indistinguishable from one where the model was never asked.

    Emphatically **not** an authority record. This says a proposal was made. Whether it was
    permitted is ``policy.decision``, whether a human agreed is ``approval.granted``,
    whether it happened is the execution, and whether it worked is
    ``verification.completed``. Five different facts, five different events, on purpose.
    """

    REMOTE_AUTHENTICATION = "remote.authentication"
    """A remote message's sender was cryptographically established -- or could not be.

    A genuinely new fact, and the test for that is whether an existing member could carry
    it. ``a2a.message`` records that a message reached a status; it has no key, no
    algorithm, no protocol version and no notion of a sender being *established* rather than
    *declared*. Without this event a trail could not distinguish "the message was refused
    because the sequence was wrong" from "the message was refused because the signature did
    not verify", and those call for very different responses from whoever reads it.

    Deliberately **one** member with a status scalar, exactly as ``a2a.message`` is. An
    authentication that succeeded and one that failed are the same fact with a different
    outcome; ``remote.identity_verified`` and ``remote.message_rejected`` would be two names
    for one event and would drift apart. A transport failure is carried here too, as a
    status: it is still "this message did not authenticate, and here is why".

    Carries identifiers, a key id, an algorithm, a protocol version, a status and a digest.
    **Never** key material, never a signature, never payload text, never a credential.

    Emphatically not an authority record. This says who sent something. Whether they may do
    anything about it is ``policy.decision``, ``approval.granted``, the lifecycle gate and
    ``verification.completed`` -- as it has always been.
    """

    REMOTE_KEY_REVOKED = "remote.key_revoked"
    """A signing key's authority to authenticate was withdrawn.

    The other genuinely new fact, and it is not a message event at all: it is an operator
    action on the registry that changes what will be accepted from that moment on. Nothing
    in the existing vocabulary can express it.

    Without it the trail shows messages from a key being accepted and then, with no
    intervening record, refused -- and silence is indistinguishable from the mechanism
    failing, which is the same argument that earned ``agent.restriction_refused`` its
    place.
    """
