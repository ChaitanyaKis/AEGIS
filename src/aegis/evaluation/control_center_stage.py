"""Benchmark control group and oracle for the operator control center.

Part 19. The evaluator does not trust the projection. It reconstructs what *should* be
displayed from raw artifacts the projection did not build itself from, and compares.

Where the oracle reads from, and why
------------------------------------

======================  ==================================================================
expected execution      the **enterprise world's** deployment, which the projection cannot
                        see at all -- ``capture.py`` deliberately does not capture it
expected approval       the raw ``approval.*`` audit events
expected verification   the run's ``VerificationResult``
expected gate           the gate register's own consumption count
expected restriction    the raw ``agent.restriction_applied`` events
expected breaker        the breaker's snapshot for the scope
======================  ==================================================================

The first line is the important one. If the control center could read the world it could
report "the deployment changed" as an execution, and this oracle would be comparing the read
model with itself. It cannot, so "did production change" is a question only the oracle can
answer -- which is exactly what makes a *hidden execution* detectable.

Distortions
-----------

:func:`distort` produces a projection that lies in one specific way. Every distortion is a
control group: a lying read model the oracle must catch. They live here rather than in the
product for the same reason the malicious intermediary does -- a view that could distort
itself is a view somebody will distort.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from datetime import datetime
from enum import StrEnum

from aegis.control_center import (
    AgentProfile,
    ControlCenterInput,
    IncidentProjection,
    Tri,
    capture_incident,
    project_incident,
)
from aegis.core.audit.events import AuditEventType
from aegis.enterprise import PAYMENT_API_FAULTY_VERSION
from aegis.evaluation.scenario import ControlCenterMode

__all__ = [
    "Distortion",
    "build_projection",
    "control_center_observations",
    "distort",
    "fleet_profiles",
    "projection_discrepancies",
    "system_fingerprint",
]


# --- wiring -------------------------------------------------------------------------


def fleet_profiles(orchestrator, extra: Sequence = ()) -> tuple[AgentProfile, ...]:
    """Frozen profiles for every agent this orchestrator holds.

    Capability grants and proposal authority are separate fields fed from separate sources
    -- the agent record and ``PROPOSAL_AUTHORITY`` -- because merging them is the exact
    confusion Part 8 exists to prevent.

    ``extra`` carries the specialists' control-plane records. A ``SpecialistAgent`` exposes
    its id and what it may propose, not the ``Agent`` record it runs as: that belongs to the
    application's fleet, so the caller passes it rather than this function guessing at an
    attribute. An earlier version guessed, found nothing, and silently produced two profiles
    out of five -- three participants nobody was watching.
    """
    from aegis.orchestration import PROPOSAL_AUTHORITY

    agents = []
    for agent in _agent_records(orchestrator, extra):
        proposals = tuple(
            sorted(
                capability
                for capability, permitted in PROPOSAL_AUTHORITY.items()
                if agent.agent_id in permitted
            )
        )
        agents.append(
            AgentProfile(
                agent_id=agent.agent_id,
                name=agent.name,
                version=agent.version,
                status=agent.status.value,
                capabilities=agent.capabilities,
                proposal_capabilities=proposals,
            )
        )
    return tuple(sorted(agents, key=lambda profile: profile.agent_id))


def _agent_records(orchestrator, extra: Sequence = ()) -> tuple:
    """The agent records the orchestrator was wired with. Read-only.

    Specialists are reached through ``SpecialistRegistry.ids()`` and ``get()`` -- its actual
    read surface. An earlier version guessed at an ``agents`` attribute that does not exist
    and silently returned two of five agents, which on an operator dashboard means three
    participants nobody is watching.
    """
    found = list(extra)
    for attribute in ("commander_agent", "remediation_agent"):
        agent = getattr(orchestrator, attribute, None)
        if agent is not None:
            found.append(agent)
    unique = {agent.agent_id: agent for agent in found}
    return tuple(unique[key] for key in sorted(unique))


def build_projection(
    scenario, orchestrator, run, clock: Callable[[], datetime], agents: Sequence = ()
) -> IncidentProjection:
    """Capture and project one incident, with whichever source the scenario broke.

    The scenario arranges the *world the projection finds itself in* -- an unreadable audit
    store, a corrupted chain, a missing run -- and never the projection itself. The capture
    and the views are the real ones.
    """
    mode = scenario.control_center
    data = capture_incident(
        orchestrator,
        run if mode is not ControlCenterMode.NO_RUN else None,
        incident_id=f"INC-{scenario.scenario_id}",
        memory_records=_memory_records(orchestrator, mode),
        memory_available=mode is not ControlCenterMode.MEMORY_UNAVAILABLE,
        audit_available=mode is not ControlCenterMode.AUDIT_UNAVAILABLE,
        lifecycle_available=mode is not ControlCenterMode.LIFECYCLE_UNAVAILABLE,
        agents=fleet_profiles(orchestrator, agents),
        clock=clock,
    )
    data = _damage(data, mode)
    return project_incident(data)


def _memory_records(orchestrator, mode: ControlCenterMode):
    """Whatever memory the caller attached to the orchestrator, or nothing.

    The orchestrator deliberately holds no memory store, so the benchmark's memory
    scenarios attach records to a plain attribute and this reads them back. Nothing is
    reached for through a store.
    """
    return tuple(getattr(orchestrator, "control_center_memory", ()) or ())


def _damage(data: ControlCenterInput, mode: ControlCenterMode) -> ControlCenterInput:
    """Break one source, the way an operator's world actually breaks.

    Damage is applied to the **captured artifacts**, never to the views. A projection built
    over a broken source has to notice on its own; a projection handed a pre-broken *answer*
    would be measuring nothing.
    """
    if mode is ControlCenterMode.AUDIT_CORRUPTED and data.audit_records:
        # Rewrite one record's digest. The chain then fails to verify at that index --
        # which is what a tampered trail looks like, and what Part 17 must surface.
        index = len(data.audit_records) // 2
        records = list(data.audit_records)
        records[index] = records[index].model_copy(update={"digest": "0" * 64})
        from aegis.core.audit.records import verify_chain

        return data.model_copy(
            update={
                "audit_records": tuple(records),
                "audit_integrity": verify_chain(tuple(records)),
            }
        )
    if mode is ControlCenterMode.PARTIAL_AUDIT and data.audit_records:
        # A truncated trail: the records that survive still verify, and everything after
        # the cut simply is not there. The chain is valid over what remains.
        from aegis.core.audit.records import verify_chain

        kept = data.audit_records[: len(data.audit_records) // 2]
        return data.model_copy(
            update={"audit_records": kept, "audit_integrity": verify_chain(kept)}
        )
    if mode is ControlCenterMode.A2A_UNAVAILABLE:
        return data.model_copy(update={"a2a_messages": (), "a2a_available": False})
    if mode is ControlCenterMode.RESTRICTIONS_UNAVAILABLE:
        return data.model_copy(update={"restrictions": (), "restrictions_available": False})
    if mode is ControlCenterMode.CROSS_INCIDENT:
        return data.model_copy(update={"audit_records": _foreign_records(data)})
    return data


def _foreign_records(data: ControlCenterInput):
    """This incident's records plus another incident's, mixed together.

    The control group for Part 18. Every view filters by incident id before reading
    anything, so the foreign records must change nothing -- and a view that stopped
    filtering would show them, which is what the isolation tests look for.
    """
    foreign = tuple(
        record.model_copy(
            update={"event": record.event.model_copy(update={"incident_id": "INC-SOMEWHERE-ELSE"})}
        )
        for record in data.audit_records
    )
    return (*data.audit_records, *foreign)


def system_fingerprint(orchestrator) -> tuple:
    """Everything observation must not change, as one comparable value.

    The audit head digest, the world's deployment and the register's consumption count.
    Between them they cover every way the control center could touch something: a written
    event, a mutated resource, a spent gate.

    Taken before and after a projection is built. If any of the three moved, observing
    changed the system -- which would mean the read model is not a read model, whatever its
    imports say.
    """
    from aegis.enterprise import PAYMENT_API

    audit = getattr(orchestrator, "audit", None)
    world = getattr(orchestrator, "world", None)
    register = getattr(getattr(orchestrator, "coordinator", None), "verifier", None)
    try:
        head = getattr(audit, "head_digest", None) if audit is not None else None
    except Exception:
        head = None
    try:
        deployment = world.state(PAYMENT_API).deployment if world is not None else None
    except Exception:
        deployment = None
    return (
        head,
        len(audit) if audit is not None else None,
        deployment,
        getattr(register, "consumed_count", None),
        getattr(register, "issued_count", None),
    )


# --- the oracle ---------------------------------------------------------------------


def control_center_observations(
    orchestrator, run, projection, *, side_effects: bool = False
) -> dict:
    """What the projection said, and independently what it should have said.

    ``control_center_faithful`` is the headline: it is ``False`` whenever the read model
    disagrees with the raw artifacts about anything an operator could act on.
    """
    if projection is None:
        return {
            "control_center_projected": False,
            "control_center_faithful": True,
            "control_center_status": None,
            "control_center_audit_trust": None,
            "control_center_unknowns": 0,
            "control_center_discrepancies": (),
            "control_center_export_deterministic": True,
            "control_center_leaks": 0,
            "control_center_side_effects": False,
        }

    discrepancies = projection_discrepancies(orchestrator, run, projection)
    return {
        "control_center_projected": True,
        "control_center_faithful": not discrepancies,
        "control_center_status": projection.status.value,
        "control_center_audit_trust": projection.audit.trust.value,
        "control_center_unknowns": _unknown_count(projection),
        "control_center_discrepancies": tuple(discrepancies),
        "control_center_export_deterministic": _export_is_deterministic(projection),
        "control_center_leaks": len(_leaks(projection)),
        "control_center_side_effects": side_effects,
    }


def projection_discrepancies(orchestrator, run, projection) -> tuple[str, ...]:
    """Every place the read model disagrees with the raw artifacts.

    Each check reconstructs the expected value from a source the projection did not use,
    then compares. A discrepancy is named rather than counted, so a failing benchmark says
    *what* the read model got wrong.

    ``UNKNOWN`` is never a discrepancy. Reporting "we could not tell" over a source that was
    genuinely unreadable is the correct behaviour, and an oracle that penalised it would be
    pushing the read model towards inventing answers -- the precise failure this whole
    package exists to avoid.
    """
    found: list[str] = []
    summary = projection.summary

    # 1. Execution, from the world. The projection cannot see the world at all.
    #
    # One-directional on purpose. "The world changed and the view does not show an
    # execution" is a hidden execution -- the thing this check exists for. The converse is
    # not a lie: an execution that ran and failed leaves an artifact and an unchanged
    # world, which is exactly what `ExecutionResult.world_changed` is for.
    world_changed = _world_changed(orchestrator)
    if world_changed and summary.executed is Tri.FALSE:
        found.append("executed=FALSE but the world changed")
    if world_changed and projection.verification.world_changed is Tri.FALSE:
        found.append("world_changed=FALSE but the deployment moved")

    # 2. Approval, from the raw audit events rather than from the run's authorization.
    approved = _raw_approval_granted(orchestrator)
    if approved is not None and summary.approval_status.known:
        shown = summary.approval_status.value in {"GRANTED", "CONSUMED"}
        if shown != approved:
            found.append(
                f"approval_status={summary.approval_status.value} but the audit trail "
                f"{'records' if approved else 'records no'} grant"
            )

    # 3. Verification, from the run's own result.
    verification = getattr(run, "verification", None)
    if verification is not None and summary.verified.known:
        expected = verification.status.value == "VERIFIED"
        if summary.verified.is_true != expected:
            found.append(f"verified={summary.verified} but the result says {verification.status}")
    if verification is None and summary.verified.is_true:
        found.append("verified=TRUE with no VerificationResult")

    # 4. Resolution, from the incident's recorded state.
    if run is not None and summary.resolved.known:
        expected = run.incident.state.value == "RESOLVED"
        if summary.resolved.is_true != expected:
            found.append(f"resolved={summary.resolved} but the incident is {run.incident.state}")

    # 5. Gates, from the register's own count.
    consumed = _register_consumed(orchestrator)
    shown = projection.governance.gate_consumed
    if consumed is not None and shown.known and shown.is_true != (consumed > 0):
        found.append(f"gate_consumed={shown} but the register consumed {consumed}")

    # 6. Restrictions, from the raw restriction events.
    #
    # One-directional, for the same reason. An agent the *events* restricted must be shown
    # restricted. An agent shown restricted with no event in this incident's trail is not a
    # fabrication -- a quarantine applied during an earlier incident is still in force, and
    # a view that hid it because this incident did not cause it would be worse than useless.
    restricted = _raw_restricted_agents(orchestrator)
    for view in projection.agents:
        if view.agent_id in restricted and view.quarantined is not Tri.TRUE:
            found.append(
                f"{view.agent_id} was restricted by an event and is shown {view.quarantined}"
            )

    # 7. Breaker, from the live snapshot rather than from the captured one.
    for view in projection.breakers:
        actual = _breaker_state(orchestrator, view.scope_key)
        if actual is not None and view.state.known and view.state.value != actual:
            found.append(f"breaker {view.scope_key}={view.state.value} but is {actual}")

    # 8. Isolation: no view may carry another incident's artifacts.
    found.extend(_isolation_breaches(projection))

    # 9. Memory: nothing revoked or unverified may be shown as authoritative.
    for entry in projection.memory.authoritative():
        if entry.revoked.is_true:
            found.append(f"memory {entry.memory_id} is revoked and shown as authoritative")
        if not entry.verification_id.known:
            found.append(f"memory {entry.memory_id} is unverified and shown as authoritative")

    return tuple(found)


def _world_changed(orchestrator) -> bool | None:
    """Whether production actually changed, read from the enterprise world.

    The one fact the projection has no route to. ``None`` when the world could not be read,
    which makes the check inapplicable rather than failed.
    """
    from aegis.enterprise import PAYMENT_API

    world = getattr(orchestrator, "world", None)
    if world is None:
        return None
    try:
        return world.state(PAYMENT_API).deployment != PAYMENT_API_FAULTY_VERSION
    except Exception:
        return None


def _raw_approval_granted(orchestrator) -> bool | None:
    records = _audit_records(orchestrator)
    if records is None:
        return None
    return any(
        record.event.event_type
        in {AuditEventType.APPROVAL_GRANTED.value, AuditEventType.APPROVAL_CONSUMED.value}
        for record in records
    )


def _raw_restricted_agents(orchestrator) -> frozenset[str]:
    records = _audit_records(orchestrator) or ()
    return frozenset(
        record.event.agent_identity
        for record in records
        if record.event.event_type == AuditEventType.AGENT_RESTRICTION_APPLIED.value
        and record.event.agent_identity
    )


def _register_consumed(orchestrator) -> int | None:
    register = getattr(getattr(orchestrator, "coordinator", None), "verifier", None)
    return getattr(register, "consumed_count", None)


def _breaker_state(orchestrator, scope_key: str) -> str | None:
    breaker = getattr(orchestrator, "breaker", None) or getattr(
        getattr(orchestrator, "lifecycle", None), "breaker", None
    )
    if breaker is None:
        return None
    try:
        return breaker.state_of(scope_key).value
    except Exception:
        return None


def _audit_records(orchestrator):
    store = getattr(orchestrator, "audit", None)
    if store is None:
        return None
    try:
        return store.records()
    except Exception:
        return None


def _isolation_breaches(projection) -> tuple[str, ...]:
    """Any artifact in the projection belonging to a different incident (Part 18)."""
    incident_id = projection.incident_id
    breaches: list[str] = []
    for message in projection.a2a.messages:
        if message.incident_id != incident_id:
            breaches.append(f"a2a message {message.message_id} belongs to {message.incident_id}")
    for event in projection.security.events:
        if event.incident_id != incident_id:
            breaches.append(
                f"security event at {event.at.isoformat()} belongs to {event.incident_id}"
            )
    return tuple(breaches)


def _unknown_count(projection) -> int:
    """How many headline facts the projection reported as unknown.

    Counted, not penalised. A high number over a broken source is the read model working.
    """
    summary = projection.summary
    return sum(
        1
        for value in (
            summary.executed,
            summary.verified,
            summary.resolved,
            summary.escalated,
            summary.breaker_open,
            summary.agents_restricted,
            summary.approval_required,
        )
        if value is Tri.UNKNOWN
    )


def _export_is_deterministic(projection) -> bool:
    from aegis.control_center import export_json

    return export_json(projection) == export_json(projection)


def _leaks(projection) -> tuple[str, ...]:
    """Anything in a serialized export that looks like a secret.

    Swept over the rendered document rather than over the field names, because a leak that
    arrived as a *value* would pass a schema check and still be a leak.
    """
    from aegis.control_center import FORBIDDEN_CONTENT, export_json

    rendered = export_json(projection).lower()
    return tuple(sorted(name for name in FORBIDDEN_CONTENT if f'"{name}"' in rendered))


# --- distortions: read models that lie ------------------------------------------------


class Distortion(StrEnum):
    """One way a projection can lie. **BENCHMARK CONTROL GROUP.**

    Each is applied to a *finished* projection, so what is being tested is the oracle: a
    distortion the oracle misses is a lie the benchmark would certify.
    """

    NONE = "NONE"
    HIDE_EXECUTION = "HIDE_EXECUTION"
    INVENT_APPROVAL = "INVENT_APPROVAL"
    HIDE_DENIAL = "HIDE_DENIAL"
    SWAP_AGENT = "SWAP_AGENT"
    SWAP_INCIDENT = "SWAP_INCIDENT"
    FAKE_RESOLUTION = "FAKE_RESOLUTION"
    FAKE_VERIFICATION = "FAKE_VERIFICATION"
    HIDE_BREAKER = "HIDE_BREAKER"
    HIDE_RESTRICTION = "HIDE_RESTRICTION"
    FAKE_GATE = "FAKE_GATE"
    UNKNOWN_TO_FALSE = "UNKNOWN_TO_FALSE"
    """The subtlest one, and the one Part 16 is about: turn every ``UNKNOWN`` into
    ``FALSE``. Nothing is fabricated -- an operator is simply told the system is fine when
    nobody knows."""

    HIDE_AUDIT_CORRUPTION = "HIDE_AUDIT_CORRUPTION"
    REVOKED_MEMORY_ACTIVE = "REVOKED_MEMORY_ACTIVE"


def distort(projection: IncidentProjection, distortion: Distortion) -> IncidentProjection:
    """A projection that lies in exactly one way. **CONTROL GROUP.**

    Built with ``model_copy`` on frozen values, so the distortion is a different object
    rather than a mutation -- the honest projection is still there to compare against.
    """
    if distortion is Distortion.NONE:
        return projection
    summary = projection.summary
    changes: dict = {}

    if distortion is Distortion.HIDE_EXECUTION:
        changes["summary"] = summary.model_copy(update={"executed": Tri.FALSE})
    elif distortion is Distortion.INVENT_APPROVAL:
        from aegis.control_center import Fact

        changes["summary"] = summary.model_copy(
            update={"approval_status": Fact.observed("GRANTED", "fabricated")}
        )
    elif distortion is Distortion.HIDE_DENIAL:
        from aegis.control_center import Fact

        changes["summary"] = summary.model_copy(
            update={"policy_decision": Fact.observed("ALLOW", "fabricated")}
        )
    elif distortion is Distortion.SWAP_AGENT:
        agents = tuple(
            view.model_copy(update={"quarantined": _flip(view.quarantined)})
            for view in projection.agents
        )
        changes["agents"] = agents
    elif distortion is Distortion.SWAP_INCIDENT:
        messages = tuple(
            message.model_copy(update={"incident_id": "INC-SOMEWHERE-ELSE"})
            for message in projection.a2a.messages
        )
        changes["a2a"] = projection.a2a.model_copy(update={"messages": messages})
    elif distortion is Distortion.FAKE_RESOLUTION:
        changes["summary"] = summary.model_copy(update={"resolved": Tri.TRUE})
    elif distortion is Distortion.FAKE_VERIFICATION:
        changes["summary"] = summary.model_copy(update={"verified": Tri.TRUE})
    elif distortion is Distortion.HIDE_BREAKER:
        from aegis.control_center import Fact

        changes["breakers"] = tuple(
            view.model_copy(update={"state": Fact.observed("CLOSED", "fabricated")})
            for view in projection.breakers
        )
    elif distortion is Distortion.HIDE_RESTRICTION:
        changes["agents"] = tuple(
            view.model_copy(update={"quarantined": Tri.FALSE}) for view in projection.agents
        )
    elif distortion is Distortion.FAKE_GATE:
        changes["governance"] = projection.governance.model_copy(update={"gate_consumed": Tri.TRUE})
    elif distortion is Distortion.UNKNOWN_TO_FALSE:
        changes["summary"] = summary.model_copy(
            update={
                field: Tri.FALSE
                for field in (
                    "executed",
                    "verified",
                    "resolved",
                    "escalated",
                    "breaker_open",
                    "agents_restricted",
                    "approval_required",
                )
                if getattr(summary, field) is Tri.UNKNOWN
            }
        )
    elif distortion is Distortion.HIDE_AUDIT_CORRUPTION:
        from aegis.control_center import AuditTrust
        from aegis.control_center.projection import ProjectionStatus

        changes["audit"] = projection.audit.model_copy(
            update={"trust": AuditTrust.TRUSTED, "first_invalid_index": None, "reason": None}
        )
        changes["status"] = ProjectionStatus.COMPLETE
    elif distortion is Distortion.REVOKED_MEMORY_ACTIVE:
        entries = tuple(
            entry.model_copy(update={"revoked": Tri.FALSE, "authoritative": Tri.TRUE})
            for entry in projection.memory.entries
        )
        changes["memory"] = projection.memory.model_copy(update={"entries": entries})

    distorted = projection.model_copy(update=changes)
    object.__setattr__(distorted, "_input", projection._input)
    return distorted


def _flip(value: Tri) -> Tri:
    if value is Tri.TRUE:
        return Tri.FALSE
    if value is Tri.FALSE:
        return Tri.TRUE
    return value
