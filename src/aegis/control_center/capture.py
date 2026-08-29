"""Taking a frozen snapshot of what happened, and holding nothing that could act.

The seam between the running system and the read model. Everything downstream of this
module works on :class:`ControlCenterInput` -- a frozen value -- so the projection layer
literally has no object it could call ``execute`` on. That is the Part 20 invariant
implemented by construction rather than by discipline: the control center cannot create
authority because it is never handed anything that holds any.

How this module reads
---------------------

Duck-typed, on purpose. It takes an orchestrator-shaped object and reads attributes and
read-only methods; it constructs no engine, imports no engine class and calls nothing that
changes state. A structural test sweeps the whole package for the names of every class that
can act, and for every method name that could mutate.

What it captures, and what it deliberately does not
---------------------------------------------------

It captures **recorded artifacts**: the run, the audit records and their integrity report,
memory records, A2A message records, breaker snapshots, restriction verdicts, gate counts.

It does **not** capture the enterprise world. That is not an oversight. If the projection
could read the world it could report "the deployment changed" as an execution, and the
benchmark's oracle -- which reads the world precisely to check the projection against
something the projection cannot see -- would be comparing the read model with itself.

Unavailability is a value
-------------------------

Every source has an ``*_available`` flag, and a source that could not be read produces
``False`` with no data rather than an empty tuple. An empty tuple and an unreadable store
are different facts, and Part 16 turns on not confusing them: a control center that
rendered *unavailable* as *nothing happened* would make a failure look like a quiet day.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from datetime import datetime

from pydantic import Field

from aegis.a2a.ledger import MessageRecord
from aegis.core.audit.records import AuditRecord, IntegrityReport
from aegis.core.domain import DomainModel, Identifier, NonEmptyStr, Timestamp, utc_now
from aegis.lifecycle.restriction import RestrictionVerdict
from aegis.lifecycle.state import BreakerSnapshot
from aegis.memory.models import MemoryRecord
from aegis.orchestration import OrchestrationRun

__all__ = ["AgentProfile", "ControlCenterInput", "capture_incident"]


class AgentProfile(DomainModel):
    """What the control plane records *about* an agent, frozen for display.

    Three separate fields that operators routinely conflate, kept apart deliberately
    (Part 8): a granted capability is not a permission, proposal authority is not an
    authorization, and neither is a current restriction state.
    """

    agent_id: Identifier
    name: NonEmptyStr
    version: NonEmptyStr
    status: NonEmptyStr
    """The agent's registration standing -- ``AgentLifecycleState``. Not its restriction."""

    capabilities: tuple[Identifier, ...] = Field(default_factory=tuple)
    """Capability ids the control plane has granted. **A grant record, not permission.**"""

    proposal_capabilities: tuple[Identifier, ...] = Field(default_factory=tuple)
    """Capabilities this agent may *propose*. **Not authorization to perform them.**"""


class ControlCenterInput(DomainModel):
    """Everything the read model is allowed to see, as one frozen value.

    Frozen and closed. There is no field here holding a live object, so no view built from
    it can reach an engine even by accident -- which is what makes "the control center
    cannot create authority" a property of the type rather than a promise in a docstring.
    """

    incident_id: Identifier
    captured_at: Timestamp

    run: OrchestrationRun | None = None
    run_available: bool = True
    """``False`` when the run crashed or never completed. Distinct from ``run is None``
    with ``run_available=True``, which would mean "the run completed and produced nothing"
    -- a state that should never occur and would be worth seeing if it did."""

    audit_records: tuple[AuditRecord, ...] = Field(default_factory=tuple)
    audit_available: bool = True
    audit_integrity: IntegrityReport | None = None
    audit_head_digest: NonEmptyStr | None = None
    """The digest of the last record the *store* holds.

    Captured so truncation is detectable. A chain that verifies proves nothing was altered;
    it says nothing about whether the records handed over are all of them. Comparing the
    last record's digest against the store's own head is what separates "a short history"
    from "a history with the end missing".
    """

    memory_records: tuple[MemoryRecord, ...] = Field(default_factory=tuple)
    memory_available: bool = True

    a2a_messages: tuple[MessageRecord, ...] = Field(default_factory=tuple)
    a2a_available: bool = True

    lifecycle_available: bool = True
    breakers: tuple[BreakerSnapshot, ...] = Field(default_factory=tuple)
    restrictions: tuple[RestrictionVerdict, ...] = Field(default_factory=tuple)
    restrictions_available: bool = True

    gates_issued: int | None = None
    gates_consumed: int | None = None
    """``None`` when the register could not be read. Zero means zero."""

    agents: tuple[AgentProfile, ...] = Field(default_factory=tuple)
    remote_enabled: bool = False

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}({self.incident_id}, {len(self.audit_records)} audit, "
            f"{len(self.a2a_messages)} a2a, {len(self.memory_records)} memory)"
        )


def _read(source, name: str, default=None):
    """Read one attribute, treating any failure as "unavailable".

    Broad on purpose. This module runs against a system that may have crashed mid-incident,
    and an exception here would deny an operator the parts that *are* readable -- which is
    the moment they most need them. Every caller pairs the value with an availability flag,
    so a swallowed failure becomes a visible ``UNKNOWN`` downstream rather than a silent
    default.
    """
    try:
        value = getattr(source, name)
    except Exception:
        return default
    return value if value is not None else default


def _call(source, name: str, *args, default=None):
    """Call one read-only method, treating any failure as "unavailable".

    Only ever used with the literal method names below -- ``records``,
    ``verify_integrity``, ``conversation_ids``, ``messages_for``, ``snapshot``, ``check``,
    ``key_for``. A structural test asserts every call site here names a method from that
    read-only list, so this helper cannot become a route to a mutating method.
    """
    method = _read(source, name)
    if method is None:
        return default
    try:
        return method(*args)
    except Exception:
        return default


def capture_incident(
    orchestrator,
    run: OrchestrationRun | None = None,
    *,
    incident_id: str | None = None,
    memory_records: Sequence[MemoryRecord] = (),
    memory_available: bool = True,
    audit_available: bool = True,
    lifecycle_available: bool = True,
    agents: Sequence[AgentProfile] = (),
    clock: Callable[[], datetime] = utc_now,
) -> ControlCenterInput:
    """Freeze one incident's recorded artifacts into a read-model input.

    Args:
        orchestrator: The orchestrator that ran the incident. Read only -- see the module
            docstring for what "read only" means structurally here.
        run: The frozen run, when one was produced. ``None`` for a crashed or partial run,
            which is a case the read model must handle rather than refuse.
        incident_id: Overrides the run's own id, for a run that never got far enough to
            have one.
        memory_records: Memory the caller wants projected. Passed in rather than reached
            for, because the orchestrator deliberately does not hold a memory store.
        memory_available / audit_available / lifecycle_available: Set ``False`` to model a
            source that could not be read. The read model then reports ``UNKNOWN`` for
            everything derived from it -- never an empty result.

    Every source is captured with its own availability flag, and the flags are honoured
    downstream. Nothing here interprets, summarises or decides; interpretation happens in
    the view modules, from this frozen value and nothing else.
    """
    captured_at = clock()
    resolved_id = incident_id or _incident_id_of(run)
    if not resolved_id:
        # Every view filters by incident id before reading anything (Part 18), so a capture
        # with no id would filter its own artifacts away and render a busy incident as an
        # empty one. That is a fabricated state, and the caller has to say which incident
        # this is -- exactly as `UnknownIncident` refuses to answer for a typo.
        raise ValueError(
            "capture_incident needs an incident_id when no run is supplied; without one "
            "every view would filter out the artifacts it was given"
        )

    audit = _read(orchestrator, "audit")
    records: tuple[AuditRecord, ...] = ()
    integrity: IntegrityReport | None = None
    head: str | None = None
    if audit_available and audit is not None:
        found = _call(audit, "records", default=None)
        if found is None:
            audit_available = False
        else:
            records = tuple(found)
            integrity = _call(audit, "verify_integrity", default=None)
            if integrity is None:
                audit_available = False
            head = _read(audit, "head_digest")

    a2a_messages, a2a_available = _capture_a2a(orchestrator)
    breakers = _capture_breakers(orchestrator, run) if lifecycle_available else ()
    restrictions, restrictions_available = _capture_restrictions(orchestrator, run, agents)
    issued, consumed = _capture_gates(orchestrator)

    return ControlCenterInput(
        incident_id=resolved_id,
        captured_at=captured_at,
        run=run,
        run_available=run is not None,
        audit_records=records,
        audit_available=audit_available,
        audit_integrity=integrity,
        audit_head_digest=head,
        memory_records=tuple(memory_records),
        memory_available=memory_available,
        a2a_messages=a2a_messages,
        a2a_available=a2a_available,
        lifecycle_available=lifecycle_available,
        breakers=breakers,
        restrictions=restrictions,
        restrictions_available=restrictions_available,
        gates_issued=issued,
        gates_consumed=consumed,
        agents=tuple(agents),
        remote_enabled=_read(orchestrator, "remote") is not None,
    )


def _incident_id_of(run: OrchestrationRun | None) -> str | None:
    if run is None:
        return None
    incident = _read(run, "incident")
    return _read(incident, "incident_id")


def _capture_a2a(orchestrator) -> tuple[tuple[MessageRecord, ...], bool]:
    """Every message the ledger holds, through its public read surface only."""
    broker = _read(orchestrator, "a2a")
    ledger = _read(broker, "ledger")
    if ledger is None:
        return (), False
    conversations = _call(ledger, "conversation_ids", default=None)
    if conversations is None:
        return (), False
    messages: list[MessageRecord] = []
    for conversation in conversations:
        found = _call(ledger, "messages_for", conversation, default=())
        messages.extend(found)
    return tuple(messages), True


def _capture_breakers(orchestrator, run: OrchestrationRun | None) -> tuple[BreakerSnapshot, ...]:
    """Snapshots for the scopes this incident actually touched.

    The breaker is owned by the lifecycle manager, so that is where it is looked for; the
    orchestrator's own attribute is checked first because a caller may have wired one
    directly. Scope keys come from the run's action, so the view shows the breaker an
    operator is asking about rather than every scope the process has ever seen.

    A snapshot is a frozen value with no route back to the breaker
    (:class:`~aegis.lifecycle.state.BreakerSnapshot`), which is why capturing one is safe:
    holding it gives no way to open, close or reset anything.
    """
    breaker = _read(orchestrator, "breaker") or _read(_read(orchestrator, "lifecycle"), "breaker")
    if breaker is None:
        return ()
    action = _read(run, "action")
    capability = _read(action, "capability")
    resource = _read(action, "target_resource")
    if capability is None:
        return ()
    key = _scope_key(breaker, capability, resource)
    if key is None:
        return ()
    snapshot = _call(breaker, "snapshot", key, default=None)
    return (snapshot,) if snapshot is not None else ()


def _scope_key(breaker, capability: str, resource: str | None) -> str | None:
    """The breaker's own scope key for this capability and resource.

    Asked of the breaker rather than reconstructed here: the scope is configuration, and a
    control center that computed its own key would show a scope nobody is actually using
    the moment the configured scope changed.
    """
    try:
        return breaker.key_for(capability=capability, resource=resource)
    except Exception:
        return None


def _capture_restrictions(
    orchestrator, run: OrchestrationRun | None, agents: Sequence[AgentProfile]
) -> tuple[tuple[RestrictionVerdict, ...], bool]:
    """One verdict per known agent, for the scope this incident used.

    ``check`` returns a frozen :class:`~aegis.lifecycle.restriction.RestrictionVerdict` and
    changes nothing -- it is the registry's read method, and the only one used here.
    """
    coordinator = _read(orchestrator, "coordinator")
    registry = _read(coordinator, "restrictions") or _read(orchestrator, "restrictions")
    if registry is None:
        return (), False
    action = _read(run, "action")
    capability = _read(action, "capability")
    resource = _read(action, "target_resource")
    verdicts: list[RestrictionVerdict] = []
    for agent in agents:
        verdict = _check_restriction(registry, agent.agent_id, capability, resource)
        if verdict is not None:
            verdicts.append(verdict)
    return tuple(verdicts), True


def _check_restriction(registry, agent_id: str, capability, resource):
    try:
        return registry.check(agent_id, capability=capability, resource=resource)
    except Exception:
        return None


def _capture_gates(orchestrator) -> tuple[int | None, int | None]:
    """How many lifecycle gates were issued and consumed.

    ``None`` when the register could not be read, which is not the same as zero. An
    operator seeing "0 gates consumed" should be able to trust that no gate was consumed.
    """
    coordinator = _read(orchestrator, "coordinator")
    register = _read(coordinator, "verifier")
    if register is None:
        return None, None
    return _read(register, "issued_count"), _read(register, "consumed_count")
