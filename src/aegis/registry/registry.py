"""The governed agent registry: lifecycle, versioning, discovery and eligibility.

This is the object the delegation path consults. Its whole job is to answer one question
deterministically — *may this agent, at this version, receive this work right now?* — and
to make every status change that could affect that answer an audited, legal transition.

What the registry is not
------------------------

It is not an authorization system. :meth:`AgentRegistry.eligibility` returning
``eligible`` means an agent may be *handed a task*. It says nothing about what the agent
may then do, because that is settled downstream by the capability registry, the policy
engine, human approval, the lifecycle gate and verification, none of which read this
module. Adding a registry check in front of delegation narrows what can happen; it can
never widen it.

It is also not the same thing as :class:`~aegis.lifecycle.restriction.AgentRestrictionRegistry`.
That mechanism quarantines an agent for *observed runtime behaviour* — repeated failures
against healthy services. This one records *administrative standing*: who registered a
build, who approved it, whether it is in service. They are deliberately separate and are
allowed to disagree; an agent can be administratively ACTIVE and behaviourally
quarantined, and it is then refused, because both are consulted and either can refuse.

Determinism
-----------

Two properties, and neither is incidental.

**Version selection is total and ordered.** Asking for an agent without naming a version
selects the highest *eligible* version by numeric comparison — never the most recently
inserted, never dictionary order. Adding a 1.10.0 to a fleet holding 1.9.0 changes the
selection in the one direction a reader expects.

**Nothing here is reachable from a model.** Every mutating method takes an ``actor`` and a
``reason`` that the application supplies from its own wiring. There is no method that
takes a proposal, no parsing of model output, and no name lookup that becomes an
attribute or an import — an agent id is a dictionary key, so an invented name produces
``UNKNOWN_AGENT`` and nothing else.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from datetime import datetime

from aegis.core.domain import DomainModel, NonEmptyStr, utc_now
from aegis.registry.errors import (
    AgentAlreadyRegistered,
    IllegalRegistryTransition,
    RegistryRefusal,
    UnknownAgentVersion,
    UnknownRegisteredAgent,
)
from aegis.registry.records import (
    AgentRegistration,
    ApprovalStatus,
    RegistryStatus,
    RegistryTransition,
    transition_is_legal,
)
from aegis.registry.versions import AgentVersion

__all__ = ["AgentRegistry", "EligibilityVerdict"]


class EligibilityVerdict(DomainModel):
    """Whether an agent may receive delegated work, and why not when it may not.

    Always carries the refusal *reason* as a closed enum member and, whenever a
    registration was found at all, the ``status`` it was found in. A refusal that says
    only "no" forces the reader to guess between "never registered", "awaiting approval"
    and "revoked this morning", which are three very different incidents.
    """

    agent_id: NonEmptyStr
    requested_version: NonEmptyStr | None = None
    """The version the caller pinned, or ``None`` when it asked for the selected one."""

    eligible: bool
    refusal: RegistryRefusal = RegistryRefusal.NONE
    detail: NonEmptyStr
    registration: AgentRegistration | None = None
    """The registration the decision was made about, when one was found.

    Present on refusals too — a suspended agent's record is exactly what an operator needs
    in order to decide whether to resume it.
    """

    @property
    def status(self) -> RegistryStatus | None:
        """The status the decision was made against, if a registration was found."""
        return self.registration.status if self.registration is not None else None

    @property
    def coordinate(self) -> str:
        """``agent-id@1.2.0`` when resolved, otherwise the bare id."""
        if self.registration is not None:
            return self.registration.coordinate
        if self.requested_version is not None:
            return f"{self.agent_id}@{self.requested_version}"
        return self.agent_id


class AgentRegistry:
    """Registrations keyed by ``(agent_id, version)``, with a governed lifecycle.

    Args:
        registrations: Pre-built registrations to seed the registry with. Seeding is for
            an application composing its declared fleet at start-up; each one is inserted
            exactly as given, so a caller that seeds an ACTIVE agent is asserting that it
            was approved elsewhere and is accountable for that.
        clock: Timestamp source for transitions. Injected, so a run is reproducible.

    The registry holds no locks and is not thread-safe. The service runs one incident per
    request against its own object graph, so there is no shared mutable registry to race
    on; a deployment that shares one across threads would need to add that itself.
    """

    def __init__(
        self,
        registrations: Iterable[AgentRegistration] = (),
        *,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        self._records: dict[tuple[str, str], AgentRegistration] = {}
        self._transitions: list[RegistryTransition] = []
        self._clock = clock
        for record in registrations:
            if record.key in self._records:
                raise AgentAlreadyRegistered(f"{record.coordinate} is already registered")
            self._records[record.key] = record

    # --- registration ----------------------------------------------------------------

    def register(
        self,
        *,
        agent_id: str,
        version: str | AgentVersion,
        name: str,
        description: str,
        owner: str,
        department: str,
        identity: str,
        capabilities: Sequence[str] = (),
    ) -> AgentRegistration:
        """Create a new registration at DRAFT.

        A registration always starts at DRAFT with ``PENDING`` approval, whatever the
        caller wanted, because there is no argument here that could say otherwise. That
        is ``claude.md`` section 9's rule expressed as an API shape rather than as a
        check: registering an already-approved agent is not a call this class offers.

        Raises:
            AgentAlreadyRegistered: if this exact ``(agent_id, version)`` exists. Never
                an overwrite — a new build must not inherit an old build's approval.
        """
        parsed = AgentVersion.parse(version)
        key = (agent_id, str(parsed))
        if key in self._records:
            raise AgentAlreadyRegistered(
                f"{agent_id}@{parsed} is already registered; register a new version "
                f"instead of replacing an approved one"
            )
        now = self._clock()
        record = AgentRegistration(
            agent_id=agent_id,
            version=parsed,
            name=name,
            description=description,
            owner=owner,
            department=department,
            capabilities=tuple(capabilities),
            status=RegistryStatus.DRAFT,
            approval_status=ApprovalStatus.PENDING,
            identity=identity,
            created_at=now,
            updated_at=now,
        )
        self._records[key] = record
        return record

    # --- lifecycle -------------------------------------------------------------------

    def publish(
        self, agent_id: str, version: str | AgentVersion, *, actor: str, reason: str = "published"
    ) -> AgentRegistration:
        """DRAFT -> PUBLISHED. Makes the registration discoverable, not usable."""
        return self._transition(agent_id, version, RegistryStatus.PUBLISHED, actor, reason)

    def approve(
        self,
        agent_id: str,
        version: str | AgentVersion,
        *,
        approver: str,
        reason: str = "approved for service",
    ) -> AgentRegistration:
        """PUBLISHED -> APPROVED, recording who approved it and when.

        ``approver`` is a human or a system of record supplied by the application. The
        registry does not validate that the approver is entitled to approve — that is the
        deployment's identity system's job — but it does record the claim, so an approval
        can never be anonymous.
        """
        record = self._transition(
            agent_id, version, RegistryStatus.APPROVED, approver, reason
        )
        updated = record.model_copy(
            update={
                "approval_status": ApprovalStatus.GRANTED,
                "approved_by": approver,
                "approved_at": record.updated_at,
            }
        )
        self._records[updated.key] = updated
        return updated

    def reject(
        self,
        agent_id: str,
        version: str | AgentVersion,
        *,
        approver: str,
        reason: str,
    ) -> AgentRegistration:
        """Refuse approval and revoke the version.

        A rejected build is revoked rather than left published, because a version a human
        looked at and refused should not stay in the discovery surface waiting for someone
        to approve it on a worse day.
        """
        record = self._transition(agent_id, version, RegistryStatus.REVOKED, approver, reason)
        updated = record.model_copy(update={"approval_status": ApprovalStatus.REJECTED})
        self._records[updated.key] = updated
        return updated

    def activate(
        self,
        agent_id: str,
        version: str | AgentVersion,
        *,
        actor: str,
        reason: str = "activated",
    ) -> AgentRegistration:
        """APPROVED -> ACTIVE, or SUSPENDED -> ACTIVE.

        Refuses to activate a version whose approval is not ``GRANTED``, even if the
        status transition itself would be legal. The two are tracked separately, so a
        record could otherwise reach ACTIVE while carrying ``PENDING`` — an agent in
        service that nobody approved, which is the exact outcome this package exists to
        make impossible.
        """
        record = self._require(agent_id, version)
        if record.approval_status is not ApprovalStatus.GRANTED:
            raise IllegalRegistryTransition(
                f"{record.coordinate} cannot be activated: approval is "
                f"{record.approval_status}, not GRANTED"
            )
        return self._transition(agent_id, version, RegistryStatus.ACTIVE, actor, reason)

    def suspend(
        self, agent_id: str, version: str | AgentVersion, *, actor: str, reason: str
    ) -> AgentRegistration:
        """ACTIVE -> SUSPENDED. Reversible. ``reason`` is required, not defaulted."""
        return self._transition(agent_id, version, RegistryStatus.SUSPENDED, actor, reason)

    def revoke(
        self, agent_id: str, version: str | AgentVersion, *, actor: str, reason: str
    ) -> AgentRegistration:
        """Anything -> REVOKED. Terminal: no call on this class leads back out."""
        return self._transition(agent_id, version, RegistryStatus.REVOKED, actor, reason)

    def _transition(
        self,
        agent_id: str,
        version: str | AgentVersion,
        target: RegistryStatus,
        actor: str,
        reason: str,
    ) -> AgentRegistration:
        """The single checked path by which any status changes.

        Every lifecycle method above routes through here, so the transition table is
        consulted exactly once per change and there is no method that can move a
        registration along an edge the table does not contain.
        """
        record = self._require(agent_id, version)
        if not transition_is_legal(record.status, target):
            legal = ", ".join(sorted(s.value for s in _legal_from(record.status))) or "none"
            raise IllegalRegistryTransition(
                f"{record.coordinate} may not move from {record.status} to {target}; "
                f"legal from {record.status}: {legal}"
            )
        now = self._clock()
        updated = record.model_copy(
            update={"status": target, "updated_at": now, "status_reason": reason}
        )
        self._records[updated.key] = updated
        self._transitions.append(
            RegistryTransition(
                agent_id=updated.agent_id,
                version=updated.version,
                before=record.status,
                after=target,
                actor=actor,
                reason=reason,
                occurred_at=now,
            )
        )
        return updated

    # --- lookup ----------------------------------------------------------------------

    def _require(self, agent_id: str, version: str | AgentVersion) -> AgentRegistration:
        parsed = AgentVersion.parse(version)
        record = self._records.get((agent_id, str(parsed)))
        if record is not None:
            return record
        if not self.versions_of(agent_id):
            raise UnknownRegisteredAgent(f"no agent {agent_id!r} is registered")
        known = ", ".join(str(v) for v in self.versions_of(agent_id))
        raise UnknownAgentVersion(
            f"agent {agent_id!r} has no version {parsed}; registered: {known}"
        )

    def get(self, agent_id: str, version: str | AgentVersion) -> AgentRegistration | None:
        """The registration at this exact version, or ``None``."""
        try:
            parsed = AgentVersion.parse(version)
        except ValueError:
            return None
        return self._records.get((agent_id, str(parsed)))

    def versions_of(self, agent_id: str) -> tuple[AgentVersion, ...]:
        """Every registered version of one agent, ascending."""
        return tuple(sorted(r.version for r in self._records.values() if r.agent_id == agent_id))

    def agent_ids(self) -> tuple[str, ...]:
        """Every registered agent id, sorted."""
        return tuple(sorted({r.agent_id for r in self._records.values()}))

    def select(self, agent_id: str) -> AgentRegistration | None:
        """The highest **eligible** version of one agent, or ``None``.

        "Highest eligible" rather than "highest": suspending 2.0.0 falls back to an
        active 1.9.0 rather than refusing the agent outright, which is what makes
        suspension a usable operational control rather than an outage.
        """
        candidates = [r for r in self._records.values() if r.agent_id == agent_id and r.eligible]
        return max(candidates, key=lambda r: r.version) if candidates else None

    def resolve(
        self, agent_id: str, version: str | AgentVersion | None = None
    ) -> AgentRegistration | None:
        """The pinned version if one is named, otherwise the selected one."""
        return self.get(agent_id, version) if version is not None else self.select(agent_id)

    # --- discovery -------------------------------------------------------------------

    def discover(
        self,
        *,
        capability: str | None = None,
        department: str | None = None,
        owner: str | None = None,
        status: RegistryStatus | None = None,
        eligible_only: bool = True,
    ) -> tuple[AgentRegistration, ...]:
        """Find registrations matching every supplied filter.

        Args:
            eligible_only: When ``True`` (the default) only registrations that may
                actually receive work are returned. The default is the restrictive one
                deliberately: a discovery surface that lists suspended and revoked agents
                by default is one a caller will eventually delegate to.

        Returns registrations sorted by ``(agent_id, version)`` so the order is stable
        across processes, which matters because this output reaches audit and evidence.
        """
        found = [
            record
            for record in self._records.values()
            if (capability is None or record.declares(capability))
            and (department is None or record.department == department)
            and (owner is None or record.owner == owner)
            and (status is None or record.status is status)
            and (not eligible_only or record.eligible)
        ]
        return tuple(sorted(found, key=lambda r: (r.agent_id, r.version)))

    # --- the delegation question -----------------------------------------------------

    def eligibility(
        self,
        agent_id: str,
        version: str | AgentVersion | None = None,
        *,
        capability: str | None = None,
        identity: str | None = None,
    ) -> EligibilityVerdict:
        """May this agent receive delegated work right now?

        The checks run in a fixed order — exists, version resolves, approved, active,
        declares the capability, matches the identity — and the first failure decides.
        The order is the useful one: a caller told ``UNKNOWN_AGENT`` should not also have
        to wonder whether the capability would have matched.

        Never raises. A refusal is a value, because the caller is a delegation path that
        must record and continue rather than crash.
        """
        try:
            requested = str(AgentVersion.parse(version)) if version is not None else None
        except ValueError as e:
            return EligibilityVerdict(
                agent_id=agent_id,
                requested_version=str(version) if version is not None else None,
                eligible=False,
                refusal=RegistryRefusal.UNKNOWN_VERSION,
                detail=f"invalid version format: {e}",
            )

        def refuse(
            reason: RegistryRefusal, detail: str, record: AgentRegistration | None = None
        ) -> EligibilityVerdict:
            return EligibilityVerdict(
                agent_id=agent_id,
                requested_version=requested,
                eligible=False,
                refusal=reason,
                detail=detail,
                registration=record,
            )

        known = self.versions_of(agent_id)
        if not known:
            return refuse(RegistryRefusal.UNKNOWN_AGENT, f"no agent {agent_id!r} is registered")

        if requested is not None:
            record = self._records.get((agent_id, requested))
            if record is None:
                return refuse(
                    RegistryRefusal.UNKNOWN_VERSION,
                    f"agent {agent_id!r} has no version {requested}; registered: "
                    f"{', '.join(str(v) for v in known)}",
                )
        else:
            record = self.select(agent_id)
            if record is None:
                statuses = ", ".join(
                    f"{r.version}={r.status}"
                    for r in sorted(
                        (r for r in self._records.values() if r.agent_id == agent_id),
                        key=lambda r: r.version,
                    )
                )
                return refuse(
                    RegistryRefusal.NO_SELECTABLE_VERSION,
                    f"agent {agent_id!r} has no eligible version; registered: {statuses}",
                )

        if record.status is RegistryStatus.REVOKED:
            return refuse(
                RegistryRefusal.REVOKED,
                f"{record.coordinate} was revoked: {record.status_reason or 'no reason recorded'}",
                record,
            )
        if record.approval_status is not ApprovalStatus.GRANTED:
            return refuse(
                RegistryRefusal.NOT_APPROVED,
                f"{record.coordinate} has approval status {record.approval_status}; "
                f"only a GRANTED version may receive work",
                record,
            )
        if record.status not in _ELIGIBLE:
            return refuse(
                RegistryRefusal.NOT_ACTIVE,
                f"{record.coordinate} is {record.status}"
                + (f": {record.status_reason}" if record.status_reason else "")
                + "; only an ACTIVE version may receive work",
                record,
            )
        if capability is not None and not record.declares(capability):
            return refuse(
                RegistryRefusal.CAPABILITY_NOT_DECLARED,
                f"{record.coordinate} does not declare capability {capability!r}; declares: "
                f"{', '.join(record.capabilities) or 'none'}",
                record,
            )
        if identity is not None and record.identity != identity:
            return refuse(
                RegistryRefusal.IDENTITY_MISMATCH,
                f"{record.coordinate} is registered under a different identity than the "
                f"one supplied",
                record,
            )

        return EligibilityVerdict(
            agent_id=agent_id,
            requested_version=requested,
            eligible=True,
            refusal=RegistryRefusal.NONE,
            detail=f"{record.coordinate} is {record.status} and approved",
            registration=record,
        )

    # --- history ---------------------------------------------------------------------

    def transitions(self) -> tuple[RegistryTransition, ...]:
        """Every status change this registry made, in order."""
        return tuple(self._transitions)

    def registrations(self) -> tuple[AgentRegistration, ...]:
        """Every registration, sorted by ``(agent_id, version)``."""
        return tuple(sorted(self._records.values(), key=lambda r: (r.agent_id, r.version)))

    def snapshot(self) -> Mapping[str, str]:
        """``{"remediation@1.0.0": "ACTIVE", ...}`` — the fleet, for evidence and health."""
        return {r.coordinate: r.status.value for r in self.registrations()}

    def __len__(self) -> int:
        return len(self._records)

    def __iter__(self) -> Iterator[AgentRegistration]:
        return iter(self.registrations())

    def __contains__(self, agent_id: object) -> bool:
        """Whether *any* version of this id is registered."""
        return isinstance(agent_id, str) and bool(self.versions_of(agent_id))

    def __repr__(self) -> str:
        return f"{type(self).__name__}({len(self._records)} registrations)"


_ELIGIBLE = frozenset({RegistryStatus.ACTIVE})


def _legal_from(status: RegistryStatus) -> frozenset[RegistryStatus]:
    from aegis.registry.records import LEGAL_TRANSITIONS

    return LEGAL_TRANSITIONS.get(status, frozenset())
