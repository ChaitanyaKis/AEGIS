"""The orchestrator — wiring, and nothing more.

It connects the Commander to the deterministic core and to the enterprise:

    COMMANDER -> proposals / tool requests
        -> ORCHESTRATOR
            -> POLICY -> APPROVAL -> STATE MACHINE -> ENTERPRISE
            -> OBSERVATIONS -> VERIFICATION -> AUDIT

What it deliberately is not
---------------------------

It is not a second policy engine. It computes no risk, makes no authorization decision,
grants no approval and decides no state transition. Every one of those is a call into an
existing component, and the orchestrator's own logic is limited to *which* component to
call next and in what order.

Two consequences worth stating, because they are what stop the layer growing teeth:

* It never inspects a decision to decide whether it is *safe* — only which branch of the
  wiring it belongs to. Safety is the policy engine's answer.
* It never constructs an ``Action`` field that a deterministic engine owns. Risk and blast
  radius arrive from the assessment pipeline, and nothing here writes them.

The loop is bounded by an explicit step count. There is no ``while True``, and every
terminal condition is enumerated in :class:`OrchestrationOutcome`.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import datetime
from enum import StrEnum

from pydantic import Field, JsonValue

from aegis.a2a import (
    A2ABroker,
    A2AEnvelope,
    A2AError,
    A2ARejection,
    A2AVerdict,
    AgentDirectory,
    MessageType,
)
from aegis.a2a.remote import RemoteChannel, RemoteDelivery
from aegis.agents.commander import Commander, CommanderContext
from aegis.agents.decisions import CommanderDecision, CommanderProposal, DecisionType
from aegis.agents.findings import AgentFinding
from aegis.agents.model import ModelError
from aegis.agents.specialists import SpecialistTask
from aegis.core.approval import (
    ApprovalEngine,
    ApprovalError,
    ExecutionAuthorization,
)
from aegis.core.approval.fingerprint import action_fingerprint
from aegis.core.assessment import Assessment, AssessmentPipeline
from aegis.core.audit import AuditEventType, AuditRecorder, AuditStore
from aegis.core.capabilities import CapabilityRegistry
from aegis.core.domain import (
    Action,
    Agent,
    DomainModel,
    Incident,
    IncidentState,
    NonEmptyStr,
    PolicyDecisionType,
    utc_now,
)
from aegis.core.incidents import IncidentStateMachine
from aegis.core.policy import PolicyEngine, PolicyEvaluation
from aegis.core.verification import (
    ExpectedState,
    VerificationEngine,
    VerificationResult,
)
from aegis.enterprise import ActionExecutor, EnterpriseWorld, ExecutionResult, ObservationSource
from aegis.lifecycle import (
    AgentRestrictionRegistry,
    CircuitBreaker,
    LifecycleCoordinator,
    LifecycleGateRejected,
    LifecycleLimits,
    LifecycleManager,
    LifecycleRecord,
    LifecycleStatePersistence,
    StopReason,
)
from aegis.orchestration.approval import (
    ApprovalProvider,
    ApprovalVerdict,
    DeterministicApprovalProvider,
)
from aegis.orchestration.delegation import (
    DELEGATION_MATRIX,
    DelegationResult,
    SpecialistRegistry,
)
from aegis.orchestration.tools import GovernedToolbox, ToolKind, ToolRegistry

__all__ = ["DEFAULT_MAX_STEPS", "IncidentOrchestrator", "OrchestrationOutcome", "OrchestrationRun"]

DEFAULT_MAX_STEPS = 8
"""How many Commander decisions one incident may consume before the loop stops."""

PROPOSAL_AUTHORITY: dict[str, frozenset[str]] = {
    "production.rollback": frozenset({"remediation"}),
}
"""Which agent may *propose* which capability.

Separate from, and stricter than, policy. Policy asks whether the accountable agent may
*perform* an action; this asks whether the proposing agent is the right one to have raised
it at all. ``claude.md`` section 7 gives remediation proposals to the Remediation agent, so
the Commander reaches a rollback by delegating — never by drafting one itself.

A capability absent from this map is proposable by nobody.
"""

COMMANDER_TOOLS = frozenset(
    {"get_service_health", "get_metrics", "get_recent_deployments", "get_dependency_health"}
)
"""What the Commander may inspect itself.

Deliberately not everything: security signals belong to the Security agent, and giving the
orchestrating agent every tool would make delegation decorative.
"""

_INTAKE_PATH = (
    IncidentState.RECEIVED,
    IncidentState.CLASSIFIED,
    IncidentState.INVESTIGATING,
    IncidentState.IMPACT_ASSESSED,
    IncidentState.PLAN_PROPOSED,
    IncidentState.POLICY_CHECK,
)
"""The linear prefix of the lifecycle, walked one legal edge at a time."""


class OrchestrationOutcome(StrEnum):
    """Every way a run can end. All of them are terminal and none is a default."""

    RESOLVED = "RESOLVED"
    ESCALATED = "ESCALATED"
    DEGRADED = "DEGRADED"
    """Executed, but verification did not establish the expected state."""

    DENIED = "DENIED"
    """Policy refused the proposal. Nothing executed."""

    APPROVAL_REJECTED = "APPROVAL_REJECTED"
    PROPOSAL_REJECTED = "PROPOSAL_REJECTED"
    """A proposal was malformed, not proposable, or raised by an agent without authority."""

    MODEL_FAILURE = "MODEL_FAILURE"
    """The model timed out, was unavailable or produced invalid output."""

    STEP_LIMIT = "STEP_LIMIT"
    LIFECYCLE_STOPPED = "LIFECYCLE_STOPPED"
    """The lifecycle manager ended the run: a budget was exhausted or the breaker refused.

    Distinct from STEP_LIMIT, which is only ever the step bound. This one carries a
    :class:`~aegis.lifecycle.models.StopReason` naming which limit applied.
    """

    NOT_EXECUTABLE = "NOT_EXECUTABLE"
    """Authorized, but no execution authorization exists for this path. See :meth:`_execute`."""


class OrchestrationRun(DomainModel):
    """Everything one incident produced. Frozen and canonically serializable."""

    incident: Incident
    outcome: OrchestrationOutcome
    detail: NonEmptyStr
    context: CommanderContext
    steps_used: int = Field(ge=0)
    """Commander decisions consumed. This is what ``max_steps`` bounds.

    Distinct from ``len(context.history)``, which also counts steps the orchestrator
    recorded on its own — a recovery, for instance — and so can be larger.
    """
    action: Action | None = None
    assessment: Assessment | None = None
    evaluation: PolicyEvaluation | None = None
    authorization: ExecutionAuthorization | None = None
    execution: ExecutionResult | None = None
    verification: VerificationResult | None = None
    audit_head_digest: str
    lifecycle: LifecycleRecord | None = None
    """Why automation stopped, with counters, the applicable limit and breaker state.

    Present on every run, including a clean resolution: "why did this stop" should be
    answerable for the ordinary case too, not only the alarming ones (Part 9).
    """

    @property
    def resolved(self) -> bool:
        return self.outcome is OrchestrationOutcome.RESOLVED


class IncidentOrchestrator:
    """Runs one incident: Commander decides, the control plane governs, AEGIS records.

    Args:
        commander: The reasoning agent.
        registry: Capability catalogue.
        world: The simulated enterprise.
        commander_agent: Identity the Commander's *reads* are attributed to.
        remediation_agent: Identity a proposed remediation is attributed to. Separate on
            purpose — ``claude.md`` section 7 forbids the Commander from holding
            production-mutation authority, and attributing a rollback to it produces a
            policy DENY rather than a courtesy refusal.
        expected_state: What "recovered" means, for verification.
        approval_provider: How a human is reached. Never a model.
        clock: Injected everywhere, so a run is reproducible.
        max_steps: Hard ceiling on Commander decisions.
    """

    def __init__(
        self,
        commander: Commander,
        registry: CapabilityRegistry,
        world: EnterpriseWorld,
        *,
        commander_agent: Agent,
        remediation_agent: Agent,
        expected_state: ExpectedState,
        approval_provider: ApprovalProvider | None = None,
        tool_registry: ToolRegistry | None = None,
        specialists: SpecialistRegistry | None = None,
        clock: Callable[[], datetime] = utc_now,
        max_steps: int = DEFAULT_MAX_STEPS,
        historical_memory: Mapping[str, JsonValue] | None = None,
        limits: LifecycleLimits | None = None,
        breaker: CircuitBreaker | None = None,
        lifecycle_state: LifecycleStatePersistence | None = None,
        restrictions: AgentRestrictionRegistry | None = None,
        a2a_broker: A2ABroker | None = None,
        remote_channel: RemoteChannel | None = None,
    ) -> None:
        if max_steps < 1:
            raise ValueError("max_steps must be at least 1")
        self.commander = commander
        self.world = world
        self.commander_agent = commander_agent
        self.remediation_agent = remediation_agent
        self.expected_state = expected_state
        self.max_steps = max_steps
        # `limits` is authoritative when supplied; otherwise the caller's max_steps is
        # honoured so existing wiring keeps its meaning. Either way the bound is explicit
        # configuration, and nothing a model produces can reach it.
        self.limits = (
            limits
            if limits is not None
            else LifecycleLimits(
                max_steps=max_steps,
                # A caller supplying only max_steps means "this many decisions"; the
                # derived budgets must fit inside it rather than describing a bound that
                # could never be reached.
                max_recovery_attempts=min(
                    LifecycleLimits.model_fields["max_recovery_attempts"].default, max_steps
                ),
            )
        )
        self.max_steps = self.limits.max_steps
        self.lifecycle = LifecycleManager(
            limits=self.limits,
            breaker=(
                breaker
                if breaker is not None
                # A supplied breaker keeps its own persistence. Otherwise one is built
                # here, durable when the caller provided somewhere to keep it: the
                # orchestrator wires the breaker, it does not decide the storage policy.
                else CircuitBreaker(clock=clock, persistence=lifecycle_state)
            ),
            clock=clock,
        )
        self._clock = clock
        self.historical_memory = dict(historical_memory or {})
        """Organizational history to show the model, as opaque JSON.

        The orchestrator does not import :mod:`aegis.memory` and never will: it carries
        this blob from the caller into ``CommanderContext`` and therefore into
        ``ModelRequest.data``, and reads nothing in it. Keeping the wiring one-directional
        is what stops memory becoming a route into the control plane — no policy, risk,
        approval or verification path here can consult it, because nothing here can parse
        it (Part 13, Part 24).
        """

        self.pipeline = AssessmentPipeline(registry, world.dependency_graph())
        self.policy_engine = PolicyEngine(registry, clock=clock)
        self.approval_engine = ApprovalEngine(self.policy_engine, clock=clock)
        self.verification_engine = VerificationEngine(clock=clock)
        self.machine = IncidentStateMachine(clock=clock)
        # The coordinator owns the gate register; the executor holds it only as a
        # verifier. That asymmetry is the boundary: the executor can check and spend a
        # gate, and has no way to mint one.
        self.coordinator = LifecycleCoordinator(
            self.lifecycle, restrictions=restrictions, clock=clock
        )
        self.executor = ActionExecutor(world, clock=clock, gate_verifier=self.coordinator.verifier)
        self.observations = ObservationSource(world)
        self.audit = AuditStore()
        self.recorder = AuditRecorder(self.audit, clock=clock)
        self.approval_provider = approval_provider or DeterministicApprovalProvider()
        self.registry = tool_registry or ToolRegistry()
        self.toolbox = GovernedToolbox(
            self.registry,
            self.policy_engine,
            world,
            commander_agent,
            allowed_tools=COMMANDER_TOOLS,
            clock=clock,
        )

        self.specialists = specialists
        # The A2A boundary. Built here rather than injected because the *directory* has to
        # describe the fleet this orchestrator actually holds: an agent that is not wired
        # up is not an agent a message may reach. The matrix travels down from
        # `delegation.py` rather than being reached for up from `aegis.a2a`, which is what
        # keeps one delegation policy while leaving the A2A package free of orchestration
        # imports (Part 3 and Part 20 together).
        self.a2a = a2a_broker or A2ABroker(
            AgentDirectory(
                {commander_agent.agent_id, *(specialists.ids() if specialists else ())},
                DELEGATION_MATRIX,
            ),
            clock=clock,
        )
        self.remote = remote_channel
        """The remote A2A boundary, when one is wired up (Prompt 17).

        ``None`` by default, and the local path is then exactly what it was. When a channel
        is present every delegation is serialized, signed, carried over a transport that may
        lose or corrupt it, parsed back, verified against the registry, and only then handed
        to :attr:`a2a` -- *the same broker*, under the identity the signature established
        rather than the identity the wiring asserted.

        Optional rather than mandatory because a remote boundary is a deployment choice, not
        an architectural one. Nothing about policy, approval, risk, the lifecycle gate or
        verification changes in either configuration, which is the property the benchmark's
        remote family exists to measure.
        """

        self.findings: tuple[AgentFinding, ...] = ()
        self._attempt = 0
        self._decisions = 0
        self._last_completed: dict | None = None
        """Artifacts of the most recent remediation that reached execution.

        Kept so a run the lifecycle later stops can still report what actually happened to
        the enterprise. Without it, a third attempt blocked by a budget would return a run
        with no execution and no verification, and an investigator would have to
        reconstruct from the audit log that anything had run at all (Part 37).
        """
        self._incident: Incident | None = None

    # --- lifecycle ------------------------------------------------------------------

    def _advance_to(self, target: IncidentState, *, reason: str, actor: str, **guards) -> None:
        """Walk the intake path to ``target``, one legal edge at a time.

        Every hop goes through the real state machine and is recorded. The orchestrator
        chooses *where to head*; the machine decides whether each step is permitted.
        """
        assert self._incident is not None
        while self._incident.state is not target:
            index = _INTAKE_PATH.index(self._incident.state)
            self._transition(_INTAKE_PATH[index + 1], reason=reason, actor=actor, **guards)

    def _transition(self, to_state: IncidentState, *, reason: str, actor: str, **guards) -> None:
        assert self._incident is not None
        result = self.machine.transition_detailed(
            self._incident, to_state, reason=reason, actor=actor, **guards
        )
        self._incident = result.incident
        self.recorder.record_state_transition(result.transition)

    # --- the loop -------------------------------------------------------------------

    def run(self, incident: Incident, *, affected_resource: str) -> OrchestrationRun:
        """Drive one incident to a terminal outcome.

        Args:
            incident: The incident as received.
            affected_resource: The resource the report concerns, as the reporter named it.
                Untrusted like the rest of the payload — naming a resource does not grant
                access to it, and every read against it is still authorized.

        The Commander chooses what to investigate and when to propose. Whether any of it
        is permitted, and whether the incident may resolve, is decided elsewhere.
        """
        self._incident = incident
        self.lifecycle.begin(incident.incident_id)
        context = CommanderContext(
            incident_id=incident.incident_id,
            incident_payload=_incident_payload(incident, affected_resource),
            lifecycle_state=incident.state,
            historical_memory=self.historical_memory,
        )
        self._transition(
            IncidentState.CLASSIFIED,
            reason=f"incident received from {incident.source}",
            actor=f"agent:{self.commander.agent_id}",
        )
        context = context.with_lifecycle_state(self._incident.state)

        for step in range(self.max_steps):
            # The lifecycle manager gets the first word every iteration: terminal state,
            # step budget, consecutive failures and deadline are all checked before the
            # model is asked for anything.
            verdict = self.lifecycle.may_continue(self._incident.state)
            if verdict.stopped:
                return self._stop_lifecycle(verdict, context)
            self.lifecycle.record_step()
            self._decisions = step + 1
            try:
                decision = self.commander.decide(
                    context,
                    available_tools=self.toolbox.available_tool_ids(),
                    tool_specifications=self.toolbox.available_tool_specifications(),
                    # From the delegation matrix itself, intersected with the fleet this
                    # orchestrator actually holds. Not a second list to keep in step: the
                    # matrix stays the authority, and `dispatch` re-checks the edge on the
                    # way in regardless of what the model was shown.
                    available_specialists=self._delegation_targets(),
                )
            except ModelError as error:
                # A model failure is never permission. State is preserved exactly.
                self._record_model_decision(
                    agent_id=self.commander.agent_id,
                    provider=self.commander.model_name,
                    step=step,
                    error=error,
                )
                return self._finish(
                    OrchestrationOutcome.MODEL_FAILURE,
                    f"model failed at step {step + 1}: {type(error).__name__}: {error}",
                    context,
                )
            self._record_model_decision(
                agent_id=self.commander.agent_id,
                provider=self.commander.model_name,
                step=step,
                decision=decision,
            )

            if decision.decision_type is DecisionType.ESCALATE:
                self._transition(
                    IncidentState.ESCALATED,
                    reason=decision.reasoning_summary,
                    actor=f"agent:{self.commander.agent_id}",
                )
                context = context.with_step(
                    decision=decision,
                    note="commander escalated",
                    lifecycle_state=self._incident.state,
                )
                return self._finish(OrchestrationOutcome.ESCALATED, "commander escalated", context)

            if decision.decision_type is DecisionType.WAIT:
                context = context.with_step(decision=decision, note="commander waited")
                continue

            if decision.decision_type is DecisionType.INVESTIGATE:
                context = self._investigate(decision, context)
                continue

            if decision.decision_type is DecisionType.DELEGATE:
                context, run = self._delegate(decision, context)
                if run is None:
                    continue
                if self._may_recover(run, step):
                    context = self._recover(run)
                    continue
                return run

            run = self._remediate(decision, context, proposing_agent=self.commander.agent_id)
            if self._may_recover(run, step):
                context = self._recover(run)
                continue
            return run

        # Falling out of the loop is itself a lifecycle stop. Routing it through the
        # manager means an exhausted step budget escalates to a human rather than ending
        # the run quietly mid-incident (Part 8).
        return self._stop_lifecycle(self.lifecycle.may_continue(self._incident.state), context)

    def _stop_lifecycle(self, verdict, context: CommanderContext) -> OrchestrationRun:
        """End the run because the lifecycle manager said so.

        An escalating verdict transitions the incident to ESCALATED through the real state
        machine — the manager never sets incident state itself, and adds no terminal state
        of its own. A plain stop leaves the incident where it is, which is what a terminal
        state already being reached means.
        """
        assert self._incident is not None
        if verdict.escalates and self._incident.state not in {
            IncidentState.RESOLVED,
            IncidentState.ESCALATED,
        }:
            self._transition(
                IncidentState.ESCALATED,
                reason=verdict.detail,
                actor="system:lifecycle-manager",
            )
        outcome = (
            OrchestrationOutcome.ESCALATED
            if self._incident.state is IncidentState.ESCALATED
            else OrchestrationOutcome.LIFECYCLE_STOPPED
        )
        return self._finish(
            outcome,
            verdict.detail,
            context,
            lifecycle_decision=verdict,
            **(self._last_completed or {}),
        )

    def _may_recover(self, run: OrchestrationRun, step: int) -> bool:
        """Whether a degraded remediation should be retried rather than ending the run.

        Only a DEGRADED outcome recovers, and only when the lifecycle manager still permits
        it: the recovery budget, the step budget and the breaker are all consulted. Every
        other terminal outcome — denied, rejected, escalated, model failure — stands.
        """
        if run.outcome is not OrchestrationOutcome.DEGRADED:
            return False
        if step + 1 >= self.max_steps:
            return False
        return not self.lifecycle.may_recover(self._incident.state).stopped

    def _recover(self, run: OrchestrationRun) -> CommanderContext:
        """Walk DEGRADED -> RECOVERING -> INVESTIGATING through the real state machine.

        The incident re-enters the workflow at investigation, never at execution: the
        transition table has no edge from either recovery state to EXECUTING, so a second
        remediation must pass through POLICY_CHECK again like the first.
        """
        assert self._incident is not None
        self._transition(
            IncidentState.RECOVERING,
            reason="verification did not establish recovery; attempting again",
            actor=f"agent:{self.commander.agent_id}",
        )
        self._transition(
            IncidentState.INVESTIGATING,
            reason="resuming investigation after a failed remediation",
            actor=f"agent:{self.commander.agent_id}",
        )
        self.lifecycle.record_recovery()
        return run.context.with_step(
            decision=CommanderDecision(
                decision_type=DecisionType.WAIT,
                reasoning_summary="remediation did not verify; the incident has recovered "
                "to investigation",
            ),
            note="recovered to investigation after a failed remediation",
            observation={"recovery_attempt": True},
            lifecycle_state=self._incident.state,
        )

    # --- branches -------------------------------------------------------------------

    def _delegation_targets(self) -> tuple[str, ...]:
        """Who the Commander may delegate to, read from the delegation matrix.

        :meth:`~aegis.orchestration.delegation.SpecialistRegistry.targets_for` already
        intersects the matrix with the specialists that were actually constructed, so this
        is a projection of the one authoritative map rather than a second copy of it. Empty
        when no fleet is wired up, which is the honest answer: an agent that does not exist
        is not one a message may reach.

        Showing the model this list narrows what it can name. It widens nothing —
        ``dispatch`` checks the target, the edge and the task type again on the way in, and
        a delegation the matrix forbids is refused whether or not the model was told.
        """
        if self.specialists is None:
            return ()
        return self.specialists.targets_for(self.commander.agent_id)

    def _investigate(
        self, decision: CommanderDecision, context: CommanderContext
    ) -> CommanderContext:
        """Run one governed read and fold the result into the context."""
        assert self._incident is not None
        assert decision.tool_request is not None
        if self._incident.state is IncidentState.CLASSIFIED:
            self._advance_to(
                IncidentState.INVESTIGATING,
                reason="commander began investigation",
                actor=f"agent:{self.commander.agent_id}",
            )

        result = self.toolbox.invoke(decision.tool_request.tool_id, decision.tool_request.arguments)
        # The *attempt* is recorded, not only the answer. A read that was denied or came
        # back empty is still a read that happened, and a Commander that cannot see it
        # will ask for the same denied tool until the step bound stops it.
        #
        # `detail` travels with the outcome, because the outcome alone is not actionable:
        # INVALID_ARGUMENTS without "missing required argument(s): resource" tells an agent
        # that something is wrong and not what, which is exactly how a loop starts. The
        # detail is AEGIS-authored deterministic text from the toolbox — it grants nothing,
        # and it arrives in the untrusted data channel like every other observation.
        observation = {
            **dict(result.data),
            "tool_attempted": result.tool_id,
            "tool_outcome": str(result.outcome),
            "tool_detail": result.detail,
        }
        return context.with_step(
            decision=decision,
            note=f"{result.tool_id} -> {result.outcome}",
            observation=observation,
            evidence=result.evidence,
            lifecycle_state=self._incident.state,
        )

    def _delegate(
        self, decision: CommanderDecision, context: CommanderContext
    ) -> tuple[CommanderContext, OrchestrationRun | None]:
        """Hand one bounded task to one specialist.

        The Commander names who and what kind of work; the incident, step and bound come
        from authoritative state, so a model cannot misstate which incident it is working
        on. A remediation finding that carries a proposal goes straight into the same
        governance path every other proposal takes.
        """
        assert self._incident is not None
        assert decision.delegation is not None
        request = decision.delegation

        if self.specialists is None:
            return (
                context.with_step(
                    decision=decision, note="delegation unavailable: no specialists registered"
                ),
                None,
            )

        if self._incident.state is IncidentState.CLASSIFIED:
            self._advance_to(
                IncidentState.INVESTIGATING,
                reason="commander began delegated investigation",
                actor=f"agent:{self.commander.agent_id}",
            )

        task = SpecialistTask(
            incident_id=self._incident.incident_id,
            task_type=request.task_type,
            target_resource=request.target_resource,
            evidence_refs=request.evidence_refs,
            incident_payload=context.incident_payload,
            step=context.step,
            max_steps=self.max_steps,
        )

        # Every delegation crosses the A2A boundary first. A refused message means no
        # specialist runs at all, which is the point: identity, ordering, freshness and
        # bounds are settled before any reasoning happens on the message's behalf.
        envelope, refusal = self._open_a2a_message(request, context)
        if envelope is None:
            return (
                context.with_step(
                    decision=decision,
                    note=f"a2a refused: {refusal.rejection}",
                    observation={
                        "delegation_attempted": request.target_agent_id,
                        "a2a_rejection": str(refusal.rejection),
                    },
                    lifecycle_state=self._incident.state,
                ),
                None,
            )

        result = self.specialists.dispatch(self.commander.agent_id, request.target_agent_id, task)

        finding = result.finding
        finding = self._close_a2a_message(envelope, result, finding)
        self._record_model_decision(
            agent_id=request.target_agent_id,
            provider=f"specialist:{request.target_agent_id}",
            step=context.step,
            finding=finding,
            detail=result.outcome.value,
        )
        if finding is not None:
            self.findings = (*self.findings, finding)

        context = context.with_step(
            decision=decision,
            note=f"delegate {request.target_agent_id} -> {result.outcome}",
            observation=_finding_summary(result),
            evidence=finding.supporting_evidence if finding is not None else (),
            lifecycle_state=self._incident.state,
        )

        # A remediation proposal enters governance here. Nothing else a specialist says
        # changes what happens next.
        if finding is not None and finding.proposal is not None:
            proposal_decision = CommanderDecision(
                decision_type=DecisionType.PROPOSE_ACTION,
                reasoning_summary=finding.summary,
                proposal=finding.proposal,
            )
            return context, self._remediate(
                proposal_decision,
                context,
                proposing_agent=finding.agent_id,
                record_step=False,
            )
        return context, None

    def _remediate(
        self,
        decision: CommanderDecision,
        context: CommanderContext,
        *,
        proposing_agent: str,
        record_step: bool = True,
    ) -> OrchestrationRun:
        """Take a proposal through assessment, policy, approval, execution and verification."""
        assert self._incident is not None
        assert decision.proposal is not None

        self._attempt += 1
        self.lifecycle.record_remediation_attempt()
        action, problem = self._build_action(decision.proposal, proposing_agent)
        if action is None:
            context = context.with_step(decision=decision, note=f"proposal rejected: {problem}")
            return self._finish(
                OrchestrationOutcome.PROPOSAL_REJECTED,
                f"commander proposal rejected: {problem}",
                context,
            )

        if record_step:
            context = context.with_step(decision=decision, note="proposal accepted for assessment")
        # Proposing an action records it on the incident. This is a data update, not a
        # lifecycle transition, so it does not go through the state machine — but it is
        # what lets the resolution guard later confirm the verified action was one of
        # this incident's proposals.
        self._incident = self._incident.model_copy(
            update={
                "proposed_actions": (*self._incident.proposed_actions, action.action_id),
                "updated_at": self._clock(),
            }
        )
        self._advance_to(
            IncidentState.PLAN_PROPOSED,
            reason=decision.reasoning_summary,
            actor=f"agent:{self.commander.agent_id}",
        )

        # 1. Deterministic assessment. The proposal carried no risk and gets one here.
        assessment = self.pipeline.assess(action)
        self.recorder.record_assessment(assessment)
        if not assessment.ok:
            self._transition(
                IncidentState.ESCALATED,
                reason=assessment.failure_reason or "assessment failed",
                actor="system:assessment-pipeline",
            )
            return self._finish(
                OrchestrationOutcome.ESCALATED,
                f"assessment could not complete: {assessment.failure_reason}",
                context,
                action=action,
                assessment=assessment,
            )
        action = assessment.require_assessed_action()

        self._advance_to(
            IncidentState.POLICY_CHECK,
            reason="submitting proposal for authorization",
            actor=f"agent:{self.commander.agent_id}",
        )

        # 2. Policy decides. The orchestrator only routes the answer.
        evaluation = self.policy_engine.evaluate_detailed(action, self.remediation_agent)
        self.recorder.record_policy_decision(evaluation, action, self.remediation_agent)
        decision_type = evaluation.decision.decision

        if decision_type is PolicyDecisionType.DENY:
            # Anomaly detection runs here too, with nothing executed. A refusal is not an
            # anomaly — that is the whole point of Part 13 — but a *broken audit chain*
            # discovered during a denied run still is, and only running this check after
            # execution would leave the denial path unwatched.
            self.coordinator.record_governance_anomaly(
                action,
                accountable_agent=self.remediation_agent,
                executed=False,
                authorization_present=False,
                policy_decision=decision_type,
                authorized_action_id=None,
                verified_action_id=None,
                audit_valid=self.audit.verify_integrity().valid,
            )
            self._transition(
                IncidentState.ESCALATED,
                reason=evaluation.decision.reason,
                actor="system:policy-engine",
            )
            return self._finish(
                OrchestrationOutcome.DENIED,
                f"policy denied the proposal: {evaluation.decision.reason}",
                context,
                action=action,
                assessment=assessment,
                evaluation=evaluation,
            )

        # The breaker is asked here, *before* a human is, so a blocked path never spends
        # an approval it cannot use (Part 19). It is asked again immediately before
        # execution, because a breaker that opens in between must still stop the action.
        gate = self.lifecycle.may_remediate(action)
        if gate.stopped:
            self._transition(
                IncidentState.ESCALATED,
                reason=gate.detail,
                actor="system:lifecycle-manager",
            )
            # Deliberately reports the *previous* completed attempt's artifacts rather
            # than this blocked proposal. What an investigator needs from the run object is
            # the last thing that actually reached the enterprise; the blocked proposal is
            # fully described by `detail`, the audit trail and the lifecycle record.
            return self._finish(
                OrchestrationOutcome.ESCALATED,
                gate.detail,
                context,
                lifecycle_decision=gate,
                **(
                    self._last_completed
                    or {"action": action, "assessment": assessment, "evaluation": evaluation}
                ),
            )

        authorization: ExecutionAuthorization | None = None
        if decision_type is PolicyDecisionType.REQUIRE_APPROVAL:
            authorization, rejection = self._seek_approval(action, evaluation)
            if authorization is None:
                return self._finish(
                    OrchestrationOutcome.APPROVAL_REJECTED,
                    rejection or "approval was not granted",
                    context,
                    action=action,
                    assessment=assessment,
                    evaluation=evaluation,
                )
            self._transition(
                IncidentState.EXECUTING,
                reason="human approval consumed",
                actor=f"agent:{self.remediation_agent.agent_id}",
                authorization=authorization,
            )
        else:
            return self._finish(
                OrchestrationOutcome.NOT_EXECUTABLE,
                (
                    "policy allows this action, but execution requires an approval "
                    "artifact and the ALLOW path produces none; not wired in this milestone"
                ),
                context,
                action=action,
                assessment=assessment,
                evaluation=evaluation,
            )

        # 3. The enterprise carries it out — if the lifecycle still permits it.
        #
        # A consumed approval is evidence a human agreed to this action. It is not a token
        # that outranks a stop: if the breaker opened between approval and execution, the
        # action does not run, the incident does not resolve, and the blocked attempt is
        # never recorded as a success (Part 20).
        fingerprint = action_fingerprint(action)
        final_gate = self.lifecycle.may_execute(action, fingerprint)
        if final_gate.stopped:
            self._transition(
                IncidentState.ESCALATED,
                reason=final_gate.detail,
                actor="system:lifecycle-manager",
            )
            # Nothing executed under this authorization. Reporting the previous completed
            # attempt keeps the run honest about what reached production; a blocked action
            # is never dressed up as one that ran (Part 20).
            return self._finish(
                OrchestrationOutcome.ESCALATED,
                final_gate.detail,
                context,
                lifecycle_decision=final_gate,
                **(
                    self._last_completed
                    or {
                        "action": action,
                        "assessment": assessment,
                        "evaluation": evaluation,
                        "authorization": authorization,
                    }
                ),
            )

        # The gate is requested here, after approval and immediately before execution,
        # so it proves the lifecycle was crossed for *this* attempt. A refusal is routed
        # into an escalation rather than raised: a blocked action must become a recorded
        # stop, never an exception something upstream might swallow into success.
        issue = self.coordinator.request_gate(
            action,
            accountable_agent=self.remediation_agent,
            incident_state=self._incident.state,
            lifecycle_decision=final_gate,
        )
        self._record_gate(issue, action, final_gate)
        if not issue.issued:
            self._transition(
                IncidentState.ESCALATED,
                reason=issue.refused_reason or "the lifecycle gate was refused",
                actor="system:lifecycle-coordinator",
            )
            return self._finish(
                OrchestrationOutcome.ESCALATED,
                issue.refused_reason or "the lifecycle gate was refused",
                context,
                lifecycle_decision=final_gate,
                **(
                    self._last_completed
                    or {
                        "action": action,
                        "assessment": assessment,
                        "evaluation": evaluation,
                        "authorization": authorization,
                    }
                ),
            )

        try:
            execution = self.executor.execute(
                action, authorization, at=self._clock(), gate=issue.gate
            )
        except LifecycleGateRejected as refusal:
            # The executor refused the gate. That is the boundary working, and it must
            # become a recorded stop rather than an exception escaping the run — an
            # exception is something a caller might swallow into success.
            self.recorder.record_gate_event(
                AuditEventType.LIFECYCLE_GATE_REJECTED,
                gate_id=refusal.rejection.gate_id,
                incident_id=action.incident_id,
                action_id=action.action_id,
                action_fingerprint=fingerprint,
                lifecycle_scope=self.lifecycle.scope_for(action),
                lifecycle_state=self._incident.state.value,
                breaker_state=self.lifecycle.breaker.state_of(
                    self.lifecycle.scope_for(action)
                ).value,
                reason=f"{refusal.rejection.check}: {refusal.rejection.reason}",
            )
            self._transition(
                IncidentState.ESCALATED,
                reason=f"the lifecycle gate was rejected: {refusal.rejection.reason}",
                actor="system:action-executor",
            )
            return self._finish(
                OrchestrationOutcome.ESCALATED,
                f"the lifecycle gate was rejected at {refusal.rejection.check}: "
                f"{refusal.rejection.reason}",
                context,
                lifecycle_decision=final_gate,
                **(
                    self._last_completed
                    or {
                        "action": action,
                        "assessment": assessment,
                        "evaluation": evaluation,
                        "authorization": authorization,
                    }
                ),
            )
        # Counted after the executor accepted, so `execution_count` means "executions the
        # enterprise actually performed". A refused gate is not an execution, and counting
        # one would make the gate-bypass check — executions versus gates consumed — unable
        # to tell a blocked attempt from a real bypass.
        self.lifecycle.record_execution(fingerprint)
        self._record_gate_consumed(issue.gate)
        self._transition(
            IncidentState.VERIFYING,
            reason=f"execution reported {execution.outcome}",
            actor=f"agent:{self.remediation_agent.agent_id}",
        )

        # 4. Verification looks at the world, never at what execution reported.
        observations = self.observations.observe(action.target_resource, at=self._clock())
        verification = self.verification_engine.verify(
            action,
            self.expected_state,
            observations,
            verification_id=f"ver-{self._incident.incident_id}-{self._attempt}",
        )
        self.recorder.record_verification(verification)

        # Execution and verification are classified separately and thresholded separately:
        # an action the enterprise refused and one that ran without taking effect are
        # different problems (Part 21).
        before = self.coordinator.check_restriction(
            action, accountable_agent=self.remediation_agent
        )
        self.coordinator.record_outcome(
            action,
            accountable_agent=self.remediation_agent,
            execution_outcome=execution.outcome,
            verification_status=verification.status,
            verification_id=verification.verification_id,
        )
        self._record_restriction_applied(
            action,
            before,
            self.coordinator.check_restriction(action, accountable_agent=self.remediation_agent),
        )
        self.coordinator.record_governance_anomaly(
            action,
            accountable_agent=self.remediation_agent,
            executed=True,
            authorization_present=authorization is not None,
            policy_decision=decision_type,
            authorized_action_id=(
                authorization.approval.action_id if authorization is not None else None
            ),
            verified_action_id=verification.action_id,
            audit_valid=self.audit.verify_integrity().valid,
        )

        if verification.verified:
            self._transition(
                IncidentState.RESOLVED,
                reason=verification.reason,
                actor="system:verification",
                verification=verification,
                action=action,
            )
            outcome, detail = OrchestrationOutcome.RESOLVED, verification.reason
        else:
            self._transition(
                IncidentState.DEGRADED,
                reason=verification.reason,
                actor="system:verification",
            )
            outcome, detail = OrchestrationOutcome.DEGRADED, verification.reason

        self._last_completed = {
            "action": action,
            "assessment": assessment,
            "evaluation": evaluation,
            "authorization": authorization,
            "execution": execution,
            "verification": verification,
        }
        return self._finish(outcome, detail, context, **self._last_completed)

    def _seek_approval(
        self, action: Action, evaluation: PolicyEvaluation
    ) -> tuple[ExecutionAuthorization | None, str | None]:
        """Raise an approval, ask a human, and spend it if they said yes.

        The model is not consulted anywhere in this method.
        """
        assert self._incident is not None
        self._transition(
            IncidentState.AWAITING_APPROVAL,
            reason=evaluation.decision.reason,
            actor="system:policy-engine",
            policy_decision=evaluation.decision,
        )
        try:
            pending = self.approval_engine.request(
                approval_id=f"apr-{self._incident.incident_id}-{self._attempt}",
                action=action,
                agent=self.remediation_agent,
                decision=evaluation.decision,
            )
            self.recorder.record_approval(pending)

            verdict = self.approval_provider.review(pending)
            if verdict is not ApprovalVerdict.GRANT:
                rejected = self.approval_engine.reject(pending, by=self.approval_provider.approver)
                self.recorder.record_approval(rejected)
                self._transition(
                    IncidentState.PLAN_PROPOSED,
                    reason="human rejected the proposed remediation",
                    actor=self.approval_provider.approver,
                )
                return None, "a human rejected the proposed remediation"

            approved = self.approval_engine.approve(pending, by=self.approval_provider.approver)
            self.recorder.record_approval(approved)
            authorization = self.approval_engine.consume_for_execution(
                approved, action, self.remediation_agent
            )
            self.recorder.record_approval(authorization.approval)
            return authorization, None
        except ApprovalError as error:
            return None, f"approval could not be completed: {error}"

    # --- proposal adapter -----------------------------------------------------------

    def _build_action(
        self, proposal: CommanderProposal, proposing_agent: str
    ) -> tuple[Action | None, str | None]:
        """Turn a validated proposal into an ``Action``, or explain why not.

        The one place model output becomes a control-plane object. It refuses anything the
        registry does not declare proposable, and anything whose arguments do not match the
        declared schema. The resulting Action carries no risk and no blast radius — those
        are the assessment pipeline's to supply.
        """
        assert self._incident is not None
        permitted = PROPOSAL_AUTHORITY.get(proposal.capability_id, frozenset())
        if proposing_agent not in permitted:
            return None, (
                f"{proposing_agent} may not propose {proposal.capability_id!r}; only "
                f"{', '.join(sorted(permitted)) or 'no agent'} may"
            )
        registry = self.registry
        tool = registry.proposable(proposal.capability_id)
        if tool is None:
            return None, (
                f"capability {proposal.capability_id!r} is not proposable; proposable "
                f"capabilities: {', '.join(registry.ids(kind=ToolKind.PROPOSE)) or 'none'}"
            )
        problem = registry.validate_arguments(tool, proposal.arguments)
        if problem is not None:
            return None, f"{proposal.capability_id}: {problem}"
        if not self.world.contains(proposal.target_resource):
            return None, f"resource {proposal.target_resource!r} is not declared"

        return (
            Action(
                action_id=f"act-{self._incident.incident_id}-{self._attempt}",
                incident_id=self._incident.incident_id,
                requesting_agent=self.remediation_agent.agent_id,
                capability=proposal.capability_id,
                target_resource=proposal.target_resource,
                arguments=dict(proposal.arguments),
                evidence=proposal.evidence_references,
            ),
            None,
        )

    # --- result ---------------------------------------------------------------------

    def _finish(
        self,
        outcome: OrchestrationOutcome,
        detail: str,
        context: CommanderContext,
        *,
        lifecycle_decision=None,
        **artifacts,
    ) -> OrchestrationRun:
        """Assemble the run, including the structured account of why it ended.

        The lifecycle record is produced for *every* outcome, not only for stops the
        manager caused: "why did automation stop, how many attempts were there, what was
        the breaker doing" should be answerable for a clean resolution too (Part 9).
        """
        assert self._incident is not None
        record = self.lifecycle.finish(
            final_state=self._incident.state,
            decision=lifecycle_decision,
            detail=detail,
        )
        if lifecycle_decision is not None and lifecycle_decision.stopped:
            self._record_lifecycle_stop(record)
        return OrchestrationRun(
            incident=self._incident,
            outcome=outcome,
            detail=detail,
            context=context.with_lifecycle_state(self._incident.state),
            steps_used=self._decisions,
            audit_head_digest=self.audit.head_digest,
            lifecycle=record,
            **artifacts,
        )

    # --- the A2A boundary -----------------------------------------------------------

    def _conversation_id(self) -> str:
        """One conversation per incident. Deterministic, so a run stays reproducible."""
        assert self._incident is not None
        return f"conv-{self._incident.incident_id}"

    def _open_a2a_message(self, request, context) -> tuple[A2AEnvelope | None, A2AVerdict | None]:
        """Issue, send and admit one delegation message.

        ``accountable_sender`` is ``self.commander.agent_id`` — the identity from the
        wiring, never the one a model wrote. A Commander whose model claimed to be
        remediation would still issue as the Commander, and :meth:`A2ABroker.admit`
        re-checks the same equality for anything arriving by another route.

        Returns:
            ``(envelope, None)`` when the message was admitted, ``(None, verdict)`` when it
            was refused. A refusal is a value the caller must unpack, not an exception it
            could forget to catch.
        """
        assert self._incident is not None
        task_id = f"task-{self._incident.incident_id}-{context.step}"
        try:
            return self._issue_and_admit(request, context, task_id)
        except A2AError as error:
            # Durable state could not be read or written. That is a refusal, not a crash:
            # the delegation does not happen, the refusal is recorded, and the lifecycle
            # decides what follows. A persistence failure must never be the reason
            # something is delivered — and an unhandled exception here would skip the very
            # audit record that proves it was not.
            refusal = A2AVerdict.refuse(
                A2ARejection.MALFORMED,
                f"A2A state is unusable: {type(error).__name__}: {error}",
            )
            self._record_a2a(None, "REFUSED", refusal, task_id=task_id, request=request)
            return None, refusal

    def _issue_and_admit(self, request, context, task_id):
        """The message path proper. Separated so every A2A failure has one place to be caught."""
        assert self._incident is not None
        issued = self.a2a.issue(
            accountable_sender=self.commander.agent_id,
            recipient_agent_id=request.target_agent_id,
            incident_id=self._incident.incident_id,
            conversation_id=self._conversation_id(),
            task_id=task_id,
            task_type=request.task_type,
            message_type=MessageType.TASK_REQUEST,
            target_resource=request.target_resource,
            evidence_refs=request.evidence_refs,
            payload=dict(context.incident_payload),
        )
        if isinstance(issued, A2AVerdict):
            self._record_a2a(None, "REFUSED", issued, task_id=task_id, request=request)
            return None, issued

        self._record_a2a(issued, "ISSUED", None)
        sent = self.a2a.send(issued)
        if not sent.accepted:
            self._record_a2a(issued, "REJECTED", sent)
            return None, sent

        recipient = self.specialists.get(request.target_agent_id) if self.specialists else None
        handles = recipient.task_type if recipient is not None else None
        if self.remote is None:
            verdict = self.a2a.admit(
                issued,
                accountable_sender=self.commander.agent_id,
                expected_incident_id=self._incident.incident_id,
                expected_conversation_id=self._conversation_id(),
                expected_task_id=task_id,
                recipient_handles=handles,
            )
        else:
            verdict = self._admit_remotely(issued, recipient, handles)
        self._record_a2a(issued, "ACCEPTED" if verdict.accepted else "REJECTED", verdict)
        if not verdict.accepted:
            self.a2a.reject(issued, verdict)
            return None, verdict
        return issued, None

    def _admit_remotely(self, issued: A2AEnvelope, recipient, handles) -> A2AVerdict:
        """Carry one delegation across the remote boundary and admit what comes back.

        The whole of the integration, and deliberately small. The message is signed as
        ``self.commander.agent_id`` -- the wiring, never a model's claim -- put on the
        transport, taken off, authenticated, and then handed to the *same*
        :meth:`A2ABroker.admit` the local path uses, with ``accountable_sender`` supplied by
        the signature instead of by this method.

        Every refusal on the way becomes an ordinary :class:`A2AVerdict`, so the caller
        above cannot tell a remote refusal from a local one and does not need to. What it
        must never be able to do is mistake one for a delivery, which is why there is no
        path here that returns an acceptance without ``delivery.admitted`` being true.
        """
        assert self._incident is not None
        as_agent = recipient.agent_id if recipient is not None else issued.recipient_agent_id
        delivery = self.remote.carry(
            issued,
            signed_by=self.commander.agent_id,
            as_agent=as_agent,
            expected_incident_id=self._incident.incident_id,
            expected_conversation_id=issued.conversation_id,
            recipient_handles=handles,
        )
        self._record_remote(issued, delivery)
        if delivery.local is not None:
            return delivery.local
        return A2AVerdict.refuse(
            A2ARejection.MALFORMED,
            f"remote boundary refused the message: {delivery.verdict.rejection} "
            f"({delivery.verdict.detail})",
            issued.message_id,
        )

    def _record_remote(self, envelope: A2AEnvelope, delivery: RemoteDelivery) -> None:
        """Record one ``remote.authentication`` event. Identifiers and a digest only.

        Recorded for refusals as well as successes, and with the *claimed* and
        *authenticated* agent ids kept apart. A trail that showed only the established
        identity could not show the moment a claim and a fact disagreed, and that moment is
        the one worth having a record of.
        """
        assert self._incident is not None
        # The *authentication* verdict, not the final outcome. A message that authenticated
        # perfectly and was then refused locally must appear here as AUTHENTICATED, or the
        # trail could not distinguish "we could not tell who sent this" from "we knew
        # exactly who sent it and refused it anyway" -- which are different incidents.
        verdict = delivery.authentication
        self.recorder.record_remote_authentication(
            incident_id=self._incident.incident_id,
            message_id=envelope.message_id,
            conversation_id=envelope.conversation_id,
            claimed_agent_id=envelope.sender_agent_id,
            status="AUTHENTICATED" if verdict.authenticated else "REFUSED",
            protocol_version=self.remote.protocol_version,
            key_id=verdict.key_id,
            authenticated_agent_id=verdict.agent_id if verdict.authenticated else None,
            digest=envelope.seal,
            rejection=verdict.rejection.value if verdict.rejection else None,
        )

    def _close_a2a_message(self, request_envelope: A2AEnvelope, result, finding):
        """Return the specialist's answer as a bound response, and check who it came from.

        Part 9. A finding survives only if the response's sender is the agent the request
        was sent to *and* the finding claims that same agent *and* the finding is about this
        incident. Any mismatch drops the finding: a transport that let a specialist return
        another specialist's conclusion would be an identity system with a hole in it.
        """
        assert self._incident is not None
        try:
            return self._issue_response(request_envelope, result, finding)
        except A2AError as error:
            self._record_a2a(
                None,
                "REFUSED",
                A2AVerdict.refuse(
                    A2ARejection.MALFORMED,
                    f"A2A state is unusable: {type(error).__name__}: {error}",
                ),
                task_id=request_envelope.task_id,
            )
            return None

    def _issue_response(self, request_envelope: A2AEnvelope, result, finding):
        """The response path proper, so a persistence failure here is a refusal too."""
        assert self._incident is not None
        response = self.a2a.issue(
            accountable_sender=request_envelope.recipient_agent_id,
            recipient_agent_id=request_envelope.sender_agent_id,
            incident_id=request_envelope.incident_id,
            conversation_id=request_envelope.conversation_id,
            task_id=request_envelope.task_id,
            task_type=request_envelope.task_type,
            message_type=MessageType.TASK_RESULT,
            target_resource=request_envelope.target_resource,
            evidence_refs=result.result.observations if result.result is not None else (),
            payload={"outcome": result.outcome.value, "detail": result.detail},
        )
        if isinstance(response, A2AVerdict):
            self._record_a2a(None, "REFUSED", response, task_id=request_envelope.task_id)
            return None

        if self.remote is None:
            bound = self.a2a.bind_response(request_envelope, response, finding)
        else:
            # The answer crosses the same boundary the request did, signed by the
            # specialist that produced it. A response is *bound*, never *admitted* --
            # the delegation matrix says a specialist may send to nobody, which is right
            # for delegation and wrong for a reply, so the remote path mirrors the local
            # asymmetry rather than inventing a second rule.
            delivery = self.remote.carry_response(
                response,
                request_envelope,
                finding,
                signed_by=request_envelope.recipient_agent_id,
                as_agent=request_envelope.sender_agent_id,
            )
            self._record_remote(response, delivery)
            bound = (
                delivery.local
                if delivery.local is not None
                else A2AVerdict.refuse(
                    A2ARejection.RESPONSE_IDENTITY_MISMATCH,
                    f"remote boundary refused the response: {delivery.verdict.rejection} "
                    f"({delivery.verdict.detail})",
                    response.message_id,
                )
            )
        self._record_a2a(
            response,
            "COMPLETED" if bound.accepted else "REJECTED",
            bound,
            finding_id=finding.finding_id if finding is not None else None,
        )
        return finding if bound.accepted else None

    def _record_a2a(
        self,
        envelope: A2AEnvelope | None,
        status: str,
        verdict: A2AVerdict | None,
        *,
        task_id: str | None = None,
        request=None,
        finding_id: str | None = None,
    ) -> None:
        """Record one A2A message event. Identifiers and a digest, never payload text."""
        assert self._incident is not None
        rejection = verdict.rejection.value if verdict and verdict.rejection else None
        if envelope is None:
            # A message that could not even be built still leaves a trail, or a refused
            # delegation would be indistinguishable from one never attempted.
            self.recorder.record_a2a_message(
                incident_id=self._incident.incident_id,
                message_id=verdict.message_id if verdict and verdict.message_id else "unissued",
                conversation_id=self._conversation_id(),
                sender_agent_id=self.commander.agent_id,
                recipient_agent_id=(request.target_agent_id if request is not None else "unknown"),
                task_id=task_id or "unknown",
                task_type=(request.task_type.value if request is not None else "UNKNOWN"),
                status=status,
                digest="none",
                sequence=0,
                rejection=rejection,
            )
            return
        self.recorder.record_a2a_message(
            incident_id=self._incident.incident_id,
            message_id=envelope.message_id,
            conversation_id=envelope.conversation_id,
            sender_agent_id=envelope.sender_agent_id,
            recipient_agent_id=envelope.recipient_agent_id,
            task_id=envelope.task_id,
            task_type=envelope.task_type.value,
            status=status,
            digest=envelope.seal,
            sequence=envelope.sequence,
            target_resource=envelope.target_resource,
            rejection=rejection,
            finding_id=finding_id,
        )

    def _record_model_decision(
        self,
        *,
        agent_id: str,
        provider: str,
        step: int,
        decision: CommanderDecision | None = None,
        finding: AgentFinding | None = None,
        error: BaseException | None = None,
        detail: str | None = None,
    ) -> None:
        """Record what the reasoning layer asked for, before anything decides about it.

        Written for every model call — decision, finding and failure alike — so the trail
        answers "what did the model want" independently of "what was allowed". Those are
        different facts and Part 12 requires them to stay distinguishable.

        Nothing provider-specific reaches this method or the recorder it calls. It passes
        the provider's own ``name``, an agent id and enum values; it imports no provider
        module, holds no client and cannot tell which implementation answered. That is
        what keeps orchestration provider-independent while still recording the provider.
        """
        assert self._incident is not None
        proposal = decision.proposal if decision is not None else None
        if proposal is None and finding is not None:
            proposal = finding.proposal
        decision_type = None
        if decision is not None:
            decision_type = decision.decision_type.value
        elif finding is not None:
            decision_type = finding.finding_type.value
        elif error is None and detail:
            decision_type = detail
        self.recorder.record_model_decision(
            incident_id=self._incident.incident_id,
            agent_id=agent_id,
            provider=provider,
            step=step,
            decision_type=decision_type,
            tool_id=decision.tool_request.tool_id
            if decision is not None and decision.tool_request
            else None,
            delegate_to=decision.delegation.target_agent_id
            if decision is not None and decision.delegation
            else None,
            proposed_capability=proposal.capability_id if proposal is not None else None,
            proposed_resource=proposal.target_resource if proposal is not None else None,
            failure_type=type(error).__name__ if error is not None else None,
        )

    def _record_gate(self, issue, action, decision) -> None:
        """Write the gate issue or refusal into the audit log.

        Both are recorded. A refusal is the boundary working and is exactly what an
        investigator looking for attempted bypasses needs to find; recording only the
        successes would make a blocked attempt indistinguishable from one that never
        happened.
        """
        assert self._incident is not None
        gate = issue.gate
        scope = self.lifecycle.scope_for(action)
        self.recorder.record_gate_event(
            AuditEventType.LIFECYCLE_GATE_ISSUED
            if issue.issued
            else AuditEventType.LIFECYCLE_GATE_REJECTED,
            gate_id=gate.gate_id if gate else f"gate-refused-{action.action_id}",
            incident_id=action.incident_id,
            action_id=action.action_id,
            action_fingerprint=action_fingerprint(action),
            lifecycle_scope=scope,
            lifecycle_state=self._incident.state.value,
            breaker_state=self.lifecycle.breaker.state_of(scope).value,
            reason=issue.refused_reason or f"gate issued under {decision.action}",
        )
        restriction = issue.restriction
        if restriction is not None and not restriction.permitted:
            self.recorder.record_agent_restriction(
                AuditEventType.AGENT_RESTRICTION_REFUSED,
                agent_id=restriction.agent_id,
                scope_key=restriction.scope_key,
                restriction=restriction.restriction.value,
                reason=restriction.reason,
                incident_id=action.incident_id,
                capability=action.capability,
                resource=action.target_resource,
                action_fingerprint=action_fingerprint(action),
                counters={k: str(v) for k, v in restriction.failure_counts.items()},
            )

    def _record_gate_consumed(self, gate) -> None:
        assert self._incident is not None
        self.recorder.record_gate_event(
            AuditEventType.LIFECYCLE_GATE_CONSUMED,
            gate_id=gate.gate_id,
            incident_id=gate.incident_id,
            action_id=gate.action_id,
            action_fingerprint=gate.action_fingerprint,
            lifecycle_scope=gate.lifecycle_scope,
            lifecycle_state=self._incident.state.value,
            breaker_state=gate.breaker_state.value,
            reason="spent by the execution it was issued for",
        )

    def _record_restriction_applied(self, action, before, after) -> None:
        """Record a quarantine the moment it is applied, not merely when it next refuses."""
        if before is None or after is None or before.quarantined or not after.quarantined:
            return
        assert self._incident is not None
        self.recorder.record_agent_restriction(
            AuditEventType.AGENT_RESTRICTION_APPLIED,
            agent_id=after.agent_id,
            scope_key=after.scope_key,
            restriction=after.restriction.value,
            reason=after.reason,
            incident_id=action.incident_id,
            capability=action.capability,
            resource=action.target_resource,
            failure_class=after.trip_class.value if after.trip_class else None,
            action_fingerprint=action_fingerprint(action),
            counters={k: str(v) for k, v in after.failure_counts.items()},
        )

    def _record_lifecycle_stop(self, record: LifecycleRecord) -> None:
        """Write the stop, and the breaker's state if it caused it, into the audit log.

        Emitted only when the lifecycle actually stopped something. A clean resolution
        still produces a :class:`LifecycleRecord` on the run, but writing a
        ``lifecycle.stopped`` event for it would make the trail say automation was halted
        when it simply finished.
        """
        counters = record.counters
        self.recorder.record_lifecycle_stop(
            incident_id=record.incident_id,
            stop_reason=record.stop_reason.value,
            detail=record.detail,
            counters={
                "steps_used": str(counters.steps_used),
                "remediation_attempts": str(counters.remediation_attempts),
                "recovery_attempts": str(counters.recovery_attempts),
                "execution_count": str(counters.execution_count),
                "consecutive_failures": str(counters.consecutive_failures),
            },
            limit_name=record.limit_name,
            limit_value=record.limit_value,
        )
        if record.stop_reason is StopReason.CIRCUIT_OPEN and record.breaker is not None:
            self.recorder.record_circuit_event(
                AuditEventType.CIRCUIT_OPENED,
                scope_key=record.breaker.scope_key,
                state=record.breaker.state.value,
                reason=record.breaker.opened_reason or "breaker open",
                incident_id=record.incident_id,
                trip_class=(record.breaker.trip_class.value if record.breaker.trip_class else None),
            )

    def __repr__(self) -> str:
        return f"{type(self).__name__}(commander={self.commander!r}, max_steps={self.max_steps})"


def _incident_payload(incident: Incident, affected_resource: str) -> dict:
    """The incident as untrusted data for the model.

    Everything here came from outside AEGIS (``claude.md`` section 4, zone A) and is
    passed through as data. It is never formatted into an instruction.
    """
    return {
        "source": incident.source,
        "severity": incident.severity.value,
        "affected_resource": affected_resource,
        "evidence": [
            {
                "evidence_id": item.evidence_id,
                "source": item.source,
                "reference": item.reference,
                "type": item.type.value,
            }
            for item in incident.evidence
        ],
    }


def _finding_summary(result: DelegationResult) -> dict:
    """A delegation's outcome as data for the Commander's next step.

    Deliberately labelled. The Commander sees ``finding_summary`` — an agent's conclusion —
    alongside ``supporting_evidence``, which are the observation ids behind it. Keeping
    them distinct is what stops a synthesis from quietly promoting a conclusion into a
    measurement (``claude.md`` section 11).
    """
    finding = result.finding
    if finding is None:
        return {
            "delegation_outcome": result.outcome.value,
            "delegation_detail": result.detail,
            "delegation_attempted": result.target_agent_id,
        }
    return {
        "delegation_outcome": result.outcome.value,
        "delegation_attempted": result.target_agent_id,
        "finding_from_agent": finding.agent_id,
        "finding_type": finding.finding_type.value,
        "finding_summary": finding.summary,
        "finding_confidence": finding.confidence,
        "finding_recommended_next_step": finding.recommended_next_step,
        "supporting_evidence": list(finding.supporting_evidence),
    }
