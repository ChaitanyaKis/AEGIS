"""The golden incident, as an executable scenario.

**CONTROLLED SIMULATION** (``claude.md`` sections 14, 16, 17).

    payment-api on v4.8, 37% error rate, unhealthy
      -> assessment -> policy -> approval -> authorized execution
      -> changed world -> observations -> verification -> RESOLVED
      -> complete audit trail

Every stage runs the real engine. The scenario sets no risk, no blast radius, no policy
decision, no approval status, no verification status and no final incident state — each of
those is whatever the control plane computed. Its only job is wiring: it moves artifacts
between the components in the right order and records each one.

The capability registry and the agent record are injected rather than defined here. Those
are organizational configuration, not part of the synthetic enterprise, and the scenario
should be reusable against a different catalogue without editing this module.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from datetime import UTC, datetime, timedelta

from aegis.core.approval import ApprovalEngine, ExecutionAuthorization
from aegis.core.assessment import Assessment, AssessmentPipeline
from aegis.core.audit import AuditRecorder, AuditStore
from aegis.core.capabilities import CapabilityRegistry
from aegis.core.domain import (
    Action,
    Agent,
    DomainModel,
    Incident,
    IncidentState,
    RiskLevel,
    utc_now,
)
from aegis.core.incidents import IncidentStateMachine
from aegis.core.policy import PolicyEngine, PolicyEvaluation
from aegis.core.verification import (
    Comparator,
    ExpectedState,
    Observation,
    Predicate,
    VerificationEngine,
    VerificationResult,
)
from aegis.enterprise.failures import FailureType
from aegis.enterprise.models import WorldSnapshot
from aegis.enterprise.mutations import ActionExecutor, ExecutionResult
from aegis.enterprise.observations import ObservationSource
from aegis.enterprise.topology import (
    PAYMENT_API,
    PAYMENT_API_GOOD_VERSION,
    build_dependency_graph,
)
from aegis.enterprise.world import EnterpriseWorld

__all__ = [
    "GOLDEN_ACTION_ID",
    "GOLDEN_APPROVAL_ID",
    "GOLDEN_INCIDENT_ID",
    "GOLDEN_VERIFICATION_ID",
    "PAYMENT_API_RECOVERED",
    "GoldenIncidentRun",
    "GoldenIncidentScenario",
]

GOLDEN_INCIDENT_ID = "INC-2026-0001"
GOLDEN_ACTION_ID = "act-001"
GOLDEN_APPROVAL_ID = "apr-001"
GOLDEN_VERIFICATION_ID = "ver-001"

PAYMENT_API_RECOVERED = ExpectedState(
    resource=PAYMENT_API,
    predicates=(
        Predicate(attribute="health", comparator=Comparator.EQUALS, value="healthy"),
        Predicate(attribute="error_rate", comparator=Comparator.AT_MOST, value=1.0),
        Predicate(
            attribute="deployment",
            comparator=Comparator.EQUALS,
            value=PAYMENT_API_GOOD_VERSION,
        ),
    ),
    max_observation_age=timedelta(minutes=5),
    accepted_sources=("telemetry.payment-api", "deployments.payment-api"),
)
"""What "the rollback worked" means for the golden incident.

Three conditions, all required: the service reports healthy, its error rate is at or below
1%, and it is running v4.7. Evidence must be under five minutes old and must come from the
two declared feeds — a status page or an agent's opinion establishes nothing.
"""

INCIDENT_OPENED_AT = datetime(2026, 1, 1, 11, 0, 0, tzinfo=UTC)
"""When the golden incident was raised. Before any scenario clock, so ``updated_at`` holds."""


class GoldenIncidentRun(DomainModel):
    """Everything one run produced, for inspection and comparison.

    Frozen and canonically serializable, so two runs can be compared byte for byte.
    """

    world_before: WorldSnapshot
    world_after: WorldSnapshot
    assessment: Assessment
    evaluation: PolicyEvaluation
    authorization: ExecutionAuthorization | None = None
    execution: ExecutionResult
    observations: tuple[Observation, ...]
    verification: VerificationResult
    incident: Incident
    """The incident in whatever state the control plane actually left it."""

    audit_head_digest: str
    """Commits to the entire audit trail for this run."""

    @property
    def resolved(self) -> bool:
        return self.incident.state is IncidentState.RESOLVED


class GoldenIncidentScenario:
    """Runs the golden incident against a simulated enterprise.

    Args:
        registry: The capability catalogue to authorize against.
        agent: The control-plane record for the remediation agent proposing the rollback.
        clock: The scenario's clock. Everything time-dependent reads from it, so freshness
            and expiry behave predictably.
        world: The world to act on. A fresh one starts at the golden condition.
        approver: Who signs the approval off.

    A scenario instance owns one world and one audit store, and is meant to be run once.
    """

    def __init__(
        self,
        registry: CapabilityRegistry,
        agent: Agent,
        *,
        clock: Callable[[], datetime] = utc_now,
        world: EnterpriseWorld | None = None,
        approver: str = "human:oncall",
    ) -> None:
        self._clock = clock
        self._approver = approver
        self.world = world if world is not None else EnterpriseWorld()
        self.agent = agent

        self.pipeline = AssessmentPipeline(registry, build_dependency_graph())
        self.policy_engine = PolicyEngine(registry, clock=clock)
        self.approval_engine = ApprovalEngine(self.policy_engine, clock=clock)
        self.verification_engine = VerificationEngine(clock=clock)
        self.machine = IncidentStateMachine(clock=clock)
        self.executor = ActionExecutor(self.world, clock=clock)
        self.observations = ObservationSource(self.world)
        self.audit = AuditStore()
        self.recorder = AuditRecorder(self.audit, clock=clock)

    # --- setup ----------------------------------------------------------------------

    def inject(self, *failures: FailureType) -> GoldenIncidentScenario:
        """Turn on simulation controls before running. Returns self for chaining."""
        for failure in failures:
            self.world.inject_failure(failure)
        return self

    def proposal(self) -> Action:
        """The rollback the remediation agent proposes.

        Carries no risk and no blast radius: those are the assessment pipeline's to
        compute, and a proposal that asserted its own would not be trusted anyway.
        """
        return Action(
            action_id=GOLDEN_ACTION_ID,
            incident_id=GOLDEN_INCIDENT_ID,
            requesting_agent=self.agent.agent_id,
            capability="production.rollback",
            target_resource=PAYMENT_API,
            arguments={"target_version": PAYMENT_API_GOOD_VERSION},
        )

    def incident(self) -> Incident:
        """The golden incident as first received."""
        return Incident(
            incident_id=GOLDEN_INCIDENT_ID,
            source="monitoring.alerting",
            severity=RiskLevel.CRITICAL,
            state=IncidentState.RECEIVED,
            assigned_agents=("commander", "diagnostic", self.agent.agent_id),
            proposed_actions=(GOLDEN_ACTION_ID,),
            created_at=INCIDENT_OPENED_AT,
            updated_at=INCIDENT_OPENED_AT,
        )

    # --- the run --------------------------------------------------------------------

    def run(self, *, failures: Iterable[FailureType] = ()) -> GoldenIncidentRun:
        """Drive the whole lifecycle and return what every stage produced.

        The incident reaches RESOLVED only if the real engines take it there. Any stage
        that refuses — a denial, a blocked execution, a verification that establishes
        nothing — leaves the incident short of resolution, and the run reports that
        faithfully rather than forcing the ending.
        """
        self.inject(*failures)
        world_before = self.world.snapshot()
        incident = self.incident()

        def advance(to_state: IncidentState, reason: str, actor: str, **guards: object) -> Incident:
            nonlocal incident
            result = self.machine.transition_detailed(
                incident,
                to_state,
                reason=reason,
                actor=actor,
                **guards,  # type: ignore[arg-type]
            )
            incident = result.incident
            self.recorder.record_state_transition(result.transition)
            return incident

        advance(IncidentState.CLASSIFIED, "payment-api error rate 37%", "agent:commander")
        advance(IncidentState.INVESTIGATING, "diagnostic dispatched", "agent:commander")
        advance(IncidentState.IMPACT_ASSESSED, "customer impact assessed", "agent:commander")
        advance(
            IncidentState.PLAN_PROPOSED,
            f"rollback payment-api to {PAYMENT_API_GOOD_VERSION}",
            f"agent:{self.agent.agent_id}",
        )

        # 1. Assessment computes risk and blast radius. Nothing is set by hand.
        assessment = self.pipeline.assess(self.proposal())
        self.recorder.record_assessment(assessment)
        action = assessment.require_assessed_action()

        advance(
            IncidentState.POLICY_CHECK,
            "submitting plan for authorization",
            f"agent:{self.agent.agent_id}",
        )

        # 2. Policy decides. The scenario does not.
        evaluation = self.policy_engine.evaluate_detailed(action, self.agent)
        self.recorder.record_policy_decision(evaluation, action, self.agent)
        decision = evaluation.decision

        advance(
            IncidentState.AWAITING_APPROVAL,
            decision.reason,
            "system:policy-engine",
            policy_decision=decision,
        )

        # 3. A human approves, and the approval is spent for this exact action.
        pending = self.approval_engine.request(
            approval_id=GOLDEN_APPROVAL_ID,
            action=action,
            agent=self.agent,
            decision=decision,
        )
        self.recorder.record_approval(pending)
        approved = self.approval_engine.approve(pending, by=self._approver)
        self.recorder.record_approval(approved)
        authorization = self.approval_engine.consume_for_execution(approved, action, self.agent)
        self.recorder.record_approval(authorization.approval)

        advance(
            IncidentState.EXECUTING,
            "human approval consumed",
            f"agent:{self.agent.agent_id}",
            authorization=authorization,
        )

        # 4. The enterprise carries it out — or does not.
        execution = self.executor.execute(action, authorization, at=self._clock())

        advance(
            IncidentState.VERIFYING,
            f"execution reported {execution.outcome}; establishing actual state",
            f"agent:{self.agent.agent_id}",
        )

        # 5. Verification looks at the world, not at what execution reported.
        observations = self.observations.observe(PAYMENT_API, at=self._clock())
        verification = self.verification_engine.verify(
            action,
            PAYMENT_API_RECOVERED,
            observations,
            verification_id=GOLDEN_VERIFICATION_ID,
        )
        self.recorder.record_verification(verification)

        # 6. Resolution happens only if verification earned it.
        if verification.verified:
            advance(
                IncidentState.RESOLVED,
                verification.reason,
                "system:verification",
                verification=verification,
                action=action,
            )
        else:
            advance(IncidentState.DEGRADED, verification.reason, "system:verification")

        return GoldenIncidentRun(
            world_before=world_before,
            world_after=self.world.snapshot(),
            assessment=assessment,
            evaluation=evaluation,
            authorization=authorization,
            execution=execution,
            observations=observations,
            verification=verification,
            incident=incident,
            audit_head_digest=self.audit.head_digest,
        )

    def __repr__(self) -> str:
        return f"{type(self).__name__}(world={self.world!r})"
