"""The assessment pipeline — proposal in, authoritatively assessed action out.

    AGENT PROPOSAL → BLAST RADIUS → RISK → POLICY ENGINE

This module owns the first three stages. It never authorizes anything: its output is an
:class:`Assessment` whose assessed action is then handed to the existing policy engine,
which remains the sole authorization layer.

What the pipeline refuses to trust
----------------------------------

Both ``Action.risk`` and ``Action.blast_radius`` arrive from the agent plane, which is
useful for reasoning and authoritative for nothing (``claude.md`` section 4, zone B). The
pipeline reads neither. It recomputes both from declared control-plane metadata and
overwrites whatever the proposal carried, in both directions: a self-declared LOW does not
survive, and neither does a self-declared HIGH.

The original proposal is preserved on the result, so the audit trail can always show what
the agent asked for alongside what the control plane decided it actually was.

Failing closed
--------------

When the target resource is not declared in the dependency graph the reach cannot be
measured, so there is no honest risk to report. The pipeline returns
``INSUFFICIENT_INFORMATION`` with no assessed action rather than inventing one. The
caller then has nothing assessed to submit, and the policy engine denies any privileged
capability on an unassessed action.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import model_validator

from aegis.core.assessment.blast_radius import BlastRadiusAssessment, BlastRadiusEngine
from aegis.core.assessment.risk import RiskAssessment, RiskEngine
from aegis.core.capabilities import CapabilityRegistry
from aegis.core.dependencies import DependencyGraph
from aegis.core.domain import Action, DomainModel, NonEmptyStr

__all__ = ["Assessment", "AssessmentOutcome", "AssessmentPipeline"]


class AssessmentOutcome(StrEnum):
    """Whether an assessment could be completed.

    Deliberately *not* a domain enum and deliberately not a fourth
    :class:`~aegis.core.domain.enums.RiskLevel`: "could not assess" is a property of the
    attempt, not a severity, and ``RiskLevel`` stays exactly as the constitution defines
    it.
    """

    ASSESSED = "ASSESSED"
    INSUFFICIENT_INFORMATION = "INSUFFICIENT_INFORMATION"


class Assessment(DomainModel):
    """The result of assessing one proposed action.

    Carries the original proposal unchanged alongside the authoritative assessment, so
    "what the agent asked for" and "what the control plane measured" are both recoverable
    from a single record.

    The two outcomes are structurally exclusive — a validator rejects a half-built result,
    so a caller cannot mistake a failed assessment for a successful one by reading a field
    that happens to be populated.
    """

    proposal: Action
    """The action exactly as the agent proposed it, including any risk it declared."""

    outcome: AssessmentOutcome
    assessed_action: Action | None = None
    """The proposal with authoritative ``risk`` and ``blast_radius``. ``None`` on failure."""

    blast_radius: BlastRadiusAssessment | None = None
    risk: RiskAssessment | None = None
    failure_reason: NonEmptyStr | None = None
    """Why the assessment could not be completed. Present only on failure."""

    @model_validator(mode="after")
    def _outcome_matches_contents(self) -> Assessment:
        if self.outcome is AssessmentOutcome.ASSESSED:
            missing = [
                name
                for name, value in (
                    ("assessed_action", self.assessed_action),
                    ("blast_radius", self.blast_radius),
                    ("risk", self.risk),
                )
                if value is None
            ]
            if missing:
                raise ValueError(f"ASSESSED result is missing: {', '.join(missing)}")
            if self.failure_reason is not None:
                raise ValueError("ASSESSED result must not carry a failure_reason")
        else:
            if self.assessed_action is not None:
                raise ValueError(f"{self.outcome} result must not carry an assessed_action")
            if self.failure_reason is None:
                raise ValueError(f"{self.outcome} result requires a failure_reason")
        return self

    @property
    def ok(self) -> bool:
        """Whether the assessment completed."""
        return self.outcome is AssessmentOutcome.ASSESSED

    def require_assessed_action(self) -> Action:
        """The assessed action, or raise.

        Use this wherever an assessed action is required, so that a failed assessment
        cannot be silently read as an unremarkable one.

        Raises:
            ValueError: if the assessment did not complete.
        """
        if self.assessed_action is None:
            raise ValueError(
                f"action {self.proposal.action_id!r} was not assessed: {self.failure_reason}"
            )
        return self.assessed_action


class AssessmentPipeline:
    """Runs blast-radius and risk assessment over a proposed action.

    Args:
        registry: Capability definitions, used to resolve ``action.capability``.
        graph: Declared dependency graph, used to measure reach.

    Both are held by reference and never mutated. The pipeline itself is stateless, so
    the same proposal against the same registry and graph always assesses identically.
    """

    def __init__(self, registry: CapabilityRegistry, graph: DependencyGraph) -> None:
        self._registry = registry
        self._blast_radius = BlastRadiusEngine(graph)
        self._risk = RiskEngine()

    @property
    def registry(self) -> CapabilityRegistry:
        return self._registry

    @property
    def graph(self) -> DependencyGraph:
        return self._blast_radius.graph

    def assess(self, action: Action) -> Assessment:
        """Assess ``action``, ignoring any risk or blast radius it already carries.

        Args:
            action: The proposed action.

        Returns:
            An :class:`Assessment`. ``ASSESSED`` carries an ``assessed_action`` whose
            ``risk`` and ``blast_radius`` are authoritative; ``INSUFFICIENT_INFORMATION``
            carries none, and the caller must fail closed.
        """
        if not self._registry.exists(action.capability):
            return self._insufficient(action, f"capability {action.capability!r} is not registered")
        capability = self._registry.get(action.capability)

        blast_radius = self._blast_radius.assess(action, capability)
        if blast_radius is None:
            return self._insufficient(
                action,
                f"resource {action.target_resource!r} is not declared in the dependency "
                f"graph, so its reach cannot be measured",
            )

        risk = self._risk.assess(action, capability, blast_radius.blast_radius)

        return Assessment(
            proposal=action,
            outcome=AssessmentOutcome.ASSESSED,
            assessed_action=action.model_copy(
                update={
                    "risk": risk.risk,
                    "blast_radius": blast_radius.blast_radius,
                }
            ),
            blast_radius=blast_radius,
            risk=risk,
        )

    @staticmethod
    def _insufficient(action: Action, reason: str) -> Assessment:
        return Assessment(
            proposal=action,
            outcome=AssessmentOutcome.INSUFFICIENT_INFORMATION,
            failure_reason=reason,
        )

    def __repr__(self) -> str:
        return f"{type(self).__name__}(registry={self._registry!r}, graph={self.graph!r})"
