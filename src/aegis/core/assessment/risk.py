"""The risk engine — a deterministic, explainable risk level for a proposed action.

Four declared properties each impose a *floor* on the action's risk, and the result is
the highest of them. Nothing else participates: no model, no network, no clock, no
randomness, no natural-language interpretation of anything an agent wrote.

Why a maximum
-------------

``claude.md`` section 5 requires conservative semantics, and Part 9 of this milestone
requires that no benign-looking property can pull a known-dangerous one downwards. Taking
the maximum of independently-computed floors makes that structural rather than merely
tested: raising any single input can only raise or hold the result, and no input can ever
lower it. Every safety invariant in this layer follows from that one property.

Why these four
--------------

* **Capability risk class** — the organisation's own declared verdict on the capability.
* **Blast radius impact** — how far the concrete action reaches, from declared
  dependencies.
* **Reversibility** — an effect that cannot be undone forecloses recovery, so it cannot
  be low risk regardless of how small its reach is.
* **Data classification** — reaching restricted data is a risk in itself
  (``claude.md`` section 13, exfiltration).

``approval_requirement`` is deliberately *not* an input. Approval is the governance
response to risk, not evidence of it, and feeding it back in would make risk and the
policy engine's RISK_BASED branch circular.
"""

from __future__ import annotations

from pydantic import Field

from aegis.core.assessment.scale import max_risk
from aegis.core.domain import (
    Action,
    BlastRadius,
    Capability,
    DataClassification,
    DomainModel,
    NonEmptyStr,
    RiskLevel,
)

__all__ = ["SENSITIVITY_FLOORS", "RiskAssessment", "RiskEngine", "RiskFactor"]

SENSITIVITY_FLOORS: dict[DataClassification, RiskLevel] = {
    DataClassification.PUBLIC: RiskLevel.LOW,
    DataClassification.INTERNAL: RiskLevel.LOW,
    DataClassification.CONFIDENTIAL: RiskLevel.MEDIUM,
    DataClassification.RESTRICTED: RiskLevel.HIGH,
}
"""Risk floor implied by the sensitivity of the data a capability can reach."""

IRREVERSIBLE_FLOOR = RiskLevel.HIGH
"""Risk floor for an effect that cannot be undone."""


class RiskFactor(DomainModel):
    """One declared property and the risk floor it imposes.

    A structured record, not a rationale. ``detail`` states the input that was read, so a
    reader can check it against the capability definition without re-running anything.
    """

    name: NonEmptyStr
    """Stable machine-readable factor id, e.g. ``capability_risk_class``."""

    contribution: RiskLevel
    """The floor this factor imposes on its own."""

    detail: NonEmptyStr
    """The declared input this floor was read from."""


class RiskAssessment(DomainModel):
    """A computed risk level and every factor that produced it.

    Answers "why was this HIGH?" from data alone: read ``deciding_factors``. There is no
    model output here and no chain-of-thought — every field is recomputable from the same
    capability and blast radius.
    """

    risk: RiskLevel
    """The authoritative assessed risk: the maximum of all factor contributions."""

    factors: tuple[RiskFactor, ...] = Field(min_length=1)
    """Every factor considered, in evaluation order, including the ones that did not bind."""

    @property
    def deciding_factors(self) -> tuple[RiskFactor, ...]:
        """The factors whose contribution equals the final risk."""
        return tuple(factor for factor in self.factors if factor.contribution is self.risk)


class RiskEngine:
    """Computes the authoritative risk of a proposed action.

    Stateless and pure. The same action, capability and blast radius always produce the
    same assessment.
    """

    def assess(
        self, action: Action, capability: Capability, blast_radius: BlastRadius
    ) -> RiskAssessment:
        """Compute the risk of ``action``.

        ``action.risk`` is never read. Whatever a proposing agent declared about its own
        risk is untrusted input, and this engine recomputes the value from declared
        control-plane metadata instead (``claude.md`` section 2).

        Args:
            action: The proposed action. Only its capability reference and target are
                relevant, and both are supplied resolved by the caller.
            capability: The resolved capability definition it would exercise.
            blast_radius: The *computed* blast radius, from the blast-radius engine.
                Passing an agent-supplied blast radius here would defeat the point; the
                assessment pipeline never does.

        Returns:
            The assessment. Always succeeds: every input is required and already
            validated, so there is no partial-information path here — insufficient
            information is caught upstream, where the blast radius could not be measured.
        """
        factors = (
            RiskFactor(
                name="capability_risk_class",
                contribution=capability.risk_class,
                detail=f"capability {capability.capability_id} is declared {capability.risk_class}",
            ),
            RiskFactor(
                name="blast_radius_impact",
                contribution=blast_radius.impact,
                detail=(
                    f"action reaches {len(blast_radius.scope)} resource(s) at "
                    f"{blast_radius.impact} impact"
                ),
            ),
            RiskFactor(
                name="reversibility",
                contribution=RiskLevel.LOW if capability.reversible else IRREVERSIBLE_FLOOR,
                detail=(
                    f"capability {capability.capability_id} is "
                    f"{'reversible' if capability.reversible else 'irreversible'}"
                ),
            ),
            RiskFactor(
                name="data_classification",
                contribution=SENSITIVITY_FLOORS[capability.data_classification],
                detail=(
                    f"capability {capability.capability_id} reaches "
                    f"{capability.data_classification} data"
                ),
            ),
        )
        return RiskAssessment(
            risk=max_risk(factor.contribution for factor in factors),
            factors=factors,
        )

    def __repr__(self) -> str:
        return f"{type(self).__name__}()"
