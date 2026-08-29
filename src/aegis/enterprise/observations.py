"""Turning simulated world state into observations the verification engine can read.

**CONTROLLED SIMULATION** (``claude.md`` sections 14, 17). Synthetic measurements of
synthetic services — not real telemetry.

    world state -> Evidence -> Observation -> VerificationEngine

The simulator adapts to the verification contract, never the other way round. It emits the
evidence types the engine already accepts (``TELEMETRY`` and ``DEPLOYMENT``) and source
names the expectation already trusts. Nothing in the verification engine's allowlist was
widened to let the simulator in — and in particular nothing here emits ``TOOL_RESULT``,
which the engine rejects precisely so that a tool reporting success cannot resolve an
incident.

Two sources per resource
------------------------

``telemetry.<name>`` reports how the resource is behaving (``health``, ``error_rate``);
``deployments.<name>`` reports what it is running (``deployment``). Splitting them is what
makes ``verification_failure`` expressible: the telemetry source can go dark while the
deployment source keeps reporting, which is a real shape of partial information.

Determinism
-----------

No clock is read here and no identifier is generated randomly. The caller supplies the
observation time, and ids are derived from the resource, the source kind and that time —
so the same world observed at the same instant produces byte-identical observations.
"""

from __future__ import annotations

from datetime import datetime

from aegis.core.domain import Evidence, EvidenceType
from aegis.core.verification import Observation
from aegis.enterprise.failures import STALE_TELEMETRY_OFFSET, FailureType
from aegis.enterprise.world import EnterpriseWorld

__all__ = ["OBSERVATION_CONFIDENCE", "ObservationSource"]

OBSERVATION_CONFIDENCE = 0.95
"""Declared confidence on simulated measurements.

Fixed rather than varied: the verification engine deliberately ignores confidence, so a
varying value would suggest an influence it does not have.
"""


def _short_name(resource_id: str) -> str:
    """``service:payment-api`` -> ``payment-api``. Used only to build source names."""
    _, _, name = resource_id.partition(":")
    return name or resource_id


def _stamp(moment: datetime) -> str:
    """Compact UTC timestamp for identifiers: ``20260101T120000Z``.

    Compact because identifiers are constrained; ``+00:00`` would be rejected.
    """
    return moment.strftime("%Y%m%dT%H%M%SZ")


class ObservationSource:
    """Reads the simulated world and reports what it currently shows.

    Args:
        world: The world to observe. Read only — observing never changes it.
    """

    def __init__(self, world: EnterpriseWorld) -> None:
        self._world = world

    @property
    def world(self) -> EnterpriseWorld:
        return self._world

    def telemetry_source(self, resource_id: str) -> str:
        """Source name of the telemetry feed for a resource."""
        return f"telemetry.{_short_name(resource_id)}"

    def deployment_source(self, resource_id: str) -> str:
        """Source name of the deployment feed for a resource."""
        return f"deployments.{_short_name(resource_id)}"

    def observe(self, resource_id: str, *, at: datetime) -> tuple[Observation, ...]:
        """Every observation the sources currently report about one resource.

        Args:
            resource_id: Exact resource id.
            at: The instant of measurement. Supplied, never read from a clock.

        Returns:
            The telemetry and deployment observations, in that order. The telemetry
            observation is absent while ``verification_failure`` is injected.

        Raises:
            UnknownResourceError: if the resource is not declared. An undeclared resource
                produces no observation at all — never a reassuring one.
        """
        state = self._world.state(resource_id)
        observed_at = self._observed_at(at)

        observations: list[Observation] = []
        if not self._world.is_failing(FailureType.VERIFICATION_FAILURE):
            observations.append(
                self._build(
                    resource_id=resource_id,
                    kind="telemetry",
                    source=self.telemetry_source(resource_id),
                    evidence_type=EvidenceType.TELEMETRY,
                    observed_at=observed_at,
                    values={"health": state.health.value, "error_rate": state.error_rate},
                )
            )
        observations.append(
            self._build(
                resource_id=resource_id,
                kind="deployment",
                source=self.deployment_source(resource_id),
                evidence_type=EvidenceType.DEPLOYMENT,
                observed_at=observed_at,
                values={"deployment": state.deployment},
            )
        )
        return tuple(observations)

    def observe_all(self, *, at: datetime) -> tuple[Observation, ...]:
        """Observations for every declared resource, in sorted resource order."""
        return tuple(
            observation
            for resource_id in self._world.resources()
            for observation in self.observe(resource_id, at=at)
        )

    def _observed_at(self, at: datetime) -> datetime:
        """When the measurement was taken — backdated while telemetry is stale."""
        if self._world.is_failing(FailureType.STALE_TELEMETRY):
            return at - STALE_TELEMETRY_OFFSET
        return at

    @staticmethod
    def _build(
        *,
        resource_id: str,
        kind: str,
        source: str,
        evidence_type: EvidenceType,
        observed_at: datetime,
        values: dict[str, float | str],
    ) -> Observation:
        observation_id = f"obs-{kind}-{_short_name(resource_id)}-{_stamp(observed_at)}"
        return Observation(
            evidence=Evidence(
                evidence_id=observation_id,
                source=source,
                reference=f"{source}/{_stamp(observed_at)}",
                timestamp=observed_at,
                type=evidence_type,
                confidence=OBSERVATION_CONFIDENCE,
            ),
            resource=resource_id,
            values=values,
        )

    def __repr__(self) -> str:
        return f"{type(self).__name__}(world={self._world!r})"
