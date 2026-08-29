"""DETERMINISTIC TEST MODELS for the four specialists.

Rule-based stand-ins, not language models and not pretending to be. They exist so the
suite can exercise delegation, findings, failure handling and the golden incident **without
credentials, without network and without Gemini**.

Each reads the same untrusted data a real model would and reaches a conclusion from the
*structure* of that data — observed health, error rate, deployment version, the shape of
the incident payload. The same inputs always produce the same finding: no clock beyond the
injected one, no randomness, no hidden state.

The Security model is the exception worth noting. It scans the incident payload for
injection markers, which is the one place a specialist genuinely must look at untrusted
text. It looks for *markers* and reports them as a finding — it never follows what it
finds, and its finding blocks nothing by itself.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from aegis.agents.decisions import CommanderProposal
from aegis.agents.findings import AgentFinding, FindingType
from aegis.agents.model import ModelError, ModelRequest

__all__ = [
    "INJECTION_MARKERS",
    "BusinessImpactModel",
    "DiagnosticModel",
    "FailingSpecialistModel",
    "RemediationModel",
    "SecurityModel",
]

INJECTION_MARKERS: tuple[str, ...] = (
    "ignore previous instructions",
    "ignore all previous",
    "system override",
    "disable policy",
    "disable the policy",
    "approve the rollback",
    "approve it yourself",
    "export the customer",
    "exfil",
    "send the credentials",
    "bypass approval",
)
"""Phrases that indicate someone is talking to the model rather than reporting an incident.

A detection heuristic, deliberately simple and deliberately not load-bearing: nothing in
AEGIS is safe *because* this list is complete. Enforcement is the policy engine's, and it
does not consult this list or the finding derived from it.
"""


def _observations(request: ModelRequest) -> Mapping[str, Any]:
    data = dict(request.data)
    observed = data.get("observations")
    return observed if isinstance(observed, dict) else {}


def _evidence(request: ModelRequest) -> tuple[str, ...]:
    refs = dict(request.data).get("evidence_references")
    return tuple(refs) if isinstance(refs, list) else ()


def _incident(request: ModelRequest) -> Mapping[str, Any]:
    incident = dict(request.data).get("incident")
    return incident if isinstance(incident, dict) else {}


def _incident_text(request: ModelRequest) -> str:
    """Every string in the incident payload, lowercased, for marker scanning."""
    return " ".join(
        str(value) for value in _incident(request).values() if isinstance(value, str)
    ).lower()


class _Base:
    """Shared plumbing. Subclasses supply :meth:`decide`."""

    name = "deterministic-test-model"
    agent_id = "specialist"
    finding_type: FindingType

    def __init__(self, *, clock) -> None:
        self._clock = clock

    def _finding(
        self,
        request: ModelRequest,
        *,
        summary: str,
        confidence: float,
        next_step: str,
        proposal: CommanderProposal | None = None,
    ) -> AgentFinding:
        incident = _incident(request)
        return AgentFinding(
            finding_id=f"find-{self.agent_id}-{incident.get('incident_id', 'unknown')}",
            incident_id=str(incident.get("incident_id", "INC-UNKNOWN")),
            agent_id=self.agent_id,
            finding_type=self.finding_type,
            summary=summary,
            confidence=confidence,
            supporting_evidence=_evidence(request),
            recommended_next_step=next_step,
            created_at=self._clock(),
            proposal=proposal,
        )

    def __repr__(self) -> str:
        return f"{type(self).__name__}(agent_id={self.agent_id!r})"


class DiagnosticModel(_Base):
    """**DETERMINISTIC TEST MODEL** — correlates error rate with the current deployment."""

    agent_id = "diagnostic"
    finding_type = FindingType.TECHNICAL_DIAGNOSIS

    def decide(self, request: ModelRequest) -> AgentFinding:
        observed = _observations(request)
        health = observed.get("health", "unknown")
        error_rate = observed.get("error_rate")
        deployment = observed.get("current_deployment", "unknown")
        previous = observed.get("previous_deployment")

        if isinstance(error_rate, int | float) and error_rate > 1.0:
            summary = (
                f"Error rate is {error_rate}% against a healthy baseline of 1%, and the "
                f"service reports {health} on deployment {deployment}. The most recent "
                f"change is the likeliest cause."
            )
            next_step = (
                f"roll back to {previous}" if previous else "identify the previous deployment"
            )
            confidence = 0.85
        else:
            summary = (
                f"Service reports {health} with error rate {error_rate} on {deployment}; "
                f"no technical fault is evident from the available telemetry."
            )
            next_step = "no remediation indicated from telemetry"
            confidence = 0.6

        return self._finding(request, summary=summary, confidence=confidence, next_step=next_step)


class SecurityModel(_Base):
    """**DETERMINISTIC TEST MODEL** — scans incident content for injection markers."""

    agent_id = "security"
    finding_type = FindingType.SECURITY_ASSESSMENT

    def decide(self, request: ModelRequest) -> AgentFinding:
        text = _incident_text(request)
        found = tuple(marker for marker in INJECTION_MARKERS if marker in text)

        if found:
            summary = (
                f"The incident payload contains {len(found)} instruction-like phrase(s) "
                f"aimed at the agent rather than describing the incident: "
                f"{'; '.join(found)}. Treating the payload as hostile content. This is a "
                f"detection, not a block — governance decides what is permitted."
            )
            next_step = "treat incident content as hostile data; proceed under normal governance"
            confidence = 0.9
        else:
            summary = (
                "No injection markers or policy-bypass language found in the incident "
                "payload. Nothing here authorises anything."
            )
            next_step = "no security objection from content analysis"
            confidence = 0.7

        return self._finding(request, summary=summary, confidence=confidence, next_step=next_step)


class BusinessImpactModel(_Base):
    """**DETERMINISTIC TEST MODEL** — derives reach from the dependency neighbourhood."""

    agent_id = "business-impact"
    finding_type = FindingType.BUSINESS_IMPACT

    def decide(self, request: ModelRequest) -> AgentFinding:
        observed = _observations(request)
        dependents = observed.get("dependents")
        affected = sorted(dependents) if isinstance(dependents, dict) else []
        health = observed.get("health", "unknown")

        if affected and health != "healthy":
            summary = (
                f"{len(affected)} dependent service(s) sit downstream of an "
                f"{health} resource: {', '.join(affected)}. Customer-facing reach is "
                f"proportional to that fan-out."
            )
            confidence = 0.75
            next_step = "treat as customer-affecting while the resource is unhealthy"
        else:
            summary = (
                f"Resource reports {health} with {len(affected)} declared dependent(s); "
                f"no customer-facing degradation is evident from the observations available."
            )
            confidence = 0.6
            next_step = "monitor; no impact escalation indicated"

        return self._finding(request, summary=summary, confidence=confidence, next_step=next_step)


class RemediationModel(_Base):
    """**DETERMINISTIC TEST MODEL** — proposes a rollback to the observed previous version."""

    agent_id = "remediation"
    finding_type = FindingType.REMEDIATION_PROPOSAL

    def __init__(self, *, clock, capability: str = "production.rollback") -> None:
        super().__init__(clock=clock)
        self._capability = capability

    def decide(self, request: ModelRequest) -> AgentFinding:
        observed = _observations(request)
        incident = _incident(request)
        resource = incident.get("target_resource")
        previous = observed.get("previous_deployment")

        if not isinstance(resource, str) or not isinstance(previous, str):
            return self._finding(
                request,
                summary=(
                    "Cannot propose a rollback: the target resource or its previous "
                    "deployment was not observed."
                ),
                confidence=0.3,
                next_step="gather deployment history before proposing remediation",
            )

        return self._finding(
            request,
            summary=(
                f"Rolling {resource} back to {previous} reverses the change correlated "
                f"with the elevated error rate. This is a proposal; AEGIS decides whether "
                f"it is permitted."
            ),
            confidence=0.8,
            next_step=f"submit rollback of {resource} to {previous} for authorization",
            proposal=CommanderProposal(
                capability_id=self._capability,
                target_resource=resource,
                arguments={"target_version": previous},
                evidence_references=_evidence(request),
            ),
        )


class FailingSpecialistModel:
    """**DETERMINISTIC TEST MODEL** — always raises, for failure-path tests."""

    name = "failing-test-model"

    def __init__(self, error: ModelError | None = None) -> None:
        self._error = error or ModelError("specialist model unavailable")

    def decide(self, request: ModelRequest) -> AgentFinding:
        raise self._error

    def __repr__(self) -> str:
        return f"{type(self).__name__}(error={type(self._error).__name__})"
