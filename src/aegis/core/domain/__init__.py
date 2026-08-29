"""AEGIS domain contracts.

The single source of truth for what an agent, capability, incident, action, policy
decision, piece of evidence and audit event *are*. Everything else in AEGIS — the
deterministic control plane, the agent plane, the simulated enterprise, the evaluation
harness — is written against these types.

Deliberately inert: this package contains data contracts and their invariants only. It
holds no policy logic, no risk or blast-radius calculation, no state-machine
transitions, no I/O and no LLM calls. Those belong to the components listed in
``claude.md`` section 3 and arrive in later milestones.
"""

from aegis.core.domain.action import Action, BlastRadius
from aegis.core.domain.agent import Agent, AgentEndpoint
from aegis.core.domain.audit import AuditEvent, StateValue
from aegis.core.domain.base import (
    AgentRef,
    CapabilityRef,
    DomainModel,
    EvidenceRef,
    Identifier,
    IncidentRef,
    NonEmptyStr,
    Timestamp,
    utc_now,
)
from aegis.core.domain.capability import Capability
from aegis.core.domain.enums import (
    AgentLifecycleState,
    ApprovalRequirement,
    DataClassification,
    EvidenceType,
    IncidentState,
    PolicyDecisionType,
    RiskLevel,
)
from aegis.core.domain.evidence import Evidence
from aegis.core.domain.incident import Incident
from aegis.core.domain.policy import PolicyDecision
from aegis.core.domain.serialization import from_dict, from_json, to_dict, to_json

__all__ = [
    "Action",
    "Agent",
    "AgentEndpoint",
    "AgentLifecycleState",
    "AgentRef",
    "ApprovalRequirement",
    "AuditEvent",
    "BlastRadius",
    "Capability",
    "CapabilityRef",
    "DataClassification",
    "DomainModel",
    "Evidence",
    "EvidenceRef",
    "EvidenceType",
    "Identifier",
    "Incident",
    "IncidentRef",
    "IncidentState",
    "NonEmptyStr",
    "PolicyDecision",
    "PolicyDecisionType",
    "RiskLevel",
    "StateValue",
    "Timestamp",
    "from_dict",
    "from_json",
    "to_dict",
    "to_json",
    "utc_now",
]
