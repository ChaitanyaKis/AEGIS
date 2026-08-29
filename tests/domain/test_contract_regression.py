"""Pins the shape of every domain contract.

Later milestones (policy engine, state machine, audit store, evaluation harness) will be
written against these fields. Adding, removing or renaming one is a deliberate contract
change and must show up here as a failing test, not as a surprise downstream.
"""

from __future__ import annotations

import pytest

from aegis.core.domain import (
    Action,
    Agent,
    AgentEndpoint,
    AuditEvent,
    BlastRadius,
    Capability,
    DomainModel,
    Evidence,
    Incident,
    PolicyDecision,
)

EXPECTED_FIELDS: dict[type[DomainModel], list[str]] = {
    Agent: [
        "agent_id",
        "name",
        "version",
        "status",
        "identity_reference",
        "capabilities",
        "endpoint",
    ],
    AgentEndpoint: ["kind", "reference", "metadata"],
    Capability: [
        "capability_id",
        "description",
        "risk_class",
        "resource_scope",
        "data_classification",
        "reversible",
        "approval_requirement",
        "allowed_agents",
    ],
    Incident: [
        "incident_id",
        "source",
        "severity",
        "state",
        "evidence",
        "assigned_agents",
        "proposed_actions",
        "created_at",
        "updated_at",
    ],
    Action: [
        "action_id",
        "incident_id",
        "requesting_agent",
        "capability",
        "target_resource",
        "arguments",
        "evidence",
        "risk",
        "blast_radius",
    ],
    BlastRadius: ["scope", "impact"],
    PolicyDecision: [
        "decision",
        "reason",
        "policy_reference",
        "evaluated_at",
        "evidence",
    ],
    Evidence: [
        "evidence_id",
        "source",
        "reference",
        "timestamp",
        "type",
        "confidence",
    ],
    AuditEvent: [
        "event_id",
        "timestamp",
        "actor",
        "agent_identity",
        "incident_id",
        "event_type",
        "input_reference",
        "decision",
        "policy_reference",
        "tool",
        "result",
        "state_before",
        "state_after",
        "evidence",
    ],
}

EXPECTED_REQUIRED_FIELDS: dict[type[DomainModel], set[str]] = {
    Agent: {"agent_id", "name", "version", "status", "identity_reference"},
    AgentEndpoint: {"kind", "reference"},
    Capability: {
        "capability_id",
        "description",
        "risk_class",
        "data_classification",
        "reversible",
        "approval_requirement",
    },
    Incident: {
        "incident_id",
        "source",
        "severity",
        "state",
        "created_at",
        "updated_at",
    },
    Action: {
        "action_id",
        "incident_id",
        "requesting_agent",
        "capability",
        "target_resource",
    },
    BlastRadius: {"impact"},
    PolicyDecision: {"decision", "reason", "policy_reference", "evaluated_at"},
    Evidence: {"evidence_id", "source", "reference", "timestamp", "type", "confidence"},
    AuditEvent: {"event_id", "timestamp", "actor", "event_type"},
}


@pytest.mark.parametrize(
    ("model_type", "expected"),
    list(EXPECTED_FIELDS.items()),
    ids=lambda value: value.__name__ if isinstance(value, type) else "",
)
def test_model_fields_are_exact(model_type: type[DomainModel], expected: list[str]) -> None:
    assert list(model_type.model_fields) == expected


@pytest.mark.parametrize(
    ("model_type", "expected"),
    list(EXPECTED_REQUIRED_FIELDS.items()),
    ids=lambda value: value.__name__ if isinstance(value, type) else "",
)
def test_required_fields_are_exact(model_type: type[DomainModel], expected: set[str]) -> None:
    required = {name for name, field in model_type.model_fields.items() if field.is_required()}
    assert required == expected


@pytest.mark.parametrize("model_type", list(EXPECTED_FIELDS))
def test_every_model_is_frozen_and_closed(model_type: type[DomainModel]) -> None:
    """Immutability and closed schemas are structural guarantees, not conventions."""
    assert model_type.model_config["frozen"] is True
    assert model_type.model_config["extra"] == "forbid"


def test_public_surface_is_stable() -> None:
    """The domain package export list is itself part of the contract."""
    import aegis.core.domain as domain

    assert set(domain.__all__) == {
        "Action",
        "Agent",
        "AgentEndpoint",
        "AuditEvent",
        "BlastRadius",
        "Capability",
        "Evidence",
        "Incident",
        "PolicyDecision",
        "AgentLifecycleState",
        "ApprovalRequirement",
        "DataClassification",
        "EvidenceType",
        "IncidentState",
        "PolicyDecisionType",
        "RiskLevel",
        "AgentRef",
        "CapabilityRef",
        "DomainModel",
        "EvidenceRef",
        "Identifier",
        "IncidentRef",
        "NonEmptyStr",
        "StateValue",
        "Timestamp",
        "utc_now",
        "from_dict",
        "from_json",
        "to_dict",
        "to_json",
    }
    for name in domain.__all__:
        assert hasattr(domain, name), name


FORBIDDEN_DOMAIN_IMPORTS = frozenset(
    {
        "google",
        "vertexai",
        "anthropic",
        "openai",
        "httpx",
        "requests",
        "aiohttp",
        "socket",
        "urllib",
        "sqlite3",
    }
)


def test_domain_layer_imports_nothing_that_talks_to_the_outside_world() -> None:
    """The domain layer is inert: contracts only, no I/O and no model calls.

    A static check of the actual import statements, so it stays honest regardless of
    what the test runner happens to have loaded. Guards the constitution's build order
    and the rule that the control plane never delegates a decision to an LLM.
    """
    import ast
    import pathlib

    import aegis.core.domain as domain

    package_dir = pathlib.Path(domain.__path__[0])
    offenders: list[str] = []

    for source_file in sorted(package_dir.glob("*.py")):
        tree = ast.parse(source_file.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                roots = [alias.name.split(".")[0] for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                roots = [(node.module or "").split(".")[0]]
            else:
                continue
            offenders += [
                f"{source_file.name}: {root}" for root in roots if root in FORBIDDEN_DOMAIN_IMPORTS
            ]

    assert offenders == []
