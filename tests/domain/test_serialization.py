"""Serialization must be lossless, canonical and validating.

Domain objects cross process boundaries as audit records, event payloads and evaluation
fixtures. Three properties are load-bearing and tested here: a round trip preserves the
object, equal objects produce identical bytes, and a malformed payload is rejected
rather than absorbed.
"""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from aegis.core.domain import (
    Action,
    Agent,
    AuditEvent,
    Capability,
    DomainModel,
    Evidence,
    Incident,
    IncidentState,
    PolicyDecision,
    PolicyDecisionType,
    RiskLevel,
    from_dict,
    from_json,
    to_dict,
    to_json,
)


@pytest.fixture
def all_models(
    evidence: Evidence,
    capability: Capability,
    agent: Agent,
    incident: Incident,
    action: Action,
    policy_decision: PolicyDecision,
    audit_event: AuditEvent,
) -> list[DomainModel]:
    return [evidence, capability, agent, incident, action, policy_decision, audit_event]


def test_json_round_trip_preserves_every_model(all_models: list[DomainModel]) -> None:
    for model in all_models:
        restored = from_json(type(model), to_json(model))
        assert restored == model, type(model).__name__


def test_dict_round_trip_preserves_every_model(all_models: list[DomainModel]) -> None:
    for model in all_models:
        restored = from_dict(type(model), to_dict(model))
        assert restored == model, type(model).__name__


def test_round_trip_preserves_nested_and_collection_fields(incident: Incident) -> None:
    """Embedded evidence and tuple fields survive the trip with their types intact."""
    restored = from_json(Incident, to_json(incident))
    assert restored.evidence == incident.evidence
    assert isinstance(restored.evidence[0], Evidence)
    assert isinstance(restored.assigned_agents, tuple)
    assert restored.state is IncidentState.INVESTIGATING
    assert restored.severity is RiskLevel.CRITICAL


def test_enums_serialize_to_their_string_values(audit_event: AuditEvent) -> None:
    payload = to_dict(audit_event)
    assert payload["decision"] == "REQUIRE_APPROVAL"
    assert payload["state_before"] == "POLICY_CHECK"
    assert payload["state_after"] == "AWAITING_APPROVAL"


def test_audit_payload_stays_flat(audit_event: AuditEvent) -> None:
    """Audit records are transported and indexed; keep them scalar plus id lists."""
    for key, value in to_dict(audit_event).items():
        assert value is None or isinstance(value, str | list), key


def test_timestamps_serialize_as_utc_iso8601(evidence: Evidence) -> None:
    assert to_dict(evidence)["timestamp"] == "2026-01-01T12:00:00Z"


def test_json_output_is_canonical(action: Action) -> None:
    """Equal objects produce byte-identical JSON regardless of construction order."""
    reordered = Action(
        target_resource=action.target_resource,
        capability=action.capability,
        requesting_agent=action.requesting_agent,
        incident_id=action.incident_id,
        action_id=action.action_id,
        blast_radius=action.blast_radius,
        risk=action.risk,
        evidence=action.evidence,
        arguments={"drain_seconds": 30, "target_version": "v4.7"},
    )
    assert to_json(reordered) == to_json(action)
    assert json.loads(to_json(action)) == to_dict(action)


def test_json_output_has_sorted_keys(policy_decision: PolicyDecision) -> None:
    keys = list(json.loads(to_json(policy_decision)))
    assert keys == sorted(keys)


def test_indent_is_cosmetic_only(policy_decision: PolicyDecision) -> None:
    assert json.loads(to_json(policy_decision, indent=2)) == to_dict(policy_decision)


def test_optional_fields_round_trip_as_null(action: Action) -> None:
    minimal = action.model_copy(update={"risk": None, "blast_radius": None})
    payload = to_dict(minimal)
    assert payload["risk"] is None
    assert payload["blast_radius"] is None
    assert from_dict(Action, payload) == minimal


def test_deserialization_rejects_unknown_fields(policy_decision: PolicyDecision) -> None:
    payload = to_dict(policy_decision)
    payload["override"] = "ignore-deny"
    with pytest.raises(ValidationError):
        from_dict(PolicyDecision, payload)


def test_deserialization_rejects_invalid_enum_values(policy_decision: PolicyDecision) -> None:
    payload = to_dict(policy_decision)
    payload["decision"] = "MAYBE"
    with pytest.raises(ValidationError):
        from_dict(PolicyDecision, payload)


def test_deserialization_rejects_missing_required_fields(agent: Agent) -> None:
    payload = to_dict(agent)
    del payload["version"]
    with pytest.raises(ValidationError):
        from_dict(Agent, payload)


def test_deserialization_rejects_naive_timestamps(audit_event: AuditEvent) -> None:
    payload = to_dict(audit_event)
    payload["timestamp"] = "2026-01-01T12:00:00"
    with pytest.raises(ValidationError):
        from_dict(AuditEvent, payload)


def test_deserialization_rejects_malformed_json() -> None:
    with pytest.raises(ValidationError):
        from_json(PolicyDecision, "{not json")


def test_serialized_payload_is_plain_json(all_models: list[DomainModel]) -> None:
    """No Python-specific types leak into the wire format."""
    for model in all_models:
        assert json.loads(to_json(model)) is not None


def test_policy_decision_payload_shape(policy_decision: PolicyDecision) -> None:
    """Golden shape for the most safety-critical contract."""
    assert to_dict(policy_decision) == {
        "decision": PolicyDecisionType.REQUIRE_APPROVAL.value,
        "reason": "production.rollback is HIGH risk and always requires human approval.",
        "policy_reference": "policy:production-mutation/v1#rollback",
        "evaluated_at": "2026-01-01T12:00:00Z",
        "evidence": ["ev-error-rate-001"],
    }
