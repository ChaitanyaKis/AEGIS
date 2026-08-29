"""Capability registry behaviour.

The registry is the authoritative source of capability definitions in-process, so its
refusals matter as much as its answers: it must never overwrite, never guess, and never
turn an unknown capability into something permissive.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from aegis.core.capabilities import (
    CapabilityRegistry,
    CapabilityRegistryError,
    DuplicateCapabilityError,
    UnknownCapabilityError,
    resource_in_scope,
)
from aegis.core.domain import ApprovalRequirement, Capability, DataClassification, RiskLevel
from tests.fleet import (
    ALL_CAPABILITIES,
    CUSTOMER_DATABASE,
    DIAGNOSTIC,
    LOGS_READ,
    ORDER_SERVICE,
    PAYMENT_API,
    PRODUCTION_ROLLBACK,
    REMEDIATION,
    TELEMETRY_READ,
    UNREGISTERED,
    build_registry,
)

# --- registration -------------------------------------------------------------------


def test_register_then_retrieve() -> None:
    registry = CapabilityRegistry()
    registry.register(TELEMETRY_READ)
    assert registry.get("telemetry.read") is TELEMETRY_READ


def test_constructor_registers_an_iterable() -> None:
    registry = CapabilityRegistry(ALL_CAPABILITIES)
    assert len(registry) == len(ALL_CAPABILITIES)


def test_empty_registry_holds_nothing() -> None:
    registry = CapabilityRegistry()
    assert len(registry) == 0
    assert registry.list() == ()
    assert not registry.exists("telemetry.read")


def test_duplicate_registration_is_rejected() -> None:
    """Registration is never an overwrite."""
    registry = CapabilityRegistry([TELEMETRY_READ])
    with pytest.raises(DuplicateCapabilityError) as excinfo:
        registry.register(TELEMETRY_READ)
    assert excinfo.value.capability_id == "telemetry.read"


def test_duplicate_registration_does_not_replace_the_definition() -> None:
    """A second definition for a known id must not widen the first one's authority."""
    registry = CapabilityRegistry([LOGS_READ])
    widened = LOGS_READ.model_copy(
        update={"resource_scope": (PAYMENT_API, ORDER_SERVICE, CUSTOMER_DATABASE)}
    )
    with pytest.raises(DuplicateCapabilityError):
        registry.register(widened)
    assert registry.get("logs.read").resource_scope == (PAYMENT_API,)


def test_duplicate_registration_raises_the_registry_base_error() -> None:
    registry = CapabilityRegistry([TELEMETRY_READ])
    with pytest.raises(CapabilityRegistryError):
        registry.register(TELEMETRY_READ)


# --- lookup -------------------------------------------------------------------------


def test_unknown_capability_lookup_raises() -> None:
    """An unknown capability fails explicitly; it never resolves to a default."""
    registry = build_registry()
    with pytest.raises(UnknownCapabilityError) as excinfo:
        registry.get("production.delete-everything")
    assert excinfo.value.capability_id == "production.delete-everything"


def test_unknown_capability_error_is_a_key_error() -> None:
    registry = build_registry()
    with pytest.raises(KeyError):
        registry.get("nope")


def test_exists_distinguishes_known_from_unknown() -> None:
    registry = build_registry()
    assert registry.exists("production.rollback")
    assert not registry.exists("production.delete-everything")


def test_contains_matches_exists() -> None:
    registry = build_registry()
    assert "production.rollback" in registry
    assert "production.delete-everything" not in registry


# --- listing ------------------------------------------------------------------------


def test_list_returns_every_capability() -> None:
    registry = build_registry()
    assert set(registry.list()) == set(ALL_CAPABILITIES)


def test_list_order_is_deterministic_and_independent_of_registration_order() -> None:
    forward = CapabilityRegistry(ALL_CAPABILITIES)
    backward = CapabilityRegistry(tuple(reversed(ALL_CAPABILITIES)))
    assert forward.list() == backward.list()
    assert [c.capability_id for c in forward.list()] == sorted(
        c.capability_id for c in ALL_CAPABILITIES
    )


def test_registry_state_does_not_mutate_through_returned_objects() -> None:
    """Returned capabilities are frozen values; the list is a fresh tuple."""
    registry = build_registry()
    listed = registry.list()
    assert isinstance(listed, tuple)

    capability = registry.get("logs.read")
    with pytest.raises(ValidationError):
        capability.resource_scope = (CUSTOMER_DATABASE,)  # type: ignore[misc]

    # Deriving a widened copy leaves the registry untouched.
    capability.model_copy(update={"resource_scope": (CUSTOMER_DATABASE,)})
    assert registry.get("logs.read").resource_scope == (PAYMENT_API,)
    assert registry.list() == listed


# --- ownership ----------------------------------------------------------------------


def test_agent_holds_a_granted_capability() -> None:
    registry = build_registry()
    assert registry.has_capability(DIAGNOSTIC, "telemetry.read")
    assert registry.has_capability(DIAGNOSTIC, "logs.read")


def test_agent_does_not_hold_a_capability_it_was_never_granted() -> None:
    registry = build_registry()
    assert not registry.has_capability(DIAGNOSTIC, "production.rollback")


def test_ownership_requires_both_sides_of_the_grant() -> None:
    """An agent record claiming a capability is not enough; the capability must agree."""
    registry = build_registry()
    assert "production.rollback" in UNREGISTERED.capabilities
    assert UNREGISTERED.agent_id not in PRODUCTION_ROLLBACK.allowed_agents
    assert not registry.has_capability(UNREGISTERED, "production.rollback")


def test_ownership_requires_the_agent_record_to_declare_it() -> None:
    """The reverse: an allowed agent that was not granted the capability holds nothing."""
    registry = build_registry()
    ungranted = REMEDIATION.model_copy(update={"capabilities": ()})
    assert ungranted.agent_id in PRODUCTION_ROLLBACK.allowed_agents
    assert not registry.has_capability(ungranted, "production.rollback")


def test_unregistered_capability_is_never_held() -> None:
    registry = CapabilityRegistry()
    assert not registry.has_capability(REMEDIATION, "production.rollback")


# --- resource scope -----------------------------------------------------------------


def test_resource_in_declared_scope() -> None:
    registry = build_registry()
    assert registry.resource_in_scope("production.rollback", PAYMENT_API)
    assert registry.resource_in_scope("production.rollback", ORDER_SERVICE)


def test_resource_outside_declared_scope() -> None:
    registry = build_registry()
    assert not registry.resource_in_scope("production.rollback", CUSTOMER_DATABASE)


def test_scope_matching_is_exact_with_no_prefix_or_wildcard_semantics() -> None:
    """Documented: exact string equality only. No hierarchy, no globs, no fuzziness."""
    assert not resource_in_scope(PRODUCTION_ROLLBACK, "service:payment-api/replica-1")
    assert not resource_in_scope(PRODUCTION_ROLLBACK, "service:payment")
    assert not resource_in_scope(PRODUCTION_ROLLBACK, "payment-api")
    assert not resource_in_scope(PRODUCTION_ROLLBACK, "service:*")
    assert not resource_in_scope(PRODUCTION_ROLLBACK, "*")
    assert not resource_in_scope(PRODUCTION_ROLLBACK, "SERVICE:PAYMENT-API")


def test_empty_scope_reaches_nothing() -> None:
    """An empty resource_scope is not a wildcard."""
    unscoped = Capability(
        capability_id="incident.update",
        description="Update an incident record.",
        risk_class=RiskLevel.LOW,
        data_classification=DataClassification.INTERNAL,
        reversible=True,
        approval_requirement=ApprovalRequirement.NONE,
        allowed_agents=("commander",),
    )
    assert unscoped.resource_scope == ()
    assert not resource_in_scope(unscoped, PAYMENT_API)
    assert not resource_in_scope(unscoped, "")


def test_unregistered_capability_scopes_nothing() -> None:
    registry = CapabilityRegistry()
    assert not registry.resource_in_scope("production.rollback", PAYMENT_API)


def test_repr_is_informative_and_stable() -> None:
    assert repr(build_registry()) == f"CapabilityRegistry({len(ALL_CAPABILITIES)} capabilities)"
