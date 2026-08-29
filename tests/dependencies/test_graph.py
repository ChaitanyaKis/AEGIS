"""Dependency graph behaviour.

The graph's job is to be boringly correct about two things: which way edges point, and
the difference between "declared with nothing depending on it" and "never heard of it".
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from aegis.core.dependencies import DependencyGraph, ResourceNode, UnknownResourceError
from aegis.core.domain import RiskLevel
from tests.fleet import (
    API_GATEWAY,
    CUSTOMER_DATABASE,
    NOTIFICATION_SERVICE,
    ORDER_SERVICE,
    PAYMENT_API,
    PAYMENT_DB,
    UNKNOWN_RESOURCE,
    build_graph,
)

# --- construction -------------------------------------------------------------------


def test_graph_reports_its_declared_resources() -> None:
    graph = build_graph()
    assert len(graph) == 8
    assert PAYMENT_API in graph
    assert graph.resources() == tuple(sorted(graph.resources()))


def test_duplicate_resource_is_rejected() -> None:
    node = ResourceNode(resource_id="service:a", criticality=RiskLevel.LOW)
    with pytest.raises(ValueError, match="duplicate resource"):
        DependencyGraph([node, node])


def test_dangling_edge_is_rejected() -> None:
    """A dangling edge would silently understate blast radius, so it is an error."""
    with pytest.raises(ValueError, match="undeclared resource"):
        DependencyGraph(
            [
                ResourceNode(
                    resource_id="service:a",
                    depends_on=("service:missing",),
                    criticality=RiskLevel.LOW,
                )
            ]
        )


def test_self_dependency_is_rejected() -> None:
    with pytest.raises(ValidationError):
        ResourceNode(
            resource_id="service:a",
            depends_on=("service:a",),
            criticality=RiskLevel.LOW,
        )


def test_criticality_is_required() -> None:
    """There is no safe default for how much a resource matters."""
    with pytest.raises(ValidationError):
        ResourceNode(resource_id="service:a")


def test_empty_graph_is_valid_and_knows_nothing() -> None:
    graph = DependencyGraph([])
    assert len(graph) == 0
    assert not graph.contains(PAYMENT_API)


# --- direction ----------------------------------------------------------------------


def test_dependencies_point_downstream() -> None:
    graph = build_graph()
    assert graph.dependencies(PAYMENT_API) == (PAYMENT_DB,)
    assert graph.dependencies(ORDER_SERVICE) == ("db:order", PAYMENT_API)


def test_dependents_point_upstream() -> None:
    """What breaks if this resource is disturbed."""
    graph = build_graph()
    assert graph.dependents(PAYMENT_API) == (API_GATEWAY, ORDER_SERVICE)
    assert graph.dependents(PAYMENT_DB) == (PAYMENT_API,)


def test_transitive_dependents_follow_the_chain() -> None:
    graph = build_graph()
    assert graph.transitive_dependents(PAYMENT_DB) == (
        API_GATEWAY,
        ORDER_SERVICE,
        PAYMENT_API,
    )


def test_transitive_dependents_exclude_the_resource_itself() -> None:
    graph = build_graph()
    assert PAYMENT_API not in graph.transitive_dependents(PAYMENT_API)


def test_top_of_the_graph_has_no_dependents() -> None:
    graph = build_graph()
    assert graph.dependents(API_GATEWAY) == ()
    assert graph.transitive_dependents(API_GATEWAY) == ()


def test_leaf_has_no_dependencies() -> None:
    graph = build_graph()
    assert graph.dependencies(NOTIFICATION_SERVICE) == ()


# --- known-empty versus unknown -----------------------------------------------------


def test_declared_resource_with_no_dependents_is_a_measurement() -> None:
    """Zero dependents is a fact about a resource we know."""
    graph = build_graph()
    assert graph.contains(CUSTOMER_DATABASE)
    assert graph.dependents(CUSTOMER_DATABASE) == ()
    assert graph.transitive_dependents(CUSTOMER_DATABASE) == ()


@pytest.mark.parametrize(
    "lookup",
    ["dependencies", "dependents", "transitive_dependents", "node", "criticality"],
)
def test_unknown_resource_raises_rather_than_returning_empty(lookup: str) -> None:
    """Missing information must never be readable as zero impact."""
    graph = build_graph()
    with pytest.raises(UnknownResourceError) as excinfo:
        getattr(graph, lookup)(UNKNOWN_RESOURCE)
    assert excinfo.value.resource == UNKNOWN_RESOURCE


def test_contains_is_the_only_tolerant_lookup() -> None:
    graph = build_graph()
    assert graph.contains(CUSTOMER_DATABASE)
    assert not graph.contains(UNKNOWN_RESOURCE)


def test_unknown_resource_error_is_a_key_error() -> None:
    graph = build_graph()
    with pytest.raises(KeyError):
        graph.node(UNKNOWN_RESOURCE)


# --- matching -----------------------------------------------------------------------


@pytest.mark.parametrize(
    "near_miss",
    [
        "service:payment",
        "payment-api",
        "service:payment-api/replica-1",
        "SERVICE:PAYMENT-API",
        "service:*",
    ],
)
def test_lookup_is_exact_with_no_prefix_or_fuzzy_matching(near_miss: str) -> None:
    graph = build_graph()
    assert not graph.contains(near_miss)
    with pytest.raises(UnknownResourceError):
        graph.dependents(near_miss)


# --- determinism and immutability ---------------------------------------------------


def test_lookups_are_sorted_and_repeatable() -> None:
    graph = build_graph()
    for _ in range(3):
        assert graph.dependents(PAYMENT_API) == (API_GATEWAY, ORDER_SERVICE)
        assert graph.transitive_dependents(PAYMENT_DB) == (
            API_GATEWAY,
            ORDER_SERVICE,
            PAYMENT_API,
        )


def test_graph_is_independent_of_declaration_order() -> None:
    from tests.fleet import BASE_TOPOLOGY

    forward = DependencyGraph(BASE_TOPOLOGY)
    backward = DependencyGraph(tuple(reversed(BASE_TOPOLOGY)))
    for resource in forward.resources():
        assert forward.dependents(resource) == backward.dependents(resource)
        assert forward.transitive_dependents(resource) == backward.transitive_dependents(resource)


def test_returned_collections_cannot_mutate_the_graph() -> None:
    graph = build_graph()
    dependents = graph.dependents(PAYMENT_API)
    assert isinstance(dependents, tuple)
    assert isinstance(graph.node(PAYMENT_API), ResourceNode)
    with pytest.raises(ValidationError):
        graph.node(PAYMENT_API).criticality = RiskLevel.LOW  # type: ignore[misc]
    assert graph.criticality(PAYMENT_API) is RiskLevel.HIGH


def test_cycles_do_not_hang_traversal() -> None:
    """A cyclic declaration is survivable; each resource is visited once."""
    graph = DependencyGraph(
        [
            ResourceNode(
                resource_id="service:a",
                depends_on=("service:b",),
                criticality=RiskLevel.LOW,
            ),
            ResourceNode(
                resource_id="service:b",
                depends_on=("service:a",),
                criticality=RiskLevel.LOW,
            ),
        ]
    )
    assert graph.transitive_dependents("service:a") == ("service:b",)
    assert graph.transitive_dependents("service:b") == ("service:a",)


def test_repr_is_informative() -> None:
    assert repr(build_graph()) == "DependencyGraph(8 resources)"
