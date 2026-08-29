"""Blast-radius engine behaviour, including the dependency monotonicity invariant."""

from __future__ import annotations

import pytest

from aegis.core.assessment import (
    REACH_THRESHOLDS,
    BlastRadiusEngine,
    RiskEngine,
    is_disruptive,
)
from aegis.core.dependencies import DependencyGraph, ResourceNode
from aegis.core.domain import RiskLevel, to_json
from tests.fleet import (
    API_GATEWAY,
    CUSTOMER_DATABASE,
    NOTIFICATION_SERVICE,
    ORDER_SERVICE,
    PAYMENT_API,
    PAYMENT_DB,
    PRODUCTION_ROLLBACK,
    TELEMETRY_READ,
    UNKNOWN_RESOURCE,
    build_action,
    build_graph,
)

ROLLBACK_ON_PAYMENT_API = build_action(
    requesting_agent="remediation",
    capability="production.rollback",
    target_resource=PAYMENT_API,
)

# --- known resources ----------------------------------------------------------------


def test_known_resource_with_dependents(blast_radius_engine: BlastRadiusEngine) -> None:
    assessment = blast_radius_engine.assess(ROLLBACK_ON_PAYMENT_API, PRODUCTION_ROLLBACK)
    assert assessment is not None
    assert assessment.target == PAYMENT_API
    assert set(assessment.blast_radius.scope) == {
        PAYMENT_API,
        ORDER_SERVICE,
        API_GATEWAY,
    }
    assert assessment.affected_count == 3
    assert assessment.direct_dependents == (API_GATEWAY, ORDER_SERVICE)


def test_known_resource_with_zero_dependents(
    blast_radius_engine: BlastRadiusEngine,
) -> None:
    """Declared and isolated: a real measurement of one affected resource."""
    action = build_action(
        requesting_agent="remediation",
        capability="production.rollback",
        target_resource=CUSTOMER_DATABASE,
    )
    assessment = blast_radius_engine.assess(action, PRODUCTION_ROLLBACK)
    assert assessment is not None
    assert assessment.blast_radius.scope == (CUSTOMER_DATABASE,)
    assert assessment.affected_count == 1
    assert assessment.transitive_dependents == ()


def test_single_dependency_chain(blast_radius_engine: BlastRadiusEngine) -> None:
    action = build_action(
        requesting_agent="remediation",
        capability="production.rollback",
        target_resource=PAYMENT_DB,
    )
    assessment = blast_radius_engine.assess(action, PRODUCTION_ROLLBACK)
    assert assessment is not None
    assert assessment.direct_dependents == (PAYMENT_API,)
    assert assessment.affected_count == 4


def test_target_is_always_in_scope(blast_radius_engine: BlastRadiusEngine) -> None:
    for resource in (PAYMENT_API, CUSTOMER_DATABASE, NOTIFICATION_SERVICE):
        action = build_action(
            requesting_agent="remediation",
            capability="production.rollback",
            target_resource=resource,
        )
        assessment = blast_radius_engine.assess(action, PRODUCTION_ROLLBACK)
        assert assessment is not None
        assert resource in assessment.blast_radius.scope


# --- unknown resources --------------------------------------------------------------


def test_unknown_resource_yields_no_assessment(
    blast_radius_engine: BlastRadiusEngine,
) -> None:
    """Unmeasured, not measured-as-zero."""
    action = build_action(
        requesting_agent="remediation",
        capability="production.rollback",
        target_resource=UNKNOWN_RESOURCE,
    )
    assert blast_radius_engine.assess(action, PRODUCTION_ROLLBACK) is None


def test_unknown_resource_is_distinguishable_from_an_isolated_one(
    blast_radius_engine: BlastRadiusEngine,
) -> None:
    isolated = blast_radius_engine.assess(
        build_action(
            requesting_agent="remediation",
            capability="production.rollback",
            target_resource=CUSTOMER_DATABASE,
        ),
        PRODUCTION_ROLLBACK,
    )
    unknown = blast_radius_engine.assess(
        build_action(
            requesting_agent="remediation",
            capability="production.rollback",
            target_resource=UNKNOWN_RESOURCE,
        ),
        PRODUCTION_ROLLBACK,
    )
    assert isolated is not None
    assert unknown is None


# --- disruption gate ----------------------------------------------------------------


def test_low_risk_capability_does_not_reach_dependents(
    blast_radius_engine: BlastRadiusEngine,
) -> None:
    """Reading telemetry from a service does not take down its callers."""
    action = build_action(
        requesting_agent="diagnostic",
        capability="telemetry.read",
        target_resource=PAYMENT_API,
    )
    assessment = blast_radius_engine.assess(action, TELEMETRY_READ)
    assert assessment is not None
    assert assessment.disruptive is False
    assert assessment.blast_radius.scope == (PAYMENT_API,)
    assert assessment.blast_radius.impact is RiskLevel.LOW


def test_topological_facts_are_reported_even_when_not_disruptive(
    blast_radius_engine: BlastRadiusEngine,
) -> None:
    """The graph facts stay visible; only ``scope`` narrows."""
    action = build_action(
        requesting_agent="diagnostic",
        capability="telemetry.read",
        target_resource=PAYMENT_API,
    )
    assessment = blast_radius_engine.assess(action, TELEMETRY_READ)
    assert assessment is not None
    assert assessment.transitive_dependents == (API_GATEWAY, ORDER_SERVICE)
    assert assessment.affected_count == 1


def test_disruption_gate_reads_only_the_declared_risk_class() -> None:
    assert not is_disruptive(TELEMETRY_READ)
    assert is_disruptive(PRODUCTION_ROLLBACK)
    for level in (RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL):
        assert is_disruptive(TELEMETRY_READ.model_copy(update={"risk_class": level}))


# --- impact -------------------------------------------------------------------------


def test_impact_combines_reach_and_criticality(
    blast_radius_engine: BlastRadiusEngine,
) -> None:
    assessment = blast_radius_engine.assess(ROLLBACK_ON_PAYMENT_API, PRODUCTION_ROLLBACK)
    assert assessment is not None
    assert assessment.reach_impact is RiskLevel.MEDIUM
    assert assessment.max_criticality is RiskLevel.HIGH
    assert assessment.blast_radius.impact is RiskLevel.HIGH


def test_critical_criticality_lifts_impact_even_at_minimal_reach(
    blast_radius_engine: BlastRadiusEngine,
) -> None:
    """One isolated but critical resource is not a small blast radius."""
    action = build_action(
        requesting_agent="remediation",
        capability="production.rollback",
        target_resource=CUSTOMER_DATABASE,
    )
    assessment = blast_radius_engine.assess(action, PRODUCTION_ROLLBACK)
    assert assessment is not None
    assert assessment.reach_impact is RiskLevel.LOW
    assert assessment.blast_radius.impact is RiskLevel.CRITICAL


def test_reach_thresholds_are_published_and_ascending() -> None:
    bounds = [bound for bound, _ in REACH_THRESHOLDS]
    assert bounds == sorted(bounds)
    assert REACH_THRESHOLDS[0] == (1, RiskLevel.LOW)


# --- monotonicity -------------------------------------------------------------------


def _rollback_scope(graph: DependencyGraph, resource: str) -> set[str]:
    engine = BlastRadiusEngine(graph)
    assessment = engine.assess(
        build_action(
            requesting_agent="remediation",
            capability="production.rollback",
            target_resource=resource,
        ),
        PRODUCTION_ROLLBACK,
    )
    assert assessment is not None
    return set(assessment.blast_radius.scope)


def test_adding_a_dependent_grows_the_blast_radius() -> None:
    """A new consumer of payment-api enlarges what a rollback of it reaches."""
    before = _rollback_scope(build_graph(), PAYMENT_API)
    after = _rollback_scope(
        build_graph(
            [
                ResourceNode(
                    resource_id="service:reporting",
                    depends_on=(PAYMENT_API,),
                    criticality=RiskLevel.LOW,
                )
            ]
        ),
        PAYMENT_API,
    )
    assert before < after
    assert "service:reporting" in after


def test_adding_a_dependency_never_shrinks_the_blast_radius() -> None:
    """Giving payment-api another thing to depend on cannot make it reach less."""
    before = _rollback_scope(build_graph(), PAYMENT_API)
    enriched = build_graph([ResourceNode(resource_id="db:cache", criticality=RiskLevel.LOW)])
    # payment-api now also depends on db:cache
    rebuilt = DependencyGraph(
        [
            node.model_copy(update={"depends_on": (*node.depends_on, "db:cache")})
            if node.resource_id == PAYMENT_API
            else node
            for node in [enriched.node(r) for r in enriched.resources()]
        ]
    )
    assert _rollback_scope(rebuilt, PAYMENT_API) >= before


def test_no_added_edge_shrinks_any_resources_blast_radius() -> None:
    """The general invariant: more connectivity never means less impact, anywhere."""
    base = build_graph()
    enriched = build_graph(
        [
            ResourceNode(
                resource_id="service:reporting",
                depends_on=(PAYMENT_API, ORDER_SERVICE),
                criticality=RiskLevel.MEDIUM,
            )
        ]
    )
    for resource in base.resources():
        assert _rollback_scope(base, resource) <= _rollback_scope(enriched, resource)


def test_growing_the_blast_radius_never_lowers_its_impact() -> None:
    from aegis.core.assessment import RISK_ORDER

    base = build_graph()
    enriched = build_graph(
        [
            ResourceNode(
                resource_id=f"service:consumer-{index}",
                depends_on=(PAYMENT_API,),
                criticality=RiskLevel.LOW,
            )
            for index in range(5)
        ]
    )
    engines = [BlastRadiusEngine(base), BlastRadiusEngine(enriched)]
    impacts = []
    for engine in engines:
        assessment = engine.assess(ROLLBACK_ON_PAYMENT_API, PRODUCTION_ROLLBACK)
        assert assessment is not None
        impacts.append(assessment.blast_radius.impact)
    assert RISK_ORDER[impacts[1]] >= RISK_ORDER[impacts[0]]


def test_growing_the_blast_radius_never_lowers_final_risk(
    risk_engine: RiskEngine,
) -> None:
    from aegis.core.assessment import RISK_ORDER

    risks = []
    for graph in (
        build_graph(),
        build_graph(
            [
                ResourceNode(
                    resource_id=f"service:consumer-{index}",
                    depends_on=(PAYMENT_API,),
                    criticality=RiskLevel.LOW,
                )
                for index in range(5)
            ]
        ),
    ):
        assessment = BlastRadiusEngine(graph).assess(ROLLBACK_ON_PAYMENT_API, PRODUCTION_ROLLBACK)
        assert assessment is not None
        risks.append(
            risk_engine.assess(
                ROLLBACK_ON_PAYMENT_API, PRODUCTION_ROLLBACK, assessment.blast_radius
            ).risk
        )
    assert RISK_ORDER[risks[1]] >= RISK_ORDER[risks[0]]


# --- determinism --------------------------------------------------------------------


def test_repeated_assessment_is_byte_identical(
    blast_radius_engine: BlastRadiusEngine,
) -> None:
    first = blast_radius_engine.assess(ROLLBACK_ON_PAYMENT_API, PRODUCTION_ROLLBACK)
    second = blast_radius_engine.assess(ROLLBACK_ON_PAYMENT_API, PRODUCTION_ROLLBACK)
    assert first is not None
    assert second is not None
    assert to_json(first) == to_json(second)


def test_declaration_order_does_not_change_the_result() -> None:
    from tests.fleet import BASE_TOPOLOGY

    forward = BlastRadiusEngine(DependencyGraph(BASE_TOPOLOGY))
    backward = BlastRadiusEngine(DependencyGraph(tuple(reversed(BASE_TOPOLOGY))))
    first = forward.assess(ROLLBACK_ON_PAYMENT_API, PRODUCTION_ROLLBACK)
    second = backward.assess(ROLLBACK_ON_PAYMENT_API, PRODUCTION_ROLLBACK)
    assert first is not None
    assert second is not None
    assert to_json(first) == to_json(second)


def test_agent_supplied_blast_radius_is_ignored(
    blast_radius_engine: BlastRadiusEngine,
) -> None:
    """A proposal that describes its own reach does not get to keep that description."""
    from aegis.core.domain import BlastRadius

    self_described = ROLLBACK_ON_PAYMENT_API.model_copy(
        update={
            "blast_radius": BlastRadius(scope=("service:nothing-important",), impact=RiskLevel.LOW)
        }
    )
    assessment = blast_radius_engine.assess(self_described, PRODUCTION_ROLLBACK)
    honest = blast_radius_engine.assess(ROLLBACK_ON_PAYMENT_API, PRODUCTION_ROLLBACK)
    assert assessment is not None
    assert honest is not None
    assert to_json(assessment) == to_json(honest)
    assert assessment.blast_radius.impact is RiskLevel.HIGH


@pytest.mark.parametrize("resource", [PAYMENT_API, PAYMENT_DB, CUSTOMER_DATABASE])
def test_affected_count_matches_scope(
    blast_radius_engine: BlastRadiusEngine, resource: str
) -> None:
    action = build_action(
        requesting_agent="remediation",
        capability="production.rollback",
        target_resource=resource,
    )
    assessment = blast_radius_engine.assess(action, PRODUCTION_ROLLBACK)
    assert assessment is not None
    assert assessment.affected_count == len(assessment.blast_radius.scope)
