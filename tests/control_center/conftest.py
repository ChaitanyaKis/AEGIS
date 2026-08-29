"""Fixtures for the control-center suite: real runs, real artifacts, real projections.

Nothing is mocked that matters. Every projection here is built by capturing a genuine
orchestrator that genuinely ran an incident, so a test that passes is a test about the
artifacts AEGIS actually produces.

The broken-source fixtures are the interesting ones. They damage the *captured input* --
an unreadable store, a rewritten digest, a truncated trail -- and never the views. A
projection handed a pre-broken answer would be measuring nothing.
"""

from __future__ import annotations

import pytest

from aegis.control_center import (
    ControlCenterInput,
    IncidentProjection,
    capture_incident,
    project_incident,
)
from aegis.core.audit.records import verify_chain
from aegis.enterprise import PAYMENT_API, EnterpriseWorld
from aegis.evaluation.control_center_stage import fleet_profiles
from tests.fleet import (
    BUSINESS_IMPACT,
    COMMANDER,
    DIAGNOSTIC,
    REMEDIATION,
    SECURITY,
    fixed_clock,
)
from tests.orchestration.conftest import build_incident, build_orchestrator

FLEET = (COMMANDER, DIAGNOSTIC, SECURITY, BUSINESS_IMPACT, REMEDIATION)
"""The control-plane records for the whole fleet.

A ``SpecialistAgent`` exposes its id and what it may propose, not the ``Agent`` record it
runs as -- so the records come from the fleet the application wired up, which is where they
actually live."""

__all__ = ["capture", "corrupt", "truncate"]


def capture(orchestrator, run, **overrides) -> ControlCenterInput:
    """Freeze one orchestrator's artifacts, with the fleet profiles filled in."""
    settings = {
        "agents": fleet_profiles(orchestrator, FLEET),
        "clock": fixed_clock,
    }
    settings.update(overrides)
    return capture_incident(orchestrator, run, **settings)


def corrupt(data: ControlCenterInput, index: int | None = None) -> ControlCenterInput:
    """Rewrite one record's digest, so the chain fails to verify at that index.

    What a tampered trail actually looks like: the records are all there and one of them no
    longer matches itself. The integrity report is recomputed from the damaged records, so
    the projection is told what a real verification would tell it.
    """
    records = list(data.audit_records)
    position = len(records) // 2 if index is None else index
    records[position] = records[position].model_copy(update={"digest": "0" * 64})
    return data.model_copy(
        update={
            "audit_records": tuple(records),
            "audit_integrity": verify_chain(tuple(records)),
        }
    )


def truncate(data: ControlCenterInput, keep: int | None = None) -> ControlCenterInput:
    """Drop the tail of the trail, leaving a prefix that still verifies perfectly.

    The subtle damage. A truncated prefix passes every chain check -- a valid chain proves
    no *tampering*, not *completeness* -- so the only thing that can detect it is the
    store's own head digest, which is left untouched here on purpose.
    """
    kept = data.audit_records[: len(data.audit_records) // 2 if keep is None else keep]
    return data.model_copy(update={"audit_records": kept, "audit_integrity": verify_chain(kept)})


@pytest.fixture
def resolved():
    """A clean, fully resolved incident: orchestrator, run, and every artifact intact."""
    orchestrator = build_orchestrator()
    run = orchestrator.run(build_incident(), affected_resource=PAYMENT_API)
    return orchestrator, run


@pytest.fixture
def data(resolved) -> ControlCenterInput:
    orchestrator, run = resolved
    return capture(orchestrator, run)


@pytest.fixture
def projection(data: ControlCenterInput) -> IncidentProjection:
    return project_incident(data)


@pytest.fixture
def denied():
    """A run policy refused. Nothing executed, and the world is untouched."""
    from tests.fleet import DIAGNOSTIC

    orchestrator = build_orchestrator(remediation_agent=DIAGNOSTIC)
    run = orchestrator.run(build_incident(), affected_resource=PAYMENT_API)
    return orchestrator, run


@pytest.fixture
def escalated():
    """A run with nothing to roll back to, which escalates rather than inventing a fix."""
    from aegis.enterprise import AUTH_SERVICE

    orchestrator = build_orchestrator(world=EnterpriseWorld())
    run = orchestrator.run(build_incident(), affected_resource=AUTH_SERVICE)
    return orchestrator, run
