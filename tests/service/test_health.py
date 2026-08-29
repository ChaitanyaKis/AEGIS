"""What ``/health`` says, and whether it is telling the truth.

A health endpoint that only ever answered ``{"status": "ok"}`` would be a liveness probe
and nothing else. This one also reports the governance configuration the process is
actually running, and these tests check that the report is *derived* from the constants
rather than a copy that could drift away from them.
"""

from __future__ import annotations

import json

from aegis.enterprise import PAYMENT_API, EnterpriseWorld
from aegis.orchestration.delegation import DELEGATION_MATRIX
from aegis.orchestration.orchestrator import COMMANDER_TOOLS, PROPOSAL_AUTHORITY
from aegis.service import AegisService, LiveMode
from aegis.service.app import governance_projection


def test_health_is_ok_without_credentials_or_network(service: AegisService) -> None:
    """The readiness probe must never depend on a provider. A container that reported
    unhealthy because Gemini was unreachable would fail to deploy for a reason that has
    nothing to do with whether it can serve a deterministic incident."""
    response = service.health()
    assert response.status == 200
    assert response.payload["status"] == "ok"
    assert response.payload["modes"]["deterministic"] is True


def test_health_reports_the_real_proposal_authority(service: AegisService) -> None:
    """Derived from the module that owns it. If ``PROPOSAL_AUTHORITY`` changed, this
    changes with it and the service could not report a map it is not running."""
    reported = service.health().payload["governance"]["proposal_authority"]
    assert reported == {
        capability: sorted(agents) for capability, agents in PROPOSAL_AUTHORITY.items()
    }
    assert reported == {"production.rollback": ["remediation"]}


def test_health_reports_the_real_commander_tools(service: AegisService) -> None:
    reported = service.health().payload["governance"]["commander_tools"]
    assert reported == sorted(COMMANDER_TOOLS)
    assert "get_security_signals" not in reported, "security signals belong to the Security agent"


def test_health_reports_the_real_delegation_matrix(service: AegisService) -> None:
    reported = service.health().payload["governance"]["delegation_matrix"]
    assert reported == {agent: sorted(targets) for agent, targets in DELEGATION_MATRIX.items()}
    assert reported["commander"] == ["business-impact", "diagnostic", "remediation", "security"]
    for specialist in ("diagnostic", "security", "business-impact", "remediation"):
        assert reported[specialist] == [], "a specialist may delegate to nobody"


def test_the_projection_is_a_copy_and_cannot_be_used_to_mutate_the_constants() -> None:
    """A reader of ``/health`` holds lists, not the frozensets and mappings themselves.
    Handing out the live objects would make a read-only endpoint a write primitive."""
    projection = governance_projection()
    projection["commander_tools"].append("production.rollback")
    projection["delegation_matrix"]["diagnostic"].append("remediation")
    projection["proposal_authority"]["production.rollback"].append("commander")

    assert "production.rollback" not in COMMANDER_TOOLS
    assert DELEGATION_MATRIX["diagnostic"] == frozenset()
    assert PROPOSAL_AUTHORITY["production.rollback"] == frozenset({"remediation"})


def test_health_says_the_enterprise_is_simulated(service: AegisService) -> None:
    """``claude.md`` section 17: never blur a controlled simulation into a real
    integration. Anyone reading the deployed service is told which this is."""
    enterprise = service.health().payload["enterprise"]
    assert enterprise["simulated"] is True
    assert "synthetic" in enterprise["note"]
    assert PAYMENT_API in enterprise["resources"]
    assert enterprise["resources"] == list(EnterpriseWorld().resources())


def test_health_reports_live_mode_honestly() -> None:
    """Two independent conditions, both reported. "Enabled" alone is not "available"."""
    opted_in = AegisService(
        registry=object(),  # type: ignore[arg-type] — health touches none of this
        agents={},
        expected_state=object(),  # type: ignore[arg-type]
        model_factory=lambda mode: None,  # type: ignore[arg-type,return-value]
        specialist_factory=lambda world, models: None,  # type: ignore[arg-type,return-value]
        live_mode=LiveMode(enabled=True, credentials_present=False),
    )
    reported = opted_in.health().payload
    assert reported["live_mode"] == {
        "enabled": True,
        "credentials_present": False,
        "available": False,
    }
    assert reported["modes"]["live"] is False


def test_health_carries_no_credentials(service: AegisService) -> None:
    """The endpoint is public in the demo deployment. A sweep says so rather than a
    promise, and the ``LiveMode`` fields are booleans by construction."""
    document = json.dumps(service.health().payload).lower()
    for forbidden in ("api_key", "apikey", "google_api_key", "password", "bearer", "credential="):
        assert forbidden not in document
