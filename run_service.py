"""Serve AEGIS over HTTP — the composition root for the container image.

    uv run python run_service.py                  # http://127.0.0.1:8080
    uv run python run_service.py --check          # build everything, print /health, exit

This is the deployment counterpart of ``run_benchmark.py`` (Track A, deterministic) and
``run_live_incident.py`` (Track B, one real model). It adds no governance and removes none:
``POST /incident`` reaches the enterprise through
:func:`~aegis.evaluation.live.run_live_incident`, which is the same function the Track B
runner calls, wired to the same orchestrator the benchmark drives.

Why the fleet comes from ``tests.fleet``
----------------------------------------

For the reason ``run_benchmark.py`` gives: the declared organizational configuration the
rest of the suite asserts against is the one worth demonstrating. A second copy written for
the service could drift from it, and a demonstration of a fleet nobody tests would prove
nothing about the one that is tested.

Safe by default
---------------

The service starts in deterministic mode. It needs no credentials, makes no network call
and spends nothing, and every governance control is exercised exactly as it is offline.
Calling a real provider requires **two** independent conditions:

    AEGIS_SERVICE_ALLOW_LIVE=true    (or --allow-live)   the operator opted in
    GOOGLE_API_KEY=... / Vertex AI configured            credentials exist

With both, ``{"mode": "live"}`` drives the *Commander* with Gemini and keeps the four
specialists deterministic — one live variable rather than five, which is also what
``run_live_incident.py --deterministic-specialists`` does. Without both, that request is a
409 and nothing is called.

The enterprise is the simulator (``claude.md`` section 14). It is synthetic and
deterministic, and neither this script nor the service describes it as anything else.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Callable
from datetime import datetime

from run_live_incident import build_specialists
from tests.fleet import COMMANDER, REMEDIATION, build_registry

from aegis.agents.deterministic import DeterministicCommanderModel
from aegis.agents.specialists import (
    BusinessImpactModel,
    DiagnosticModel,
    RemediationModel,
    SecurityModel,
)
from aegis.core.domain import utc_now
from aegis.enterprise import PAYMENT_API_RECOVERED, EnterpriseWorld
from aegis.orchestration import SpecialistRegistry
from aegis.service import AegisService, IncidentMode, LiveMode, ModelSet, port_from_env, serve

ALLOW_LIVE_ENV_VAR = "AEGIS_SERVICE_ALLOW_LIVE"
"""Operator opt-in for live provider calls. Absent or falsey means deterministic only."""

DETERMINISTIC_SPECIALIST_MODELS = {
    "diagnostic": DiagnosticModel,
    "security": SecurityModel,
    "business-impact": BusinessImpactModel,
    "remediation": RemediationModel,
}

SERVICE_FLEET = {"commander": COMMANDER, "remediation": REMEDIATION}
"""The accountable agent records the orchestrator needs by name. The specialists arrive
through the specialist registry, each with its own identity and toolbox."""


def allow_live_from_env(env: dict[str, str] | None = None) -> bool:
    source = os.environ if env is None else env
    return str(source.get(ALLOW_LIVE_ENV_VAR, "")).strip().lower() in {"1", "true", "yes"}


def deterministic_models() -> ModelSet:
    """The rule-based fleet. **DETERMINISTIC TEST MODELS** — not language models."""
    return ModelSet(
        commander=DeterministicCommanderModel(),
        specialist_for=lambda agent_id: DETERMINISTIC_SPECIALIST_MODELS[agent_id](clock=utc_now),
        commander_model="deterministic-test-model",
        specialist_model="deterministic-test-model",
    )


def live_models() -> ModelSet:
    """A real Gemini Commander with deterministic specialists.

    Imported here rather than at module scope so that a deterministic deployment never
    needs ``google-genai`` installed, and a container that was never opted in never
    constructs a client.
    """
    from aegis.integrations.gemini import GeminiCommanderModel, GeminiProviderConfig

    config = GeminiProviderConfig.from_env()
    return ModelSet(
        commander=GeminiCommanderModel(config=config),
        specialist_for=lambda agent_id: DETERMINISTIC_SPECIALIST_MODELS[agent_id](clock=utc_now),
        commander_model=config.model,
        specialist_model="deterministic-test-model",
    )


def build_service(
    *, allow_live: bool = False, clock: Callable[[], datetime] = utc_now
) -> AegisService:
    """Wire the service. No socket, so this is also what ``--check`` and the tests build.

    Args:
        clock: Injected so a test can pin it and assert against the real wiring rather
            than against a second, easier one built for the occasion.
    """
    registry = build_registry()

    def model_factory(mode: IncidentMode) -> ModelSet:
        return live_models() if mode is IncidentMode.LIVE else deterministic_models()

    def specialist_factory(world: EnterpriseWorld, models: ModelSet) -> SpecialistRegistry:
        return build_specialists(world, registry, models.specialist_for)

    return AegisService(
        registry=registry,
        agents=SERVICE_FLEET,
        expected_state=PAYMENT_API_RECOVERED,
        model_factory=model_factory,
        specialist_factory=specialist_factory,
        live_mode=LiveMode(enabled=allow_live, credentials_present=_credentials_present()),
        clock=clock,
    )


def _credentials_present() -> bool:
    """Whether *some* credential configuration exists. Reads no value and prints none.

    The import is local and guarded: a deterministic deployment does not have
    ``google-genai`` installed, and the absence of the provider means the absence of
    credentials rather than a crash at startup.
    """
    try:
        from aegis.integrations.gemini import credentials_present
    except ImportError:  # pragma: no cover — exercised only without the optional extra
        return False
    return credentials_present()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="0.0.0.0", help="bind address (default: 0.0.0.0)")
    parser.add_argument(
        "--port",
        type=int,
        default=None,
        help="bind port (default: $PORT, or 8080 — Cloud Run sets $PORT)",
    )
    parser.add_argument(
        "--allow-live",
        action="store_true",
        help=f"permit mode=live requests (or set {ALLOW_LIVE_ENV_VAR}=true). Still requires "
        "credentials, and a live request costs money.",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="build the service, print the /health payload and exit without binding a port",
    )
    args = parser.parse_args(argv)

    service = build_service(allow_live=args.allow_live or allow_live_from_env())

    if args.check:
        print(json.dumps(service.health().payload, indent=2, sort_keys=True))
        return 0

    try:
        port = args.port if args.port is not None else port_from_env()
    except ValueError as error:
        print(f"Cannot determine a port: {error}", file=sys.stderr)
        return 2

    serve(service, host=args.host, port=port)
    return 0


if __name__ == "__main__":
    sys.exit(main())
