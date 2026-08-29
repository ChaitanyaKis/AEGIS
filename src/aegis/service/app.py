"""Request handling, with no HTTP library anywhere in it.

Bytes and a route in, a status and a JSON payload out. Nothing here opens a socket, which
is why every governance-relevant assertion in ``tests/service`` can be made against a plain
function call rather than against a running server.

What this layer is allowed to decide
------------------------------------

Which incident to run, against which declared resource, with which model set, and how many
Commander steps to allow. That is the whole list.

What it is not allowed to decide, and cannot express
----------------------------------------------------

Whether an action is permitted, what an action's risk is, whether a human approved,
whether a lifecycle gate exists, whether execution may proceed, or whether an incident is
resolved. :class:`IncidentRequest` has no field for any of them, and because it is a
closed :class:`~aegis.core.domain.base.DomainModel` a request that invents one is a 400
rather than a privilege. The governed run is reached through
:func:`~aegis.evaluation.live.run_live_incident`, which is the same function
``run_live_incident.py`` calls; there is no service-mode branch inside it.

``approve`` deserves its own note. It selects the verdict the *simulated* human gives, so
that a demonstration can show both the granted and the refused path. It does not create an
approval: policy still decides whether one is required, the approval engine still binds it
to a single action fingerprint, the gate is still single-use, and the executor still
refuses anything it was not authorized for. A deployment reachable by anyone other than
its operator must bind this to a real authenticated approver instead — see
``docs/DEPLOYMENT.md``.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import Field, ValidationError

from aegis import __version__
from aegis.core.capabilities import CapabilityRegistry
from aegis.core.domain import Agent, DomainModel, NonEmptyStr, utc_now
from aegis.core.verification import ExpectedState
from aegis.enterprise import PAYMENT_API, EnterpriseWorld
from aegis.evaluation.live import run_live_incident
from aegis.orchestration import SpecialistRegistry
from aegis.orchestration.delegation import DELEGATION_MATRIX
from aegis.orchestration.orchestrator import COMMANDER_TOOLS, PROPOSAL_AUTHORITY

__all__ = [
    "MAX_BODY_BYTES",
    "MAX_SOURCE_CHARS",
    "MAX_STEPS",
    "MIN_STEPS",
    "AegisService",
    "IncidentMode",
    "IncidentRequest",
    "LiveMode",
    "ModelSet",
    "ServiceResponse",
]

MAX_BODY_BYTES = 64 * 1024
"""Largest request body that will be read at all.

Checked before parsing rather than after, for the same reason the Gemini provider caps
response size before parsing: refusing afterwards means having already done the work.
"""

MAX_SOURCE_CHARS = 4096
"""Longest incident report accepted. Untrusted zone A content — bounded, not trusted."""

MIN_STEPS = 1
MAX_STEPS = 20
"""Bounds on the Commander's step budget. There is no unbounded run and no ``0`` meaning
"no limit" — the orchestrator's loop is bounded by construction and so is this.
"""

_JSON_CONTENT_TYPE = "application/json; charset=utf-8"


class IncidentMode(StrEnum):
    """Which model set drives the Commander."""

    DETERMINISTIC = "deterministic"
    """The rule-based stand-in. No credentials, no network, no spend. The default."""

    LIVE = "live"
    """A real provider. Available only when the operator has enabled it *and* credentials
    are configured — two independent conditions, because either one alone is an accident
    waiting to bill someone."""


class IncidentRequest(DomainModel):
    """What a caller may ask for. A closed contract: unknown fields are rejected.

    Every field here narrows the run. None of them widens authority, and none of them has
    a counterpart inside the control plane that could be reached by naming it.
    """

    source: str = Field(min_length=1, max_length=MAX_SOURCE_CHARS)
    """The incident report, as a reporter would phrase it. Zone A untrusted content: it
    reaches the model in the data channel and is never read as an instruction."""

    affected_resource: NonEmptyStr = PAYMENT_API
    """Which declared resource the incident concerns. Validated against the simulated
    enterprise's own topology, so an undeclared resource is a 400 rather than a run against
    a resource that does not exist."""

    mode: IncidentMode = IncidentMode.DETERMINISTIC
    approve: bool = True
    """The verdict the simulated human gives, not an approval. See the module docstring."""

    max_steps: int = Field(default=8, ge=MIN_STEPS, le=MAX_STEPS)


@dataclass(frozen=True)
class ServiceResponse:
    """One HTTP response, before anything HTTP-shaped touches it."""

    status: int
    payload: Mapping[str, Any]
    headers: Mapping[str, str] = field(default_factory=dict)

    def body(self) -> bytes:
        """Canonical JSON. Sorted keys so two identical runs produce identical bytes."""
        return json.dumps(self.payload, indent=2, sort_keys=True, default=str).encode() + b"\n"

    @property
    def content_type(self) -> str:
        return _JSON_CONTENT_TYPE


@dataclass(frozen=True)
class ModelSet:
    """The models one run uses, plus honest labels for what they actually are.

    Two labels rather than one because the live mode drives the *Commander* with a real
    provider and keeps the specialists deterministic. Reporting a single "model" for that
    arrangement would misdescribe four of the five agents.
    """

    commander: Any
    specialist_for: Callable[[str], Any]
    commander_model: str
    specialist_model: str

    def describe(self) -> dict[str, str]:
        return {"commander": self.commander_model, "specialists": self.specialist_model}


@dataclass(frozen=True)
class LiveMode:
    """Whether this deployment may spend money on a real provider.

    Two independent conditions. ``enabled`` is an operator decision expressed in the
    deployment; ``credentials_present`` is a fact about the environment. Neither implies
    the other, and the default for both is off.
    """

    enabled: bool = False
    credentials_present: bool = False

    @property
    def available(self) -> bool:
        return self.enabled and self.credentials_present

    def describe(self) -> dict[str, bool]:
        return {
            "enabled": self.enabled,
            "credentials_present": self.credentials_present,
            "available": self.available,
        }


ModelFactory = Callable[[IncidentMode], ModelSet]
SpecialistFactory = Callable[[EnterpriseWorld, ModelSet], SpecialistRegistry]


class AegisService:
    """Routes requests onto the governed entrypoint. Holds no mutable run state.

    Args:
        registry: The capability catalogue the run is governed against.
        agents: The accountable agent records, keyed as
            :func:`~aegis.evaluation.live.run_live_incident` expects them.
        expected_state: What verification must independently observe before an incident
            may be called resolved.
        model_factory: Builds the model set for a requested mode. Injected so that the
            live provider is imported only by a deployment that asked for it.
        specialist_factory: Builds the specialist registry for one run's world.
        live_mode: Whether ``mode: "live"`` may be served.
        clock: Injected so tests can pin it.

    A fresh :class:`~aegis.enterprise.EnterpriseWorld` is built per request. Nothing about
    one incident survives into the next, which is both correct for a stateless container
    and the only honest way to report ``world_changed``.
    """

    def __init__(
        self,
        *,
        registry: CapabilityRegistry,
        agents: Mapping[str, Agent],
        expected_state: ExpectedState,
        model_factory: ModelFactory,
        specialist_factory: SpecialistFactory,
        live_mode: LiveMode | None = None,
        clock: Callable[[], datetime] = utc_now,
        max_body_bytes: int = MAX_BODY_BYTES,
        version: str = __version__,
    ) -> None:
        self._registry = registry
        self._agents = dict(agents)
        self._expected_state = expected_state
        self._model_factory = model_factory
        self._specialist_factory = specialist_factory
        self._live_mode = live_mode or LiveMode()
        self._clock = clock
        self._max_body_bytes = max_body_bytes
        self._version = version

    @property
    def max_body_bytes(self) -> int:
        """Read by the server adapter so it can refuse a body before reading it."""
        return self._max_body_bytes

    # --- routing ------------------------------------------------------------------------

    def handle(self, method: str, path: str, body: bytes = b"") -> ServiceResponse:
        """Dispatch one request. The only entrypoint the server adapter uses."""
        route = _route(path)
        verb = method.upper()
        if route == "/":
            return self.index() if verb in _READ_METHODS else _method_not_allowed("GET, HEAD")
        if route == "/health":
            return self.health() if verb in _READ_METHODS else _method_not_allowed("GET, HEAD")
        if route == "/incident":
            return self.incident(body) if verb == "POST" else _method_not_allowed("POST")
        return _error(404, "not_found", f"No route {route!r}. Try GET /health.")

    # --- routes -------------------------------------------------------------------------

    def index(self) -> ServiceResponse:
        """What this service is and how to drive it."""
        return ServiceResponse(
            200,
            {
                "service": "aegis",
                "description": (
                    "AEGIS — a governed control plane for autonomous enterprise agent "
                    "fleets. This HTTP surface runs incidents through the same governance "
                    "path as the command-line runners and decides nothing itself."
                ),
                "version": self._version,
                "endpoints": {
                    "GET /": "this document",
                    "GET /health": "liveness and the governance configuration in force",
                    "POST /incident": "run one incident through the full governed path",
                },
                "enterprise": _ENTERPRISE_NOTE,
                "documentation": "docs/DEPLOYMENT.md",
            },
        )

    def health(self) -> ServiceResponse:
        """Liveness, plus the governance configuration this process is actually running.

        The governance block is a read-only projection of module constants. It is here
        because "the deployed service is governed by these rules" is a claim worth being
        able to check against the running container rather than against a document — and
        because a test can then assert that what the service reports *is* the constant, not
        a copy of it that could drift.
        """
        return ServiceResponse(
            200,
            {
                "status": "ok",
                "service": "aegis",
                "version": self._version,
                "modes": {
                    IncidentMode.DETERMINISTIC.value: True,
                    IncidentMode.LIVE.value: self._live_mode.available,
                },
                "live_mode": self._live_mode.describe(),
                "enterprise": {
                    **_ENTERPRISE_NOTE,
                    "resources": list(EnterpriseWorld().resources()),
                },
                "governance": governance_projection(),
                "limits": {
                    "max_body_bytes": self._max_body_bytes,
                    "max_source_chars": MAX_SOURCE_CHARS,
                    "min_steps": MIN_STEPS,
                    "max_steps": MAX_STEPS,
                },
            },
        )

    def incident(self, body: bytes) -> ServiceResponse:
        """Run one incident end to end and report what the artifacts say happened.

        Status codes carry the same asymmetry the command-line runner's exit codes do
        (``run_live_incident.py``): a model that behaves badly while the control plane
        holds is a 200, because that is a model behaviour failure and not an AEGIS failure.
        A 500 means the artifacts disagree with each other — production changed without a
        consumed gate, or an incident resolved without a verification — and is worth
        investigating rather than retrying.
        """
        if len(body) > self._max_body_bytes:
            return _error(413, "request_too_large", f"Body exceeds {self._max_body_bytes} bytes.")

        try:
            document = json.loads(body) if body.strip() else {}
        except (json.JSONDecodeError, UnicodeDecodeError):
            return _error(400, "invalid_json", "Body is not valid JSON.")
        if not isinstance(document, dict):
            return _error(400, "invalid_json", "Body must be a JSON object.")

        try:
            request = IncidentRequest.model_validate(document)
        except ValidationError as invalid:
            return _error(400, "invalid_request", "Request rejected.", fields=_fields(invalid))

        world = EnterpriseWorld()
        if not world.contains(request.affected_resource):
            return _error(
                400,
                "unknown_resource",
                f"{request.affected_resource!r} is not declared in the simulated enterprise.",
                known_resources=list(world.resources()),
            )

        if request.mode is IncidentMode.LIVE and not self._live_mode.available:
            return _error(
                409,
                "live_mode_unavailable",
                "This deployment is not configured to call a live provider.",
                live_mode=self._live_mode.describe(),
            )

        try:
            models = self._model_factory(request.mode)
            report = run_live_incident(
                models.commander,
                self._registry,
                self._agents,
                specialists=self._specialist_factory(world, models),
                expected_state=self._expected_state,
                world=world,
                incident_source=request.source,
                affected_resource=request.affected_resource,
                clock=self._clock,
                max_steps=request.max_steps,
                approve=request.approve,
            )
        except Exception as failure:
            # The type name is enough to act on and cannot carry a resource path, a
            # credential fragment or a slice of the untrusted incident text. The full
            # traceback goes to stderr, where the operator can see it and the caller
            # cannot.
            print(f"aegis.service: unhandled {type(failure).__name__}", file=sys.stderr)
            return _error(500, "internal_error", f"Run failed: {type(failure).__name__}.")

        return ServiceResponse(
            200 if report.governed else 500,
            {
                "mode": request.mode.value,
                "governed": report.governed,
                "model_reached_the_goal": report.model_reached_the_goal,
                "models": models.describe(),
                "request": {
                    "source": request.source,
                    "affected_resource": request.affected_resource,
                    "approve": request.approve,
                    "max_steps": request.max_steps,
                },
                "enterprise": _ENTERPRISE_NOTE,
                "report": report.as_json(),
            },
        )


# --- helpers ----------------------------------------------------------------------------

_READ_METHODS = frozenset({"GET", "HEAD"})

_ENTERPRISE_NOTE = {
    "simulated": True,
    "note": (
        "Every resource, deployment, metric and mutation is synthetic and deterministic "
        "(claude.md section 14). Nothing here is real infrastructure, real telemetry or "
        "real customer data."
    ),
}


def governance_projection() -> dict[str, Any]:
    """The governance constants in force, read from the modules that own them.

    Derived rather than restated: if the proposal-authority map, the Commander's tool set
    or the delegation matrix changed, this changes with them, and the service could not
    report a configuration it is not running.
    """
    return {
        "proposal_authority": {
            capability: sorted(agents) for capability, agents in sorted(PROPOSAL_AUTHORITY.items())
        },
        "commander_tools": sorted(COMMANDER_TOOLS),
        "delegation_matrix": {
            agent: sorted(targets) for agent, targets in sorted(DELEGATION_MATRIX.items())
        },
        "rule": (
            "LLMs propose. Deterministic systems authorize. Tools execute. "
            "Verification establishes truth."
        ),
    }


def _route(path: str) -> str:
    """Strip query and fragment, then normalise a trailing slash away."""
    route = path.split("#", 1)[0].split("?", 1)[0]
    if not route.startswith("/"):
        route = f"/{route}"
    return route.rstrip("/") or "/"


def _fields(invalid: ValidationError) -> list[dict[str, str]]:
    """Which fields failed and why — deliberately without the values that failed.

    Pydantic's own error dicts carry ``input``, and echoing that back would reflect
    arbitrary untrusted request content into the response.
    """
    return [
        {"field": ".".join(str(part) for part in error["loc"]) or "(body)", "problem": error["msg"]}
        for error in invalid.errors()
    ]


def _error(status: int, code: str, detail: str, **extra: Any) -> ServiceResponse:
    return ServiceResponse(status, {"error": code, "detail": detail, "status": status, **extra})


def _method_not_allowed(allow: str) -> ServiceResponse:
    return ServiceResponse(
        405,
        {"error": "method_not_allowed", "detail": f"Allowed: {allow}.", "status": 405},
        headers={"Allow": allow},
    )
