"""HTTP surface for AEGIS — an adapter, not a second control plane.

This package exists for one reason: a container needs something to listen on a port.
It contains no policy, no authorization, no risk computation, no approval decision and no
state-transition logic, and it must never acquire any. Everything it can do, it does by
calling the same governed entrypoint the command-line runners call.

    HTTP request
        -> aegis.service.app.AegisService
            -> aegis.evaluation.live.run_live_incident
                -> IncidentOrchestrator (policy, approval, lifecycle, gate, executor,
                   observation, verification, audit — all unchanged)

There is deliberately no route that reaches :class:`~aegis.enterprise.ActionExecutor`,
names a capability, selects an agent, or supplies an authorization. A request chooses an
incident to run and nothing about how it is governed.

Two modules, split so the governance-relevant half can be tested without a socket:

* :mod:`aegis.service.app` — pure request handling. Bytes in, status and payload out.
* :mod:`aegis.service.server` — a stdlib ``ThreadingHTTPServer`` adapter that binds
  ``$PORT``. No framework, and therefore no new dependency.
"""

from aegis.service.app import (
    MAX_BODY_BYTES,
    MAX_SOURCE_CHARS,
    MAX_STEPS,
    MIN_STEPS,
    AegisService,
    IncidentMode,
    IncidentRequest,
    LiveMode,
    ModelSet,
    ServiceResponse,
)
from aegis.service.server import make_handler, port_from_env, serve

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
    "make_handler",
    "port_from_env",
    "serve",
]
