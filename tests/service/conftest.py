"""Fixtures for the HTTP surface.

The service under test is the one ``run_service.py`` builds, with the clock pinned. Testing
a second, easier service wired for the occasion would prove nothing about the one that
ships in the container.
"""

from __future__ import annotations

import json
import socket
from collections.abc import Callable

import pytest
from run_service import ALLOW_LIVE_ENV_VAR, build_service

from aegis.evaluation.live import GOLDEN_INCIDENT_SOURCE
from aegis.service import AegisService, ServiceResponse
from tests.fleet import fixed_clock

PLACEHOLDER_API_KEY = "not-a-real-key-composition-only"
"""Obviously fake, and never sent anywhere: the tests that set it also block the network."""

GEMINI_ENV_VARS = (
    "GOOGLE_API_KEY",
    "GEMINI_API_KEY",
    "GOOGLE_GENAI_USE_VERTEXAI",
    "GOOGLE_CLOUD_PROJECT",
    "GOOGLE_CLOUD_LOCATION",
    "AEGIS_GEMINI_MODEL",
    "AEGIS_GEMINI_TIMEOUT_SECONDS",
)
"""Every variable that changes which branch the live path takes."""


@pytest.fixture
def service() -> AegisService:
    """Deterministic mode, no live provider, pinned clock."""
    return build_service(allow_live=False, clock=fixed_clock)


@pytest.fixture
def post(service: AegisService) -> Callable[..., ServiceResponse]:
    """POST a JSON document to ``/incident``."""

    def _post(document: dict | None = None, *, path: str = "/incident") -> ServiceResponse:
        body = json.dumps(document if document is not None else {}).encode()
        return service.handle("POST", path, body)

    return _post


@pytest.fixture
def golden(post: Callable[..., ServiceResponse]) -> ServiceResponse:
    """The golden incident, run through the HTTP layer."""
    return post({"source": GOLDEN_INCIDENT_SOURCE})


@pytest.fixture
def live_environment(monkeypatch: pytest.MonkeyPatch) -> str:
    """The exact environment a deployment sets to open live mode, and nothing else.

    Every other Gemini variable is cleared first. A developer with Vertex AI configured
    would otherwise take the ``use_vertex`` branch while CI took the API-key one, and the
    two would be testing different code.

    Returns the placeholder key, so a test can assert it never surfaces.
    """
    for name in GEMINI_ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("GOOGLE_API_KEY", PLACEHOLDER_API_KEY)
    monkeypatch.setenv(ALLOW_LIVE_ENV_VAR, "true")
    return PLACEHOLDER_API_KEY


@pytest.fixture
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make every outbound socket use fail, so "it did not call out" is proven not promised.

    Name resolution and connect are both blocked, because blocking one leaves the other as
    a way out. ``OSError`` is what an unreachable network actually raises, and it is what
    the Gemini provider's ``_translate`` classifies as a transport failure -- so a blocked
    call travels exactly the path a real outage would, rather than a synthetic one.
    """

    def _blocked(*args: object, **kwargs: object) -> None:
        raise ConnectionRefusedError("network access is blocked in this test")

    monkeypatch.setattr(socket, "getaddrinfo", _blocked)
    monkeypatch.setattr(socket, "create_connection", _blocked)
    monkeypatch.setattr(socket.socket, "connect", _blocked)
    monkeypatch.setattr(socket.socket, "connect_ex", _blocked)
