"""Fixtures for the HTTP surface.

The service under test is the one ``run_service.py`` builds, with the clock pinned. Testing
a second, easier service wired for the occasion would prove nothing about the one that
ships in the container.
"""

from __future__ import annotations

import json
from collections.abc import Callable

import pytest
from run_service import build_service

from aegis.evaluation.live import GOLDEN_INCIDENT_SOURCE
from aegis.service import AegisService, ServiceResponse
from tests.fleet import fixed_clock


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
