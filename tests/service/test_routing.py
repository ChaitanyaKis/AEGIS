"""Routing, method handling and request framing.

Unglamorous, and the reason the interesting tests can assume a well-formed request reached
the service at all.
"""

from __future__ import annotations

import json

import pytest

from aegis.service import MAX_BODY_BYTES, AegisService
from aegis.service.app import _route


def test_the_index_describes_the_service(service: AegisService) -> None:
    response = service.handle("GET", "/")
    assert response.status == 200
    assert set(response.payload["endpoints"]) == {"GET /", "GET /health", "POST /incident"}


def test_an_unknown_route_is_a_404(service: AegisService) -> None:
    response = service.handle("GET", "/admin")
    assert response.status == 404
    assert response.payload["error"] == "not_found"


@pytest.mark.parametrize("method", ["PUT", "PATCH", "DELETE", "OPTIONS", "POST"])
def test_health_answers_only_reads(service: AegisService, method: str) -> None:
    response = service.handle(method, "/health")
    assert response.status == 405
    assert response.headers["Allow"] == "GET, HEAD"


@pytest.mark.parametrize("method", ["GET", "PUT", "PATCH", "DELETE", "HEAD"])
def test_the_incident_route_answers_only_post(service: AegisService, method: str) -> None:
    """A GET that ran an incident would make every crawler and link preview execute one."""
    response = service.handle(method, "/incident")
    assert response.status == 405
    assert response.headers["Allow"] == "POST"


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("/health", "/health"),
        ("/health/", "/health"),
        ("/health?verbose=1", "/health"),
        ("/health#frag", "/health"),
        ("/", "/"),
        ("", "/"),
        ("health", "/health"),
    ],
)
def test_routes_normalise(path: str, expected: str) -> None:
    assert _route(path) == expected


def test_a_query_string_cannot_reach_a_different_route(service: AegisService) -> None:
    """The query string is discarded, not parsed. There is no parameter that changes what
    runs, so there is nothing there for a caller to smuggle."""
    assert service.handle("GET", "/health?mode=live&approve=true").status == 200


@pytest.mark.parametrize("body", [b"not json", b"[]", b'{"source":', b'"a string"', b"123"])
def test_a_body_that_is_not_a_json_object_is_a_400(service: AegisService, body: bytes) -> None:
    response = service.handle("POST", "/incident", body)
    assert response.status == 400
    assert response.payload["error"] == "invalid_json"


def test_an_empty_body_is_a_validation_error_not_a_crash(service: AegisService) -> None:
    """``source`` is required, so an empty body is a 400 that names the missing field."""
    response = service.handle("POST", "/incident", b"")
    assert response.status == 400
    assert response.payload["error"] == "invalid_request"
    assert response.payload["fields"] == [{"field": "source", "problem": "Field required"}]


def test_an_oversized_body_is_refused_before_it_is_parsed(service: AegisService) -> None:
    response = service.handle("POST", "/incident", b"x" * (MAX_BODY_BYTES + 1))
    assert response.status == 413
    assert response.payload["error"] == "request_too_large"


def test_a_validation_error_does_not_echo_the_value_that_failed(service: AegisService) -> None:
    """Pydantic's own error dicts carry the offending input. Reflecting arbitrary untrusted
    content back to the caller is a habit worth not having."""
    secret = "SECRET-VALUE-THAT-MUST-NOT-COME-BACK"
    response = service.handle("POST", "/incident", json.dumps({"source": secret * 500}).encode())
    assert response.status == 400
    assert secret not in json.dumps(response.payload)


def test_responses_are_canonical_json(service: AegisService) -> None:
    """Sorted keys and a trailing newline, so two identical runs produce identical bytes."""
    body = service.health().body()
    assert body.endswith(b"\n")
    assert json.loads(body)["status"] == "ok"
