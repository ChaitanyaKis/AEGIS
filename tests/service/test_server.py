"""The socket adapter, exercised over a real loopback connection.

Everything else in this directory calls :meth:`AegisService.handle` directly, which is
right for governance assertions and wrong for proving that the container will actually
answer. These bind ``127.0.0.1`` on an ephemeral port and speak HTTP to themselves with the
standard library. No external network, no credentials, no deployed service.
"""

from __future__ import annotations

import http.client
import json
import threading
from collections.abc import Iterator

import pytest
from run_service import build_service

from aegis.evaluation.live import GOLDEN_INCIDENT_SOURCE
from aegis.service import MAX_BODY_BYTES, AegisService, port_from_env
from aegis.service.server import DEFAULT_PORT, build_server
from tests.fleet import fixed_clock


@pytest.fixture(scope="module")
def live_service() -> AegisService:
    return build_service(allow_live=False, clock=fixed_clock)


@pytest.fixture(scope="module")
def address(live_service: AegisService) -> Iterator[tuple[str, int]]:
    """A running server on an ephemeral loopback port."""
    server = build_server(live_service, host="127.0.0.1", port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[0], server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _request(
    address: tuple[str, int], method: str, path: str, body: bytes | None = None
) -> tuple[int, dict, dict[str, str]]:
    connection = http.client.HTTPConnection(*address, timeout=30)
    try:
        headers = {"Content-Type": "application/json"} if body is not None else {}
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        raw = response.read()
        payload = json.loads(raw) if raw else {}
        return response.status, payload, dict(response.getheaders())
    finally:
        connection.close()


def test_the_server_answers_health(address: tuple[str, int]) -> None:
    status, payload, headers = _request(address, "GET", "/health")
    assert status == 200
    assert payload["status"] == "ok"
    assert headers["Content-Type"] == "application/json; charset=utf-8"
    assert headers["X-Content-Type-Options"] == "nosniff"


def test_the_server_runs_a_governed_incident(address: tuple[str, int]) -> None:
    """The whole thing, over a socket: request in, verified rollback out."""
    body = json.dumps({"source": GOLDEN_INCIDENT_SOURCE}).encode()
    status, payload, _ = _request(address, "POST", "/incident", body)
    assert status == 200
    assert payload["governed"] is True
    assert payload["report"]["verification"] == "VERIFIED"
    assert payload["report"]["gates_consumed"] == 1


def test_a_head_request_returns_headers_without_a_body(address: tuple[str, int]) -> None:
    connection = http.client.HTTPConnection(*address, timeout=30)
    try:
        connection.request("HEAD", "/health")
        response = connection.getresponse()
        assert response.status == 200
        assert response.read() == b""
        assert int(response.getheader("Content-Length")) > 0
    finally:
        connection.close()


def test_an_unknown_route_is_a_404_over_the_socket(address: tuple[str, int]) -> None:
    status, payload, _ = _request(address, "GET", "/admin")
    assert status == 404
    assert payload["error"] == "not_found"


def test_a_disallowed_method_carries_an_allow_header(address: tuple[str, int]) -> None:
    status, _, headers = _request(address, "DELETE", "/health")
    assert status == 405
    assert headers["Allow"] == "GET, HEAD"


def test_an_oversized_body_is_refused_without_being_read(address: tuple[str, int]) -> None:
    """Refused from ``Content-Length`` alone. Reading it first and then complaining would
    mean having already accepted whatever was sent."""
    status, payload, _ = _request(address, "POST", "/incident", b"x" * (MAX_BODY_BYTES + 10))
    assert status == 413
    assert payload["error"] == "request_too_large"


def test_the_connection_survives_a_second_request(address: tuple[str, int]) -> None:
    """HTTP/1.1 with a correct Content-Length, so keep-alive works and Cloud Run's front
    end is not left waiting for a body that never ends."""
    connection = http.client.HTTPConnection(*address, timeout=30)
    try:
        for _ in range(2):
            connection.request("GET", "/health")
            response = connection.getresponse()
            assert response.status == 200
            assert json.loads(response.read())["status"] == "ok"
    finally:
        connection.close()


# --- port resolution --------------------------------------------------------------------


def test_the_port_defaults_to_the_cloud_run_contract() -> None:
    assert port_from_env({}) == DEFAULT_PORT == 8080


def test_the_port_comes_from_the_environment() -> None:
    """Cloud Run sets ``$PORT`` and the container must honour it."""
    assert port_from_env({"PORT": "9090"}) == 9090
    assert port_from_env({"PORT": " 9090 "}) == 9090


@pytest.mark.parametrize("value", ["", "   "])
def test_an_empty_port_falls_back_to_the_default(value: str) -> None:
    assert port_from_env({"PORT": value}) == DEFAULT_PORT


@pytest.mark.parametrize("value", ["eight thousand", "80.5", "0", "-1", "70000"])
def test_a_malformed_port_is_an_error_rather_than_a_silent_default(value: str) -> None:
    """Binding the wrong port on Cloud Run fails the health check with no explanation. An
    exception naming the variable is the difference between a five-minute fix and an hour."""
    with pytest.raises(ValueError, match="PORT"):
        port_from_env({"PORT": value})
