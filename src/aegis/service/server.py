"""The socket half — a stdlib adapter, chosen so the deployment adds no dependency.

``ThreadingHTTPServer`` is enough for what this container is: a single-purpose service
behind the Cloud Run front end, which terminates TLS and does the load balancing. It is
not a general-purpose web stack, and ``docs/DEPLOYMENT.md`` says so rather than implying
otherwise. If this ever needed to serve real traffic, the right move is to put a proper
ASGI server in front of :class:`~aegis.service.app.AegisService` — which is possible
precisely because the request handling has no HTTP library in it.

Nothing in this module makes a decision about an incident. It moves bytes between a socket
and :meth:`~aegis.service.app.AegisService.handle`, and logs what happened.

Request bodies are never logged. They carry untrusted zone A content, which in this project
routinely includes working prompt-injection payloads, and a log line is a place that content
would be read back later by something that trusts it.
"""

from __future__ import annotations

import os
import sys
import time
from collections.abc import Mapping
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from socketserver import BaseServer
from typing import Any

from aegis.service.app import AegisService, ServiceResponse

__all__ = ["DEFAULT_PORT", "build_server", "make_handler", "port_from_env", "serve"]

DEFAULT_PORT = 8080
"""Cloud Run's default contract. ``$PORT`` overrides it and is what Cloud Run actually sets."""

PORT_ENV_VAR = "PORT"


def port_from_env(env: Mapping[str, str] | None = None) -> int:
    """The port to bind, from ``$PORT``.

    A malformed value is an error rather than a silent fall back to the default: binding
    the wrong port on Cloud Run fails the deployment health check with no explanation,
    and a startup exception naming the variable is far easier to act on.
    """
    source = os.environ if env is None else env
    raw = str(source.get(PORT_ENV_VAR, "")).strip()
    if not raw:
        return DEFAULT_PORT
    try:
        port = int(raw)
    except ValueError as error:
        raise ValueError(f"{PORT_ENV_VAR} is not a number: {raw!r}") from error
    if not 1 <= port <= 65535:
        raise ValueError(f"{PORT_ENV_VAR} is out of range: {port}")
    return port


def make_handler(service: AegisService) -> type[BaseHTTPRequestHandler]:
    """Bind one service to a request-handler class."""

    class _Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "aegis"
        sys_version = ""

        def __init__(self, request: Any, address: Any, server: BaseServer) -> None:
            self._service = service
            super().__init__(request, address, server)

        # Every verb routes to the same dispatcher so that an unsupported method gets the
        # service's own 405 (with an ``Allow`` header) rather than the base class's 501.
        def do_GET(self) -> None:
            self._dispatch("GET")

        def do_HEAD(self) -> None:
            self._dispatch("HEAD")

        def do_POST(self) -> None:
            self._dispatch("POST")

        def do_PUT(self) -> None:
            self._dispatch("PUT")

        def do_PATCH(self) -> None:
            self._dispatch("PATCH")

        def do_DELETE(self) -> None:
            self._dispatch("DELETE")

        def do_OPTIONS(self) -> None:
            self._dispatch("OPTIONS")

        def _dispatch(self, method: str) -> None:
            started = time.perf_counter()
            body, refusal = self._read_body()
            if refusal is not None:
                # The body was refused without being read, so the bytes still in flight
                # would be parsed as the next request on a kept-alive connection. Closing
                # is the only correct answer; leaving it open desynchronises the stream.
                self.close_connection = True
                response = refusal
            else:
                response = self._service.handle(method, self.path, body)
            self._respond(response, head_only=method == "HEAD", close=refusal is not None)
            elapsed = (time.perf_counter() - started) * 1000
            self._log(method, response.status, elapsed)

        def _read_body(self) -> tuple[bytes, ServiceResponse | None]:
            """Read the body, refusing an oversized or unparseable length before reading it."""
            raw = self.headers.get("Content-Length")
            if raw is None:
                return b"", None
            try:
                length = int(raw)
            except ValueError:
                return b"", _refusal(
                    400, "invalid_content_length", "Content-Length is not a number."
                )
            if length < 0:
                return b"", _refusal(400, "invalid_content_length", "Content-Length is negative.")
            if length > self._service.max_body_bytes:
                return b"", _refusal(413, "request_too_large", "Body is too large.")
            return self.rfile.read(length), None

        def _respond(
            self, response: ServiceResponse, *, head_only: bool, close: bool = False
        ) -> None:
            payload = response.body()
            self.send_response(response.status)
            self.send_header("Content-Type", response.content_type)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            if close:
                self.send_header("Connection", "close")
            for name, value in response.headers.items():
                self.send_header(name, value)
            self.end_headers()
            if not head_only:
                self.wfile.write(payload)

        def _log(self, method: str, status: int, elapsed_ms: float) -> None:
            # Method, route, status, duration. No body, no headers, no query string:
            # anything the caller controls is untrusted content that has no business being
            # written somewhere it will later be read back.
            route = self.path.split("?", 1)[0]
            print(
                f"aegis.service {method} {route} -> {status} ({elapsed_ms:.1f} ms)",
                file=sys.stderr,
            )

        def log_message(self, format: str, *args: Any) -> None:
            """Silence the base class's own stdout logging; :meth:`_log` is the one line."""

    return _Handler


def build_server(
    service: AegisService, *, host: str = "0.0.0.0", port: int = DEFAULT_PORT
) -> ThreadingHTTPServer:
    """Construct a bound server without serving, so a test can pick an ephemeral port."""
    return ThreadingHTTPServer((host, port), make_handler(service))


def serve(service: AegisService, *, host: str = "0.0.0.0", port: int = DEFAULT_PORT) -> None:
    """Bind and serve until interrupted."""
    server = build_server(service, host=host, port=port)
    bound_host, bound_port = server.server_address[:2]
    print(f"aegis.service listening on http://{bound_host}:{bound_port}", file=sys.stderr)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


def _refusal(status: int, code: str, detail: str) -> ServiceResponse:
    return ServiceResponse(status, {"error": code, "detail": detail, "status": status})
