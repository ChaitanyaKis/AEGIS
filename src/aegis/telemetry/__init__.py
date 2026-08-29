"""AEGIS telemetry — structured OpenTelemetry spans for the governed execution path.

Optional: spans are no-ops when ``opentelemetry-sdk`` is not installed.
Telemetry failure never affects governance correctness.

Imports::

    from aegis.telemetry import AegisTelemetry, NoOpSpan, Span, get_telemetry, set_telemetry
"""

from aegis.telemetry.tracing import (
    AegisTelemetry,
    NoOpSpan,
    Span,
    get_telemetry,
    set_telemetry,
)

__all__ = [
    "AegisTelemetry",
    "NoOpSpan",
    "Span",
    "get_telemetry",
    "set_telemetry",
]
