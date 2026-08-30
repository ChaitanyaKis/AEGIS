"""Structured observability for AEGIS — thin OpenTelemetry wrapper.

Design principles
-----------------

1. **Optional dependency.** If ``opentelemetry-sdk`` is not installed, every call in this
   module is a no-op. Governance never fails because telemetry is absent.

2. **Telemetry failure is never governance failure.** All span operations are wrapped in
   ``try/except``; an exception in instrumentation cannot propagate into the control plane.

3. **No secrets in spans.** Attribute helpers never record credentials, raw incident text
   (beyond a size-bounded excerpt), or API keys. The helpers document what they do and do
   not record, so a reader can audit the claim.

4. **Parent-child hierarchy reflects real execution.** The incident span is the root; each
   phase (input_security, commander, delegation, policy, approval, gate, execution,
   verification) is a child of it. That is the structure of the real path, not a parallel
   demo.

Usage::

    from aegis.telemetry import AegisTelemetry, Span

    telemetry = AegisTelemetry()          # no-op if otel not installed
    with telemetry.incident_span("INC-001") as span:
        span.set("outcome", "RESOLVED")
        with telemetry.input_security_span(span) as s:
            s.set("decision", "ALLOW")
"""

from __future__ import annotations

import contextlib
from collections.abc import Generator
from typing import Any

__all__ = ["AegisTelemetry", "NoOpSpan", "Span"]


# ---------------------------------------------------------------------------
# Span abstraction (thin, works with or without otel)
# ---------------------------------------------------------------------------


class Span:
    """A live span. Wraps an OTEL span when available, acts as a no-op when not."""

    __slots__ = ("_otel", "_span")

    def __init__(self, span: Any, *, otel_available: bool) -> None:
        self._span = span
        self._otel = otel_available

    def set(self, key: str, value: Any) -> None:
        """Set an attribute. Silently ignored if OTEL is unavailable or the span is a no-op."""
        if not self._otel:
            return
        # Attribute setting is best-effort: a span attribute is diagnostic, and a
        # tracer that rejects one must never break the run it is describing.
        with contextlib.suppress(Exception):
            self._span.set_attribute(
                key,
                value if isinstance(value, str | bool | int | float) else str(value),
            )

    def set_error(self, exc: BaseException) -> None:
        """Record an exception on the span without re-raising it."""
        if not self._otel:
            return
        try:
            from opentelemetry import trace  # type: ignore[import-not-found]

            self._span.set_status(trace.Status(trace.StatusCode.ERROR, str(exc)))
            self._span.record_exception(exc)
        except Exception:
            pass

    def set_ok(self) -> None:
        """Mark the span as successful."""
        if not self._otel:
            return
        try:
            from opentelemetry import trace  # type: ignore[import-not-found]

            self._span.set_status(trace.Status(trace.StatusCode.OK))
        except Exception:
            pass

    def raw(self) -> Any:
        """The underlying OTEL span, for callers that need to pass it as a parent."""
        return self._span


class NoOpSpan(Span):
    """A span that records nothing. Used when OTEL is unavailable."""

    def __init__(self) -> None:
        super().__init__(None, otel_available=False)


# ---------------------------------------------------------------------------
# Telemetry singleton
# ---------------------------------------------------------------------------

_TRACER_NAME = "aegis"


class AegisTelemetry:
    """Provides OTEL spans for the AEGIS execution path.

    Args:
        service_name: Reported service name. Defaults to ``"aegis"``.
        exporter: An OTEL ``SpanExporter`` to use for testing (e.g. ``InMemorySpanExporter``).
                  When ``None`` and OTEL is installed, uses the OTEL SDK's default
                  configuration (environment-variable driven).
        enabled: Explicit on/off switch. Defaults to ``True``; set to ``False`` to
                 force no-op mode regardless of OTEL availability.

    Telemetry failure rule: every span context-manager is wrapped so that an OTEL error
    cannot propagate into the governance path. If a span cannot be started, the context
    manager yields a :class:`NoOpSpan` and the caller proceeds normally.
    """

    def __init__(
        self,
        *,
        service_name: str = "aegis",
        exporter: Any = None,
        enabled: bool = True,
    ) -> None:
        self._enabled = enabled
        self._tracer = None
        if not enabled:
            return
        try:
            from opentelemetry import trace  # type: ignore[import-not-found]
            from opentelemetry.sdk.resources import Resource  # type: ignore[import-not-found]
            from opentelemetry.sdk.trace import TracerProvider  # type: ignore[import-not-found]
            from opentelemetry.sdk.trace.export import (
                SimpleSpanProcessor,  # type: ignore[import-not-found]
            )

            resource = Resource.create({"service.name": service_name})
            provider = TracerProvider(resource=resource)
            if exporter is not None:
                provider.add_span_processor(SimpleSpanProcessor(exporter))
            trace.set_tracer_provider(provider)
            self._tracer = trace.get_tracer(_TRACER_NAME)
        except ImportError:
            # OTEL not installed — all spans are no-ops
            self._tracer = None
        except Exception:
            self._tracer = None

    @property
    def available(self) -> bool:
        return self._tracer is not None

    # --- span factories -----------------------------------------------------------------

    @contextlib.contextmanager
    def incident_span(self, incident_id: str) -> Generator[Span, None, None]:
        """Root span for one incident run. All other spans are children of this one."""
        yield from self._span("aegis.incident", {"incident_id": incident_id})

    @contextlib.contextmanager
    def input_security_span(self, parent: Span) -> Generator[Span, None, None]:
        yield from self._child_span("aegis.input_security", parent)

    @contextlib.contextmanager
    def commander_span(self, parent: Span, *, step: int) -> Generator[Span, None, None]:
        yield from self._child_span("aegis.commander", parent, {"step": step})

    @contextlib.contextmanager
    def delegation_span(
        self, parent: Span, *, target: str, task_type: str
    ) -> Generator[Span, None, None]:
        yield from self._child_span(
            "aegis.delegation", parent, {"target_agent": target, "task_type": task_type}
        )

    @contextlib.contextmanager
    def policy_span(self, parent: Span) -> Generator[Span, None, None]:
        yield from self._child_span("aegis.policy", parent)

    @contextlib.contextmanager
    def approval_span(self, parent: Span) -> Generator[Span, None, None]:
        yield from self._child_span("aegis.approval", parent)

    @contextlib.contextmanager
    def gate_span(self, parent: Span) -> Generator[Span, None, None]:
        yield from self._child_span("aegis.lifecycle_gate", parent)

    @contextlib.contextmanager
    def execution_span(self, parent: Span) -> Generator[Span, None, None]:
        yield from self._child_span("aegis.execution", parent)

    @contextlib.contextmanager
    def verification_span(self, parent: Span) -> Generator[Span, None, None]:
        yield from self._child_span("aegis.verification", parent)

    # --- internals ----------------------------------------------------------------------

    @contextlib.contextmanager
    def _span(self, name: str, attrs: dict[str, Any] | None = None) -> Generator[Span, None, None]:
        if self._tracer is None:
            yield NoOpSpan()
            return
        try:
            with self._tracer.start_as_current_span(name) as raw:
                span = Span(raw, otel_available=True)
                if attrs:
                    for k, v in attrs.items():
                        span.set(k, v)
                try:
                    yield span
                    span.set_ok()
                except Exception as exc:
                    span.set_error(exc)
                    raise
        except Exception:
            yield NoOpSpan()

    @contextlib.contextmanager
    def _child_span(
        self, name: str, parent: Span, attrs: dict[str, Any] | None = None
    ) -> Generator[Span, None, None]:
        if self._tracer is None:
            yield NoOpSpan()
            return
        try:
            from opentelemetry import trace  # type: ignore[import-not-found]

            parent_raw = parent.raw()
            ctx = None
            if parent_raw is not None:
                ctx = trace.set_span_in_context(parent_raw)
            with self._tracer.start_as_current_span(name, context=ctx) as raw:
                span = Span(raw, otel_available=True)
                if attrs:
                    for k, v in attrs.items():
                        span.set(k, v)
                try:
                    yield span
                    span.set_ok()
                except Exception as exc:
                    span.set_error(exc)
                    raise
        except Exception:
            yield NoOpSpan()


# ---------------------------------------------------------------------------
# Singleton for module-level default use
# ---------------------------------------------------------------------------

_default: AegisTelemetry | None = None


def get_telemetry() -> AegisTelemetry:
    """Return the process-default telemetry instance, creating it if needed."""
    global _default
    if _default is None:
        _default = AegisTelemetry()
    return _default


def set_telemetry(instance: AegisTelemetry) -> None:
    """Replace the process-default telemetry instance (for testing)."""
    global _default
    _default = instance
