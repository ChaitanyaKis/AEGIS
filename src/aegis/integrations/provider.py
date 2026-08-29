"""Provider-neutral facts about model calls: what was asked, what came back, how long.

Nothing here knows what a provider *is*. It works against
:class:`~aegis.agents.model.ModelClient` and plain scalars, so the deterministic model, the
replay provider and Gemini are all recorded the same way and the recording layer needs no
branch for any of them (Part 9).

Two rules this module exists to keep
------------------------------------

**Content is never recorded, only digests.** A request carries the incident payload, tool
output and organizational history — untrusted material that may contain hostile text, and
which is already recorded, once, where it belongs. A digest proves two runs sent the same
thing without copying it into a second place. Credentials never enter here at all: the
provider holds them, the request never carries them, and nothing in :class:`ProviderCall`
has anywhere to put one.

**Recording changes nothing.** :class:`RecordingModelClient` returns exactly what the inner
client returned and raises exactly what it raised. It has no fallback, no retry, no default
decision and no way to turn a failure into an answer — a recorder that could alter a
decision would be a second, undeclared reasoning layer.
"""

from __future__ import annotations

import hashlib
import time
from collections.abc import Callable, Mapping
from enum import StrEnum
from typing import Any

from pydantic import Field, JsonValue

from aegis.agents.decisions import CommanderDecision
from aegis.agents.findings import AgentFinding
from aegis.agents.model import (
    MalformedModelOutput,
    ModelError,
    ModelOutput,
    ModelRefused,
    ModelRequest,
    ModelTimeout,
    ModelUnavailable,
)
from aegis.core.domain import DomainModel, NonEmptyStr
from aegis.core.domain.serialization import to_json

__all__ = [
    "FAILURE_CATEGORY_ATTRIBUTE",
    "FailureCategory",
    "ProviderCall",
    "ProviderTrace",
    "RecordingModelClient",
    "classify_failure",
    "digest_of",
    "request_digest",
    "tag_failure",
]

FAILURE_CATEGORY_ATTRIBUTE = "aegis_failure_category"
"""Attribute a provider may set on a raised :class:`ModelError` to refine its category.

The exception hierarchy in :mod:`aegis.agents.model` is deliberately coarse: three of the
categories below all raise :class:`~aegis.agents.model.ModelUnavailable`, because a caller
must treat "quota exhausted", "service down" and "connection reset" identically — none of
them is permission. Telemetry wants the difference, so a provider tags the exception and
:func:`classify_failure` reads the tag.

A tag refines a category; it can never *widen* the exception's meaning, because the
exception type is what every caller actually branches on.
"""


class FailureCategory(StrEnum):
    """Why a model call produced no decision. Recorded, never acted on."""

    NONE = "NONE"
    """The call succeeded."""

    TIMEOUT = "TIMEOUT"
    UNAVAILABLE = "UNAVAILABLE"
    """The provider was reachable in principle but did not serve the request."""

    QUOTA = "QUOTA"
    """Rate limited or out of quota. Distinct from UNAVAILABLE because the operator's
    remedy is different, and because a run that fails this way was not a system fault."""

    TRANSPORT = "TRANSPORT"
    """The connection failed. Nothing was learned about the provider's state."""

    CONFIGURATION = "CONFIGURATION"
    """Credentials, project or model id were absent, rejected or unusable."""

    REFUSED = "REFUSED"
    """The provider declined to answer — a safety filter or a content block."""

    MALFORMED = "MALFORMED"
    """Something came back and it was not a valid decision."""

    UNKNOWN = "UNKNOWN"
    """An error the provider could not classify. Fails closed like every other."""

    @property
    def failed(self) -> bool:
        return self is not FailureCategory.NONE


_BY_EXCEPTION_TYPE: tuple[tuple[type[BaseException], FailureCategory], ...] = (
    (ModelTimeout, FailureCategory.TIMEOUT),
    (ModelRefused, FailureCategory.REFUSED),
    (MalformedModelOutput, FailureCategory.MALFORMED),
    (ModelUnavailable, FailureCategory.UNAVAILABLE),
    (ModelError, FailureCategory.UNKNOWN),
)
"""Fallback classification, most specific first. Used when a provider set no tag."""


def tag_failure[E: BaseException](error: E, category: FailureCategory) -> E:
    """Attach a failure category to an exception and return it, for ``raise tag_failure(...)``.

    Returns the same exception object, so the traceback and the ``from`` chain a provider
    builds are untouched.
    """
    setattr(error, FAILURE_CATEGORY_ATTRIBUTE, category)
    return error


def classify_failure(error: BaseException | None) -> FailureCategory:
    """The category of one failure: the provider's tag if it set one, else the type.

    Never raises and never returns ``None``: an unclassifiable error is
    :attr:`FailureCategory.UNKNOWN`, which is still a failure and still not permission.
    """
    if error is None:
        return FailureCategory.NONE
    tagged = getattr(error, FAILURE_CATEGORY_ATTRIBUTE, None)
    if isinstance(tagged, FailureCategory):
        return tagged
    for exception_type, category in _BY_EXCEPTION_TYPE:
        if isinstance(error, exception_type):
            return category
    return FailureCategory.UNKNOWN


def digest_of(text: str) -> str:
    """SHA-256 of a UTF-8 string, hex. The one hash function this package uses."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def request_digest(request: ModelRequest) -> str:
    """A stable digest of one request, over its canonical serialization.

    Canonical because :func:`~aegis.core.domain.serialization.to_json` sorts keys: the same
    request always produces the same digest, and two runs can be compared without either
    one keeping the untrusted content it sent.
    """
    return digest_of(to_json(request))


class ProviderCall(DomainModel):
    """One completed model call, reduced to scalars.

    Every field is either a hash, an identifier, an enum value or a number. There is no
    field for prompt text, response text, credentials or endpoints, which is why this can
    be recorded, printed and diffed without leaking anything.
    """

    provider: NonEmptyStr
    """The provider's ``name``, as the model boundary reports it."""

    model_id: NonEmptyStr
    """Which model was asked. May equal ``provider`` for providers without a model id."""

    call_index: int = Field(ge=0)
    request_digest: NonEmptyStr
    response_digest: NonEmptyStr | None = None
    """Digest of the canonical serialization of what came back, when anything did."""

    decision_type: NonEmptyStr | None = None
    tool_id: NonEmptyStr | None = None
    delegate_to: NonEmptyStr | None = None
    proposed_capability: NonEmptyStr | None = None
    """What the model *proposed*. Recording it is not honouring it — every one of these
    still had to survive assessment, policy, approval, the lifecycle and verification."""

    latency_ms: float = Field(ge=0.0)
    failure_category: FailureCategory = FailureCategory.NONE
    failure_type: NonEmptyStr | None = None
    """The exception class name, when the call failed."""

    prompt_tokens: int | None = Field(default=None, ge=0)
    response_tokens: int | None = Field(default=None, ge=0)
    total_tokens: int | None = Field(default=None, ge=0)
    finish_reason: NonEmptyStr | None = None

    @property
    def failed(self) -> bool:
        return self.failure_category.failed


class ProviderTrace:
    """Every call one provider made, in order.

    Mutable and deliberately not a domain contract: it is a collector that grows during a
    run. :meth:`as_record` freezes it into serializable scalars when the run is over.

    Not thread-safe, and not meant to be: one trace belongs to one run.
    """

    def __init__(self, *, provider: str, model_id: str | None = None) -> None:
        self.provider = provider
        self.model_id = model_id or provider
        self._calls: list[ProviderCall] = []

    @property
    def calls(self) -> tuple[ProviderCall, ...]:
        return tuple(self._calls)

    def append(self, call: ProviderCall) -> ProviderCall:
        self._calls.append(call)
        return call

    @property
    def call_count(self) -> int:
        return len(self._calls)

    @property
    def failure_count(self) -> int:
        return sum(1 for call in self._calls if call.failed)

    @property
    def total_latency_ms(self) -> float:
        return sum(call.latency_ms for call in self._calls)

    @property
    def total_tokens(self) -> int | None:
        """Tokens across every call, or ``None`` if no provider reported any.

        ``None`` rather than zero on purpose: a provider that reports nothing has not told
        us the cost was zero, and reporting zero would be inventing a number.
        """
        counted = [call.total_tokens for call in self._calls if call.total_tokens is not None]
        return sum(counted) if counted else None

    def decision_sequence(self) -> tuple[str, ...]:
        return tuple(call.decision_type for call in self._calls if call.decision_type)

    def tool_sequence(self) -> tuple[str, ...]:
        return tuple(call.tool_id for call in self._calls if call.tool_id)

    def delegation_sequence(self) -> tuple[str, ...]:
        return tuple(call.delegate_to for call in self._calls if call.delegate_to)

    def failure_categories(self) -> tuple[str, ...]:
        return tuple(call.failure_category.value for call in self._calls if call.failed)

    def as_record(self) -> dict[str, JsonValue]:
        """The trace as plain JSON-safe data, for a Track B report."""
        return {
            "provider": self.provider,
            "model_id": self.model_id,
            "call_count": self.call_count,
            "failure_count": self.failure_count,
            "total_latency_ms": round(self.total_latency_ms, 3),
            "total_tokens": self.total_tokens,
            "decision_sequence": list(self.decision_sequence()),
            "tool_sequence": list(self.tool_sequence()),
            "delegation_sequence": list(self.delegation_sequence()),
            "failure_categories": list(self.failure_categories()),
            "calls": [call.model_dump(mode="json") for call in self._calls],
        }

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(provider={self.provider!r}, calls={self.call_count}, "
            f"failures={self.failure_count})"
        )


class RecordingModelClient:
    """Wraps any :class:`~aegis.agents.model.ModelClient` and records what it did.

    Args:
        inner: The provider to record. Any implementation, including another recorder.
        trace: Where to record. One is built if none is given.
        clock: Monotonic source of elapsed time, injected so latency is testable. Returns
            seconds; only differences are used, so its origin is irrelevant.

    Transparent by construction: :meth:`decide` returns the inner client's value unchanged
    and re-raises its exception unchanged. It cannot substitute a decision, because it has
    no decision to substitute — there is no default anywhere in this class.

    Token counts, when a provider reports them, are read through the optional
    ``last_call_metadata`` attribute: a mapping of plain scalars the provider refreshes on
    each call. Optional and duck-typed on purpose, so a provider with no notion of tokens
    needs no changes and no provider type reaches this module.
    """

    def __init__(
        self,
        inner: Any,
        *,
        trace: ProviderTrace | None = None,
        clock: Callable[[], float] = time.perf_counter,
    ) -> None:
        self._inner = inner
        self.name = getattr(inner, "name", type(inner).__name__)
        self.trace = trace or ProviderTrace(
            provider=self.name, model_id=str(getattr(inner, "model", self.name))
        )
        self._clock = clock

    @property
    def inner(self) -> Any:
        return self._inner

    def decide(self, request: ModelRequest) -> ModelOutput:
        started = self._clock()
        try:
            output = self._inner.decide(request)
        except BaseException as error:  # recorded, then re-raised unchanged
            self._record(request, started, error=error)
            raise
        self._record(request, started, output=output)
        return output

    def _record(
        self,
        request: ModelRequest,
        started: float,
        *,
        output: ModelOutput | None = None,
        error: BaseException | None = None,
    ) -> ProviderCall:
        latency_ms = max((self._clock() - started) * 1000.0, 0.0)
        metadata = _metadata_of(self._inner)
        call = ProviderCall(
            provider=self.name,
            model_id=self.trace.model_id,
            call_index=self.trace.call_count,
            request_digest=request_digest(request),
            response_digest=digest_of(to_json(output)) if output is not None else None,
            latency_ms=round(latency_ms, 3),
            failure_category=classify_failure(error),
            failure_type=type(error).__name__ if error is not None else None,
            prompt_tokens=_int_or_none(metadata.get("prompt_tokens")),
            response_tokens=_int_or_none(metadata.get("response_tokens")),
            total_tokens=_int_or_none(metadata.get("total_tokens")),
            finish_reason=_str_or_none(metadata.get("finish_reason")),
            **_output_fields(output),
        )
        return self.trace.append(call)

    def __repr__(self) -> str:
        return f"{type(self).__name__}(inner={self._inner!r})"


def _output_fields(output: ModelOutput | None) -> dict[str, str | None]:
    """What the model proposed, as scalars. Nothing here is consulted by anything."""
    if isinstance(output, CommanderDecision):
        return {
            "decision_type": output.decision_type.value,
            "tool_id": output.tool_request.tool_id if output.tool_request else None,
            "delegate_to": output.delegation.target_agent_id if output.delegation else None,
            "proposed_capability": output.proposal.capability_id if output.proposal else None,
        }
    if isinstance(output, AgentFinding):
        return {
            "decision_type": output.finding_type.value,
            "tool_id": None,
            "delegate_to": None,
            "proposed_capability": output.proposal.capability_id if output.proposal else None,
        }
    return {
        "decision_type": None,
        "tool_id": None,
        "delegate_to": None,
        "proposed_capability": None,
    }


def _metadata_of(inner: Any) -> Mapping[str, Any]:
    """A provider's optional per-call metadata, defensively.

    A provider that raises from this property, or returns something that is not a mapping,
    contributes no telemetry rather than breaking the run: recording must never be able to
    change what happens.
    """
    try:
        metadata = getattr(inner, "last_call_metadata", None)
    except Exception:  # a broken provider must not break the recorder
        return {}
    return metadata if isinstance(metadata, Mapping) else {}


def _int_or_none(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def _str_or_none(value: Any) -> str | None:
    return value if isinstance(value, str) and value.strip() else None
