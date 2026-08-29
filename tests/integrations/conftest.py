"""Fakes standing in for the Gemini SDK, shaped like the real one.

Every attribute name here was read off the installed ``google-genai`` 2.19.0 package —
``response.text``, ``response.candidates[0].finish_reason``,
``response.prompt_feedback.block_reason``, ``response.usage_metadata.prompt_token_count``
and friends. That matters: a fake shaped by guesswork proves the provider handles a
response *the test author imagined*, which is worth nothing.

``tests/integrations/test_sdk_shape.py`` closes the remaining gap by asserting, against
the installed package, that these names really exist and that the real exception classes
classify the way the provider expects.

None of this makes a network call, and none of it needs a credential.
"""

from __future__ import annotations

from typing import Any

import pytest

from aegis.agents.model import ModelRequest

VALID_DECISION = '{"decision_type": "WAIT", "reasoning_summary": "Waiting for telemetry."}'

DEFAULT_CANDIDATES = object()
"""Sentinel meaning "build the usual single STOP candidate"; ``None`` and ``[]`` are
meaningful values a real response can carry, so neither can serve as the default."""


class FakeEnum:
    """Stands in for an SDK enum member, which carries ``.name``."""

    def __init__(self, name: str) -> None:
        self.name = name

    def __str__(self) -> str:  # pragma: no cover - only for diagnostics
        return f"FinishReason.{self.name}"


class FakeUsage:
    """Shaped like ``types.GenerateContentResponseUsageMetadata``."""

    def __init__(self, prompt: int = 1200, candidates: int = 60, total: int = 1260) -> None:
        self.prompt_token_count = prompt
        self.candidates_token_count = candidates
        self.total_token_count = total


class FakeCandidate:
    def __init__(self, finish_reason: str | None = "STOP") -> None:
        self.finish_reason = FakeEnum(finish_reason) if finish_reason else None


class FakeFeedback:
    def __init__(self, block_reason: str | None = None) -> None:
        self.block_reason = FakeEnum(block_reason) if block_reason else None


class FakeResponse:
    """Shaped like ``types.GenerateContentResponse``.

    ``text`` is a plain attribute rather than a property because the provider only reads
    it; the real class computes it from candidate parts and may yield ``None``, which is
    reproduced by passing ``text=None``.
    """

    def __init__(
        self,
        text: str | None = VALID_DECISION,
        *,
        finish_reason: str | None = "STOP",
        block_reason: str | None = None,
        candidates: Any = DEFAULT_CANDIDATES,
        usage: FakeUsage | None = None,
        model_version: str | None = "gemini-2.5-flash-001",
    ) -> None:
        self.text = text
        self.candidates = (
            [FakeCandidate(finish_reason)] if candidates is DEFAULT_CANDIDATES else candidates
        )
        self.prompt_feedback = FakeFeedback(block_reason)
        self.usage_metadata = usage if usage is not None else FakeUsage()
        self.model_version = model_version


class FakeModels:
    """Stands in for ``client.models``. Scripted, and records what it was asked."""

    def __init__(self, *outcomes: Any) -> None:
        self._outcomes = list(outcomes)
        self.calls: list[dict[str, Any]] = []

    def generate_content(self, **kwargs: Any) -> Any:
        self.calls.append(kwargs)
        if not self._outcomes:
            raise AssertionError("the fake client was called more times than it was scripted")
        outcome = self._outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome


class FakeClient:
    """Stands in for ``genai.Client``."""

    def __init__(self, *outcomes: Any) -> None:
        self.models = FakeModels(*outcomes)


class FakeApiError(Exception):
    """Shaped like ``google.genai.errors.APIError``: carries an integer ``code``."""

    def __init__(self, code: int, message: str = "api error") -> None:
        super().__init__(f"{code} {message}")
        self.code = code


class FakeTimeout(Exception):
    """Named like ``httpx.TimeoutException``, and — like it — *not* a ``TimeoutError``."""


class FakeConnectError(Exception):
    """Named like ``httpx.ConnectError``."""


@pytest.fixture
def request_one() -> ModelRequest:
    """One ordinary request, with untrusted data in the only channel that carries it."""
    return ModelRequest(
        task="Decide the next step.",
        data={"incident": {"incident_id": "INC-1", "affected_resource": "service:payment-api"}},
        available_tools=("get_service_health", "get_metrics"),
        step=0,
        max_steps=6,
    )
