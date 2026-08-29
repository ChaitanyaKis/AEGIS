"""Gemini model provider — the only file in AEGIS permitted to know Google exists.

Status, stated plainly under ``claude.md`` section 17
-----------------------------------------------------

* ``google-genai`` **is installed** in this project's environment (2.19.0), and the API
  surface used below was read off the installed package rather than from memory.
* **This provider has now been executed live**, against Vertex AI with
  ``gemini-2.5-flash``, and two incidents were driven end to end through the unchanged
  governance path. That makes the transport a REAL PLATFORM INTEGRATION and no longer a
  shape-verified one. The precise scope of what those runs establish — and what a sample
  of two does not — is recorded in ``docs/PROVIDER.md``.
* What the live runs do **not** establish is reliability. A language model is
  probabilistic; two runs are two observations, and no claim in this repository is derived
  from them beyond "this happened, and here is the trace".
* Everything below the transport — configuration, error classification, refusal detection,
  size limits, output validation — is also exercised by the offline suite against a fake
  client, so the deterministic path does not depend on the live one having been run.

Isolation
---------

Nothing else in AEGIS imports this module, and a structural test asserts that no module
outside this file imports ``google`` at all. The Commander depends on the
:class:`~aegis.agents.model.ModelClient` protocol; the deterministic model is the canonical
offline path; the whole suite and the whole benchmark pass with the SDK uninstalled. The
SDK import is deferred to construction so that *importing* this module never fails and
never touches the network.

Authority
---------

None. This class turns text into a
:class:`~aegis.agents.decisions.CommanderDecision` or raises. It cannot authorize, approve,
execute, verify, resolve, or reach any control-plane engine, because it holds none of them
and imports none of them. Gemini's opinion about risk is not representable: the decision
contract forbids the field.

Usage::

    uv sync --extra gemini
    export GOOGLE_API_KEY=...          # or configure Vertex AI, see from_env
    model = GeminiCommanderModel.from_env()
    commander = Commander(model)
"""

from __future__ import annotations

import os
from collections.abc import Callable, Mapping
from typing import Any, cast

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
    parse_decision,
    parse_finding,
)
from aegis.agents.prompt import render
from aegis.integrations.provider import FailureCategory, tag_failure

__all__ = [
    "API_KEY_ENV_VARS",
    "DEFAULT_GEMINI_MODEL",
    "DEFAULT_MAX_RESPONSE_BYTES",
    "MODEL_ENV_VAR",
    "REFUSAL_FINISH_REASONS",
    "GeminiCommanderModel",
    "GeminiProviderConfig",
    "GeminiSpecialistModel",
    "credentials_present",
]

DEFAULT_GEMINI_MODEL = "gemini-2.5-flash"
"""Model id used unless the caller or the environment names another.

Flash rather than Pro as the default: the Commander runs a bounded loop of small
structured-output decisions, and the cheaper model keeps a live trial affordable. Neither
choice has been measured here — see ``docs/PROVIDER.md``.
"""

API_KEY_ENV_VARS = ("GOOGLE_API_KEY", "GEMINI_API_KEY")
"""Where an API key is read from, in order. The SDK reads the same names."""

MODEL_ENV_VAR = "AEGIS_GEMINI_MODEL"
VERTEX_FLAG_ENV_VAR = "GOOGLE_GENAI_USE_VERTEXAI"
PROJECT_ENV_VAR = "GOOGLE_CLOUD_PROJECT"
LOCATION_ENV_VAR = "GOOGLE_CLOUD_LOCATION"
TIMEOUT_ENV_VAR = "AEGIS_GEMINI_TIMEOUT_SECONDS"

DEFAULT_MAX_RESPONSE_BYTES = 256 * 1024
"""Largest response body that will be parsed at all.

A decision is a few hundred bytes. Anything approaching this is either a runaway
generation or an attempt to exhaust the parser, and both are refused *before* JSON parsing
rather than after — checking afterwards would mean having already done the expensive work.
"""

REFUSAL_FINISH_REASONS = frozenset(
    {
        "SAFETY",
        "RECITATION",
        "BLOCKLIST",
        "PROHIBITED_CONTENT",
        "SPII",
        "IMAGE_SAFETY",
        "IMAGE_PROHIBITED_CONTENT",
        "IMAGE_RECITATION",
    }
)
"""Finish reasons that mean the provider declined, taken from ``types.FinishReason``.

Compared as strings rather than against the imported enum so that classification works
with the SDK absent, and so that a finish reason added by a future SDK version degrades to
"not a refusal, so parse it" — which fails closed at the parser — rather than to an
``AttributeError`` inside the provider.
"""

_QUOTA_STATUS_CODES = frozenset({429})
_CONFIGURATION_STATUS_CODES = frozenset({400, 401, 403, 404})


class GeminiProviderConfig:
    """Non-secret configuration for the provider.

    Deliberately **not** a :class:`~aegis.core.domain.base.DomainModel`: every domain model
    in AEGIS is canonically serializable, and a serializable object with somewhere to put
    an API key is a credential waiting to be written to a log. There is no key field here
    at all. The key travels from the environment or the caller straight into the SDK
    client and is never stored on any AEGIS object.

    Args:
        model: Gemini model id.
        use_vertex: Route through Vertex AI rather than the Gemini Developer API.
        project: Google Cloud project, Vertex only.
        location: Google Cloud location, Vertex only.
        timeout_seconds: Request deadline. Surfaced as :class:`ModelTimeout`.
        max_response_bytes: Refusal threshold for oversized responses.
        max_output_tokens: Generation ceiling. A second, provider-side bound on the same
            runaway the byte limit catches client-side.
    """

    def __init__(
        self,
        *,
        model: str = DEFAULT_GEMINI_MODEL,
        use_vertex: bool = False,
        project: str | None = None,
        location: str | None = None,
        timeout_seconds: float = 30.0,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
        max_output_tokens: int = 2048,
    ) -> None:
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if max_response_bytes <= 0:
            raise ValueError("max_response_bytes must be positive")
        self.model = model
        self.use_vertex = use_vertex
        self.project = project
        self.location = location
        self.timeout_seconds = timeout_seconds
        self.max_response_bytes = max_response_bytes
        self.max_output_tokens = max_output_tokens

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None, **overrides) -> GeminiProviderConfig:
        """Read configuration from the environment. Reads no key and stores no key."""
        source = os.environ if env is None else env
        vertex = str(source.get(VERTEX_FLAG_ENV_VAR, "")).strip().lower() in {"1", "true", "yes"}
        timeout = source.get(TIMEOUT_ENV_VAR)
        settings: dict[str, Any] = {
            "model": source.get(MODEL_ENV_VAR) or DEFAULT_GEMINI_MODEL,
            "use_vertex": vertex,
            "project": source.get(PROJECT_ENV_VAR) or None,
            "location": source.get(LOCATION_ENV_VAR) or None,
        }
        if timeout:
            try:
                settings["timeout_seconds"] = float(timeout)
            except ValueError as error:
                raise ValueError(f"{TIMEOUT_ENV_VAR} is not a number: {timeout!r}") from error
        settings.update(overrides)
        return cls(**settings)

    def describe(self) -> dict[str, Any]:
        """Everything about this configuration that is safe to print. No credentials."""
        return {
            "model": self.model,
            "use_vertex": self.use_vertex,
            "project": self.project,
            "location": self.location,
            "timeout_seconds": self.timeout_seconds,
            "max_response_bytes": self.max_response_bytes,
            "max_output_tokens": self.max_output_tokens,
        }

    def __repr__(self) -> str:
        return f"{type(self).__name__}(model={self.model!r}, use_vertex={self.use_vertex})"


def credentials_present(env: Mapping[str, str] | None = None) -> bool:
    """Whether *some* credential configuration exists. Never reads or returns a value.

    True means a live call is worth attempting; it does not mean the credential is valid,
    which only the provider can establish and only by being called.
    """
    source = os.environ if env is None else env
    if any(source.get(name) for name in API_KEY_ENV_VARS):
        return True
    vertex = str(source.get(VERTEX_FLAG_ENV_VAR, "")).strip().lower() in {"1", "true", "yes"}
    return bool(vertex and source.get(PROJECT_ENV_VAR))


class _GeminiModel:
    """Shared transport for the Commander and specialist providers.

    One class rather than two copies: the Commander wants a decision and a specialist wants
    a finding, and the only difference is which parser validates the text. Everything that
    matters for safety — configuration, error classification, refusal detection, size
    limits — is therefore written once and tested once.
    """

    name = "gemini"
    _parse: Callable[[str], ModelOutput]

    def __init__(
        self,
        *,
        config: GeminiProviderConfig | None = None,
        api_key: str | None = None,
        client: Any | None = None,
        env: Mapping[str, str] | None = None,
    ) -> None:
        self.config = config or GeminiProviderConfig.from_env(env)
        self.model = self.config.model
        self._last_call_metadata: dict[str, Any] = {}
        self._client = client if client is not None else self._build_client(api_key, env)

    # --- construction ---------------------------------------------------------------

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None, **overrides):
        """Build from environment configuration, or fail saying exactly what is missing."""
        return cls(config=GeminiProviderConfig.from_env(env, **overrides), env=env)

    def _build_client(self, api_key: str | None, env: Mapping[str, str] | None) -> Any:
        """Import the SDK and build a client, or explain why it cannot be done.

        Deferred to construction on purpose: importing this module must never fail, so the
        abstraction stays inspectable in an environment without the provider.

        Fails **loudly and at construction**, never at first use and never by degrading to
        something that answers. A provider that cannot be built produces no decisions, and
        no decision is the safe outcome.
        """
        source = os.environ if env is None else env
        key = api_key or next((source[n] for n in API_KEY_ENV_VARS if source.get(n)), None)
        if key is None and not self.config.use_vertex:
            raise tag_failure(
                ModelUnavailable(
                    "no Gemini credentials: set one of "
                    f"{', '.join(API_KEY_ENV_VARS)}, or configure Vertex AI with "
                    f"{VERTEX_FLAG_ENV_VAR}=true and {PROJECT_ENV_VAR}"
                ),
                FailureCategory.CONFIGURATION,
            )
        if self.config.use_vertex and not self.config.project:
            raise tag_failure(
                ModelUnavailable(f"Vertex AI requested but {PROJECT_ENV_VAR} is not set"),
                FailureCategory.CONFIGURATION,
            )
        try:
            from google import genai
        except ImportError as error:
            raise tag_failure(
                ModelUnavailable(
                    "the google-genai package is not installed; install it with "
                    "`uv sync --extra gemini`. AEGIS runs its full suite and benchmark "
                    "on the deterministic model without it"
                ),
                FailureCategory.CONFIGURATION,
            ) from error
        try:
            if self.config.use_vertex:
                return genai.Client(
                    vertexai=True, project=self.config.project, location=self.config.location
                )
            return genai.Client(api_key=key)
        except Exception as error:
            raise tag_failure(
                ModelUnavailable(f"could not build a Gemini client: {type(error).__name__}"),
                FailureCategory.CONFIGURATION,
            ) from error

    # --- the call -------------------------------------------------------------------

    @property
    def last_call_metadata(self) -> Mapping[str, Any]:
        """Token counts and finish reason for the most recent call, as plain scalars.

        Read by :class:`~aegis.integrations.provider.RecordingModelClient` through duck
        typing, so no Google type ever leaves this module.
        """
        return dict(self._last_call_metadata)

    def decide(self, request: ModelRequest) -> ModelOutput:
        """Ask Gemini for one structured output.

        The system instruction and the untrusted data go in separate channels exactly as
        :func:`~aegis.agents.prompt.render` assembles them, so incident content never
        occupies the instruction position.

        Raises:
            ModelTimeout: the request exceeded its deadline.
            ModelUnavailable: the provider could not be reached, was out of quota, or is
                misconfigured.
            ModelRefused: the provider declined to answer.
            MalformedModelOutput: the reply is not a valid decision or finding.
        """
        self._last_call_metadata = {}
        system_instruction, user_content = render(request)
        try:
            response = self._client.models.generate_content(
                model=self.config.model,
                contents=user_content,
                config={
                    "system_instruction": system_instruction,
                    "response_mime_type": "application/json",
                    "temperature": 0.0,
                    "max_output_tokens": self.config.max_output_tokens,
                    "http_options": {"timeout": int(self.config.timeout_seconds * 1000)},
                },
            )
        except ModelError:
            raise
        except BaseException as error:
            raise _translate(error, self.config.timeout_seconds) from error

        self._last_call_metadata = _usage_of(response)
        return self._parse(self._read_text(response))

    def _read_text(self, response: Any) -> str:
        """Pull the JSON body out of a provider response, or say why there is none.

        Order matters. A refusal is detected *before* the text is read, because a blocked
        response has no text and "no text" would otherwise be reported as malformed output
        — which would tell an operator the model babbled when it actually declined.
        """
        refusal = _refusal_reason(response)
        if refusal is not None:
            raise tag_failure(ModelRefused(refusal), FailureCategory.REFUSED)

        text = _response_text(response)
        if text is None:
            raise tag_failure(
                MalformedModelOutput(
                    f"could not read text from a {type(response).__name__} response"
                ),
                FailureCategory.MALFORMED,
            )
        if not text.strip():
            raise tag_failure(
                MalformedModelOutput("the provider returned an empty response"),
                FailureCategory.MALFORMED,
            )
        size = len(text.encode("utf-8", errors="ignore"))
        if size > self.config.max_response_bytes:
            raise tag_failure(
                MalformedModelOutput(
                    f"the provider returned {size} bytes, over the "
                    f"{self.config.max_response_bytes}-byte limit; refused unparsed"
                ),
                FailureCategory.MALFORMED,
            )
        return text

    def describe(self) -> dict[str, Any]:
        """Non-secret description of this provider, for a Track B report."""
        return {"provider": self.name, **self.config.describe()}

    def __repr__(self) -> str:
        return f"{type(self).__name__}(model={self.config.model!r})"


class GeminiCommanderModel(_GeminiModel):
    """A Commander model backed by Gemini. **Implemented and live-verified.**

    Differs from :class:`GeminiSpecialistModel` in exactly one thing: which validator the
    response text goes through. Both validators are the shared ones in
    :mod:`aegis.agents.model`, so a provider cannot have its own, laxer idea of what a
    valid decision is.
    """

    name = "gemini-commander"
    _parse = staticmethod(parse_decision)

    def decide(self, request: ModelRequest) -> CommanderDecision:
        return cast(CommanderDecision, super().decide(request))


class GeminiSpecialistModel(_GeminiModel):
    """A specialist model backed by Gemini. **Implemented; not live-verified.**

    The Commander path has been run live; this one has not. The live trials used
    ``--deterministic-specialists`` so that exactly one model was the variable under test.
    """

    name = "gemini-specialist"
    _parse = staticmethod(parse_finding)

    def decide(self, request: ModelRequest) -> AgentFinding:
        return cast(AgentFinding, super().decide(request))


# --- translation --------------------------------------------------------------------


def _translate(error: BaseException, timeout_seconds: float) -> ModelError:
    """Turn any provider exception into a tagged :class:`ModelError`.

    Classified **structurally** rather than by ``isinstance`` against imported SDK types:
    by the presence of an integer HTTP ``code`` (which ``google.genai.errors.APIError``
    sets), and by exception class name for transport failures. Three reasons:

    * it works with the SDK uninstalled, so the whole classifier is testable offline;
    * ``httpx.TimeoutException`` is **not** a subclass of the builtin ``TimeoutError``, so
      catching ``TimeoutError`` — as the previous version of this file did — silently
      misfiled every real timeout as "unavailable";
    * the SDK may raise ``httpx`` or ``requests`` exceptions depending on which transport
      the Vertex and Developer paths use, and both are handled by one rule.

    Every branch fails closed. There is no path here that returns a decision, a default or
    ``None`` — the return type is an exception, so the caller has nothing else to do with
    it but raise.
    """
    name = type(error).__name__
    code = getattr(error, "code", None)

    if isinstance(error, TimeoutError) or "Timeout" in name:
        return tag_failure(
            ModelTimeout(f"gemini did not answer within {timeout_seconds}s ({name})"),
            FailureCategory.TIMEOUT,
        )
    if isinstance(code, int) and not isinstance(code, bool):
        if code in _QUOTA_STATUS_CODES:
            return tag_failure(
                ModelUnavailable(f"gemini rate limited or out of quota (HTTP {code})"),
                FailureCategory.QUOTA,
            )
        if code in _CONFIGURATION_STATUS_CODES:
            return tag_failure(
                ModelUnavailable(
                    f"gemini rejected the request (HTTP {code}); check "
                    "credentials, project and model id"
                ),
                FailureCategory.CONFIGURATION,
            )
        return tag_failure(
            ModelUnavailable(f"gemini returned HTTP {code}"), FailureCategory.UNAVAILABLE
        )
    if isinstance(error, ConnectionError | OSError) or name.endswith(
        ("ConnectError", "ReadError", "WriteError", "NetworkError", "ProtocolError")
    ):
        return tag_failure(
            ModelUnavailable(f"gemini transport failure ({name})"), FailureCategory.TRANSPORT
        )
    return tag_failure(ModelUnavailable(f"gemini request failed: {name}"), FailureCategory.UNKNOWN)


def _refusal_reason(response: Any) -> str | None:
    """Why the provider declined, or ``None`` if it did not.

    Reads three independent signals, because the SDK reports a block in different places
    depending on whether the *prompt* or the *candidate* was filtered:
    ``prompt_feedback.block_reason``, an empty candidate list, and a candidate finish
    reason in :data:`REFUSAL_FINISH_REASONS`.

    Defensive throughout: a response shape this does not recognise yields ``None`` and the
    text path takes over, which still fails closed at the parser.
    """
    feedback = getattr(response, "prompt_feedback", None)
    block_reason = getattr(feedback, "block_reason", None)
    if block_reason is not None:
        return f"the provider blocked the prompt: {_enum_name(block_reason)}"

    candidates = getattr(response, "candidates", None)
    if candidates is not None and len(candidates) == 0:
        return "the provider returned no candidates"

    if candidates:
        finish = _enum_name(getattr(candidates[0], "finish_reason", None))
        if finish and finish.upper() in REFUSAL_FINISH_REASONS:
            return f"the provider stopped generating: {finish}"
    return None


def _response_text(response: Any) -> str | None:
    """The response body as text, tolerating the shapes a fake or a real client returns.

    ``GenerateContentResponse.text`` is a property that returns ``None`` when there is no
    text part, so a missing body is a legitimate outcome here rather than an error.
    """
    text = getattr(response, "text", None)
    if isinstance(text, str):
        return text
    if isinstance(response, str):
        return response
    return None


def _usage_of(response: Any) -> dict[str, Any]:
    """Token counts and finish reason as plain scalars. Never raises."""
    usage = getattr(response, "usage_metadata", None)
    candidates = getattr(response, "candidates", None) or ()
    finish = _enum_name(getattr(candidates[0], "finish_reason", None)) if candidates else None
    return {
        "prompt_tokens": _non_negative_int(getattr(usage, "prompt_token_count", None)),
        "response_tokens": _non_negative_int(getattr(usage, "candidates_token_count", None)),
        "total_tokens": _non_negative_int(getattr(usage, "total_token_count", None)),
        "finish_reason": finish,
        "model_version": _plain_str(getattr(response, "model_version", None)),
    }


def _enum_name(value: Any) -> str | None:
    """The name of an SDK enum member, or the string form of whatever was given."""
    if value is None:
        return None
    name = getattr(value, "name", None)
    if isinstance(name, str):
        return name
    return str(value)


def _non_negative_int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def _plain_str(value: Any) -> str | None:
    return value if isinstance(value, str) and value.strip() else None
