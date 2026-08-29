"""Does the installed ``google-genai`` actually look the way the provider assumes?

Everything else in this package tests the provider against a fake. A fake shaped by
guesswork proves the provider handles a response the test author imagined, so this file
closes the loop by asserting the same names and behaviours against the **real installed
package** — no credentials, no network, no request.

It skips cleanly when the SDK is absent, which is the supported deterministic
configuration. Skipping loses this check and nothing else: the provider's own logic is
covered offline either way.

What this cannot prove: that the live API behaves as the SDK's types say. Only a real
call establishes that, and none has been made here.
"""

from __future__ import annotations

import pytest

from aegis.integrations.gemini import REFUSAL_FINISH_REASONS, _translate
from aegis.integrations.provider import FailureCategory, classify_failure

genai = pytest.importorskip("google.genai", reason="google-genai is an optional extra")
types = pytest.importorskip("google.genai.types")
errors = pytest.importorskip("google.genai.errors")


class TestClientSurface:
    def test_the_client_accepts_the_arguments_the_provider_passes(self) -> None:
        import inspect

        parameters = inspect.signature(genai.Client.__init__).parameters
        for name in ("api_key", "vertexai", "project", "location"):
            assert name in parameters, f"genai.Client has no {name} parameter"

    def test_generate_content_accepts_model_contents_and_config(self) -> None:
        import inspect

        parameters = inspect.signature(genai.models.Models.generate_content).parameters
        assert {"model", "contents", "config"} <= set(parameters)


class TestGenerationConfig:
    @pytest.mark.parametrize(
        "field",
        [
            "system_instruction",
            "response_mime_type",
            "temperature",
            "http_options",
            "max_output_tokens",
        ],
    )
    def test_every_config_key_the_provider_sends_exists(self, field: str) -> None:
        assert field in types.GenerateContentConfig.model_fields

    def test_the_http_timeout_really_is_in_milliseconds(self) -> None:
        """The provider multiplies seconds by 1000; if this ever changes, that is a bug."""
        description = types.HttpOptions.model_fields["timeout"].description or ""
        assert "millisecond" in description.lower()

    def test_a_full_config_validates(self) -> None:
        """Not just the field names — the values the provider sends are acceptable."""
        config = types.GenerateContentConfig.model_validate(
            {
                "system_instruction": "instruction",
                "response_mime_type": "application/json",
                "temperature": 0.0,
                "max_output_tokens": 2048,
                "http_options": {"timeout": 30000},
            }
        )
        assert config.http_options is not None
        assert config.http_options.timeout == 30000


class TestResponseSurface:
    @pytest.mark.parametrize(
        "field", ["candidates", "prompt_feedback", "usage_metadata", "model_version"]
    )
    def test_every_response_field_the_provider_reads_exists(self, field: str) -> None:
        assert field in types.GenerateContentResponse.model_fields

    def test_response_text_is_a_property_that_may_be_absent(self) -> None:
        """``_response_text`` treats a missing body as legitimate, because it is."""
        assert isinstance(getattr(types.GenerateContentResponse, "text", None), property)
        assert types.GenerateContentResponse().text is None

    @pytest.mark.parametrize(
        "field",
        ["prompt_token_count", "candidates_token_count", "total_token_count"],
    )
    def test_every_usage_field_the_provider_reads_exists(self, field: str) -> None:
        assert field in types.GenerateContentResponseUsageMetadata.model_fields

    def test_candidate_carries_a_finish_reason(self) -> None:
        assert "finish_reason" in types.Candidate.model_fields

    def test_every_refusal_finish_reason_is_a_real_member(self) -> None:
        """A typo here would silently reclassify a safety block as ordinary output."""
        actual = {member.name for member in types.FinishReason}
        assert actual >= REFUSAL_FINISH_REASONS, sorted(REFUSAL_FINISH_REASONS - actual)

    def test_stop_is_not_treated_as_a_refusal(self) -> None:
        assert types.FinishReason.STOP.name not in REFUSAL_FINISH_REASONS


class TestRealErrorClassification:
    """The bug this file was written to catch, and its neighbours.

    The Prompt 13 provider caught the builtin ``TimeoutError``. ``httpx.TimeoutException``
    is not one, so every real Gemini timeout would have been filed as "unavailable". These
    assertions run against the actual exception classes.
    """

    def test_the_sdk_timeout_is_not_a_builtin_timeout_error(self) -> None:
        httpx = pytest.importorskip("httpx")
        assert not issubclass(httpx.TimeoutException, TimeoutError)

    def test_a_real_httpx_timeout_is_classified_as_a_timeout(self) -> None:
        httpx = pytest.importorskip("httpx")
        translated = _translate(httpx.ReadTimeout("read timed out"), 30.0)
        assert classify_failure(translated) is FailureCategory.TIMEOUT

    def test_a_real_httpx_connect_error_is_classified_as_transport(self) -> None:
        httpx = pytest.importorskip("httpx")
        translated = _translate(httpx.ConnectError("refused"), 30.0)
        assert classify_failure(translated) is FailureCategory.TRANSPORT

    @pytest.mark.parametrize(
        ("code", "expected"),
        [
            (429, FailureCategory.QUOTA),
            (500, FailureCategory.UNAVAILABLE),
            (503, FailureCategory.UNAVAILABLE),
            (401, FailureCategory.CONFIGURATION),
            (403, FailureCategory.CONFIGURATION),
            (404, FailureCategory.CONFIGURATION),
        ],
    )
    def test_real_api_errors_classify_by_status(self, code: int, expected: FailureCategory) -> None:
        error = errors.APIError(code, {"error": {"message": "m", "status": "S"}})
        assert error.code == code
        assert classify_failure(_translate(error, 30.0)) is expected

    def test_a_real_client_error_and_server_error_both_carry_a_code(self) -> None:
        payload = {"error": {"message": "m", "status": "S"}}
        assert errors.ClientError(429, payload).code == 429
        assert errors.ServerError(503, payload).code == 503

    def test_every_translation_produces_a_model_error(self) -> None:
        from aegis.agents.model import ModelError

        payload = {"error": {"message": "m", "status": "S"}}
        for raised in (
            errors.ClientError(429, payload),
            errors.ServerError(503, payload),
            TimeoutError("t"),
            RuntimeError("unexpected"),
        ):
            assert isinstance(_translate(raised, 30.0), ModelError)


class TestRealClientConstruction:
    """The closest thing to "executable in a configured environment" that can be checked
    without a credential.

    A real ``genai.Client`` is built through AEGIS's own construction path — no injected
    fake — with a placeholder key. The SDK builds its client lazily and contacts nothing at
    construction, so this reaches the network never and still proves the wiring: the
    arguments are accepted, the client exists, and ``models.generate_content`` is there to
    be called.

    What it does not prove: that a request would succeed. Only a credential and a live call
    establish that, and neither exists here.
    """

    PLACEHOLDER = "not-a-real-key-construction-only"

    def test_a_real_sdk_client_is_built_through_the_provider(self) -> None:
        from aegis.integrations.gemini import GeminiCommanderModel

        provider = GeminiCommanderModel(api_key=self.PLACEHOLDER)
        assert type(provider._client).__name__ == "Client"
        assert hasattr(provider._client.models, "generate_content")

    def test_the_vertex_path_also_builds_a_real_client(self) -> None:
        from aegis.integrations.gemini import GeminiCommanderModel, GeminiProviderConfig

        provider = GeminiCommanderModel(
            config=GeminiProviderConfig(
                use_vertex=True, project="a-project", location="us-central1"
            )
        )
        assert type(provider._client).__name__ == "Client"

    def test_the_placeholder_key_never_reaches_a_description_or_repr(self) -> None:
        import json

        from aegis.integrations.gemini import GeminiCommanderModel

        provider = GeminiCommanderModel(api_key=self.PLACEHOLDER)
        assert self.PLACEHOLDER not in json.dumps(provider.describe())
        assert self.PLACEHOLDER not in repr(provider)
        assert self.PLACEHOLDER not in repr(vars(provider))

    def test_the_specialist_provider_builds_the_same_way(self) -> None:
        from aegis.integrations.gemini import GeminiSpecialistModel

        provider = GeminiSpecialistModel(api_key=self.PLACEHOLDER)
        assert type(provider._client).__name__ == "Client"
