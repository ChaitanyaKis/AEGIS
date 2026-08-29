"""``run_service.py`` — the composition root the container actually runs.

The service is only as safe as the thing that wires it. These check the wiring: which
fleet it demonstrates, what the default mode is, and that opting into a live provider takes
two independent decisions rather than one.
"""

from __future__ import annotations

import json

import pytest
import run_service

from aegis.enterprise import PAYMENT_API_RECOVERED
from aegis.service import IncidentMode
from tests.fleet import COMMANDER, REMEDIATION, fixed_clock


def test_the_service_demonstrates_the_fleet_the_suite_asserts_against() -> None:
    """The same argument ``run_benchmark.py`` makes. A demonstration of a fleet nobody
    tests would prove nothing about the one that is tested."""
    assert run_service.SERVICE_FLEET["commander"] is COMMANDER
    assert run_service.SERVICE_FLEET["remediation"] is REMEDIATION


def test_the_expected_state_is_the_declared_one() -> None:
    """Verification compares against the project's declared recovered state, not one the
    service invented for itself."""
    assert run_service.PAYMENT_API_RECOVERED is PAYMENT_API_RECOVERED


def test_the_default_deployment_is_deterministic_and_spends_nothing() -> None:
    service = run_service.build_service()
    payload = service.health().payload
    assert payload["modes"]["deterministic"] is True
    assert payload["live_mode"]["enabled"] is False


def test_opting_in_alone_does_not_make_live_mode_available(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Two independent conditions. An operator who set the flag but configured no
    credentials gets a 409, not a confusing provider error at request time."""
    monkeypatch.setattr(run_service, "_credentials_present", lambda: False)
    payload = run_service.build_service(allow_live=True).health().payload
    assert payload["live_mode"] == {
        "enabled": True,
        "credentials_present": False,
        "available": False,
    }


def test_credentials_alone_do_not_make_live_mode_available(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The converse. A container that found a key in its environment does not start
    spending because of it."""
    monkeypatch.setattr(run_service, "_credentials_present", lambda: True)
    payload = run_service.build_service(allow_live=False).health().payload
    assert payload["live_mode"]["available"] is False


@pytest.mark.parametrize("value", ["true", "TRUE", "1", "yes", " true "])
def test_the_opt_in_environment_variable_is_read(value: str) -> None:
    assert run_service.allow_live_from_env({run_service.ALLOW_LIVE_ENV_VAR: value}) is True


@pytest.mark.parametrize("value", ["", "false", "0", "no", "maybe", "TRUE-ish"])
def test_anything_else_is_not_an_opt_in(value: str) -> None:
    """Fails closed. An unrecognised value is not permission."""
    assert run_service.allow_live_from_env({run_service.ALLOW_LIVE_ENV_VAR: value}) is False


def test_the_opt_in_is_absent_by_default() -> None:
    assert run_service.allow_live_from_env({}) is False


def test_the_deterministic_models_are_labelled_as_what_they_are() -> None:
    """``claude.md`` section 17. The rule-based stand-in is not a language model and the
    response must never let a reader think Gemini ran."""
    models = run_service.deterministic_models()
    assert models.commander_model == "deterministic-test-model"
    assert models.specialist_model == "deterministic-test-model"
    assert models.describe() == {
        "commander": "deterministic-test-model",
        "specialists": "deterministic-test-model",
    }


def test_the_model_factory_serves_deterministic_without_touching_the_provider() -> None:
    """No import of ``google-genai``, no client, no credential read. The Gemini import
    lives inside :func:`run_service.live_models` for exactly this reason."""
    service = run_service.build_service(clock=fixed_clock)
    response = service.handle("POST", "/incident", b'{"source":"monitoring.alerting: x"}')
    assert response.status == 200
    assert response.payload["models"]["commander"] == "deterministic-test-model"


def test_the_live_model_set_keeps_the_specialists_deterministic() -> None:
    """One live variable rather than five, matching
    ``run_live_incident.py --deterministic-specialists``. Checked from the source, since
    building the set would construct a client."""
    import inspect

    source = inspect.getsource(run_service.live_models)
    assert 'specialist_model="deterministic-test-model"' in source
    assert "GeminiCommanderModel" in source
    assert "GeminiSpecialistModel" not in source


def test_check_prints_health_and_exits_zero(capsys: pytest.CaptureFixture[str]) -> None:
    """What the Docker health check and CI run. Builds the whole service, binds nothing."""
    assert run_service.main(["--check"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "ok"
    assert payload["governance"]["proposal_authority"] == {"production.rollback": ["remediation"]}


def test_a_malformed_port_is_reported_rather_than_guessed(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("PORT", "not-a-port")
    assert run_service.main([]) == 2
    assert "PORT" in capsys.readouterr().err


def test_the_incident_mode_enum_has_exactly_two_members() -> None:
    """There is no third mode, and in particular no mode that skips governance."""
    assert {mode.value for mode in IncidentMode} == {"deterministic", "live"}
