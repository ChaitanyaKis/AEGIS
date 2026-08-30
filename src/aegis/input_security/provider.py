"""Input security providers: the boundary between untrusted content and the model.

Architecture:

    UNTRUSTED INPUT
          ↓
    InputSecurityProvider.screen(content)
          ↓
    InputSecurityVerdict (ALLOW | BLOCK)
          ↓
    ALLOW → model-facing pipeline
    BLOCK → audit + refuse, model never called

Two implementations are provided here:

DeterministicInputSecurity
    Pattern-based, deterministic, no network calls, no credentials. This is what the test
    suite uses and what the service uses by default. It covers known prompt injection
    patterns and policy-violation signals. Because it is deterministic, two calls with the
    same input always produce the same verdict, which is the property that lets the
    benchmark and the test suite rely on it.

ModelArmorInputSecurity (optional)
    Google Cloud Model Armor adapter. Only importable when ``google-cloud-modelarmor`` is
    installed (part of the ``modelarmor`` optional dependency group). If the package is
    absent and this class is constructed, it raises ``ImportError`` at construction time
    rather than at screening time — fail closed rather than silently allowing content.

Failure semantics
-----------------

An unavailable or erroring provider blocks by default (``fail_open=False``). A deployment
that explicitly sets ``fail_open=True`` must accept that a provider outage is an ALLOW, and
that decision belongs to the operator, not to AEGIS. The default is never open.
"""

from __future__ import annotations

import re
from typing import Protocol, runtime_checkable

from aegis.input_security.verdict import (
    InputSecurityCategory,
    InputSecurityVerdict,
)

__all__ = [
    "DeterministicInputSecurity",
    "InputSecurityProvider",
    "ModelArmorInputSecurity",
    "PassThroughInputSecurity",
]

# ---------------------------------------------------------------------------
# Protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class InputSecurityProvider(Protocol):
    """The boundary every untrusted incident payload must cross.

    Implementations must be:
    - **Deterministic or explicitly probabilistic**: the caller needs to know which.
    - **Fail-closed by default**: an error must not become permission.
    - **Side-effect free on the payload**: screening reads content, never modifies it.
    """

    @property
    def name(self) -> str:
        """Short identifier, shown in audit records and telemetry. No credentials."""
        ...

    def screen(self, content: str) -> InputSecurityVerdict:
        """Screen one piece of untrusted content.

        Returns:
            An ALLOW or BLOCK verdict. Never raises — errors are captured as BLOCK
            verdicts with category PROVIDER_ERROR.
        """
        ...


# ---------------------------------------------------------------------------
# Pattern catalogue for the deterministic provider
# ---------------------------------------------------------------------------

# Prompt injection: patterns that attempt to hijack instruction-following.
_INJECTION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(
        r"\bignore\s+(all\s+)?(previous|prior|above|earlier)"
        r"\s+(instructions?|prompts?|rules?|context)\b",
        re.IGNORECASE,
    ),
    re.compile(r"\bnow\s+(you\s+are|act\s+as|pretend\s+to\s+be|become)\b", re.IGNORECASE),
    re.compile(r"\b(system\s+prompt|system\s+message)\s*[:=]", re.IGNORECASE),
    re.compile(r"<\s*/?system\s*>", re.IGNORECASE),
    re.compile(
        r"\bforget\s+(everything|all)\s+(you\s+)?(were\s+)?(told|instructed|trained)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\byour\s+(new|real|true|actual)"
        r"\s+(instructions?|purpose|goal|role|task)\s+(is|are)\b",
        re.IGNORECASE,
    ),
    re.compile(r"\bDAN\s+mode\b", re.IGNORECASE),
    re.compile(r"\bjailbreak\b", re.IGNORECASE),
    re.compile(r"\b(execute|run|eval)\s*\(\s*['\"]", re.IGNORECASE),
    # Separator-based injection attempts
    re.compile(r"---+\s*(SYSTEM|HUMAN|ASSISTANT|USER|INSTRUCTION)", re.IGNORECASE),
    re.compile(r"###\s*(SYSTEM|NEW INSTRUCTION|OVERRIDE)", re.IGNORECASE),
    # Role-play override attempts
    re.compile(
        r"\byou\s+(must|should|will|shall)\s+(now\s+)?(ignore|disregard|forget)\b", re.IGNORECASE
    ),
]

# Policy violations: content that should not enter a production governance system.
_POLICY_PATTERNS: list[re.Pattern[str]] = [
    # Attempts to exfiltrate data through the incident payload
    re.compile(
        r"\b(exfiltrate|exfiltration|steal|leak)\s+(all\s+)?(data|credentials?|secrets?|keys?|tokens?)\b",
        re.IGNORECASE,
    ),
    # Commands that could be confused for legitimate orchestration
    re.compile(
        r"\b(grant|give|add)\s+(yourself|itself|the\s+agent)\s+(admin|root|sudo|superuser)\s+(access|privileges?|rights?)\b",
        re.IGNORECASE,
    ),
]


# ---------------------------------------------------------------------------
# Deterministic provider
# ---------------------------------------------------------------------------


class DeterministicInputSecurity:
    """Pattern-based input screening. Deterministic, no network, no credentials.

    Checks for known prompt injection patterns and policy violations. Because this is
    pattern-based, it can be defeated by a determined adversary — it is a first-line
    check, not a guarantee. The governance core downstream provides independent
    containment; this narrows the attack surface at the model boundary.

    Args:
        fail_open: If True, a screening *error* becomes ALLOW. Default False (fail-closed).
            There is no scenario in AEGIS where this should be True; the parameter exists
            so the contract is explicit rather than implicit.
        extra_injection_patterns: Additional regex patterns, compiled at construction.
        extra_policy_patterns: Additional policy violation patterns.
    """

    _PROVIDER_NAME = "deterministic"

    def __init__(
        self,
        *,
        fail_open: bool = False,
        extra_injection_patterns: list[str] | None = None,
        extra_policy_patterns: list[str] | None = None,
    ) -> None:
        self._fail_open = fail_open
        self._injection = list(_INJECTION_PATTERNS)
        self._policy = list(_POLICY_PATTERNS)
        if extra_injection_patterns:
            self._injection.extend(re.compile(p, re.IGNORECASE) for p in extra_injection_patterns)
        if extra_policy_patterns:
            self._policy.extend(re.compile(p, re.IGNORECASE) for p in extra_policy_patterns)

    @property
    def name(self) -> str:
        return self._PROVIDER_NAME

    def screen(self, content: str) -> InputSecurityVerdict:
        """Screen content against known injection and policy patterns."""
        try:
            for pattern in self._injection:
                if pattern.search(content):
                    return InputSecurityVerdict.block(
                        provider=self._PROVIDER_NAME,
                        reason=f"prompt injection pattern detected: {pattern.pattern[:60]!r}",
                        category=InputSecurityCategory.PROMPT_INJECTION,
                    )
            for pattern in self._policy:
                if pattern.search(content):
                    return InputSecurityVerdict.block(
                        provider=self._PROVIDER_NAME,
                        reason=f"policy violation detected: {pattern.pattern[:60]!r}",
                        category=InputSecurityCategory.POLICY_VIOLATION,
                    )
        except Exception as error:
            if self._fail_open:
                return InputSecurityVerdict.allow(
                    provider=self._PROVIDER_NAME,
                    reason=f"provider error (fail-open): {type(error).__name__}",
                )
            return InputSecurityVerdict.block(
                provider=self._PROVIDER_NAME,
                reason=f"provider error during screening: {type(error).__name__}",
                category=InputSecurityCategory.PROVIDER_ERROR,
            )
        return InputSecurityVerdict.allow(provider=self._PROVIDER_NAME)


# ---------------------------------------------------------------------------
# Pass-through provider (for use when input security is explicitly disabled)
# ---------------------------------------------------------------------------


class PassThroughInputSecurity:
    """Always returns ALLOW. For operator use in controlled environments only.

    This provider must never be the default. It exists so an operator who has an
    independent input screening layer (e.g. an API gateway WAF) can avoid double
    screening without having to disable the boundary entirely — they declare explicitly
    that they are passing through, and AEGIS records that in the verdict.
    """

    _PROVIDER_NAME = "pass-through"

    @property
    def name(self) -> str:
        return self._PROVIDER_NAME

    def screen(self, content: str) -> InputSecurityVerdict:
        return InputSecurityVerdict.allow(
            provider=self._PROVIDER_NAME,
            reason="pass-through provider: no screening applied",
        )


# ---------------------------------------------------------------------------
# Model Armor adapter (optional import)
# ---------------------------------------------------------------------------


class ModelArmorInputSecurity:
    """Google Cloud Model Armor adapter.

    Requires ``google-cloud-modelarmor`` to be installed (the ``modelarmor`` optional
    dependency). If the package is absent, construction raises ``ImportError``
    immediately — fail closed, not silently open.

    Args:
        project: GCP project id. Read from the environment; never hardcoded.
        location: Model Armor location (e.g. ``"us-central1"``).
        template_name: The Model Armor template to evaluate against.
        fail_open: If True, a provider error becomes ALLOW. Default False.
    """

    _PROVIDER_NAME = "model-armor"

    def __init__(
        self,
        *,
        project: str,
        location: str,
        template_name: str,
        fail_open: bool = False,
    ) -> None:
        try:
            from google.cloud import modelarmor_v1  # type: ignore[import-not-found]  # noqa: F401
        except ImportError as err:
            raise ImportError(
                "google-cloud-modelarmor is required for ModelArmorInputSecurity. "
                "Install it with: pip install google-cloud-modelarmor"
            ) from err
        self._project = project
        self._location = location
        self._template_name = template_name
        self._fail_open = fail_open
        # Client is lazy-initialized so construction doesn't require credentials
        self._client = None

    @property
    def name(self) -> str:
        return self._PROVIDER_NAME

    def screen(self, content: str) -> InputSecurityVerdict:
        """Screen content using Model Armor. Never raises — errors become BLOCK."""
        try:
            from google.cloud import modelarmor_v1  # type: ignore[import-not-found]

            if self._client is None:
                self._client = modelarmor_v1.ModelArmorClient()
            template_path = (
                f"projects/{self._project}/locations/{self._location}"
                f"/templates/{self._template_name}"
            )
            request = modelarmor_v1.SanitizeUserPromptRequest(
                name=template_path,
                user_prompt_data=modelarmor_v1.DataItem(text=content),
            )
            response = self._client.sanitize_user_prompt(request=request)
            # Model Armor uses a filter_match_state to indicate violations
            match_state = getattr(response.sanitization_result, "filter_match_state", None)
            if match_state is not None and str(match_state) != "NO_MATCH":
                return InputSecurityVerdict.block(
                    provider=self._PROVIDER_NAME,
                    reason=f"Model Armor violation: {match_state}",
                    category=InputSecurityCategory.POLICY_VIOLATION,
                )
            return InputSecurityVerdict.allow(provider=self._PROVIDER_NAME)
        except Exception as error:
            if self._fail_open:
                return InputSecurityVerdict.allow(
                    provider=self._PROVIDER_NAME,
                    reason=f"provider error (fail-open): {type(error).__name__}",
                )
            return InputSecurityVerdict.block(
                provider=self._PROVIDER_NAME,
                reason=f"Model Armor unavailable: {type(error).__name__}",
                category=InputSecurityCategory.PROVIDER_ERROR,
            )
