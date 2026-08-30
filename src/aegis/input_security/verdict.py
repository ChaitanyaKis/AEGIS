"""The result of screening untrusted input before it reaches the model.

Two values, and no ambiguity between them:

    ALLOW  — the content may proceed into the model-facing reasoning pipeline.
    BLOCK  — the content must not reach the model, must not create an authorization,
             must not execute, and must leave audit evidence.

There is no WARN, no SCORE and no THRESHOLD. A screening decision is deterministic and
total: given the same input and the same provider it always produces the same answer, and
every non-ALLOW result is a BLOCK.

What a verdict is not
---------------------

It is not a governance decision. ALLOW means "this input may enter the pipeline"; it says
nothing about whether any action the model proposes will be authorized. That is still
decided by the policy engine, the approval engine, the lifecycle gate and verification,
none of which read this module.
"""

from __future__ import annotations

from enum import StrEnum

from aegis.core.domain import DomainModel, NonEmptyStr

__all__ = ["InputSecurityCategory", "InputSecurityDecision", "InputSecurityVerdict"]


class InputSecurityDecision(StrEnum):
    """The screening outcome. Exactly two values — no ambiguity, no partial acceptance."""

    ALLOW = "ALLOW"
    """The content may proceed to the model-facing pipeline."""

    BLOCK = "BLOCK"
    """The content must not reach the model. The run terminates here."""


class InputSecurityCategory(StrEnum):
    """Why input was blocked. Present only on BLOCK verdicts."""

    PROMPT_INJECTION = "PROMPT_INJECTION"
    """Content that attempts to override or subvert the model's instructions."""

    POLICY_VIOLATION = "POLICY_VIOLATION"
    """Content that violates the operator's content policy."""

    MALICIOUS_CONTENT = "MALICIOUS_CONTENT"
    """Content detected as hostile by a threat-intelligence source."""

    RATE_LIMIT = "RATE_LIMIT"
    """The provider refused the request due to quota exhaustion."""

    PROVIDER_ERROR = "PROVIDER_ERROR"
    """The security provider returned an error. Fail-closed: treated as BLOCK."""

    UNKNOWN = "UNKNOWN"
    """Blocked for an unclassified reason. Always a BLOCK."""


class InputSecurityVerdict(DomainModel):
    """The result of screening one piece of untrusted input.

    Carries the decision (ALLOW / BLOCK), the reason when blocked, and the provider
    that produced it. Immutable: no method changes the decision after the fact.
    """

    decision: InputSecurityDecision
    reason: str
    provider: NonEmptyStr
    category: InputSecurityCategory | None = None

    @property
    def allowed(self) -> bool:
        return self.decision is InputSecurityDecision.ALLOW

    @property
    def blocked(self) -> bool:
        return self.decision is InputSecurityDecision.BLOCK

    @classmethod
    def allow(
        cls, *, provider: str, reason: str = "content passed screening"
    ) -> InputSecurityVerdict:
        return cls(decision=InputSecurityDecision.ALLOW, reason=reason, provider=provider)

    @classmethod
    def block(
        cls,
        *,
        provider: str,
        reason: str,
        category: InputSecurityCategory = InputSecurityCategory.UNKNOWN,
    ) -> InputSecurityVerdict:
        return cls(
            decision=InputSecurityDecision.BLOCK,
            reason=reason,
            provider=provider,
            category=category,
        )

    def __repr__(self) -> str:
        cat = f":{self.category}" if self.category else ""
        return f"{type(self).__name__}({self.decision}{cat} via {self.provider!r})"
