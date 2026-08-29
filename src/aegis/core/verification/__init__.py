"""Verification — establishing that the enterprise actually reached the desired state.

Trust zone C (``claude.md`` sections 4, 11). Compares a declared expected state against
independent observations and returns a deterministic result. It never equates a tool
returning success with an operation having succeeded, and it never asks a model whether
something looks healthy.

An incident can only become RESOLVED on the strength of a VERIFIED result bound to that
incident and to one of its actions.
"""

from aegis.core.verification.engine import VerificationEngine, VerificationRequestError
from aegis.core.verification.expectation import Comparator, ExpectedState, Predicate
from aegis.core.verification.observation import (
    OBSERVABLE_EVIDENCE_TYPES,
    Observation,
    ObservedValue,
)
from aegis.core.verification.results import (
    STATUS_PRECEDENCE,
    CheckOutcome,
    PredicateCheck,
    VerificationResult,
    VerificationStatus,
)

__all__ = [
    "OBSERVABLE_EVIDENCE_TYPES",
    "STATUS_PRECEDENCE",
    "CheckOutcome",
    "Comparator",
    "ExpectedState",
    "Observation",
    "ObservedValue",
    "Predicate",
    "PredicateCheck",
    "VerificationEngine",
    "VerificationRequestError",
    "VerificationResult",
    "VerificationStatus",
]
