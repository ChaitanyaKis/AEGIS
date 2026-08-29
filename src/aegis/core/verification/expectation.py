"""What success looks like, as machine-evaluable predicates.

An expected state says exactly what must be true of a resource for a remediation to count
as having worked, how fresh the evidence must be, and which sources may supply it. There
is no natural language here and nothing to interpret — a reviewer can check a verification
by reading three numbers off a table.

The predicate system is deliberately **closed**: three comparators, two value types, no
expression language, no string parsing, nothing evaluated from user input. Widening it is
a code change with tests, not a configuration change.
"""

from __future__ import annotations

from datetime import timedelta
from enum import StrEnum

from pydantic import Field, model_validator

from aegis.core.domain import DomainModel, NonEmptyStr
from aegis.core.verification.observation import ObservedValue

__all__ = ["Comparator", "ExpectedState", "Predicate"]


class Comparator(StrEnum):
    """The complete set of comparisons verification can make.

    ``AT_MOST`` and ``AT_LEAST`` are numeric only; ``EQUALS`` is exact equality and works
    for both numbers and categorical values.
    """

    EQUALS = "EQUALS"
    AT_MOST = "AT_MOST"
    AT_LEAST = "AT_LEAST"


_NUMERIC_COMPARATORS = frozenset({Comparator.AT_MOST, Comparator.AT_LEAST})


class Predicate(DomainModel):
    """One condition on one observed attribute.

    Every predicate is required. There is no advisory tier: a condition worth stating is a
    condition worth failing on, and an optional check that nobody acts on is worse than no
    check at all.
    """

    attribute: NonEmptyStr
    """Attribute name to read from observations, e.g. ``error_rate``."""

    comparator: Comparator
    value: ObservedValue
    """The expected value, or the bound for an ordered comparison."""

    @model_validator(mode="after")
    def _ordered_comparisons_are_numeric(self) -> Predicate:
        if self.comparator in _NUMERIC_COMPARATORS and not isinstance(self.value, (int, float)):
            raise ValueError(f"{self.comparator} requires a numeric value")
        return self

    def describe(self) -> str:
        """Human-readable form, e.g. ``error_rate AT_MOST 1.0``. Derived, never parsed."""
        return f"{self.attribute} {self.comparator} {self.value}"


class ExpectedState(DomainModel):
    """The full definition of "this worked", for one resource.

    Every field is a fail-closed obligation on the caller: no predicates means nothing is
    being checked, no accepted sources means nothing is believed, and no freshness bound
    means yesterday's telemetry could resolve today's incident. All three are required.
    """

    resource: NonEmptyStr
    """The resource this expectation describes. Must be the action's target."""

    predicates: tuple[Predicate, ...] = Field(min_length=1)
    """Conditions that must all hold. At least one — an empty expectation verifies nothing."""

    max_observation_age: timedelta
    """How old an observation may be and still establish current state.

    Lives here rather than as a global constant because freshness is a property of what is
    being checked: a deployment version stays true for hours, an error rate for seconds.
    """

    accepted_sources: tuple[NonEmptyStr, ...] = Field(min_length=1)
    """Sources whose observations may be used, matched by exact equality.

    An allowlist rather than a trust framework (``claude.md`` section 13). Observations
    from anywhere else are ignored — not down-weighted, ignored — so an untrusted external
    payload cannot contribute to establishing that an incident is resolved.
    """

    @model_validator(mode="after")
    def _freshness_window_is_positive(self) -> ExpectedState:
        if self.max_observation_age <= timedelta(0):
            raise ValueError("max_observation_age must be positive")
        return self

    @property
    def attributes(self) -> tuple[str, ...]:
        """Every attribute some predicate depends on, sorted and de-duplicated."""
        return tuple(sorted({predicate.attribute for predicate in self.predicates}))
