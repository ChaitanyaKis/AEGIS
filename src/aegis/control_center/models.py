"""The read model's vocabulary: where a fact came from, and how sure we are of it.

Everything in this package is a **derived observation**. Nothing here is authority, and the
vocabulary is built so that saying otherwise is difficult.

Three ideas do most of the work
-------------------------------

:class:`Tri`
    A boolean with a third value. The control center reads artifacts that may simply not
    exist, and ``False`` is a claim: "there was no approval" is a different statement from
    "no approval event was recorded". Conflating them is the single most dangerous thing an
    observability layer can do to an operator, because a system designed to fail closed
    looks *safe* when it is merely silent (Part 16).

:class:`Certainty`
    Whether a value was read off an artifact, computed from artifacts by a stated rule, or
    is unavailable. A view may not present a derived value as an observed one.

:class:`Provenance`
    Which source, as of when, and whether that source was complete. Attached to every view,
    so no reader has to guess which snapshot a number came from.

The rule the whole package follows
----------------------------------

    missing evidence -> UNKNOWN

Never ``False``, never ``EMPTY``, never a default that happens to look reassuring. A
control center that turns *unavailable* into *safe* has inverted the one property AEGIS is
built around.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import Field

from aegis.core.domain import DomainModel, NonEmptyStr, Timestamp

__all__ = [
    "AuditIntegrityView",
    "AuditTrust",
    "Certainty",
    "Completeness",
    "Fact",
    "Provenance",
    "Tri",
    "ViewSource",
]


class ViewSource(StrEnum):
    """Which recorded artifact a view was built from. Closed, so a view cannot be vague.

    Every member names something that exists on disk or in a frozen value. There is no
    ``COMPUTED`` member and no ``SYSTEM`` member, because a fact with no artifact behind it
    is not a fact this package may state.
    """

    AUDIT = "AUDIT"
    """The append-only, hash-chained audit trail."""

    RUN = "RUN"
    """The frozen :class:`~aegis.orchestration.OrchestrationRun` an incident produced."""

    LIFECYCLE_STATE = "LIFECYCLE_STATE"
    MEMORY = "MEMORY"
    A2A_LEDGER = "A2A_LEDGER"
    RESTRICTION_REGISTRY = "RESTRICTION_REGISTRY"
    BREAKER = "BREAKER"
    REGISTRY = "REGISTRY"
    """The capability catalogue: what an agent *may* be granted, never what it may do now."""

    NONE = "NONE"
    """No source was available. Pairs with :attr:`Completeness.UNKNOWN`, never with data."""


class Completeness(StrEnum):
    """Whether the source behind a view held everything the view needed.

    ``PARTIAL`` is not a failure state — a run stopped halfway genuinely has a partial
    history, and reporting it as complete would be the lie. ``UNKNOWN`` means the source
    itself could not be read, which is different again.
    """

    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    UNKNOWN = "UNKNOWN"


class Certainty(StrEnum):
    """How a particular value came to be.

    Part 4 requires the distinction, and it is enforced by field rather than by convention:
    every :class:`Fact` carries one.
    """

    OBSERVED = "OBSERVED"
    """Read directly off a recorded artifact. The strongest thing this package can say."""

    DERIVED = "DERIVED"
    """Computed from observed artifacts by a rule stated in the view's docstring.

    Deliberately *not* called "inferred". Inference suggests judgement; every derivation
    here is a fixed function of recorded values, and the word should not invite a reader to
    imagine otherwise.
    """

    UNAVAILABLE = "UNAVAILABLE"
    """No artifact answers this. The value is ``None`` and the reader must treat it as
    unknown -- not as absent, not as false."""


class Tri(StrEnum):
    """A boolean that can also be "we do not know".

    The most important type in this package. Almost every operator question -- was it
    approved, did it execute, is the breaker open -- is answered from artifacts that may not
    exist, and the honest third answer has to be representable or it will be rounded to the
    convenient one.
    """

    TRUE = "TRUE"
    FALSE = "FALSE"
    UNKNOWN = "UNKNOWN"

    @classmethod
    def of(cls, value: bool | None) -> Tri:
        """``None`` becomes :attr:`UNKNOWN`. The conversion, in one place, on purpose.

        Scattered ``bool(x)`` calls are how a missing artifact silently becomes ``False``.
        """
        if value is None:
            return cls.UNKNOWN
        return cls.TRUE if value else cls.FALSE

    @property
    def known(self) -> bool:
        return self is not Tri.UNKNOWN

    @property
    def is_true(self) -> bool:
        """Strictly true. ``UNKNOWN`` is not true, and neither is it false."""
        return self is Tri.TRUE


class Provenance(DomainModel):
    """Where a view's data came from, as of when, and how complete that source was.

    Attached to every view in this package. Part 16's requirement, as a field rather than a
    convention: a reader combining two views can see that they were captured from different
    sources at different instants, instead of being handed a single "current state" that
    was never true all at once.
    """

    source: ViewSource
    as_of: Timestamp
    completeness: Completeness
    detail: NonEmptyStr | None = None
    """Why the source was partial or unknown, when it was."""

    @property
    def trustworthy(self) -> bool:
        """Whether a reader may treat this view's contents as a faithful projection.

        Not a security property and not a permission. It means only: the source was
        readable and complete. A view that is not trustworthy still shows what it found;
        it simply must not be read as the whole story.
        """
        return self.completeness is Completeness.COMPLETE and self.source is not ViewSource.NONE

    @classmethod
    def unavailable(cls, as_of: datetime, detail: str) -> Provenance:
        """The provenance of a view whose source could not be read at all."""
        return cls(
            source=ViewSource.NONE,
            as_of=as_of,
            completeness=Completeness.UNKNOWN,
            detail=detail,
        )

    def degraded(self, detail: str) -> Provenance:
        """The same source, downgraded to ``UNKNOWN``.

        Used when a source was readable but cannot be trusted -- a broken audit chain, most
        often. The data is still shown; the claim about it is withdrawn.
        """
        return self.model_copy(update={"completeness": Completeness.UNKNOWN, "detail": detail})


class Fact(DomainModel):
    """One value, with how it was arrived at.

    Deliberately generic and deliberately tiny. Anywhere the read model states something an
    operator might act on, it states it as a :class:`Fact` so the certainty travels with the
    value rather than being documented next to it.
    """

    value: NonEmptyStr | None = None
    certainty: Certainty = Certainty.UNAVAILABLE
    evidence_refs: tuple[NonEmptyStr, ...] = Field(default_factory=tuple)
    """Ids of the artifacts this rests on: event ids, action ids, evidence ids.

    Empty is permitted only for :attr:`Certainty.UNAVAILABLE`, which is checked below -- a
    stated fact with nothing behind it is exactly what this package must not produce.
    """

    def __init__(self, **data) -> None:
        super().__init__(**data)
        if self.certainty is not Certainty.UNAVAILABLE and self.value is None:
            raise ValueError("a fact that is observed or derived must have a value")
        if self.certainty is Certainty.UNAVAILABLE and self.value is not None:
            raise ValueError("an unavailable fact must not carry a value")

    @classmethod
    def observed(cls, value: object, *evidence: str) -> Fact:
        """Read straight off an artifact."""
        return cls(value=str(value), certainty=Certainty.OBSERVED, evidence_refs=tuple(evidence))

    @classmethod
    def derived(cls, value: object, *evidence: str) -> Fact:
        """Computed from artifacts by a stated rule."""
        return cls(value=str(value), certainty=Certainty.DERIVED, evidence_refs=tuple(evidence))

    @classmethod
    def unknown(cls) -> Fact:
        """No artifact answers this. Carries no value, by construction."""
        return cls(certainty=Certainty.UNAVAILABLE)

    @property
    def known(self) -> bool:
        return self.certainty is not Certainty.UNAVAILABLE

    def __repr__(self) -> str:
        return f"Fact({self.certainty}:{self.value!r})" if self.known else "Fact(UNKNOWN)"


class AuditTrust(StrEnum):
    """Whether the audit chain behind a projection verified.

    Three values and not two. A chain that could not be read is not a chain that failed:
    one is a missing source, the other is evidence of tampering, and an operator needs to
    tell them apart.
    """

    TRUSTED = "TRUSTED"
    UNTRUSTED = "UNTRUSTED"
    """The chain does not verify. Part 17: surfaced, never repaired."""

    UNAVAILABLE = "UNAVAILABLE"


class AuditIntegrityView(DomainModel):
    """The audit chain's own verdict on itself, carried into every view built from it.

    Part 17. The control center **re-verifies** the chain rather than assuming it; when the
    chain is untrusted, every audit-sourced view is downgraded to
    :attr:`Completeness.UNKNOWN` rather than being quietly rendered as authoritative.

    Nothing here repairs anything. ``first_invalid_index`` and ``trusted_prefix`` are
    reported so a reader can see exactly how much of the history still stands.
    """

    trust: AuditTrust
    records: int = Field(default=0, ge=0)
    checked: int = Field(default=0, ge=0)
    first_invalid_index: int | None = None
    reason: NonEmptyStr | None = None
    trusted_prefix: int = Field(default=0, ge=0)

    truncated: Tri = Tri.UNKNOWN
    """Whether the records shown are demonstrably fewer than the store holds.

    Separate from :attr:`trust`, because they are different failures. A chain that verifies
    proves nothing was *altered*; it proves nothing about whether the end is missing, and a
    truncated prefix verifies perfectly. Detected by comparing the last record's digest
    against the store's own head -- ``UNKNOWN`` when the head could not be read, which is
    itself worth saying.
    """

    @property
    def usable(self) -> bool:
        return self.trust is AuditTrust.TRUSTED

    @property
    def complete(self) -> bool:
        """Trusted *and* demonstrably whole. Both, or a reader is being told too much."""
        return self.usable and self.truncated is Tri.FALSE

    def __repr__(self) -> str:
        return (
            f"AuditIntegrityView({self.trust}, {self.trusted_prefix}/{self.records}, "
            f"truncated={self.truncated})"
        )
