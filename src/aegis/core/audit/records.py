"""Audit records and the tamper-evident hash chain.

An :class:`~aegis.core.domain.audit.AuditEvent` says what happened. An
:class:`AuditRecord` wraps one event with its position in history and the digests that
link it to everything recorded before it. The wrapper exists so that the domain contract
stays exactly as ``claude.md`` section 20 defines it — integrity is a property of the
*log*, not of the event.

What the chain provides
-----------------------

**Tamper evidence, and only that.** Modifying, reordering, deleting or inserting a record
breaks the chain and :func:`verify_chain` reports where. That is genuinely useful: it means
ordinary history rewriting cannot pass unnoticed.

It explicitly does **not** provide external immutability, trusted hardware, remote
attestation, non-repudiation or durability. The store is in memory and the verification
logic lives in the same process, so an attacker who can rewrite the whole store can also
recompute every digest and rewrite this module. The chain detects tampering by anything
*other* than a full-process compromise; it is not a substitute for durable trusted storage,
and nothing here should be described as making the audit log immutable.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from typing import Annotated

from pydantic import AfterValidator, Field

from aegis.core.domain import AuditEvent, DomainModel, NonEmptyStr, to_json

__all__ = [
    "GENESIS_DIGEST",
    "AuditRecord",
    "IntegrityReport",
    "record_digest",
    "verify_chain",
]

GENESIS_DIGEST = "0" * 64
"""The ``previous_digest`` of the first record in any chain.

A fixed, documented value rather than a random root: the chain exists to detect
modification, not to establish identity, and a random root would make two identical
histories serialize differently for no benefit.
"""


def _sorted_correlation(value: Mapping[str, str]) -> dict[str, str]:
    """Normalise correlation keys to sorted order so digests are order-independent."""
    return dict(sorted(value.items()))


_Correlation = Annotated[Mapping[str, str], AfterValidator(_sorted_correlation)]


class _DigestPayload(DomainModel):
    """Exactly the fields a digest covers, in one explicit model.

    Hashing a declared structure rather than an ad-hoc dict keeps the formula readable and
    makes accidentally adding or dropping a covered field a visible code change.
    """

    correlation: _Correlation
    event: AuditEvent
    previous_digest: str
    sequence: int


class AuditRecord(DomainModel):
    """One event, its position in history, and its chain digests.

    ``correlation`` carries the artifact identifiers an event relates to beyond its
    incident — ``action_id``, ``approval_id``, ``verification_id`` and so on. The domain
    event has a single ``input_reference`` slot, and a governance event routinely relates
    to several artifacts at once; keeping the extra identifiers here rather than widening
    ``AuditEvent`` follows the project's rule of preferring a package-local model. They are
    covered by the digest, so they are as tamper-evident as the event itself.
    """

    sequence: int = Field(ge=0)
    """Zero-based position in the log. Part of the digest, so a record knows where it belongs."""

    event: AuditEvent
    correlation: _Correlation = Field(default_factory=dict)
    previous_digest: str
    """Digest of the preceding record, or :data:`GENESIS_DIGEST` for the first."""

    digest: str
    """This record's digest. See :func:`record_digest` for the exact formula."""


def record_digest(
    *,
    sequence: int,
    event: AuditEvent,
    correlation: Mapping[str, str],
    previous_digest: str,
) -> str:
    """The digest of one record, as 64 lowercase hex characters.

    The formula, pinned by test::

        digest = SHA-256(canonical_json({
            "correlation":     {sorted key order},
            "event":           <canonical event>,
            "previous_digest": <hex>,
            "sequence":        <int>,
        }))

    A structured document is hashed rather than concatenated strings, so no field value can
    be crafted to imitate a field boundary. Canonicalisation is the project's existing
    :func:`~aegis.core.domain.serialization.to_json` — sorted keys, compact separators,
    UTC ISO-8601 timestamps — so the same record always digests identically across
    processes and runs.
    """
    document = to_json(
        _DigestPayload(
            correlation=correlation,
            event=event,
            previous_digest=previous_digest,
            sequence=sequence,
        )
    )
    return hashlib.sha256(document.encode("utf-8")).hexdigest()


class IntegrityReport(DomainModel):
    """The outcome of verifying a chain.

    Reports; never repairs. A log that has been tampered with stays tampered with, and the
    report says where the damage starts so the surviving prefix can still be trusted.
    """

    valid: bool
    checked: int = Field(ge=0)
    """How many records were examined before the first failure, or in total when valid."""

    first_invalid_index: int | None = None
    reason: NonEmptyStr | None = None

    @property
    def trusted_prefix(self) -> int:
        """How many records at the head of the log still verify."""
        return self.checked if self.valid else (self.first_invalid_index or 0)


def verify_chain(records: Sequence[AuditRecord]) -> IntegrityReport:
    """Recompute every digest and every link, in order.

    Detects modification of an event, a correlation, a digest or a chain link; reordering;
    deletion; and insertion — each of which changes either a recomputed digest or the
    linkage between neighbours.

    An empty log is valid: nothing has been recorded, and nothing has been altered.
    """
    expected_previous = GENESIS_DIGEST
    for index, record in enumerate(records):
        if record.sequence != index:
            return IntegrityReport(
                valid=False,
                checked=index,
                first_invalid_index=index,
                reason=(
                    f"record at position {index} claims sequence {record.sequence}; "
                    f"the log has been reordered, truncated or inserted into"
                ),
            )
        if record.previous_digest != expected_previous:
            return IntegrityReport(
                valid=False,
                checked=index,
                first_invalid_index=index,
                reason=(
                    f"record {index} links to {record.previous_digest[:12]}..., but the "
                    f"preceding record digests to {expected_previous[:12]}..."
                ),
            )
        recomputed = record_digest(
            sequence=record.sequence,
            event=record.event,
            correlation=record.correlation,
            previous_digest=record.previous_digest,
        )
        if recomputed != record.digest:
            return IntegrityReport(
                valid=False,
                checked=index,
                first_invalid_index=index,
                reason=(
                    f"record {index} ({record.event.event_id}) does not match its digest; "
                    f"its event, correlation or digest has been altered"
                ),
            )
        expected_previous = record.digest

    return IntegrityReport(valid=True, checked=len(records))
