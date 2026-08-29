"""Memory subsystem errors.

Every refusal is a distinct type carrying what was rejected and why. Admission failures
in particular are not exceptional conditions to be smoothed over — a rejected memory is
the subsystem working, and the caller needs to know which check refused it.
"""

from __future__ import annotations

__all__ = [
    "MemoryAdmissionRefused",
    "MemoryError",
    "MemoryIntegrityError",
    "MemoryNotFound",
    "UnknownMemoryRecord",
]


class MemoryError(Exception):
    """Base class for everything this package raises."""


class MemoryAdmissionRefused(MemoryError):
    """A candidate did not satisfy every admission check, so it is not authoritative.

    Args:
        check: The named check that refused, e.g. ``verification.status``. Machine-readable
            so a caller can branch on the reason without parsing prose.
        detail: What was wrong, in words.
    """

    def __init__(self, check: str, detail: str) -> None:
        self.check = check
        self.detail = detail
        super().__init__(f"memory admission refused at {check}: {detail}")


class MemoryNotFound(MemoryError):
    """A lookup named a memory id the store does not hold."""

    def __init__(self, memory_id: str) -> None:
        self.memory_id = memory_id
        super().__init__(f"no memory record with id {memory_id!r}")


class UnknownMemoryRecord(MemoryError):
    """An operation named a record the store did not produce."""

    def __init__(self, memory_id: str) -> None:
        self.memory_id = memory_id
        super().__init__(f"memory record {memory_id!r} was not issued by this store")


class MemoryIntegrityError(MemoryError):
    """Stored memory failed its integrity check and cannot be trusted."""

    def __init__(self, detail: str) -> None:
        self.detail = detail
        super().__init__(f"memory integrity check failed: {detail}")
