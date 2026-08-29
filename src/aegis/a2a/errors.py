"""A2A errors.

Nearly every A2A refusal is a returned :class:`~aegis.a2a.verdicts.A2AVerdict` rather than
an exception, for the reason given there: a returned refusal is harder to ignore than a
raised one is to swallow.

What is left here is the one class of failure a caller must not be able to continue past —
persisted state that cannot be trusted. That is raised, and raising *is* the fail-closed
behaviour: a process that cannot read its own record of which messages were already
consumed must not start as though none of them had been.
"""

from __future__ import annotations

__all__ = ["A2AError", "A2APersistenceFailure", "A2AStateCorrupt"]


class A2AError(Exception):
    """Base class for everything this package raises."""


class A2AStateCorrupt(A2AError):
    """Persisted A2A state failed its integrity or legality check.

    Raised at load. A damaged ledger is not salvaged, because a partially readable history
    looks exactly like a history in which the last few *consumptions* never happened — and
    that is precisely the lie that makes a spent message look fresh again.
    """

    def __init__(self, detail: str) -> None:
        self.detail = detail
        super().__init__(f"A2A state is not trustworthy: {detail}")


class A2APersistenceFailure(A2AError):
    """A record could not be durably written.

    Raised by the ledger when an append fails, so the caller cannot proceed believing a
    message was recorded when it was not. The broker turns this into a refusal rather than
    a delivery: **a persistence failure must never be the reason something is admitted.**
    """

    def __init__(self, detail: str) -> None:
        self.detail = detail
        super().__init__(f"A2A state could not be persisted: {detail}")
