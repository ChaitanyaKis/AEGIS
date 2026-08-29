"""Human approval, behind an adapter.

Approval is trust zone E (``claude.md`` section 4): it comes from a person. The
orchestrator does not decide it and the Commander cannot supply it — the model is never
asked, and there is no code path by which a model decision becomes an approval.

An :class:`ApprovalProvider` represents whatever channel a real deployment uses to reach a
human. AEGIS only needs the answer.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Protocol, runtime_checkable

from aegis.core.approval import Approval

__all__ = [
    "ApprovalProvider",
    "ApprovalVerdict",
    "DeterministicApprovalProvider",
]


class ApprovalVerdict(StrEnum):
    """What a human said. There is no third answer and no timeout-means-yes."""

    GRANT = "GRANT"
    REJECT = "REJECT"


@runtime_checkable
class ApprovalProvider(Protocol):
    """Reaches a human and returns their verdict.

    Implementations must not consult a model. The whole point of the boundary is that the
    thing proposing an action is not the thing permitting it.
    """

    approver: str
    """Who is answering, e.g. ``human:oncall``. Recorded on the approval artifact."""

    def review(self, approval: Approval) -> ApprovalVerdict:
        """Return the human's verdict on one approval request."""
        ...


class DeterministicApprovalProvider:
    """A fixed verdict standing in for a person. **TEST / HUMAN SIMULATION.**

    Not a human, not a model, and not an approximation of either — a constant, so that
    tests can exercise both the granted and rejected paths reproducibly. It is named
    ``human:oncall`` by default because that is what the approval record must attribute
    the decision to; the simulation is in this class, not in the label.

    Args:
        verdict: The answer to give every time.
        approver: Identity recorded on the approval.
    """

    def __init__(
        self,
        verdict: ApprovalVerdict = ApprovalVerdict.GRANT,
        *,
        approver: str = "human:oncall",
    ) -> None:
        self.verdict = verdict
        self.approver = approver
        self.reviewed: tuple[str, ...] = ()

    def review(self, approval: Approval) -> ApprovalVerdict:
        """Return the configured verdict, recording that the request was seen."""
        self.reviewed = (*self.reviewed, approval.approval_id)
        return self.verdict

    def __repr__(self) -> str:
        return f"{type(self).__name__}(verdict={self.verdict}, approver={self.approver!r})"
