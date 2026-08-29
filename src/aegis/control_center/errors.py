"""What the control center raises, and why the list is nearly empty.

A read model that raised on incomplete data would be useless exactly when it is needed
most: an operator looking at a crashed run, a corrupted trail or a half-finished incident
is looking for precisely the information that a strict parser would refuse to produce.

So the rule here is the opposite of the one in :mod:`aegis.a2a.errors`. There, refusing to
proceed *is* the safe answer, because proceeding would deliver a message. Here, refusing to
proceed would leave an operator with nothing, and nothing is not safer than a page that
says ``UNKNOWN`` in the right places.

Missing data therefore produces :attr:`~aegis.control_center.models.Tri.UNKNOWN`,
:attr:`~aegis.control_center.models.Completeness.UNKNOWN` and
:attr:`~aegis.control_center.models.Certainty.UNAVAILABLE` -- never an exception, and never
a comfortable default.

What is left is one error for a caller mistake: asking for an incident the projection does
not cover. That is a programming error rather than a data condition, and answering it with
``UNKNOWN`` would let a typo look like an empty incident.
"""

from __future__ import annotations

__all__ = ["ControlCenterError", "UnknownIncident"]


class ControlCenterError(Exception):
    """Base class for everything this package raises. Deliberately shallow."""


class UnknownIncident(ControlCenterError):
    """A view was asked for an incident this projection was not built for.

    Raised rather than answered, because it is a caller error and not a gap in the data.
    Returning an empty projection would let a mistyped id render as an incident where
    nothing happened -- which is a fabricated state, and the one thing this package exists
    not to produce.
    """

    def __init__(self, incident_id: str, available: tuple[str, ...]) -> None:
        self.incident_id = incident_id
        self.available = available
        super().__init__(
            f"no projection for incident {incident_id!r}; available: "
            f"{', '.join(available) or 'none'}"
        )
