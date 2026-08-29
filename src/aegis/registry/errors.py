"""Registry errors, and the closed vocabulary of reasons a delegation may be refused.

The refusal codes matter more than the exception types. A refusal travels into an audit
record, a trace attribute and an HTTP response, and every one of those readers needs the
*same* answer to "why". A free-text reason would give three different answers, so the
reason is an enum member and the prose is an accompanying detail.
"""

from __future__ import annotations

from enum import StrEnum

__all__ = [
    "AgentAlreadyRegistered",
    "IllegalRegistryTransition",
    "RegistryError",
    "RegistryRefusal",
    "UnknownAgentVersion",
    "UnknownRegisteredAgent",
]


class RegistryError(Exception):
    """Base class for every registry failure."""


class UnknownRegisteredAgent(RegistryError):
    """No registration exists under this agent id, at any version."""


class UnknownAgentVersion(RegistryError):
    """The agent exists, but not at the requested version.

    Distinct from :class:`UnknownRegisteredAgent` on purpose. "There is no such agent" and
    "you asked for a version that was never registered" are different operational
    problems, and collapsing them makes a typo in a version look like a missing fleet.
    """


class AgentAlreadyRegistered(RegistryError):
    """This exact ``(agent_id, version)`` is already registered.

    Re-registering is refused rather than treated as an update: a silent overwrite would
    let a new build inherit the approval a reviewed build earned, which is the single most
    valuable thing an attacker could do to a registry.
    """


class IllegalRegistryTransition(RegistryError):
    """The requested status change is not an edge in the transition table."""


class RegistryRefusal(StrEnum):
    """Why a registry check refused. Closed, so no refusal is unexplained."""

    NONE = "NONE"
    """Not refused. Present so "permitted" is a value rather than an absence."""

    UNKNOWN_AGENT = "UNKNOWN_AGENT"
    """No registration under that id."""

    UNKNOWN_VERSION = "UNKNOWN_VERSION"
    """That id exists; that version does not."""

    NO_SELECTABLE_VERSION = "NO_SELECTABLE_VERSION"
    """The agent exists and every one of its versions is ineligible.

    Separate from ``NOT_ACTIVE`` because it describes the *fleet*: an operator reading
    this knows there is no version to fall back to, rather than that one build is down.
    """

    NOT_APPROVED = "NOT_APPROVED"
    """No human has approved this version, or approval was refused."""

    NOT_ACTIVE = "NOT_ACTIVE"
    """The version is registered and approved but is not in service.

    Covers DRAFT, PUBLISHED, APPROVED and SUSPENDED. The verdict carries the actual
    status, so the distinction is never lost.
    """

    REVOKED = "REVOKED"
    """The version was permanently withdrawn. Terminal, and reported as its own reason
    rather than folded into ``NOT_ACTIVE``: an operator must be able to tell "not started
    yet" apart from "deliberately destroyed"."""

    CAPABILITY_NOT_DECLARED = "CAPABILITY_NOT_DECLARED"
    """The registration does not declare the capability the work requires.

    A discovery-and-routing check, not an authorization one. The capability registry and
    the policy engine still decide what the agent may actually exercise.
    """

    IDENTITY_MISMATCH = "IDENTITY_MISMATCH"
    """The caller named an identity that is not this registration's identity."""
