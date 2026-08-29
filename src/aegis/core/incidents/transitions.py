"""The authoritative incident transition table.

Every edge in the incident lifecycle is written out here by hand. There is no ordinal
comparison, no "later state wins", no wildcard and no fallback: a pair of states is legal
only if it appears in :data:`TRANSITIONS`. That is the point — reachability is something
a reviewer should be able to read off a table, not derive from control flow.

Transitivity is deliberately *not* implied. ``A -> B`` and ``B -> C`` say nothing about
``A -> C``; if that edge is wanted it must be written down.

Guards
------

Some edges need more than a legal predecessor. An edge's guard names the artifact the
caller must supply, and the state machine refuses the transition without it:

* ``POLICY_ALLOW`` / ``POLICY_REQUIRE_APPROVAL`` — leaving POLICY_CHECK requires the
  policy decision that justifies which way it went. This is what stops a DENY from
  walking into AWAITING_APPROVAL or EXECUTING.
* ``EXECUTION_AUTHORIZATION`` — leaving AWAITING_APPROVAL for EXECUTING requires a
  consumed approval from the approval engine (``claude.md`` section 4, zone E).
* ``VERIFICATION`` — leaving VERIFYING for RESOLVED requires a VERIFIED verification
  result bound to this incident and one of its actions (``claude.md`` section 11). A tool
  returning success is not evidence, so nothing else opens this edge.

The state machine never decides *whether* approval is required — that is the policy
engine's job. It only enforces that an incident which entered AWAITING_APPROVAL cannot
leave for EXECUTING without the artifact.
"""

from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum
from types import MappingProxyType

from aegis.core.domain import IncidentState

__all__ = ["TERMINAL_STATES", "TRANSITIONS", "TransitionGuard"]


class TransitionGuard(StrEnum):
    """What a caller must supply for an edge, beyond a legal predecessor state."""

    NONE = "NONE"
    POLICY_ALLOW = "POLICY_ALLOW"
    """Requires a PolicyDecision of ALLOW."""

    POLICY_REQUIRE_APPROVAL = "POLICY_REQUIRE_APPROVAL"
    """Requires a PolicyDecision of REQUIRE_APPROVAL."""

    EXECUTION_AUTHORIZATION = "EXECUTION_AUTHORIZATION"
    """Requires an ExecutionAuthorization for this incident, from a consumed approval."""

    VERIFICATION = "VERIFICATION"
    """Requires a VERIFIED VerificationResult for this incident and one of its actions."""


_S = IncidentState
_G = TransitionGuard

_TABLE: dict[IncidentState, dict[IncidentState, TransitionGuard]] = {
    # --- normal path (claude.md section 8) ---------------------------------------
    _S.RECEIVED: {
        _S.CLASSIFIED: _G.NONE,
        _S.DEGRADED: _G.NONE,
        _S.ESCALATED: _G.NONE,
    },
    _S.CLASSIFIED: {
        _S.INVESTIGATING: _G.NONE,
        _S.DEGRADED: _G.NONE,
        _S.ESCALATED: _G.NONE,
    },
    _S.INVESTIGATING: {
        _S.IMPACT_ASSESSED: _G.NONE,
        _S.DEGRADED: _G.NONE,
        _S.ESCALATED: _G.NONE,
    },
    _S.IMPACT_ASSESSED: {
        _S.PLAN_PROPOSED: _G.NONE,
        _S.DEGRADED: _G.NONE,
        _S.ESCALATED: _G.NONE,
    },
    _S.PLAN_PROPOSED: {
        # The only way forward is through policy. There is deliberately no edge to
        # EXECUTING or AWAITING_APPROVAL here.
        _S.POLICY_CHECK: _G.NONE,
        _S.DEGRADED: _G.NONE,
        _S.ESCALATED: _G.NONE,
    },
    _S.POLICY_CHECK: {
        _S.AWAITING_APPROVAL: _G.POLICY_REQUIRE_APPROVAL,
        _S.EXECUTING: _G.POLICY_ALLOW,
        # A denial does not stall the incident: propose a different plan, or escalate.
        _S.PLAN_PROPOSED: _G.NONE,
        _S.DEGRADED: _G.NONE,
        _S.ESCALATED: _G.NONE,
    },
    _S.AWAITING_APPROVAL: {
        _S.EXECUTING: _G.EXECUTION_AUTHORIZATION,
        # A human rejection sends the plan back, it does not execute anything.
        _S.PLAN_PROPOSED: _G.NONE,
        _S.DEGRADED: _G.NONE,
        _S.ESCALATED: _G.NONE,
    },
    _S.EXECUTING: {
        # Execution is never self-certifying: the only way onward is verification
        # (claude.md section 11).
        _S.VERIFYING: _G.NONE,
        _S.DEGRADED: _G.NONE,
        _S.ESCALATED: _G.NONE,
    },
    _S.VERIFYING: {
        # Resolution is the one claim AEGIS must never take on trust: only an independent
        # verification of actual enterprise state can close an incident.
        _S.RESOLVED: _G.VERIFICATION,
        _S.DEGRADED: _G.NONE,
        _S.ESCALATED: _G.NONE,
    },
    # --- recovery path ------------------------------------------------------------
    _S.DEGRADED: {
        _S.RECOVERING: _G.NONE,
        _S.ESCALATED: _G.NONE,
    },
    _S.RECOVERING: {
        # Recovery re-enters the workflow at diagnosis, never further along. That is
        # what keeps a degradation detour from becoming a route around POLICY_CHECK.
        _S.INVESTIGATING: _G.NONE,
        _S.DEGRADED: _G.NONE,
        _S.ESCALATED: _G.NONE,
    },
    # --- terminal states ----------------------------------------------------------
    _S.RESOLVED: {},
    _S.ESCALATED: {},
}

TRANSITIONS: Mapping[IncidentState, Mapping[IncidentState, TransitionGuard]] = MappingProxyType(
    {state: MappingProxyType(edges) for state, edges in _TABLE.items()}
)
"""Every legal edge, as ``{from_state: {to_state: guard}}``.

Read-only at runtime. Every member of :class:`~aegis.core.domain.enums.IncidentState`
appears as a key; terminal states map to an empty set of edges.
"""

TERMINAL_STATES: frozenset[IncidentState] = frozenset(
    state for state, edges in _TABLE.items() if not edges
)
"""States an incident can never leave: RESOLVED and ESCALATED (``claude.md`` section 8).

Derived from the table rather than declared separately, so the two can never disagree.
"""
