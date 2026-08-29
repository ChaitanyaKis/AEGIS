"""Incident lifecycle — the deterministic state machine (``claude.md`` section 8).

Owns which states an incident may move between and what a caller must present to make a
guarded move. It decides nothing about policy or approval; it enforces that those
decisions were made and are being carried.

Structurally guaranteed: RESOLVED only from VERIFYING, POLICY_CHECK never skipped, and
AWAITING_APPROVAL never left for EXECUTING without a consumed approval.
"""

from aegis.core.incidents.machine import (
    IncidentStateMachine,
    IncidentTransitionResult,
    InvalidIncidentTransition,
    StateTransition,
)
from aegis.core.incidents.transitions import (
    TERMINAL_STATES,
    TRANSITIONS,
    TransitionGuard,
)

__all__ = [
    "TERMINAL_STATES",
    "TRANSITIONS",
    "IncidentStateMachine",
    "IncidentTransitionResult",
    "InvalidIncidentTransition",
    "StateTransition",
    "TransitionGuard",
]
