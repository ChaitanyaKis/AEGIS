"""Deterministic failure injection.

**CONTROLLED SIMULATION** (``claude.md`` section 15). These are simulation controls, not
real faults: nothing here breaks, times out or errors for real. Each one is an explicit,
inspectable switch that makes a declared thing happen at a declared layer.

The vocabulary is closed. An arbitrary string cannot create new failure behaviour, so the
set of things the simulator can do to a scenario is exactly the set enumerated here.

Each failure affects the smallest layer that can produce it, and none of them reaches into
the control plane. In particular, none of them forces a verification outcome — they change
the world or the observations, and the verification engine then reaches its own conclusion
about what those show.
"""

from __future__ import annotations

from datetime import timedelta
from enum import StrEnum

__all__ = ["STALE_TELEMETRY_OFFSET", "FailureType"]


class FailureType(StrEnum):
    """Every failure the simulator can inject."""

    TOOL_TIMEOUT = "tool_timeout"
    """Execution layer: the simulated operation does not complete. The world is untouched."""

    TOOL_500 = "tool_500"
    """Execution layer: the simulated operation returns a server-style error. World untouched."""

    ROLLBACK_FAILURE = "rollback_failure"
    """Execution layer: the rollback runs and does not take. The world stays on the bad version.

    Distinct from the two above: the operation was attempted and reported a failure of its
    own, rather than never completing or being rejected by the endpoint.
    """

    STALE_TELEMETRY = "stale_telemetry"
    """Observation layer: measurements are older than any sane freshness window.

    The values are still accurate as of when they were taken; they are simply too old to
    establish the state *now*.
    """

    VERIFICATION_FAILURE = "verification_failure"
    """Observation layer: the telemetry source goes dark, so health and error rate are unmeasured.

    Named for its effect on the verification stage, but implemented where the cause lives:
    no observation is produced, so nothing establishes those attributes. The verification
    engine then reports INSUFFICIENT_EVIDENCE on its own — nothing forces that result.
    """


STALE_TELEMETRY_OFFSET = timedelta(hours=1)
"""How far :attr:`FailureType.STALE_TELEMETRY` backdates observations.

Comfortably beyond any freshness window a scenario would declare, so the effect does not
depend on tuning the two against each other.
"""
