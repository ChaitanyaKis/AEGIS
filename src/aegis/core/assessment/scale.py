"""Ordering over :class:`~aegis.core.domain.enums.RiskLevel`.

The domain enum deliberately declines to implement comparison: ordering risk is
control-plane behaviour, not a property of the contract. This module supplies that
behaviour for the assessment engines, in one place, so that "conservative" always means
the same thing.

Every combination in the assessment layer is a :func:`max`. That is what makes the
safety invariants structural rather than merely tested: a monotone non-decreasing
combiner cannot let one benign-looking input pull a known-dangerous one downwards.
"""

from __future__ import annotations

from collections.abc import Iterable

from aegis.core.domain import RiskLevel

__all__ = ["RISK_ORDER", "max_risk"]

RISK_ORDER: dict[RiskLevel, int] = {
    RiskLevel.LOW: 0,
    RiskLevel.MEDIUM: 1,
    RiskLevel.HIGH: 2,
    RiskLevel.CRITICAL: 3,
}
"""Rank of each risk level, low to critical."""


def max_risk(levels: Iterable[RiskLevel]) -> RiskLevel:
    """The most severe of ``levels``.

    Args:
        levels: One or more risk levels.

    Returns:
        The highest-ranked level.

    Raises:
        ValueError: if ``levels`` is empty. There is no neutral element to fall back to;
            returning LOW for "nothing to compare" would invent safety out of absence.
    """
    ranked = sorted(levels, key=lambda level: RISK_ORDER[level])
    if not ranked:
        raise ValueError("max_risk() requires at least one risk level")
    return ranked[-1]
