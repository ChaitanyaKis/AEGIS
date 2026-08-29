"""Errors raised by the capability registry.

These are *control-plane* errors, not policy decisions. The registry raises when it is
asked something it cannot answer truthfully; it never answers with a permissive default.
Callers that need a decision rather than an exception (the policy engine) ask
``exists()`` first and turn a negative into an explicit DENY.
"""

from __future__ import annotations

__all__ = [
    "CapabilityRegistryError",
    "DuplicateCapabilityError",
    "UnknownCapabilityError",
]


class CapabilityRegistryError(Exception):
    """Base class for every capability registry failure."""


class UnknownCapabilityError(CapabilityRegistryError, KeyError):
    """Raised when a capability id is not present in the registry.

    Subclasses :class:`KeyError` so that ``registry.get(...)`` behaves like the mapping
    lookup it is, while still being catchable as a registry-specific error.
    """

    def __init__(self, capability_id: str) -> None:
        self.capability_id = capability_id
        super().__init__(f"unknown capability: {capability_id!r}")


class DuplicateCapabilityError(CapabilityRegistryError):
    """Raised when a capability id is registered twice.

    Registration is never an overwrite. Silently replacing a capability definition would
    let a later registration widen authority that policy already granted against the
    earlier one.
    """

    def __init__(self, capability_id: str) -> None:
        self.capability_id = capability_id
        super().__init__(f"capability already registered: {capability_id!r}")
