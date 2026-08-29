"""Capability registry — the authoritative source of capability definitions.

Trust zone C (``claude.md`` section 4): authoritative. Resolves capability ids to
:class:`~aegis.core.domain.capability.Capability` definitions and answers the
deterministic ownership and scope questions the policy engine depends on.

In-process only. No persistence, no network, no Google Agent Registry integration —
that adapter belongs in :mod:`aegis.integrations` and does not exist yet.
"""

from aegis.core.capabilities.errors import (
    CapabilityRegistryError,
    DuplicateCapabilityError,
    UnknownCapabilityError,
)
from aegis.core.capabilities.registry import CapabilityRegistry, resource_in_scope

__all__ = [
    "CapabilityRegistry",
    "CapabilityRegistryError",
    "DuplicateCapabilityError",
    "UnknownCapabilityError",
    "resource_in_scope",
]
