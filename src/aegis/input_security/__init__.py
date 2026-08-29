"""Input security — boundary between untrusted content and model-facing reasoning.

The entry point for untrusted incident payloads. Every string that originates outside the
control plane must cross this boundary before a model sees it.

Imports::

    from aegis.input_security import (
        DeterministicInputSecurity,
        InputSecurityProvider,
        InputSecurityVerdict,
        InputSecurityDecision,
        InputSecurityCategory,
        PassThroughInputSecurity,
    )
"""

from aegis.input_security.provider import (
    DeterministicInputSecurity,
    InputSecurityProvider,
    ModelArmorInputSecurity,
    PassThroughInputSecurity,
)
from aegis.input_security.verdict import (
    InputSecurityCategory,
    InputSecurityDecision,
    InputSecurityVerdict,
)

__all__ = [
    "DeterministicInputSecurity",
    "InputSecurityCategory",
    "InputSecurityDecision",
    "InputSecurityProvider",
    "InputSecurityVerdict",
    "ModelArmorInputSecurity",
    "PassThroughInputSecurity",
]
