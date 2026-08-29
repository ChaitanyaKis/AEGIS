"""What the remote boundary raises, and the much larger set of things it does not.

The rule from :mod:`aegis.a2a.verdicts` is unchanged and is the reason this module is
short: a refusal is a **returned value**, not an exception. A caller has to unpack a
:class:`~aegis.a2a.remote.verdicts.RemoteVerdict` and route it into an audit record, and a
returned refusal is harder to ignore than a raised one is to swallow.

What is left here is the one class of failure that is not a message-level refusal at all:
the key material needed to verify a signature is unavailable. That is a *configuration*
fault rather than a hostile message, and conflating the two would let a deployment with a
missing provider look like a deployment under attack — or, far worse, let a missing
provider look like a message that passed.
"""

from __future__ import annotations

from aegis.a2a.errors import A2AError

__all__ = ["RemoteA2AError", "UnsupportedAlgorithm"]


class RemoteA2AError(A2AError):
    """Base class for everything the remote boundary raises.

    Deliberately a subclass of :class:`~aegis.a2a.errors.A2AError`, so the orchestrator's
    existing ``except A2AError`` — which already turns an unusable A2A state into a
    *recorded refusal* rather than a crash — covers the remote boundary too without a
    second handler that could drift out of step with the first.
    """


class UnsupportedAlgorithm(RemoteA2AError):
    """No provider in this deployment can handle that algorithm.

    Raised when key material is *requested*, never while a message is being judged. A
    message naming an algorithm nothing can verify is refused with
    :attr:`~aegis.a2a.remote.verdicts.RemoteRejection.UNSUPPORTED_ALGORITHM`, because a
    message must always produce a verdict — an exception escaping mid-verification is how
    an unverified message ends up somewhere that assumes it was verified.
    """

    def __init__(self, algorithm: str, available: tuple[str, ...]) -> None:
        self.algorithm = algorithm
        self.available = available
        super().__init__(
            f"no key provider handles {algorithm!r}; available: {', '.join(available) or 'none'}"
        )
