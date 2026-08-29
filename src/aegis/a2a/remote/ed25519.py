"""The only module in AEGIS that imports ``cryptography``.

The same discipline :mod:`aegis.integrations.gemini` follows for Google: one file, one
import, one structural test asserting nothing else touches it. The rest of the remote
boundary talks to :class:`~aegis.a2a.remote.keys.KeyProvider` and cannot tell which library
is underneath -- which is what "provider-neutral" has to mean if it is to mean anything.

Optional by design
------------------

``cryptography`` is **not** a required dependency of AEGIS. It arrives through the optional
``[crypto]`` extra, and when it is absent :func:`ed25519_provider` returns ``None``. The
deterministic offline benchmark therefore runs on HMAC-SHA256 from the standard library and
needs no third-party package at all, which is what Part 21 requires.

What absence does **not** do is downgrade anything. A missing provider means Ed25519 cannot
be offered; it never means an Ed25519 message is verified some other way. A message naming
an algorithm this deployment cannot handle is refused, and refusal is the only outcome.
"""

from __future__ import annotations

from aegis.a2a.remote.keys import (
    KeyAlgorithm,
    SigningKey,
    UnusableKey,
    VerifyingKey,
    looks_like_a_signature,
)

__all__ = ["ED25519_AVAILABLE", "Ed25519KeyProvider", "ed25519_provider"]

try:  # pragma: no cover - exercised by whichever branch this deployment takes
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    ED25519_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised by whichever branch this deployment takes
    ED25519_AVAILABLE = False

_SEED_BYTES = 32
"""Ed25519 private keys are exactly 32 bytes. Not a tunable."""


class _Ed25519SigningKey:
    """Holds a private key. Never serialized, never logged, never in a ``repr``."""

    __slots__ = ("_key", "_key_id")

    def __init__(self, key_id: str, key) -> None:
        self._key_id = key_id
        self._key = key

    @property
    def key_id(self) -> str:
        return self._key_id

    @property
    def algorithm(self) -> KeyAlgorithm:
        return KeyAlgorithm.ED25519

    def sign(self, message: bytes) -> str:
        return self._key.sign(message).hex()

    def __repr__(self) -> str:
        return f"_Ed25519SigningKey(key_id={self._key_id!r})"


class _Ed25519VerifyingKey:
    """Holds a public key. Safe to store, and unable to sign anything.

    The whole reason to prefer this over a symmetric MAC: a registry full of these gives a
    receiver evidence about a sender without giving the receiver the power to impersonate
    it.
    """

    __slots__ = ("_key", "_key_id")

    def __init__(self, key_id: str, key) -> None:
        self._key_id = key_id
        self._key = key

    @property
    def key_id(self) -> str:
        return self._key_id

    @property
    def algorithm(self) -> KeyAlgorithm:
        return KeyAlgorithm.ED25519

    @property
    def material(self) -> str:
        return self._key.public_bytes(Encoding.Raw, PublicFormat.Raw).hex()

    def verify(self, message: bytes, signature: str) -> bool:
        """Never raises. A hostile signature is ``False``, not an exception.

        Every failure mode collapses to the same answer on purpose: not hex, wrong length,
        mathematically invalid. A verifier that raised on one of those and returned ``False``
        on another would let the shape of a forgery pick which code path runs next.
        """
        if not looks_like_a_signature(signature):
            return False
        try:
            raw = bytes.fromhex(signature)
        except ValueError:
            return False
        try:
            self._key.verify(raw, message)
        except (InvalidSignature, ValueError, TypeError):
            return False
        return True

    def __repr__(self) -> str:
        return f"_Ed25519VerifyingKey(key_id={self._key_id!r})"


class Ed25519KeyProvider:
    """Genuine asymmetric signatures. Available only when ``cryptography`` is installed."""

    @property
    def algorithm(self) -> KeyAlgorithm:
        return KeyAlgorithm.ED25519

    def generate(
        self, key_id: str, *, seed: bytes | None = None
    ) -> tuple[SigningKey, VerifyingKey]:
        """A key pair, reproducible when a seed is given.

        The seed is padded or truncated to exactly 32 bytes rather than rejected, so a test
        can name a key with a readable byte string. **Deriving a key from a short seed is a
        simulation convenience and is not production key management** -- the not-claimed
        list in ``docs/A2A.md`` says so, and it says so because a reader who skipped this
        docstring would otherwise assume the opposite.
        """
        if seed is None:
            private = Ed25519PrivateKey.generate()
        else:
            private = Ed25519PrivateKey.from_private_bytes(
                seed.ljust(_SEED_BYTES, b"\0")[:_SEED_BYTES]
            )
        return _Ed25519SigningKey(key_id, private), _Ed25519VerifyingKey(
            key_id, private.public_key()
        )

    def verifier(self, key_id: str, material: str) -> VerifyingKey:
        """Rebuild a public key from stored hex.

        Unreadable material produces a key that verifies nothing rather than an exception.
        Corrupt registry material must not be able to crash the boundary mid-judgement: the
        message it was judging has to end in a verdict, and "this key verifies nothing" is
        the fail-closed verdict.
        """
        try:
            public = Ed25519PublicKey.from_public_bytes(bytes.fromhex(material))
        except (ValueError, TypeError):
            return UnusableKey(key_id, KeyAlgorithm.ED25519)
        return _Ed25519VerifyingKey(key_id, public)

    def __repr__(self) -> str:
        return "Ed25519KeyProvider(Ed25519)"


def ed25519_provider() -> Ed25519KeyProvider | None:
    """The provider, or ``None`` when ``cryptography`` is not installed.

    ``None`` is the honest answer and the only safe one. Returning a stub that "verified"
    everything would be a fabricated integration; returning one that raised would turn a
    packaging choice into a crash while judging a message.
    """
    return Ed25519KeyProvider() if ED25519_AVAILABLE else None
