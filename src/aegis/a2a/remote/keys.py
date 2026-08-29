"""Signing and verifying, without committing AEGIS to one cryptographic library.

Part 3. The protocol layer names an **algorithm**; it never reaches for a library. Two
protocols and a provider interface are all the rest of the package knows, so swapping
Ed25519 for something else is a new provider rather than a change to the boundary that
verifies messages.

Explicit, never implicit
------------------------

* The algorithm is a required, closed, **signed** field on every remote envelope.
* Nothing selects an algorithm on a message's behalf. A message that does not name one
  cannot be constructed.
* Nothing falls back to a weaker algorithm. A mismatch between what a message names and
  what the registry holds is a refusal, and that refusal is the whole of the downgrade
  defence -- see :mod:`aegis.a2a.remote.authenticator`.
* An algorithm no provider handles raises
  :class:`~aegis.a2a.remote.errors.UnsupportedAlgorithm` when key material is *requested*,
  and produces a refusal when a *message* names it.

What the two shipped providers actually give you
------------------------------------------------

``ED25519`` -- genuine asymmetric signatures, in :mod:`aegis.a2a.remote.ed25519`, the only
module in AEGIS that imports ``cryptography``. The registry holds a public key and nothing
that can sign. This is the algorithm for a peer that is genuinely remote.

``HMAC_SHA256`` -- a symmetric message authentication code from the standard library. It
authenticates a message against **anyone who does not hold the key**, which is exactly the
malicious-intermediary threat, and it does **not** authenticate the sender to the receiver
the way a signature does, because the receiver holds the same key and could produce the
same tag. That is a real limitation, and it is named here rather than hidden behind a field
called ``public_key`` -- which is precisely why the registry's field is called
``verification_key`` instead. It is the default for the deterministic offline benchmark
because it needs no third-party package, and ``docs/A2A.md`` says so in those words.

Key material is never persisted, never logged, never audited and never put in a ``repr``.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from collections.abc import Mapping
from enum import StrEnum
from typing import Protocol, runtime_checkable

from aegis.a2a.remote.errors import UnsupportedAlgorithm

__all__ = [
    "MAX_SIGNATURE_HEX",
    "HmacKeyProvider",
    "KeyAlgorithm",
    "KeyProvider",
    "KeyRing",
    "SigningKey",
    "UnusableKey",
    "VerifyingKey",
    "available_algorithms",
    "looks_like_a_signature",
    "provider_for",
]

MAX_SIGNATURE_HEX = 512
"""Longest signature this boundary will look at, in hex characters.

Ed25519 produces 128; an HMAC-SHA256 tag produces 64. The bound exists so a hostile peer
cannot hand the verifier a megabyte of hex and have it hashed -- a size check that happens
after the expensive work is not a size check.
"""


def looks_like_a_signature(signature: str) -> bool:
    """Whether this text could be a signature at all: non-empty, bounded, lowercase hex.

    A cheap, total predicate run before any comparison. Two things depend on it:

    * ``hmac.compare_digest`` raises on non-ASCII text, so a signature field a hostile peer
      filled with anything outside ASCII would become an exception in the middle of judging
      a message rather than a verdict;
    * the length bound means a peer cannot hand the verifier a megabyte of text and have it
      hashed. A size check that happens after the expensive work is not a size check.

    Returns ``False`` for everything questionable rather than raising, because every caller
    is mid-judgement on a hostile message and owes its own caller an answer.
    """
    return bool(
        signature
        and len(signature) <= MAX_SIGNATURE_HEX
        and len(signature) % 2 == 0
        and all(character in "0123456789abcdef" for character in signature)
    )


class KeyAlgorithm(StrEnum):
    """Every algorithm this protocol can name. Closed, so an unknown one is a schema error.

    A free string field would let a message name ``"none"`` and dare the boundary to
    interpret it. There is no ``NONE`` member and there will not be one: an algorithm that
    does not authenticate is not an algorithm, it is a downgrade with a spelling.
    """

    ED25519 = "Ed25519"
    HMAC_SHA256 = "HMAC-SHA256"


@runtime_checkable
class SigningKey(Protocol):
    """Produces a signature. Held only by the agent that owns the identity."""

    @property
    def key_id(self) -> str: ...

    @property
    def algorithm(self) -> KeyAlgorithm: ...

    def sign(self, message: bytes) -> str:
        """Sign the canonical signing payload, returning lowercase hex."""
        ...


@runtime_checkable
class VerifyingKey(Protocol):
    """Checks a signature. This is what a registry stores.

    ``material`` is what goes into
    :class:`~aegis.a2a.remote.identity.RemoteAgentIdentity`. For an asymmetric algorithm it
    is a public key and revealing it costs nothing; for a symmetric one it is shared secret
    material, which is the limitation named in the module docstring.
    """

    @property
    def key_id(self) -> str: ...

    @property
    def algorithm(self) -> KeyAlgorithm: ...

    @property
    def material(self) -> str: ...

    def verify(self, message: bytes, signature: str) -> bool:
        """Whether this signature is valid for this message under this key. Never raises."""
        ...


@runtime_checkable
class KeyProvider(Protocol):
    """Makes and reconstructs keys for exactly one algorithm."""

    @property
    def algorithm(self) -> KeyAlgorithm: ...

    def generate(
        self, key_id: str, *, seed: bytes | None = None
    ) -> tuple[SigningKey, VerifyingKey]:
        """A fresh key pair. A ``seed`` makes it reproducible; ``None`` makes it random."""
        ...

    def verifier(self, key_id: str, material: str) -> VerifyingKey:
        """Rebuild a verifying key from stored material, as a registry lookup does."""
        ...


# --- HMAC-SHA256, from the standard library -------------------------------------------


class _HmacKey:
    """One symmetric key, usable for both signing and verifying.

    Both roles on one object because that is the truth about a symmetric MAC. Splitting it
    into two classes would suggest a separation of capability the algorithm does not
    provide, and a comfortable lie in a type name is still a lie.
    """

    __slots__ = ("_key_id", "_secret")

    def __init__(self, key_id: str, secret: bytes) -> None:
        self._key_id = key_id
        self._secret = secret

    @property
    def key_id(self) -> str:
        return self._key_id

    @property
    def algorithm(self) -> KeyAlgorithm:
        return KeyAlgorithm.HMAC_SHA256

    @property
    def material(self) -> str:
        return self._secret.hex()

    def sign(self, message: bytes) -> str:
        return hmac.new(self._secret, message, hashlib.sha256).hexdigest()

    def verify(self, message: bytes, signature: str) -> bool:
        """Constant-time comparison, and no exception on malformed input.

        ``compare_digest`` rather than ``==`` so the comparison does not leak how much of a
        forged tag was correct. A signature that is not hex, or is absurdly long, is simply
        false -- a verifier that raised on bad input would turn a hostile message into an
        exception somewhere that expected a boolean.

        The :func:`looks_like_a_signature` guard is load-bearing rather than defensive.
        ``compare_digest`` **raises** ``TypeError`` on a string containing non-ASCII
        characters, and a signature field is text a hostile peer chooses, so without the
        guard a message carrying eight umlauts would end in an exception rather than a
        verdict. A mutation found that; the guard and its test exist because of it.
        """
        if not looks_like_a_signature(signature):
            return False
        return hmac.compare_digest(self.sign(message), signature)

    def __repr__(self) -> str:
        return f"_HmacKey(key_id={self._key_id!r})"


class UnusableKey:
    """A verifying key built from material that could not be read. Verifies nothing, ever.

    Registry material can be corrupt -- truncated in storage, edited by hand, written by an
    older version. When it is, the boundary must still produce a **verdict** for the message
    it was judging, because a message that ends in an exception is a message nothing decided
    about, somewhere that assumed something had.

    So an unreadable key becomes a key that refuses everything rather than a raise. The two
    shipped providers both return this, which keeps the failure mode identical whichever
    algorithm the corrupt entry named.
    """

    __slots__ = ("_algorithm", "_key_id")

    def __init__(self, key_id: str, algorithm: KeyAlgorithm) -> None:
        self._key_id = key_id
        self._algorithm = algorithm

    @property
    def key_id(self) -> str:
        return self._key_id

    @property
    def algorithm(self) -> KeyAlgorithm:
        return self._algorithm

    @property
    def material(self) -> str:
        return ""

    def verify(self, message: bytes, signature: str) -> bool:
        return False

    def __repr__(self) -> str:
        return f"UnusableKey(key_id={self._key_id!r}, {self._algorithm})"


class HmacKeyProvider:
    """Symmetric keys from ``hmac`` and ``hashlib``. No third-party package."""

    @property
    def algorithm(self) -> KeyAlgorithm:
        return KeyAlgorithm.HMAC_SHA256

    def generate(
        self, key_id: str, *, seed: bytes | None = None
    ) -> tuple[SigningKey, VerifyingKey]:
        """A key pair -- the same object twice, because the algorithm is symmetric.

        A ``seed`` is stretched through SHA-256 rather than used directly, so a short or
        low-entropy seed still produces a full-width key. Deterministic on purpose: the
        benchmark must be reproducible, and a run whose keys differ every time cannot be
        compared with the run before it. **A derived key is a simulation artifact, not
        production key management** (``docs/A2A.md``, not-claimed list).
        """
        secret = hashlib.sha256(seed).digest() if seed is not None else secrets.token_bytes(32)
        key = _HmacKey(key_id, secret)
        return key, key

    def verifier(self, key_id: str, material: str) -> VerifyingKey:
        """Rebuild a key from stored hex, or return one that verifies nothing.

        Unreadable material produces :class:`UnusableKey` rather than an exception. The
        boundary calling this is in the middle of judging a hostile message and must end in
        a verdict; a raise there turns a storage problem into an unhandled path.
        """
        try:
            secret = bytes.fromhex(material)
        except ValueError:
            return UnusableKey(key_id, KeyAlgorithm.HMAC_SHA256)
        return _HmacKey(key_id, secret)

    def __repr__(self) -> str:
        return "HmacKeyProvider(HMAC-SHA256)"


# --- provider selection ---------------------------------------------------------------


def _providers() -> Mapping[KeyAlgorithm, KeyProvider]:
    """Every provider this deployment can actually offer.

    Ed25519 appears only when its module imports, which happens only when ``cryptography``
    is installed. Absence is reported as absence: nothing here substitutes a weaker
    algorithm for a missing stronger one, because a silent substitution is a downgrade the
    deployment performed on its own behalf.
    """
    from aegis.a2a.remote.ed25519 import ed25519_provider

    found: dict[KeyAlgorithm, KeyProvider] = {KeyAlgorithm.HMAC_SHA256: HmacKeyProvider()}
    provider = ed25519_provider()
    if provider is not None:
        found[KeyAlgorithm.ED25519] = provider
    return found


def available_algorithms() -> tuple[KeyAlgorithm, ...]:
    """Which algorithms this deployment can handle, sorted. Reported, never assumed."""
    return tuple(sorted(_providers(), key=lambda algorithm: algorithm.value))


def provider_for(algorithm: KeyAlgorithm) -> KeyProvider:
    """The provider for one algorithm.

    Raises:
        UnsupportedAlgorithm: when nothing handles it. Raised here -- where key material is
            *requested* -- and never while a message is being judged, so a missing provider
            can never be mistaken for a message that verified.
    """
    providers = _providers()
    provider = providers.get(algorithm)
    if provider is None:
        raise UnsupportedAlgorithm(str(algorithm), tuple(sorted(a.value for a in providers)))
    return provider


# --- holding signing keys -------------------------------------------------------------


class KeyRing:
    """The signing keys one process legitimately holds.

    A *sender-side* object. The verifying side needs a registry, not a key ring, and the
    two are separate types so that "this process can sign as X" and "this process can
    verify X" stay separate facts a reader can tell apart.

    Nothing here is persisted, logged, audited or rendered. ``__repr__`` names key ids and
    never material, and a test asserts it -- a secret that reaches a log is a secret whose
    rotation nobody will think to trigger.
    """

    __slots__ = ("_keys",)

    def __init__(self, keys: Mapping[str, SigningKey] | None = None) -> None:
        self._keys: dict[str, SigningKey] = dict(keys or {})

    def add(self, key: SigningKey) -> None:
        """Hold one more signing key.

        Raises:
            ValueError: if that key id is already held. Overwriting would silently change
                which key an agent signs with, and that is the quiet half of every
                key-confusion bug.
        """
        if key.key_id in self._keys:
            raise ValueError(f"key {key.key_id!r} is already held")
        self._keys[key.key_id] = key

    def signer(self, key_id: str) -> SigningKey | None:
        """The signing key with this exact id, or ``None``. Exact match, never a scan."""
        return self._keys.get(key_id)

    def key_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._keys))

    def __contains__(self, key_id: object) -> bool:
        return key_id in self._keys

    def __len__(self) -> int:
        return len(self._keys)

    def __repr__(self) -> str:
        return f"KeyRing({', '.join(self.key_ids()) or 'empty'})"
