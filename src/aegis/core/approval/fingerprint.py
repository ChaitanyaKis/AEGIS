"""Deterministic fingerprints for proposed actions.

An approval authorises *one exact action*, not a description of one. The fingerprint is
what makes that binding checkable: approve, then swap the action, and the fingerprint no
longer matches (``claude.md`` section 13, privilege escalation).

The digest is taken over the whole canonical serialization rather than a chosen subset of
fields. Cherry-picking is where fingerprint bugs live — a field left out of the digest is
a field an attacker may change freely — so every field participates, including ``risk``
and ``blast_radius``. Those are deterministic outputs of the assessment pipeline, so
re-assessing an unchanged action reproduces an unchanged fingerprint.
"""

from __future__ import annotations

import hashlib

from aegis.core.domain import Action, to_json

__all__ = ["action_fingerprint"]


def action_fingerprint(action: Action) -> str:
    """SHA-256 of the action's canonical JSON, as 64 lowercase hex characters.

    Stable across processes and runs: ``to_json`` sorts keys, normalises timestamps to
    UTC and renders enums as their string values, so equal actions always digest equally
    regardless of how they were constructed.
    """
    return hashlib.sha256(to_json(action).encode("utf-8")).hexdigest()
