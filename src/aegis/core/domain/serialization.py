"""Deterministic serialization for AEGIS domain contracts.

The domain layer needs one obvious, stable way to move objects across boundaries
(event store, future API/event transport, evaluation fixtures, golden-file tests).

Guarantees
----------

* **Canonical.** :func:`to_json` sorts keys and uses compact separators, so two equal
  objects always produce byte-identical output regardless of field declaration order.
  That makes serialized audit events comparable and hashable later.
* **Explicit.** Enums serialize to their string values; timestamps to UTC ISO-8601;
  tuples to JSON arrays. Nothing is implicit or Python-specific.
* **Validated on the way in.** Deserialization goes through pydantic validation, so an
  unknown or malformed field is rejected rather than absorbed — untrusted payloads
  (``claude.md`` section 4, zone A) can never widen a contract.

There is no custom serialization machinery here: these are thin, typed wrappers over
pydantic so that call sites do not each invent their own dump options.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from aegis.core.domain.base import DomainModel

__all__ = ["from_dict", "from_json", "to_dict", "to_json"]


def to_dict(model: DomainModel) -> dict[str, Any]:
    """Serialize a domain model to JSON-compatible primitives.

    Enums become their string values and timestamps become UTC ISO-8601 strings, so the
    result is safe to hand to any JSON encoder or transport.
    """
    return model.model_dump(mode="json")


def to_json(model: DomainModel, *, indent: int | None = None) -> str:
    """Serialize a domain model to canonical JSON.

    Keys are sorted and separators compact, so the output is deterministic and stable
    across runs. Pass ``indent`` only for human-readable output; the canonical form used
    for comparison or hashing is the default un-indented one.
    """
    separators = (",", ":") if indent is None else (",", ": ")
    return json.dumps(
        to_dict(model),
        sort_keys=True,
        separators=separators,
        ensure_ascii=False,
        indent=indent,
    )


def from_dict[ModelT: DomainModel](model_type: type[ModelT], data: Mapping[str, Any]) -> ModelT:
    """Validate and construct a domain model from JSON-compatible primitives.

    Raises :class:`pydantic.ValidationError` if the payload violates the contract,
    including when it carries fields the contract does not define.
    """
    return model_type.model_validate(dict(data))


def from_json[ModelT: DomainModel](model_type: type[ModelT], raw: str | bytes) -> ModelT:
    """Validate and construct a domain model from a JSON document.

    Raises :class:`pydantic.ValidationError` if the payload violates the contract.
    """
    return model_type.model_validate_json(raw)
