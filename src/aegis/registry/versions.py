"""Agent versions, and the one rule that makes version selection deterministic.

A registry that returns "the agent" when three versions of it exist has not answered the
question. Every registration in AEGIS is keyed by ``(agent_id, version)``, and every
lookup either names a version exactly or asks for the *selected* one — never for whatever
happened to be inserted last.

The ordering is numeric on three components, so ``2.0.0`` sorts above ``1.10.0`` and
``1.10.0`` sorts above ``1.9.0``. String ordering gets both of those wrong, which is the
entire reason this module exists rather than a ``str`` field and a ``max()``.

Deliberately not a general semantic-version implementation. There are no pre-release
tags, no build metadata and no ranges, because every one of those introduces a comparison
whose answer is arguable, and a registry that has to argue about which build is newer is
a registry that cannot make a deterministic authorization decision.
"""

from __future__ import annotations

import re
from typing import Any, Self

from pydantic import GetCoreSchemaHandler
from pydantic_core import core_schema

__all__ = ["AgentVersion", "InvalidVersion"]

_PATTERN = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")
"""``MAJOR.MINOR.PATCH``, each a non-negative integer without leading zeros.

Leading zeros are refused rather than normalised: ``1.01.0`` and ``1.1.0`` would
otherwise be two spellings of one version, and a registry keyed by the spelling would
hold two registrations that compare equal.
"""


class InvalidVersion(ValueError):
    """A version string that is not exactly ``MAJOR.MINOR.PATCH``."""


class AgentVersion:
    """One immutable ``MAJOR.MINOR.PATCH`` version, ordered numerically.

    Hashable and totally ordered, so it can be a dictionary key and can be sorted
    without a key function. Equality is on the three numbers, and because the parser
    refuses leading zeros there is exactly one spelling per value.
    """

    __slots__ = ("_parts",)

    def __init__(self, text: str) -> None:
        match = _PATTERN.match(text.strip() if isinstance(text, str) else "")
        if match is None:
            raise InvalidVersion(
                f"invalid agent version {text!r}: expected MAJOR.MINOR.PATCH with "
                f"non-negative integers and no leading zeros"
            )
        self._parts = (int(match[1]), int(match[2]), int(match[3]))

    @classmethod
    def parse(cls, text: str | Self) -> Self:
        """Coerce a string or an existing version into a version."""
        return text if isinstance(text, cls) else cls(str(text))

    @property
    def major(self) -> int:
        return self._parts[0]

    @property
    def minor(self) -> int:
        return self._parts[1]

    @property
    def patch(self) -> int:
        return self._parts[2]

    @property
    def parts(self) -> tuple[int, int, int]:
        return self._parts

    def __str__(self) -> str:
        return f"{self._parts[0]}.{self._parts[1]}.{self._parts[2]}"

    def __repr__(self) -> str:
        return f"AgentVersion({str(self)!r})"

    def __eq__(self, other: object) -> bool:
        return isinstance(other, AgentVersion) and self._parts == other._parts

    def __hash__(self) -> int:
        return hash(self._parts)

    def __lt__(self, other: AgentVersion) -> bool:
        if not isinstance(other, AgentVersion):
            return NotImplemented
        return self._parts < other._parts

    def __le__(self, other: AgentVersion) -> bool:
        if not isinstance(other, AgentVersion):
            return NotImplemented
        return self._parts <= other._parts

    def __gt__(self, other: AgentVersion) -> bool:
        if not isinstance(other, AgentVersion):
            return NotImplemented
        return self._parts > other._parts

    def __ge__(self, other: AgentVersion) -> bool:
        if not isinstance(other, AgentVersion):
            return NotImplemented
        return self._parts >= other._parts

    @classmethod
    def __get_pydantic_core_schema__(
        cls, source: Any, handler: GetCoreSchemaHandler
    ) -> core_schema.CoreSchema:
        """Accept a string or an ``AgentVersion``; serialize as the canonical string.

        Present so a version can sit inside a frozen :class:`~aegis.core.domain.DomainModel`
        and survive ``model_dump_json`` as ``"1.2.0"`` rather than as an opaque object.
        """
        return core_schema.json_or_python_schema(
            json_schema=core_schema.no_info_plain_validator_function(cls.parse),
            python_schema=core_schema.no_info_plain_validator_function(cls.parse),
            serialization=core_schema.plain_serializer_function_ser_schema(
                str, return_schema=core_schema.str_schema(), when_used="always"
            ),
        )
