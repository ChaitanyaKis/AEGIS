"""Where lifecycle and breaker state is kept between operations.

The interface is deliberately two methods. There is no update, no delete, no truncate and
no reset, so **no backend implementing this can offer the breaker a way to rewrite
history** even if it wanted to — the same discipline
:class:`~aegis.memory.store.MemoryPersistence` follows, and for the same reason.

This module depends on nothing but the record type. No policy, no approval, no
verification, no agents, no orchestration, no enterprise, and no clock of its own: a
persistence layer that could read the time could make loading non-deterministic.

Failing closed
--------------

A persistence layer that cannot be trusted must never be the reason something executes.
Both implementations refuse to hand back a damaged log rather than salvaging what they can:
a partially-read history looks exactly like a history in which the last few failures never
happened, which is the specific lie that would reopen a breaker that should be shut.
"""

from __future__ import annotations

import os
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Protocol, runtime_checkable

from aegis.core.domain import from_json, to_json
from aegis.lifecycle.errors import LifecycleStateCorrupt
from aegis.lifecycle.state import LifecycleStateRecord

__all__ = [
    "InMemoryLifecycleState",
    "JsonlLifecycleState",
    "LifecycleStatePersistence",
]


@runtime_checkable
class LifecycleStatePersistence(Protocol):
    """Append-only storage for lifecycle state records.

    Implementations must preserve order exactly. The chain's meaning depends on it, and so
    does the transition-legality check performed on load.
    """

    def load(self) -> Sequence[LifecycleStateRecord]:
        """Every record, in the order it was appended."""
        ...

    def append(self, record: LifecycleStateRecord) -> None:
        """Add one record to the end. Never called with anything but the next record."""
        ...


class InMemoryLifecycleState:
    """Process-lifetime storage. **Not durable** — the default, and honest about it.

    Exists so the breaker's contract can be exercised without a filesystem and so tests are
    hermetic. Anything that must survive a restart wants :class:`JsonlLifecycleState`.
    """

    def __init__(self, records: Iterable[LifecycleStateRecord] = ()) -> None:
        self._records: list[LifecycleStateRecord] = list(records)

    def load(self) -> Sequence[LifecycleStateRecord]:
        return tuple(self._records)

    def append(self, record: LifecycleStateRecord) -> None:
        self._records.append(record)

    def __len__(self) -> int:
        return len(self._records)

    def __repr__(self) -> str:
        return f"{type(self).__name__}(records={len(self._records)})"


class JsonlLifecycleState:
    """File-backed, append-only, one canonical JSON document per line.

    No database, no driver, no schema migration — the standard library and the project's
    existing canonical serializer.

    What durability this actually provides
    --------------------------------------

    * **Survives process restart.** Records written by one process are read by the next,
      and the chain plus transition legality are checked on load.
    * **Survives power loss up to the last completed append.** Each append writes one line,
      flushes it, and ``fsync``s before returning, so a transition the breaker reported as
      recorded is on disk.
    * **Append-only in structure, not enforced by the filesystem.** Nothing stops an
      operator with write access from truncating or rewriting the file. The chain makes
      that *detectable* on the next load; it does not make it impossible.
    * **No concurrency control.** Two processes appending to one file will interleave and
      corrupt the sequence. Single-writer, and there is no locking to pretend otherwise.

    A partially written final line — a crash mid-append — is reported as damage rather than
    silently dropped. A log that quietly discards its own tail is worse than one that says
    it is broken, because the discarded tail is exactly where the recent failures live.
    """

    def __init__(self, path: str | os.PathLike[str], *, fsync: bool = True) -> None:
        self._path = Path(path)
        self._fsync = fsync

    @property
    def path(self) -> Path:
        return self._path

    def load(self) -> Sequence[LifecycleStateRecord]:
        """Every record in file order.

        A missing file reads as an empty log, which is the correct reading of "nothing has
        happened yet" and is the well-defined initial state.

        Raises:
            LifecycleStateCorrupt: if any line is not a readable record.
        """
        if not self._path.exists():
            return ()
        records: list[LifecycleStateRecord] = []
        with self._path.open("r", encoding="utf-8") as handle:
            for number, line in enumerate(handle, start=1):
                text = line.strip()
                if not text:
                    continue
                try:
                    records.append(from_json(LifecycleStateRecord, text))
                except Exception as error:
                    raise LifecycleStateCorrupt(
                        f"{self._path}: line {number} is not a readable lifecycle record "
                        f"({type(error).__name__}); the log is damaged"
                    ) from error
        return tuple(records)

    def append(self, record: LifecycleStateRecord) -> None:
        """Write one record as a single canonical line, flushed and synced."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        line = to_json(record)
        if "\n" in line:
            raise LifecycleStateCorrupt("canonical record contains a newline")
        with self._path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
            handle.flush()
            if self._fsync:
                os.fsync(handle.fileno())

    def __repr__(self) -> str:
        return f"{type(self).__name__}(path={str(self._path)!r})"
