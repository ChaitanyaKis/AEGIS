"""Where A2A message state is kept between processes.

The interface is deliberately two methods. There is no update, no delete, no truncate and
no reset, so **no backend implementing this can offer the ledger a way to rewrite history**
even if it wanted to — the same discipline
:class:`~aegis.lifecycle.persistence.LifecycleStatePersistence` and
:class:`~aegis.memory.store.MemoryPersistence` follow, and for the same reason.

This module depends on nothing but the record type. No policy, no approval, no
verification, no lifecycle, no agents, no orchestration, no enterprise, and no clock of its
own: a persistence layer that could read the time could make loading non-deterministic.

Persistence is not permission
-----------------------------

Nothing here decides whether a message may be delivered. It stores what happened and
refuses to hand back a history it cannot vouch for. A backend that cannot be trusted must
never be the reason something is admitted — which is why both implementations raise on
damage rather than salvaging what they can. A partially read log looks exactly like a log
in which the last few *consumptions* never happened, and that is precisely the lie that
would make a spent message look fresh.
"""

from __future__ import annotations

import os
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Protocol, runtime_checkable

from aegis.a2a.errors import A2APersistenceFailure, A2AStateCorrupt
from aegis.a2a.records import A2AStateRecord
from aegis.core.domain import from_json, to_json

__all__ = [
    "A2APersistence",
    "InMemoryA2APersistence",
    "JsonlA2APersistence",
]


@runtime_checkable
class A2APersistence(Protocol):
    """Append-only storage for A2A state records.

    Implementations must preserve order exactly. The chain's meaning depends on it, and so
    does the status-legality check performed on load.
    """

    def load(self) -> Sequence[A2AStateRecord]:
        """Every record, in the order it was appended."""
        ...

    def append(self, record: A2AStateRecord) -> None:
        """Add one record to the end. Never called with anything but the next record."""
        ...


class InMemoryA2APersistence:
    """Process-lifetime storage. **NOT DURABLE.**

    Stated plainly because the whole point of this milestone is durability: a ledger backed
    by this loses every consumption when the process ends, so a message captured before a
    restart *would* be replayable after one. That is the exact weakness
    :class:`JsonlA2APersistence` exists to remove.

    It remains the default and the right choice for two cases — hermetic tests, and a
    single-run process where a restart also destroys every conversation partner. It is the
    wrong choice for anything that must survive a restart, and this class will not pretend
    otherwise.
    """

    durable = False
    """Read by callers that need to know, and by a test that asserts the honesty of it."""

    def __init__(self, records: Iterable[A2AStateRecord] = ()) -> None:
        self._records: list[A2AStateRecord] = list(records)

    def load(self) -> Sequence[A2AStateRecord]:
        return tuple(self._records)

    def append(self, record: A2AStateRecord) -> None:
        self._records.append(record)

    def __len__(self) -> int:
        return len(self._records)

    def __repr__(self) -> str:
        return f"{type(self).__name__}(records={len(self._records)}, durable=False)"


class JsonlA2APersistence:
    """File-backed, append-only, one canonical JSON document per line.

    No database, no driver, no schema migration — the standard library and the project's
    existing canonical serializer.

    What durability this actually provides
    --------------------------------------

    * **Survives process restart.** Records written by one process are read by the next,
      and the chain plus status legality are checked on load. This is the property Prompt 16
      exists to establish.
    * **Survives power loss up to the last completed append.** Each append writes one line,
      flushes it, and ``fsync``s before returning, so a consumption the ledger reported as
      recorded is on disk.
    * **Append-only in structure, not enforced by the filesystem.** Nothing stops an
      operator with write access from truncating or rewriting the file. The chain makes that
      *detectable* on the next load; it does not make it impossible.
    * **No concurrency control.** Two processes appending to one file will interleave and
      corrupt the sequence. Single-writer, and there is no locking to pretend otherwise —
      see the module note in ``docs/A2A.md``.

    A partially written final line — a crash mid-append — is reported as damage rather than
    silently dropped. A log that quietly discards its own tail is worse than one that says
    it is broken, because the discarded tail is exactly where the recent consumptions live.

    The one atomicity limitation, stated rather than hidden
    ------------------------------------------------------

    A single ``write`` of one short line is not guaranteed atomic by POSIX or by Windows.
    A crash mid-line therefore leaves a truncated final record. That case is **detected**
    (the line fails to parse, and the load raises) but not **prevented**. What matters for
    security is which way the failure falls: a torn line can only ever lose the *most
    recent* record, and losing a record means the log refuses to load rather than quietly
    presenting an earlier status — so a torn write can never resurrect a consumed message.
    """

    durable = True

    def __init__(self, path: str | os.PathLike[str], *, fsync: bool = True) -> None:
        self._path = Path(path)
        self._fsync = fsync

    @property
    def path(self) -> Path:
        return self._path

    def load(self) -> Sequence[A2AStateRecord]:
        """Every record in file order.

        A missing file reads as an empty log, which is the correct reading of "nothing has
        happened yet" and is the well-defined initial state.

        Raises:
            A2AStateCorrupt: if any line is not a readable record. Including the last one:
                a truncated tail is damage, not an ending.
        """
        if not self._path.exists():
            return ()
        records: list[A2AStateRecord] = []
        with self._path.open("r", encoding="utf-8") as handle:
            for number, line in enumerate(handle, start=1):
                text = line.strip()
                if not text:
                    continue
                try:
                    records.append(from_json(A2AStateRecord, text))
                except Exception as error:
                    raise A2AStateCorrupt(
                        f"{self._path}: line {number} is not a readable A2A record "
                        f"({type(error).__name__}); the log is damaged"
                    ) from error
        return tuple(records)

    def append(self, record: A2AStateRecord) -> None:
        """Write one record as a single canonical line, flushed and synced.

        Raises:
            A2APersistenceFailure: if the record cannot be written. The ledger turns this
                into a refusal, never into a delivery.
        """
        line = to_json(record)
        if "\n" in line:
            raise A2APersistenceFailure("canonical record contains a newline")
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with self._path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")
                handle.flush()
                if self._fsync:
                    os.fsync(handle.fileno())
        except OSError as error:
            raise A2APersistenceFailure(f"{self._path}: {type(error).__name__}: {error}") from error

    def __repr__(self) -> str:
        return f"{type(self).__name__}(path={str(self._path)!r}, durable=True)"
