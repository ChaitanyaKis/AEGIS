"""File-backed memory persistence.

One canonical JSON document per line, appended in order, never rewritten. No database, no
driver, no schema migration — the standard library and the project's existing canonical
serializer (Part 10).

What durability this actually provides
--------------------------------------

Be precise, because "persistent" is easy to overclaim:

* **Survives process restart.** Records written by one process are read back by the next,
  and the chain is verified on load, so an out-of-process edit is detected.
* **Survives power loss up to the last completed append.** Each append writes one line,
  flushes it and ``fsync``s the file descriptor before returning, so a record the store
  reported as written is on disk.
* **Append-only in structure, not enforced by the filesystem.** Nothing stops a user with
  write access from truncating or rewriting the file. The chain makes that *detectable* on
  the next load; it does not make it impossible.
* **No concurrency control.** Two processes appending to the same file will interleave and
  corrupt the sequence. This is a single-writer store, and there is no locking to pretend
  otherwise.
* **No atomic multi-record transaction.** Records are appended one at a time.

A partially written final line — a crash mid-append — is detected on load and refused,
rather than silently dropped: a log that quietly discards its own tail is worse than one
that says it is damaged.
"""

from __future__ import annotations

import os
from collections.abc import Sequence
from pathlib import Path

from aegis.core.domain import from_json, to_json
from aegis.memory.errors import MemoryIntegrityError
from aegis.memory.models import MemoryRecord

__all__ = ["JsonlMemoryPersistence"]


class JsonlMemoryPersistence:
    """Append-only JSON-lines persistence for :class:`~aegis.memory.store.MemoryStore`.

    Args:
        path: The log file. Created on first append if absent; a missing file reads as an
            empty log, which is the correct reading of "nothing has been remembered yet".
        fsync: Whether to ``fsync`` after each append. On by default. Turning it off makes
            writes faster and the durability claim weaker, so it is an explicit choice.
    """

    def __init__(self, path: str | os.PathLike[str], *, fsync: bool = True) -> None:
        self._path = Path(path)
        self._fsync = fsync

    @property
    def path(self) -> Path:
        return self._path

    def load(self) -> Sequence[MemoryRecord]:
        """Every record in file order.

        Raises:
            MemoryIntegrityError: if any line is not a readable record. A damaged log is
                reported, never partially salvaged in silence.
        """
        if not self._path.exists():
            return ()
        records: list[MemoryRecord] = []
        with self._path.open("r", encoding="utf-8") as handle:
            for number, line in enumerate(handle, start=1):
                text = line.strip()
                if not text:
                    continue
                try:
                    records.append(from_json(MemoryRecord, text))
                except Exception as error:
                    raise MemoryIntegrityError(
                        f"{self._path}: line {number} is not a readable memory record "
                        f"({type(error).__name__}); the log is damaged"
                    ) from error
        return tuple(records)

    def append(self, record: MemoryRecord) -> None:
        """Write one record as a single canonical line, flushed and synced.

        Canonical serialization matters here beyond tidiness: the digest was computed over
        the same canonical form, so a record round-trips through the file without its
        integrity check changing.
        """
        self._path.parent.mkdir(parents=True, exist_ok=True)
        line = to_json(record)
        if "\n" in line:
            raise MemoryIntegrityError("canonical record contains a newline")
        with self._path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
            handle.flush()
            if self._fsync:
                os.fsync(handle.fileno())

    def __repr__(self) -> str:
        return f"{type(self).__name__}(path={str(self._path)!r})"
