"""Durable incident workflow state.

The problem this solves
-----------------------

Without durable workflow state, an incident that reaches WAITING_FOR_APPROVAL exists only
in RAM. A process restart — crash, deployment, container eviction — destroys the approval
wait and the incident must restart from scratch. That means:

* A human who approved an action may see it requested again.
* An incident that was partially remediating could re-execute.
* The "execute exactly once" guarantee is per-process, not per-incident.

This module gives each incident a durable identity across restarts. The guarantee is:

    approval_pending → persist → restart → restore → approve → execute exactly once

Duplicate execution prevention
-------------------------------

Every record is append-only. The ``execution_id`` field is set exactly once, when
execution completes. On restore, if ``execution_id`` is already set, the orchestrator
returns the stored execution result rather than executing again. This is the idempotency
key: its presence means "this action ran; do not run it again".

Failure semantics
-----------------

A WorkflowStore that cannot be read fails closed: the service refuses to start rather than
creating a second workflow for an incident that may already have executed.
"""

from __future__ import annotations

import json
import os
from collections.abc import Sequence
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Protocol, runtime_checkable

from aegis.core.domain import DomainModel, NonEmptyStr, utc_now

__all__ = [
    "InMemoryWorkflowStore",
    "JsonlWorkflowStore",
    "WorkflowRecord",
    "WorkflowState",
    "WorkflowStore",
]


class WorkflowState(StrEnum):
    """The durable lifecycle of an incident's workflow."""

    OPEN = "OPEN"
    """The incident is being processed — investigation, delegation, policy check."""

    WAITING_FOR_APPROVAL = "WAITING_FOR_APPROVAL"
    """A proposal was made; the workflow is blocked on a human decision."""

    APPROVED = "APPROVED"
    """A human approved the proposal. Execution has not yet occurred."""

    EXECUTED = "EXECUTED"
    """The action executed exactly once. Execution must not recur."""

    RESOLVED = "RESOLVED"
    """The incident resolved after a verified execution."""

    FAILED = "FAILED"
    """The incident ended without resolution (denied, escalated, model failure, etc.)."""


class WorkflowRecord(DomainModel):
    """The durable state of one incident's workflow.

    Append-only: the store never updates a record. A state transition appends a new record
    with the updated fields. The most recent record for a given ``incident_id`` is the
    current state.
    """

    incident_id: NonEmptyStr
    state: WorkflowState
    recorded_at: datetime

    # Proposal tracking
    proposal_fingerprint: str | None = None
    """Fingerprint of the action pending approval. Set when entering WAITING_FOR_APPROVAL."""

    action_id: str | None = None
    """The action id of the pending/executed action."""

    # Authorization tracking
    authorization_id: str | None = None
    """ID of the ExecutionAuthorization granted by the approval engine."""

    # Execution idempotency key
    execution_id: str | None = None
    """Set exactly once when execution completes. Its presence prevents re-execution."""

    # Outcome tracking
    outcome: str | None = None
    """The OrchestrationOutcome value when the workflow reaches RESOLVED or FAILED."""


@runtime_checkable
class WorkflowStore(Protocol):
    """Durable, append-only storage for incident workflow records."""

    def load_all(self) -> Sequence[WorkflowRecord]:
        """All records, in the order they were appended."""
        ...

    def append(self, record: WorkflowRecord) -> None:
        """Add one record to the end."""
        ...

    def latest_for(self, incident_id: str) -> WorkflowRecord | None:
        """The most recent record for this incident, or None if not found."""
        ...


class InMemoryWorkflowStore:
    """Process-lifetime workflow store. Not durable — for testing and single-request use."""

    def __init__(self) -> None:
        self._records: list[WorkflowRecord] = []

    def load_all(self) -> Sequence[WorkflowRecord]:
        return tuple(self._records)

    def append(self, record: WorkflowRecord) -> None:
        self._records.append(record)

    def latest_for(self, incident_id: str) -> WorkflowRecord | None:
        for record in reversed(self._records):
            if record.incident_id == incident_id:
                return record
        return None

    def all_for(self, incident_id: str) -> list[WorkflowRecord]:
        return [r for r in self._records if r.incident_id == incident_id]

    def __len__(self) -> int:
        return len(self._records)

    def __repr__(self) -> str:
        return f"{type(self).__name__}(records={len(self._records)})"


class JsonlWorkflowStore:
    """File-backed, append-only workflow store. One canonical JSON record per line.

    Durability characteristics:
    * Survives process restart.
    * Append is flushed and fsync'd before returning.
    * A partially-written final line is detected and reported as corruption.
    """

    def __init__(self, path: str | os.PathLike[str], *, fsync: bool = True) -> None:
        self._path = Path(path)
        self._fsync = fsync

    @property
    def path(self) -> Path:
        return self._path

    def load_all(self) -> Sequence[WorkflowRecord]:
        if not self._path.exists():
            return ()
        records: list[WorkflowRecord] = []
        with self._path.open("r", encoding="utf-8") as handle:
            for number, line in enumerate(handle, start=1):
                text = line.strip()
                if not text:
                    continue
                try:
                    data = json.loads(text)
                    records.append(WorkflowRecord.model_validate(data))
                except Exception as error:
                    raise RuntimeError(
                        f"{self._path}: line {number} is not a readable workflow record "
                        f"({type(error).__name__}); the log is damaged"
                    ) from error
        return tuple(records)

    def append(self, record: WorkflowRecord) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        line = record.model_dump_json()
        if "\n" in line:
            raise RuntimeError("canonical record contains a newline")
        with self._path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
            handle.flush()
            if self._fsync:
                os.fsync(handle.fileno())

    def latest_for(self, incident_id: str) -> WorkflowRecord | None:
        records = self.load_all()
        for record in reversed(records):
            if record.incident_id == incident_id:
                return record
        return None

    def all_for(self, incident_id: str) -> list[WorkflowRecord]:
        return [r for r in self.load_all() if r.incident_id == incident_id]

    def __repr__(self) -> str:
        return f"{type(self).__name__}(path={str(self._path)!r})"


# ---------------------------------------------------------------------------
# Helper: open or restore a workflow for one incident
# ---------------------------------------------------------------------------


def open_workflow(
    incident_id: str,
    store: WorkflowStore,
    *,
    clock: object = utc_now,
) -> WorkflowRecord:
    """Return the existing workflow record or create a new OPEN one.

    If an EXECUTED record exists, the returned record reflects that state so
    the caller can skip re-execution.
    """
    existing = store.latest_for(incident_id)
    if existing is not None:
        return existing
    now = clock() if callable(clock) else datetime.now(UTC)
    record = WorkflowRecord(
        incident_id=incident_id,
        state=WorkflowState.OPEN,
        recorded_at=now,
    )
    store.append(record)
    return record


def transition_workflow(
    incident_id: str,
    store: WorkflowStore,
    *,
    state: WorkflowState,
    clock: object = utc_now,
    **fields: object,
) -> WorkflowRecord:
    """Append a new record for ``incident_id`` with the given state and extra fields."""
    now = clock() if callable(clock) else datetime.now(UTC)
    # Pull fields from the latest record as baseline
    latest = store.latest_for(incident_id)
    base: dict = {}
    if latest is not None:
        base = latest.model_dump()
    base.update({"incident_id": incident_id, "state": state, "recorded_at": now})
    base.update({k: v for k, v in fields.items() if v is not None})
    record = WorkflowRecord.model_validate(base)
    store.append(record)
    return record
