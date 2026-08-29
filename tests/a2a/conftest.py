"""Fixtures for the A2A suite: a fixed clock, a real directory, a real broker.

Nothing is mocked that matters. The directory holds the same five agent ids and the same
delegation matrix the orchestrator uses, so a test that passes here is a test about the
configuration AEGIS actually runs.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from aegis.a2a import (
    A2ABroker,
    A2AEnvelope,
    AgentDirectory,
    InMemoryA2ATransport,
    MessageLedger,
    MessageType,
    envelope_seal,
)
from aegis.agents.decisions import TaskType
from aegis.orchestration import DELEGATION_MATRIX

FIXED_NOW = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
INCIDENT = "INC-2026-0001"
CONVERSATION = "conv-INC-2026-0001"
TASK = "task-INC-2026-0001-0"
RESOURCE = "service:payment-api"

FLEET = frozenset({"commander", "diagnostic", "security", "business-impact", "remediation"})

TASK_FOR = {
    "diagnostic": TaskType.DIAGNOSE_SERVICE,
    "security": TaskType.INVESTIGATE_SECURITY,
    "business-impact": TaskType.ASSESS_BUSINESS_IMPACT,
    "remediation": TaskType.PROPOSE_REMEDIATION,
}


class MovableClock:
    """A clock a test can advance deliberately. Never moves on its own."""

    def __init__(self, start: datetime = FIXED_NOW) -> None:
        self.now = start

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> datetime:
        self.now = self.now + timedelta(seconds=seconds)
        return self.now


@pytest.fixture
def clock() -> MovableClock:
    return MovableClock()


@pytest.fixture
def directory() -> AgentDirectory:
    """The real fleet and the real matrix — not a convenient subset."""
    return AgentDirectory(FLEET, DELEGATION_MATRIX)


@pytest.fixture
def transport() -> InMemoryA2ATransport:
    return InMemoryA2ATransport()


@pytest.fixture
def broker(directory: AgentDirectory, transport: InMemoryA2ATransport, clock) -> A2ABroker:
    return A2ABroker(
        directory,
        transport=transport,
        ledger=MessageLedger(clock=clock),
        clock=clock,
    )


def issue(broker: A2ABroker, **overrides) -> A2AEnvelope:
    """One ordinary Commander-to-Diagnostic request, unless overridden."""
    settings = {
        "accountable_sender": "commander",
        "recipient_agent_id": "diagnostic",
        "incident_id": INCIDENT,
        "conversation_id": CONVERSATION,
        "task_id": TASK,
        "task_type": TaskType.DIAGNOSE_SERVICE,
        "message_type": MessageType.TASK_REQUEST,
        "target_resource": RESOURCE,
        "payload": {"note": "please investigate"},
    }
    settings.update(overrides)
    envelope = broker.issue(**settings)
    assert isinstance(envelope, A2AEnvelope), envelope
    return envelope


def admit(broker: A2ABroker, envelope: A2AEnvelope, **overrides):
    """Admit a message with the ordinary expectations, unless overridden."""
    settings = {
        "accountable_sender": "commander",
        "expected_incident_id": INCIDENT,
        "expected_conversation_id": CONVERSATION,
        "expected_task_id": TASK,
    }
    settings.update(overrides)
    return broker.admit(envelope, **settings)


def reseal(envelope: A2AEnvelope, **changes) -> A2AEnvelope:
    """Modify an envelope and recompute its seal.

    The strong form of an attack: the message is not merely tampered with, it is
    *convincingly* tampered with. A test that only ever mangles the seal proves the hash
    works and nothing else.
    """
    changed = envelope.model_copy(update=changes)
    return changed.model_copy(update={"seal": envelope_seal(changed)})
