"""The operator control center (Prompt 18): observability that creates no authority.

    The control center is not an authorization system.
    The control center cannot grant authority.
    Displayed state is derived from recorded artifacts.
    Missing evidence is UNKNOWN.
    Audit corruption is surfaced, not repaired.
    UI state cannot override deterministic governance.

Those six lines are the whole contract. Everything below serves them.

What this package is
--------------------

A **read model**. It answers the questions an operator has to be able to ask -- what is
AEGIS doing, why did it do that, why did it refuse that, is an approval waiting, is a
breaker open, can I reconstruct the causal chain -- from artifacts that were already
recorded, and from nothing else.

    capture.py       the only module that touches a live object; produces a frozen value
    models.py        Tri, Certainty, Provenance -- the vocabulary of "we do not know"
    timeline.py      what happened, in order, with gaps left as gaps
    causal.py        what caused what, joined on identifiers rather than on adjacency
    governance.py    the governed path, the approval binding, and "why did AEGIS do this?"
    agents.py        capability vs proposal authority vs current restriction, kept apart
    lifecycle.py     counters, stop reason, breaker state
    memory.py        historical context, labelled as such and never as current state
    a2a.py           messages, five statuses, and not one byte of key material
    security.py      detections and refusals, which are not the same thing
    projection.py    the assembled view an operator holds
    search.py        narrowing, never widening
    export.py        the deterministic forensic document

Why it cannot create authority
------------------------------

By construction, not by discipline. :func:`~aegis.control_center.capture.capture_incident`
produces a frozen :class:`~aegis.control_center.capture.ControlCenterInput`, and every view
is a pure function of that value. Downstream of capture there is no engine, no store, no
registry and no broker -- **there is no object here that could be asked to do anything.**

Structural tests assert the rest: no module imports a policy engine, an approval engine, an
executor, a verification engine, a memory store, an A2A broker, a gate register or an
orchestrator; there is no ``eval``, ``exec``, ``subprocess``, dynamic import, socket or
credential anywhere in the package; and no function name here contains ``approve``,
``execute``, ``authorize``, ``reset``, ``override`` or ``force``.

Operator actions (Part 21)
--------------------------

There is no admin override, no force-approve, no force-execute, no breaker reset and no
agent release. If an operator interaction is needed it must map onto an existing governed
capability and go through the engine that owns it. A view is where you see that an approval
is waiting; it is not where you grant one.

What "read-only" does not mean
------------------------------

It does not mean safe to expose. This package renders identifiers, decisions and reasons,
and an incident's contents can be sensitive. There is no operator authentication here and
none is claimed -- Part 31 rules it out of scope, and ``docs/CONTROL_CENTER.md`` says so
rather than leaving a reader to assume otherwise.
"""

from aegis.control_center.a2a import A2AMessageView, A2AView, build_a2a
from aegis.control_center.agents import AgentActivity, AgentView, build_agents
from aegis.control_center.capture import AgentProfile, ControlCenterInput, capture_incident
from aegis.control_center.causal import (
    CausalChain,
    CausalEdge,
    CausalNode,
    ChainCompleteness,
    NodeType,
    build_causal_chain,
)
from aegis.control_center.errors import ControlCenterError, UnknownIncident
from aegis.control_center.export import (
    EXPORT_FORMAT_VERSION,
    FORBIDDEN_CONTENT,
    IncidentExport,
    export_incident,
    export_json,
)
from aegis.control_center.governance import (
    ApprovalView,
    Explanation,
    ExplanationOutcome,
    GovernanceView,
    Question,
    VerificationView,
    build_approvals,
    build_governance,
    build_verification,
    explain,
)
from aegis.control_center.lifecycle import (
    BreakerView,
    LifecycleView,
    build_breakers,
    build_lifecycle,
)
from aegis.control_center.memory import (
    HISTORICAL_CONTEXT_LABEL,
    MemoryEntryView,
    MemoryView,
    build_memory,
)
from aegis.control_center.models import (
    AuditIntegrityView,
    AuditTrust,
    Certainty,
    Completeness,
    Fact,
    Provenance,
    Tri,
    ViewSource,
)
from aegis.control_center.projection import (
    ControlCenter,
    IncidentProjection,
    IncidentSummary,
    ProjectionStatus,
    project_incident,
)
from aegis.control_center.search import (
    UNKNOWABLE_FIELDS,
    IncidentQuery,
    search,
    unknown_for,
)
from aegis.control_center.security import (
    SecurityCategory,
    SecurityEvent,
    SecurityOutcome,
    SecurityView,
    build_security,
)
from aegis.control_center.timeline import (
    IncidentTimeline,
    Phase,
    PhaseSummary,
    TimelineEntry,
    build_timeline,
)

__all__ = [
    "EXPORT_FORMAT_VERSION",
    "FORBIDDEN_CONTENT",
    "HISTORICAL_CONTEXT_LABEL",
    "UNKNOWABLE_FIELDS",
    "A2AMessageView",
    "A2AView",
    "AgentActivity",
    "AgentProfile",
    "AgentView",
    "ApprovalView",
    "AuditIntegrityView",
    "AuditTrust",
    "BreakerView",
    "CausalChain",
    "CausalEdge",
    "CausalNode",
    "Certainty",
    "ChainCompleteness",
    "Completeness",
    "ControlCenter",
    "ControlCenterError",
    "ControlCenterInput",
    "Explanation",
    "ExplanationOutcome",
    "Fact",
    "GovernanceView",
    "IncidentExport",
    "IncidentProjection",
    "IncidentQuery",
    "IncidentSummary",
    "IncidentTimeline",
    "LifecycleView",
    "MemoryEntryView",
    "MemoryView",
    "NodeType",
    "Phase",
    "PhaseSummary",
    "ProjectionStatus",
    "Provenance",
    "Question",
    "SecurityCategory",
    "SecurityEvent",
    "SecurityOutcome",
    "SecurityView",
    "TimelineEntry",
    "Tri",
    "UnknownIncident",
    "VerificationView",
    "ViewSource",
    "build_a2a",
    "build_agents",
    "build_approvals",
    "build_breakers",
    "build_causal_chain",
    "build_governance",
    "build_lifecycle",
    "build_memory",
    "build_security",
    "build_timeline",
    "build_verification",
    "capture_incident",
    "explain",
    "export_incident",
    "export_json",
    "project_incident",
    "search",
    "unknown_for",
]
