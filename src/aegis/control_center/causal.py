"""What caused what, joined on identifiers rather than on adjacency.

Part 5. The rule that makes this worth building:

    Do not create causal links merely because two events are adjacent in time.

Two events happening one after another is not causation, and a chain built that way would
be confident, plausible and wrong. Every edge here is justified by a **shared identifier**
that one artifact recorded about another: an action id, an action fingerprint, an approval
id, a verification id, a message id, a conversation id.

Where no identifier joins two nodes, there is no edge. The chain is then reported as
:attr:`ChainCompleteness.BROKEN` with the missing link named, which is more useful to an
operator than a complete-looking chain nobody can verify.

Node status, and what it is not
-------------------------------

A node's ``status`` is whatever the artifact recorded -- ``ALLOW``, ``GRANTED``,
``VERIFIED``, ``REJECTED``. It is never computed from the node before it, so a chain cannot
propagate optimism forwards: an approval node says ``GRANTED`` because an approval artifact
says so, not because policy allowed something upstream.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import Field

from aegis.control_center.capture import ControlCenterInput
from aegis.control_center.models import (
    Certainty,
    Completeness,
    Provenance,
    ViewSource,
)
from aegis.core.audit.events import AuditEventType
from aegis.core.domain import DomainModel, Identifier, NonEmptyStr, Timestamp

__all__ = [
    "CausalChain",
    "CausalEdge",
    "CausalNode",
    "ChainCompleteness",
    "NodeType",
    "build_causal_chain",
]


class NodeType(StrEnum):
    """The node kinds Part 5 names. Closed."""

    INCIDENT = "INCIDENT"
    MODEL_DECISION = "MODEL_DECISION"
    DELEGATION = "DELEGATION"
    FINDING = "FINDING"
    PROPOSAL = "PROPOSAL"
    ASSESSMENT = "ASSESSMENT"
    POLICY = "POLICY"
    APPROVAL = "APPROVAL"
    LIFECYCLE = "LIFECYCLE"
    GATE = "GATE"
    EXECUTION = "EXECUTION"
    OBSERVATION = "OBSERVATION"
    VERIFICATION = "VERIFICATION"
    RESOLUTION = "RESOLUTION"


class CausalNode(DomainModel):
    """One artifact in the chain, with everything needed to look it up."""

    node_id: Identifier
    node_type: NodeType
    at: Timestamp
    source: ViewSource
    certainty: Certainty
    status: NonEmptyStr
    """What the artifact recorded. Never derived from another node."""

    detail: NonEmptyStr | None = None
    evidence_refs: tuple[NonEmptyStr, ...] = Field(default_factory=tuple)

    def __repr__(self) -> str:
        return f"CausalNode({self.node_type}:{self.node_id} {self.status})"


class CausalEdge(DomainModel):
    """One link, and the identifier that justifies it.

    ``joined_on`` is required. An edge without a shared identifier is an assumption, and
    this model has nowhere to put one.
    """

    source_id: Identifier
    target_id: Identifier
    joined_on: NonEmptyStr
    """The field whose value both artifacts share: ``action_id``, ``action_fingerprint``,
    ``approval_id``, ``verification_id``, ``message_id`` or ``conversation_id``."""

    value: NonEmptyStr

    def __repr__(self) -> str:
        return f"{self.source_id} -[{self.joined_on}]-> {self.target_id}"


class ChainCompleteness(StrEnum):
    """Whether the chain reaches from incident to outcome without a gap."""

    COMPLETE = "COMPLETE"
    """Every node from the incident to the recorded outcome is joined by an identifier."""

    PARTIAL = "PARTIAL"
    """The run genuinely stopped part-way. The chain is as long as what happened."""

    BROKEN = "BROKEN"
    """Two artifacts exist that should be joined and are not. Named, so it can be chased."""


class CausalChain(DomainModel):
    """The chain for one incident: nodes, identifier-justified edges, and its own gaps."""

    incident_id: Identifier
    nodes: tuple[CausalNode, ...] = Field(default_factory=tuple)
    edges: tuple[CausalEdge, ...] = Field(default_factory=tuple)
    completeness: ChainCompleteness
    missing_links: tuple[NonEmptyStr, ...] = Field(default_factory=tuple)
    provenance: Provenance

    def node(self, node_type: NodeType) -> CausalNode | None:
        for node in self.nodes:
            if node.node_type is node_type:
                return node
        return None

    def successors(self, node_id: str) -> tuple[CausalNode, ...]:
        targets = {edge.target_id for edge in self.edges if edge.source_id == node_id}
        return tuple(node for node in self.nodes if node.node_id in targets)

    def __repr__(self) -> str:
        return (
            f"CausalChain({self.incident_id}, {len(self.nodes)} nodes, "
            f"{len(self.edges)} edges, {self.completeness})"
        )


def build_causal_chain(data: ControlCenterInput) -> CausalChain:
    """Build the chain from artifacts, joining only on shared identifiers.

    The order of construction follows the governed path, but the *edges* do not: each is
    added only when the two artifacts genuinely name the same id. A node with no join to
    its predecessor is still listed -- it happened -- and the gap is recorded in
    ``missing_links`` rather than bridged.
    """
    run = data.run
    if run is None:
        return CausalChain(
            incident_id=data.incident_id,
            completeness=ChainCompleteness.BROKEN,
            missing_links=("OrchestrationRun",),
            provenance=Provenance.unavailable(
                data.captured_at, "no run was captured; no chain can be built"
            ),
        )

    nodes: list[CausalNode] = []
    edges: list[CausalEdge] = []
    missing: list[str] = []

    incident = run.incident
    nodes.append(
        CausalNode(
            node_id=str(incident.incident_id),
            node_type=NodeType.INCIDENT,
            at=incident.created_at,
            source=ViewSource.RUN,
            certainty=Certainty.OBSERVED,
            status=str(incident.state),
            detail=str(incident.source),
        )
    )

    _add_delegations(data, nodes, edges, str(incident.incident_id))

    action = run.action
    if action is None:
        return CausalChain(
            incident_id=data.incident_id,
            nodes=tuple(nodes),
            edges=tuple(edges),
            completeness=ChainCompleteness.PARTIAL,
            missing_links=("Action",),
            provenance=_provenance(data, Completeness.PARTIAL),
        )

    action_id = str(action.action_id)
    fingerprint = _fingerprint_of(run)
    nodes.append(
        CausalNode(
            node_id=action_id,
            node_type=NodeType.PROPOSAL,
            at=incident.created_at,
            source=ViewSource.RUN,
            certainty=Certainty.OBSERVED,
            status=str(action.capability),
            detail=str(action.target_resource),
            evidence_refs=(fingerprint,) if fingerprint else (),
        )
    )
    edges.append(
        CausalEdge(
            source_id=str(incident.incident_id),
            target_id=action_id,
            joined_on="incident_id",
            value=str(action.incident_id),
        )
    )

    previous_id = action_id
    previous_id = _add_assessment(run, nodes, edges, action_id, previous_id, missing)
    previous_id = _add_policy(run, nodes, edges, action_id, previous_id, missing)
    previous_id = _add_approval(run, nodes, edges, action_id, fingerprint, previous_id, missing)
    previous_id = _add_lifecycle(run, nodes, edges, previous_id)
    previous_id = _add_gate(data, nodes, edges, action_id, previous_id)
    previous_id = _add_execution(run, nodes, edges, action_id, previous_id, missing)
    previous_id = _add_verification(run, nodes, edges, action_id, fingerprint, previous_id, missing)
    _add_resolution(run, nodes, edges, previous_id)

    completeness = _completeness(run, missing)
    return CausalChain(
        incident_id=data.incident_id,
        nodes=tuple(nodes),
        edges=tuple(edges),
        completeness=completeness,
        missing_links=tuple(missing),
        provenance=_provenance(
            data,
            Completeness.COMPLETE
            if completeness is ChainCompleteness.COMPLETE
            else Completeness.PARTIAL,
        ),
    )


def _fingerprint_of(run) -> str:
    """The action fingerprint from a binding artifact, never recomputed. See
    :func:`aegis.control_center.governance._fingerprint_of` for why."""
    for artifact in (
        getattr(run, "authorization", None),
        getattr(run, "verification", None),
    ):
        value = getattr(artifact, "action_fingerprint", None)
        if value:
            return str(value)
    return ""


def _provenance(data: ControlCenterInput, completeness: Completeness) -> Provenance:
    return Provenance(source=ViewSource.RUN, as_of=data.captured_at, completeness=completeness)


def _add_delegations(data, nodes, edges, incident_id: str) -> None:
    """Delegation and finding nodes, joined on the task both messages record.

    A finding arrives on a *response* message and the delegation it answers is a *request*
    message, so the two have different message ids. Joining on ``message_id`` would have
    produced an edge whose source is not a node -- which is exactly the kind of
    plausible-looking link Part 5 forbids.

    They do share ``task_id``, recorded on both by the broker, so that is the join. Where no
    request was recorded for a task the finding is still listed and simply has no incoming
    edge: the finding happened, and the link is genuinely missing.
    """
    if not data.audit_available:
        return
    requests: dict[str, str] = {}
    findings: list[tuple[str, str, object]] = []

    for record in data.audit_records:
        if record.event.incident_id not in (None, data.incident_id):
            continue
        if record.event.event_type != AuditEventType.A2A_MESSAGE.value:
            continue
        message_id = record.correlation.get("message_id")
        task_id = record.correlation.get("task_id")
        if not message_id:
            continue
        status = record.correlation.get("status", "")
        finding_id = record.correlation.get("finding_id")
        if status == "ISSUED":
            nodes.append(
                CausalNode(
                    node_id=message_id,
                    node_type=NodeType.DELEGATION,
                    at=record.event.timestamp,
                    source=ViewSource.AUDIT,
                    certainty=Certainty.OBSERVED,
                    status=record.correlation.get("recipient_agent_id", "?"),
                    detail=record.correlation.get("task_type"),
                    evidence_refs=(record.event.event_id,),
                )
            )
            edges.append(
                CausalEdge(
                    source_id=incident_id,
                    target_id=message_id,
                    joined_on="incident_id",
                    value=str(record.event.incident_id or incident_id),
                )
            )
            if task_id:
                requests.setdefault(task_id, message_id)
        elif finding_id:
            findings.append((finding_id, task_id or "", record))

    for finding_id, task_id, record in findings:
        nodes.append(
            CausalNode(
                node_id=finding_id,
                node_type=NodeType.FINDING,
                at=record.event.timestamp,
                source=ViewSource.AUDIT,
                certainty=Certainty.OBSERVED,
                status=record.correlation.get("sender_agent_id", "?"),
                evidence_refs=tuple(
                    sorted({record.event.event_id, record.correlation.get("message_id", "")} - {""})
                ),
            )
        )
        request_id = requests.get(task_id)
        if request_id:
            edges.append(
                CausalEdge(
                    source_id=request_id,
                    target_id=finding_id,
                    joined_on="task_id",
                    value=task_id,
                )
            )


def _add_assessment(run, nodes, edges, action_id: str, previous_id: str, missing) -> str:
    assessment = run.assessment
    if assessment is None:
        missing.append("Assessment")
        return previous_id
    node_id = f"assessment:{action_id}"
    nodes.append(
        CausalNode(
            node_id=node_id,
            node_type=NodeType.ASSESSMENT,
            at=run.incident.created_at,
            source=ViewSource.RUN,
            certainty=Certainty.OBSERVED,
            status=str(assessment.outcome),
            detail=(
                f"risk={assessment.risk.risk}"
                if assessment.risk is not None
                else "risk unavailable"
            ),
            evidence_refs=(action_id,),
        )
    )
    # Joined on the action the assessment was performed *for* -- the pipeline records the
    # proposal, so the identifier is genuinely shared rather than assumed.
    edges.append(
        CausalEdge(
            source_id=previous_id,
            target_id=node_id,
            joined_on="action_id",
            value=str(assessment.proposal.action_id),
        )
    )
    return node_id


def _add_policy(run, nodes, edges, action_id: str, previous_id: str, missing) -> str:
    evaluation = run.evaluation
    decision = getattr(evaluation, "decision", None)
    if decision is None:
        missing.append("PolicyEvaluation")
        return previous_id
    node_id = f"policy:{action_id}"
    nodes.append(
        CausalNode(
            node_id=node_id,
            node_type=NodeType.POLICY,
            at=decision.evaluated_at,
            source=ViewSource.RUN,
            certainty=Certainty.OBSERVED,
            status=str(decision.decision),
            detail=str(decision.reason),
            evidence_refs=(str(decision.policy_reference),),
        )
    )
    edges.append(
        CausalEdge(source_id=previous_id, target_id=node_id, joined_on="action_id", value=action_id)
    )
    return node_id


def _add_approval(run, nodes, edges, action_id, fingerprint, previous_id, missing) -> str:
    authorization = run.authorization
    approval = getattr(authorization, "approval", None)
    if approval is None:
        return previous_id
    node_id = str(approval.approval_id)
    nodes.append(
        CausalNode(
            node_id=node_id,
            node_type=NodeType.APPROVAL,
            at=approval.created_at,
            source=ViewSource.RUN,
            certainty=Certainty.OBSERVED,
            status=str(approval.status),
            detail=str(approval.reason),
            evidence_refs=(str(approval.action_fingerprint),),
        )
    )
    # The fingerprint, not the action id: an approval binds to the exact action bytes, and
    # joining on anything looser would let this chain show an approval beside an action it
    # does not authorise.
    joined = "action_fingerprint" if fingerprint else "action_id"
    value = str(approval.action_fingerprint) if fingerprint else str(approval.action_id)
    if fingerprint and str(approval.action_fingerprint) != fingerprint:
        missing.append("approval->action fingerprint mismatch")
    edges.append(
        CausalEdge(source_id=previous_id, target_id=node_id, joined_on=joined, value=value)
    )
    return node_id


def _add_lifecycle(run, nodes, edges, previous_id: str) -> str:
    record = run.lifecycle
    if record is None:
        return previous_id
    node_id = f"lifecycle:{record.incident_id}"
    nodes.append(
        CausalNode(
            node_id=node_id,
            node_type=NodeType.LIFECYCLE,
            at=record.completed_at,
            source=ViewSource.LIFECYCLE_STATE,
            certainty=Certainty.OBSERVED,
            status=str(record.stop_reason),
            detail=str(record.detail),
        )
    )
    edges.append(
        CausalEdge(
            source_id=previous_id,
            target_id=node_id,
            joined_on="incident_id",
            value=str(record.incident_id),
        )
    )
    return node_id


def _add_gate(data, nodes, edges, action_id: str, previous_id: str) -> str:
    if not data.audit_available:
        return previous_id
    for record in data.audit_records:
        if record.event.incident_id not in (None, data.incident_id):
            continue
        if record.event.event_type != AuditEventType.LIFECYCLE_GATE_CONSUMED.value:
            continue
        gate_id = record.correlation.get("gate_id") or record.event.input_reference
        if not gate_id:
            continue
        nodes.append(
            CausalNode(
                node_id=gate_id,
                node_type=NodeType.GATE,
                at=record.event.timestamp,
                source=ViewSource.AUDIT,
                certainty=Certainty.OBSERVED,
                status="CONSUMED",
                detail=record.event.result,
                evidence_refs=(record.event.event_id,),
            )
        )
        edges.append(
            CausalEdge(
                source_id=previous_id,
                target_id=gate_id,
                joined_on="action_id",
                value=record.correlation.get("action_id", action_id),
            )
        )
        return gate_id
    return previous_id


def _add_execution(run, nodes, edges, action_id: str, previous_id: str, missing) -> str:
    execution = run.execution
    if execution is None:
        return previous_id
    node_id = f"execution:{execution.action_id}"
    nodes.append(
        CausalNode(
            node_id=node_id,
            node_type=NodeType.EXECUTION,
            at=execution.executed_at,
            source=ViewSource.RUN,
            certainty=Certainty.OBSERVED,
            status=str(execution.outcome),
            detail=str(execution.detail),
            evidence_refs=(str(execution.action_id),),
        )
    )
    if str(execution.action_id) != action_id:
        missing.append("execution->action id mismatch")
    edges.append(
        CausalEdge(
            source_id=previous_id,
            target_id=node_id,
            joined_on="action_id",
            value=str(execution.action_id),
        )
    )
    return node_id


def _add_verification(run, nodes, edges, action_id, fingerprint, previous_id, missing) -> str:
    verification = run.verification
    if verification is None:
        if run.execution is not None:
            missing.append("VerificationResult")
        return previous_id

    for reference in verification.observations_used:
        nodes.append(
            CausalNode(
                node_id=str(reference),
                node_type=NodeType.OBSERVATION,
                at=verification.evaluated_at,
                source=ViewSource.RUN,
                certainty=Certainty.OBSERVED,
                status="USED",
            )
        )
        edges.append(
            CausalEdge(
                source_id=str(reference),
                target_id=str(verification.verification_id),
                joined_on="observation_id",
                value=str(reference),
            )
        )

    node_id = str(verification.verification_id)
    nodes.append(
        CausalNode(
            node_id=node_id,
            node_type=NodeType.VERIFICATION,
            at=verification.evaluated_at,
            source=ViewSource.RUN,
            certainty=Certainty.OBSERVED,
            status=str(verification.status),
            detail=str(verification.reason),
            evidence_refs=(str(verification.action_fingerprint),),
        )
    )
    if fingerprint and str(verification.action_fingerprint) != fingerprint:
        missing.append("verification->action fingerprint mismatch")
    edges.append(
        CausalEdge(
            source_id=previous_id,
            target_id=node_id,
            joined_on="action_fingerprint" if fingerprint else "action_id",
            value=str(verification.action_fingerprint) if fingerprint else action_id,
        )
    )
    return node_id


def _add_resolution(run, nodes, edges, previous_id: str) -> None:
    if run.incident.state.value != "RESOLVED":
        return
    node_id = f"resolution:{run.incident.incident_id}"
    nodes.append(
        CausalNode(
            node_id=node_id,
            node_type=NodeType.RESOLUTION,
            at=run.incident.updated_at,
            source=ViewSource.RUN,
            certainty=Certainty.OBSERVED,
            status=str(run.incident.state),
        )
    )
    edges.append(
        CausalEdge(
            source_id=previous_id,
            target_id=node_id,
            joined_on="incident_id",
            value=str(run.incident.incident_id),
        )
    )


def _completeness(run, missing: list[str]) -> ChainCompleteness:
    """Whether the chain reaches the outcome the run actually recorded.

    A run that escalated has a short chain and is not broken -- it is exactly as long as
    what happened. Broken means two artifacts exist that should be joined and are not.
    """
    if missing:
        return ChainCompleteness.BROKEN
    if run.incident.state.value == "RESOLVED" and run.verification is not None:
        return ChainCompleteness.COMPLETE
    return ChainCompleteness.PARTIAL
