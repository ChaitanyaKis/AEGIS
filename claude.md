# AEGIS — Autonomous Enterprise Agent Command & Governance Fleet

## Project Identity

**Project:** AEGIS  
**Full Name:** Autonomous Enterprise Agent Command & Governance Fleet  
**Hackathon Track:** The Fortified Enterprise Fleet  
**Build Window:** 7 days  
**Primary Platform:** Gemini Enterprise Agent Platform (GEAP)  
**Development Framework:** Google Agent Development Kit (ADK)  
**Primary Demonstration:** Autonomous enterprise incident-response fleet  

---

# 1. NORTH STAR

AEGIS is a **governed control plane for autonomous enterprise agent fleets**.

The incident-response environment is the proving ground, not the product itself.

The long-term product is a general-purpose enterprise control plane capable of:

- discovering agents
- identifying agents
- coordinating agents
- authorizing capabilities
- enforcing policy
- protecting against hostile inputs
- controlling risk
- managing human approvals
- observing autonomous execution
- evaluating agents
- recovering from failures
- learning verified organizational knowledge
- restricting/quarantining agents
- managing agent lifecycle

The core thesis:

> **Autonomy should increase organizational capability without decreasing organizational control.**

---

# 2. FUNDAMENTAL ENGINEERING LAW

This rule is NON-NEGOTIABLE:

> **LLMs propose. Deterministic systems authorize. Tools execute. Verification establishes truth.**

The LLM must NEVER be the final authority for:

- authorization
- security decisions
- policy decisions
- capability grants
- production mutation
- human approval
- state-transition authority
- explicit DENY overrides
- declaring an incident resolved without verification

An agent may propose an action.

AEGIS must independently determine whether that action is allowed.

---

# 3. ARCHITECTURE

AEGIS consists of:

```text
AEGIS CONTROL PLANE
│
├── Agent Registry Adapter
├── Capability Registry
├── Policy Engine
├── Risk Engine
├── Blast-Radius Engine
├── Approval Engine
├── Incident State Machine
├── Agent Lifecycle Manager
├── Circuit Breaker
├── Verification Engine
├── Audit/Event Store
└── Evaluation Harness

AGENT PLANE
│
├── Commander
├── Diagnostic
├── Security
├── Business Impact
└── Remediation

GOOGLE PLATFORM
│
├── Gemini
├── ADK
├── Agent Runtime
├── Agent Registry
├── Agent Identity
├── Agent Gateway
├── Model Armor
├── Memory Bank
├── Agent Observability
└── Evaluation

SIMULATED ENTERPRISE
│
├── Services
├── Telemetry
├── Logs
├── Deployments
├── Customers
├── Security Events
├── Dependencies
└── Controlled Production Actions
```

Keep the control plane conceptually separate from agent reasoning.

---

# 4. TRUST MODEL

AEGIS has five trust zones.

### Zone A — Untrusted External Input

Examples:

- incident payloads
- external messages
- third-party content
- potentially malicious tool output

Treat these as DATA.

Never automatically interpret them as instructions.

### Zone B — Agent Reasoning

LLM-generated plans, findings and proposals.

Useful for reasoning.

NOT authoritative.

### Zone C — AEGIS Control Plane

Policy, authorization, risk, capability, lifecycle and approval.

Authoritative.

### Zone D — Enterprise Resources

Synthetic enterprise services and protected resources.

Must only be accessed through governed capabilities.

### Zone E — Human Authority

Human approval for designated high-impact operations.

---

# 5. CONTROL-PLANE PRINCIPLES

## Deterministic Governance

Policy decisions must be deterministic wherever possible.

Valid decisions:

```text
ALLOW
DENY
REQUIRE_APPROVAL
```

Policy precedence:

```text
DENY
  >
REQUIRE_APPROVAL
  >
ALLOW
```

An explicit DENY can never be overridden by an LLM.

Human approval does not override hard security/policy constraints.

---

# 6. CAPABILITY-BASED AUTHORITY

Capabilities are explicit.

Examples:

```text
telemetry.read
logs.read
deployment.read
security.read
customer-impact.read

production.restart
production.rollback
production.scale
production.disable-route
customer.notify
incident.update
```

Every capability should have metadata describing:

```text
capability_id
risk_class
resource_scope
data_classification
reversibility
approval_requirement
allowed_agents
```

Agents receive least privilege.

---

# 7. INITIAL AGENT FLEET

## Commander

Purpose:

- incident classification
- memory retrieval
- agent discovery
- delegation
- evidence synthesis
- action proposal
- workflow coordination
- verification coordination
- verified memory update

Commander MUST NOT directly perform production mutation.

---

## Diagnostic

Purpose:

- logs
- metrics
- deployment correlation
- dependency inspection
- technical diagnosis

Primarily read-only.

No production mutation.

---

## Security

Purpose:

- security-event analysis
- suspicious input analysis
- attack indicators
- compromise assessment
- containment recommendation

No production mutation.

---

## Business Impact

Purpose:

- customer impact
- service impact
- SLA impact
- business severity
- downstream impact

No production mutation.

---

## Remediation

Purpose:

- propose remediation
- execute authorized remediation
- verify remediation
- stop when verification fails

This is the most privileged initial agent.

It MUST NOT:

- grant itself capabilities
- modify policy
- modify identity
- bypass approval
- override DENY
- access unrelated resources
- export customer data

---

# 8. INCIDENT STATE MACHINE

Normal path:

```text
RECEIVED
 ↓
CLASSIFIED
 ↓
INVESTIGATING
 ↓
IMPACT_ASSESSED
 ↓
PLAN_PROPOSED
 ↓
POLICY_CHECK
 ↓
AWAITING_APPROVAL
 ↓
EXECUTING
 ↓
VERIFYING
 ↓
RESOLVED
```

Recovery path:

```text
ANY STATE
 ↓
DEGRADED
 ↓
RECOVERING
 ↓
CONTINUE / ESCALATE
```

Terminal state:

```text
ESCALATED
```

State transitions must be deterministic and auditable.

---

# 9. AGENT LIFECYCLE

```text
REGISTERED
 ↓
EVALUATING
 ↓
SANDBOXED
 ↓
APPROVED
 ↓
CANARY
 ↓
ACTIVE
 ↓
RESTRICTED
 ↓
QUARANTINED
 ↓
RETIRED
```

Do not automatically grant production authority to newly registered agents.

---

# 10. CIRCUIT BREAKER

AEGIS must be able to stop agents exhibiting abnormal behavior.

Potential triggers:

- excessive tool calls
- execution timeout
- policy violations
- unexpected destinations
- excessive spend
- repeated failures
- unexpected capability requests
- security events

Response:

```text
STOP
 ↓
RESTRICT / REVOKE
 ↓
PRESERVE TRACE
 ↓
ESCALATE
 ↓
RECOVER / REPLACE
```

---

# 11. VERIFICATION

Never equate:

```text
tool returned success
```

with:

```text
operation succeeded
```

For production-changing actions:

```text
PROPOSE
 ↓
AUTHORIZE
 ↓
EXECUTE
 ↓
VERIFY
 ↓
ESTABLISH ACTUAL STATE
```

An incident can only become `RESOLVED` after verification establishes that the desired enterprise state actually exists.

---

# 12. MEMORY

Persistent memory represents organizational knowledge.

Examples:

- historical incidents
- verified root causes
- successful remediation
- operational patterns
- service dependencies
- lessons learned

Memory must have provenance.

Conceptually:

```text
memory
source
evidence
timestamp
scope
confidence
revision
```

Do NOT blindly write arbitrary LLM-generated statements into persistent organizational memory.

Only verified outcomes should become authoritative operational knowledge.

---

# 13. SECURITY

AEGIS must explicitly defend against:

- prompt injection
- tool poisoning
- memory poisoning
- privilege escalation
- data exfiltration
- unauthorized tool usage
- rogue agents
- runaway execution
- malicious external inputs

External content is never automatically authoritative.

Where available, use Google Model Armor and relevant GEAP security mechanisms.

Do not claim that AEGIS built Google-managed security products.

---

# 14. SIMULATED ENTERPRISE

The hackathon environment is synthetic and deterministic.

Initial services:

```text
API Gateway
 ├── Auth Service
 ├── Payment API
 │    └── Payment DB
 ├── Order Service
 │    └── Order DB
 └── Notification Service
```

Synthetic enterprise data may include:

- services
- deployments
- telemetry
- logs
- customers
- dependencies
- security events

Production mutations are simulated.

Never use real customer data.

---

# 15. CONTROLLED FAILURE INJECTION

The simulation should support deterministic faults such as:

```text
diagnostic_agent_down
tool_timeout
tool_500
stale_telemetry
malicious_payload
unauthorized_request
rollback_failure
verification_failure
memory_conflict
```

Failure injection is part of the product demonstration and evaluation system.

---

# 16. GOLDEN INCIDENT

The primary demonstration is:

```text
Payment API error rate = 37%
Recent deployment = v4.8
```

Expected lifecycle:

```text
Incident
 ↓
Commander
 ↓
Agent discovery
 ↓
Memory retrieval
 ↓
Diagnostic + Security + Impact
 ↓
Malicious payload detected
 ↓
Security block
 ↓
Agent failure
 ↓
Recovery
 ↓
Rollback proposal
 ↓
Risk + blast-radius analysis
 ↓
REQUIRE_APPROVAL
 ↓
Human approval
 ↓
Remediation
 ↓
Verification
 ↓
RESOLVED
 ↓
Verified memory update
 ↓
Unauthorized capability request
 ↓
DENY
 ↓
Agent restriction/quarantine
```

This scenario must be reproducible.

---

# 17. ANTI-HALLUCINATION RULE

Every capability in the project belongs to exactly one category:

### REAL PLATFORM INTEGRATION

A real Google/platform capability is actually configured and demonstrable.

### AEGIS IMPLEMENTATION

The capability is implemented by this project.

### CONTROLLED SIMULATION

The behavior is deliberately synthetic and reproducible.

Never blur these categories.

Never fabricate platform integrations.

Never claim a preview feature is available until it has been verified in the actual project environment.

Never invent metrics.

Never invent successful integration.

---

# 18. GOOGLE PLATFORM INTEGRATION RULE

Prefer real Google-managed capabilities where they materially strengthen AEGIS.

However:

> **The project must not become dependent on an unverified preview capability.**

Use abstraction boundaries.

Conceptually:

```text
AgentRegistry
 ├── Google Registry Adapter
 └── Local fallback

Policy
 ├── Google governance integration
 └── AEGIS deterministic policy

Security
 ├── Model Armor
 └── AEGIS deterministic safety controls

Observability
 ├── Google Agent Observability
 └── AEGIS audit events

Memory
 ├── Memory Bank
 └── AEGIS memory abstraction
```

The fallback is for engineering resilience, not for pretending a Google integration exists.

---

# 19. OBSERVABILITY

Expose auditable execution state.

Examples:

- incident state
- agent activity
- tool calls
- policy decisions
- approvals
- failures
- recovery
- security events
- memory operations
- verification
- final outcome

Do NOT expose or claim access to private model chain-of-thought.

Expose concise reasoning summaries, evidence references and decisions instead.

---

# 20. AUDITABILITY

Material events must generate audit records.

Conceptual schema:

```text
event_id
timestamp
actor
agent_identity
incident_id
event_type
input_reference
decision
policy_reference
tool
result
state_before
state_after
evidence
```

Audit events should be append-only/immutable at the application level.

---

# 21. EVALUATION

AEGIS must be evaluated, not merely demonstrated.

Target benchmark:

**60–100 scenarios**, optimized for coverage rather than raw count.

Scenario families:

- normal incidents
- memory
- security
- authorization
- failure recovery
- complex/cascading failures

Critical metrics:

- routing accuracy
- tool accuracy
- governance accuracy
- security detection rate
- recovery rate
- state correctness
- resolution rate
- false autonomy rate
- false denial rate
- verification correctness
- latency
- cost

Most important safety metric:

> **Unauthorized high-impact actions executed: 0**

The benchmark must be capable of proving AEGIS wrong.

---

# 22. TESTING PHILOSOPHY

Tests are not optional.

Every security boundary must have negative tests.

Examples:

```text
Diagnostic cannot rollback
Diagnostic cannot scale production
Unknown agent denied
Unknown capability denied
Out-of-scope resource denied
Hard deny cannot be overridden
High-risk action requires approval
Approval cannot authorize a prohibited action
Unverified remediation cannot resolve incident
External instructions cannot become policy
Untrusted content cannot directly modify memory
Quarantined agent cannot execute privileged actions
```

Prefer deterministic unit/integration tests for governance over LLM-based assertions.

---

# 23. DEVELOPMENT PRIORITY

Build in this order:

```text
1. Domain contracts
2. Deterministic core
3. Simulated enterprise
4. Policy engine
5. Incident state machine
6. Verification engine
7. Audit system
8. Commander
9. Specialist agents
10. Google platform integrations
11. Memory
12. Security
13. Failure recovery
14. Control Center
15. Evaluation benchmark
16. Final demo
```

Do NOT begin with UI.

Do NOT begin with five autonomous agents.

Do NOT begin with decorative features.

---

# 24. ENGINEERING STYLE

Prefer:

- simple architecture
- explicit contracts
- typed models
- deterministic behavior
- structured outputs
- small modules
- dependency inversion around external platforms
- comprehensive tests
- reproducible simulation

Avoid:

- unnecessary microservices
- giant abstractions
- hidden global state
- hardcoded agent conversations
- unrestricted tool access
- direct agent-to-production access
- LLM-controlled authorization
- arbitrary persistent memory
- fake integrations
- fake metrics

---

# 25. SEVEN-DAY PRIORITY

### Day 1

Foundation + domain contracts + deterministic core.

### Day 2

Five-agent fleet.

### Day 3

Registry + memory.

### Day 4

Identity + governance.

### Day 5

Security + recovery.

### Day 6

Observability + Control Center.

### Day 7

Evaluation + red-team + freeze.

---

# 26. CUT ORDER

If time becomes constrained:

Cut first:

- extra agents
- extra services
- animations
- unnecessary integrations
- advanced analytics
- decorative trust scores
- secondary model usage

Never cut:

1. deterministic policy
2. agent discovery
3. five-agent core
4. memory
5. identity
6. security attack
7. approval
8. remediation
9. verification
10. observability
11. audit
12. quarantine

---

# 27. DEFINITION OF DONE

The vertical slice is successful only when AEGIS can reproducibly execute:

```text
Incident
 → discovery
 → memory
 → multi-agent investigation
 → malicious-input defense
 → agent/tool failure recovery
 → remediation proposal
 → deterministic risk/policy decision
 → human approval
 → controlled execution
 → verification
 → resolution
 → verified memory update
 → unauthorized capability detection
 → agent restriction/quarantine
 → complete audit trail
```

The final system must be demonstrably real.

---

# 28. CLAUDE CODE BEHAVIOR

Claude Code is the primary implementation agent.

When working on AEGIS:

1. Read `CLAUDE.md` before making architectural decisions.
2. Treat this document as the project constitution.
3. Do not silently change the architecture.
4. Do not invent Google APIs, SDKs, services or capabilities.
5. Verify external platform assumptions before implementing them.
6. Prefer official Google documentation for Google-platform questions.
7. Clearly distinguish real integrations, AEGIS implementations and simulations.
8. Never weaken deterministic authorization to make an agent demo work.
9. Never give an agent direct uncontrolled production mutation.
10. Write tests alongside security/governance code.
11. Run tests after meaningful changes.
12. Report failures honestly.
13. Do not hide incomplete integrations behind fake success responses.
14. Keep the system runnable after every major milestone.
15. Prefer a smaller working vertical slice over a larger broken architecture.
16. Preserve reproducibility.
17. Do not add features simply because they sound impressive.
18. Challenge architectural decisions when implementation evidence contradicts the plan.
19. If a Google capability is unavailable, use the defined abstraction/fallback rather than fabricating it.
20. Maintain an implementation/evidence record for important platform integrations.

---

# 29. CURRENT BUILD MODE

The project is in:

> **FOUNDATION / IMPLEMENTATION PHASE**

The immediate objective is NOT the final demo.

The immediate objective is to establish:

```text
AEGIS CORE
+
SIMULATED ENTERPRISE
+
DETERMINISTIC GOVERNANCE
+
TESTS
```

Only after those are stable should agent intelligence become the primary focus.

---

# 30. FINAL PRINCIPLE

AEGIS should never become:

> "Five LLMs talking to each other."

It must remain:

> **A deterministic enterprise control plane that safely enables autonomous agents to reason, collaborate and act.**

Build the future architecture.

Compress it into a reliable seven-day vertical slice.

Prove it under adversarial conditions.

Never fake what has not been built.