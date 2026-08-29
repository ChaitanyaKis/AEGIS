# AEGIS — Developer Guide

Architecture lives in [`claude.md`](../claude.md), the project constitution. This
document only covers where code goes and how to run it.

## 1. Repository structure

```text
AEGIS/
├── claude.md                  project constitution — architecture, trust model, rules
├── pyproject.toml             dependencies, pytest and ruff configuration
├── README.md
├── docs/
│   └── DEVELOPMENT.md         this file
├── src/aegis/
│   ├── core/                  deterministic control plane (trust zone C, authoritative)
│   │   ├── domain/            domain contracts
│   │   ├── capabilities/      capability registry
│   │   ├── dependencies/      declared resource dependency graph
│   │   ├── assessment/        blast-radius engine, risk engine, pipeline
│   │   ├── policy/            deterministic policy engine
│   │   ├── approval/          time-bounded single-use human approval artifacts
│   │   ├── verification/      observations, expectations and the verification engine
│   │   ├── incidents/         deterministic incident state machine
│   │   └── audit/             append-only, tamper-evident application history
│   ├── enterprise/            CONTROLLED SIMULATION — synthetic world, observations,
│   │                          failure injection and the golden scenario
│   ├── agents/                agent plane (zone B) — Commander, four specialists,
│   │                          the model boundary and the finding contract
│   ├── tools/                 tool contracts, importable by agents (no control plane)
│   ├── a2a/                   governed agent-to-agent messaging; decides no authority
│   │   └── remote/            the authenticated remote security boundary (no network)
│   ├── control_center/        the operator read model; creates no authority
│   ├── orchestration/         thin wiring: governed tools, delegation, approval, the loop
│   ├── integrations/          external providers, configuration-dependent
│   ├── memory/                persistent organizational memory: admission, provenance,
│   │                          integrity, retrieval, persistence
│   ├── lifecycle/             bounded execution, retry accounting, durable breaker
│   └── evaluation/            the benchmark and the adversarial matrix: scenario contract,
│                              oracle, runner, metrics, attack classes
├── run_benchmark.py           benchmark entry point; exits non-zero when the suite fails
├── run_adversarial_report.py  adversarial matrix; exits non-zero if any attack is uncontained
├── run_live_incident.py       Track B: one incident against a real model provider
└── tests/
    ├── fleet.py               fixed capability set and agent fleet shared by suites
    ├── domain/                deterministic unit tests for the contracts
    ├── capabilities/          registry tests
    ├── dependencies/          dependency graph tests
    ├── assessment/            blast-radius, risk, pipeline and policy-integration tests
    ├── policy/                policy engine tests, including the negative matrix
    ├── approval/              approval lifecycle, expiry, replay and re-evaluation tests
    ├── verification/          predicates, freshness, conflicts and the resolution guard
    ├── incidents/             transition table, guards and the end-to-end lifecycle
    ├── audit/                 store, hash chain, recorders and trail reconstruction
    ├── enterprise/            world, observations, failures and the golden scenario
    ├── agents/                decision contracts, model boundary, prompt separation
    │   └── specialists/       the four agents, findings and authority separation
    ├── orchestration/         tool governance, delegation, recovery, the security matrix
    ├── memory/                admission, integrity, retrieval, poisoning, isolation
    ├── lifecycle/             limits, counters, breaker states, probes, bypass negatives
    ├── integrations/          provider translation, authority negatives, telemetry, SDK shape
    ├── a2a/                   envelope, identity, integrity, replay, injection, collusion,
    │   │                      durable persistence, restart and crash windows
    │   └── remote/            keys, signatures, registry, rotation, protocol versions,
    │                          transport faults, compromised peer, malicious intermediary
    ├── adversarial/           eight attack classes against the control plane, judged by
    │                          two containment standards
    ├── control_center/        freshness and UNKNOWN semantics, every view, isolation,
    │                          search, export, performance, the read-only boundary
    └── evaluation/            scenario contract, evaluator self-tests, suite invariants
```

Each package carries a module docstring stating what belongs in it. AEGIS is a single
modular application, not a set of services.

## 2. Domain model responsibilities

Everything below lives in [`src/aegis/core/domain/`](../src/aegis/core/domain/) and is
re-exported from `aegis.core.domain`.

| Model | Responsibility |
| --- | --- |
| `Agent` | Control-plane record about a fleet member: identity, version, lifecycle state, granted capability ids, endpoint reference. |
| `AgentEndpoint` | Where an agent is reachable, as an adapter-resolved `kind` + opaque `reference`. |
| `Capability` | An explicit unit of authority with its risk class, resource scope, data classification, reversibility, approval requirement and permitted agents. |
| `Incident` | The aggregate the fleet works on. Owns its `Evidence`; references agents and proposed actions by id. |
| `Action` | An operation an agent *proposes* against a resource. Carries the capability, target, arguments and supporting evidence. |
| `BlastRadius` | The assessed reach of an action. A result contract, populated later by the blast-radius engine. |
| `PolicyDecision` | An authoritative `ALLOW` / `DENY` / `REQUIRE_APPROVAL` outcome with a mandatory reason and policy reference. |
| `Evidence` | A provenance-carrying pointer to an observed fact. Never a conclusion. |
| `AuditEvent` | One immutable, flat entry in the audit log: when, who, what, which decision, which state transition. |

Enums are authoritative and asserted member-by-member in
[`tests/domain/test_enums.py`](../tests/domain/test_enums.py): `IncidentState`,
`AgentLifecycleState`, `RiskLevel`, `PolicyDecisionType`, plus the supporting
`DataClassification`, `ApprovalRequirement` and `EvidenceType`.

Four conventions run through all of them:

- **Frozen.** Domain objects are values. A state change produces a new object via
  `model_copy(update=...)`, which is what makes `state_before` / `state_after` audit
  records honest and keeps the audit log append-only.
- **Closed.** `extra="forbid"`. Untrusted input cannot smuggle fields past the boundary.
- **Owned values are embedded, cross-aggregate relations are referenced by id.**
  `Incident.evidence` holds `Evidence` objects; `Action.evidence`,
  `PolicyDecision.evidence` and `AuditEvent.evidence` hold evidence *ids*.
- **Unassessed is not safe.** `Action.risk` and `Action.blast_radius` default to `None`
  because they are outputs of deterministic engines, not claims a proposing agent may
  make about itself. Consumers must fail closed on `None`.

Serialization helpers (`to_dict`, `to_json`, `from_dict`, `from_json`) live in
[`serialization.py`](../src/aegis/core/domain/serialization.py). `to_json` is canonical:
sorted keys, compact separators, enums as strings, timestamps as UTC ISO-8601. Equal
objects always produce byte-identical output.

## 3. Where deterministic control-plane logic will live

`src/aegis/core/` — trust zone C, the authoritative half of AEGIS. Nothing in `core/`
may delegate a decision to an LLM, and nothing in it may import from `agents/`.

Built so far:

- [`core/capabilities/`](../src/aegis/core/capabilities/) — `CapabilityRegistry`, the
  in-process authoritative source of capability definitions. Resolves ids, answers
  ownership and resource-scope questions, refuses duplicates and unknowns.
- [`core/dependencies/`](../src/aegis/core/dependencies/) — `DependencyGraph`, a
  declarative record of which resources depend on which. Not the simulated enterprise;
  the enterprise will later supply a graph through this same abstraction.
- [`core/assessment/`](../src/aegis/core/assessment/) — `BlastRadiusEngine`,
  `RiskEngine` and the `AssessmentPipeline` that turns an unassessed proposal into an
  action carrying authoritative `risk` and `blast_radius`.
- [`core/policy/`](../src/aegis/core/policy/) — `PolicyEngine`, the authoritative
  security boundary. `evaluate(action, agent)` returns a `PolicyDecision`;
  `evaluate_detailed` also returns the `PolicyChecks` record behind it.
  [`rules.py`](../src/aegis/core/policy/rules.py) holds the predicates,
  [`engine.py`](../src/aegis/core/policy/engine.py) sequences them.

- [`core/approval/`](../src/aegis/core/approval/) — `ApprovalEngine` and the `Approval`
  artifact. Creates approvals only from a live `REQUIRE_APPROVAL`, and spends them via
  `consume_for_execution`, which re-evaluates policy before authorising anything.
- [`core/verification/`](../src/aegis/core/verification/) — `VerificationEngine`,
  comparing a declared `ExpectedState` against independent `Observation`s. Establishes
  enterprise truth, which is the only thing that can resolve an incident.
- [`core/incidents/`](../src/aegis/core/incidents/) — `IncidentStateMachine` over an
  explicit transition table. `transition(...)` returns a new frozen `Incident`;
  `transition_detailed` also returns the `StateTransition` record.
- [`core/audit/`](../src/aegis/core/audit/) — `AuditStore` (append-only, hash-chained),
  `AuditRecorder` (translates each control-plane artifact into an `AuditEvent`) and
  `reconstruct_incident_history`.

The end-to-end control-plane flow so far:

```text
agent proposal
  -> AssessmentPipeline  -> assessed Action
  -> PolicyEngine        -> ALLOW / DENY / REQUIRE_APPROVAL
  -> ApprovalEngine      -> ExecutionAuthorization   (only on REQUIRE_APPROVAL)
  -> IncidentStateMachine-> EXECUTING -> VERIFYING
  -> VerificationEngine  -> VERIFIED  -> RESOLVED
```

Every stage's artifact is recorded by `AuditRecorder` as it happens, so the whole run is
reconstructable from the log alone.

### The simulated enterprise

[`src/aegis/enterprise/`](../src/aegis/enterprise/) is **CONTROLLED SIMULATION**
(`claude.md` sections 14, 15, 17). Nothing in it is production infrastructure, real
telemetry, a real deployment or live customer data, and nothing should ever be described
as such. It is trust zone D: acted upon, never deciding.

- [`topology.py`](../src/aegis/enterprise/topology.py) — the **single** authoritative
  definition of the enterprise. It feeds the dependency graph, the world's initial state
  and the observation source; `tests/fleet.py` imports it rather than restating it, so the
  graph and the world cannot drift apart.
- [`world.py`](../src/aegis/enterprise/world.py) — mutable state behind declared operations
  (`deploy`, `rollback`, `set_error_rate`, `set_health`, `inject_failure`). Every read
  returns a frozen snapshot; there is no accessor for the internal mapping.
- [`mutations.py`](../src/aegis/enterprise/mutations.py) — the execution boundary. It
  requires an `ExecutionAuthorization` bound to the exact action, but it never *decides*
  authorization and never imports the policy engine.
- [`observations.py`](../src/aegis/enterprise/observations.py) — world state becomes
  `Evidence` becomes `Observation`. Emits only evidence types the verification engine
  already accepts; the allowlist was not widened for the simulator.
- [`failures.py`](../src/aegis/enterprise/failures.py) — a closed vocabulary of five
  simulation controls, each acting at the smallest layer that can produce it.
- [`scenarios.py`](../src/aegis/enterprise/scenarios.py) — the golden incident, driven
  entirely by the real engines.

**Execution success is not verification.** An `ExecutionResult` of `APPLIED` is a report
from the thing that did the work; whether the enterprise reached the desired state is
established by the verification engine from observations. Injecting `stale_telemetry`
demonstrates the gap: the rollback genuinely applies, and verification still returns
`STALE`.

**No seed, by design.** There is no randomness anywhere in the package, so there is
nothing to seed. Determinism comes from construction rather than from a fixed generator
state, which is the stronger guarantee: two worlds given the same operations are identical
because nothing could have differed.

### The agent plane

[`src/aegis/agents/`](../src/aegis/agents/) is trust zone B. The Commander interprets an
incident, chooses what to investigate, and proposes a remediation. It holds **a model
client and nothing else** — no policy engine, no approval engine, no executor, no
verification engine, no audit store, no world. A test parses every module's imports and
fails if any of those appear, so a captured model has nothing here to call.

- [`decisions.py`](../src/aegis/agents/decisions.py) — four decision types, closed
  schemas. A model emitting `risk` or `blast_radius` produces a validation error, not a
  decision carrying a risk.
- [`model.py`](../src/aegis/agents/model.py) — the `ModelClient` protocol. `ModelRequest`
  has **no instruction field**: untrusted data travels in `data`, and the system
  instruction is a module constant. Injection is impossible because the wire is absent.
- [`prompt.py`](../src/aegis/agents/prompt.py) — the constant instruction, plus `render`,
  which JSON-quotes untrusted data under one key in the user channel.
- [`deterministic.py`](../src/aegis/agents/deterministic.py) — **DETERMINISTIC TEST
  MODEL**. Rule-based, reproducible, no credentials, no network, no Gemini.

[`src/aegis/orchestration/`](../src/aegis/orchestration/) is the wiring. It computes no
risk, makes no authorization decision, grants no approval and decides no state transition
— each is a call into the component that owns it. The loop is bounded by an explicit step
count; there is no `while` loop anywhere in it.

Every read goes `Commander -> tool id -> capability -> PolicyEngine -> ALLOW/DENY ->
ObservationSource`. A tool id is a dictionary key, never a path to a callable: there is no
`eval`, `exec`, `getattr` or dynamic import in the package, so an invented tool name can
only ever produce `UNKNOWN_TOOL`.

### Running the Commander with a real model

The Gemini provider in
[`src/aegis/integrations/gemini.py`](../src/aegis/integrations/gemini.py) is
**implemented, shape-verified against the installed SDK, and live-verified on the Commander
path**. `google-genai` 2.19.0 is installed as an optional extra, every API assumption the
provider makes was read off that package rather than remembered, and two incidents have
been driven end to end by `gemini-2.5-flash` on Vertex AI.

Two runs are two observations. Nothing here derives a success rate or an expected behaviour
from them, and the specialist path has not been run live at all — both trials used
`--deterministic-specialists` so that exactly one model was the variable under test.

The deterministic model remains the canonical path: the whole suite and the whole benchmark
pass with `google` actively blocked from importing, which is checked in a subprocess rather
than assumed.

Full detail, configuration and limitations: [`docs/PROVIDER.md`](PROVIDER.md).

### The provider boundary

Three unrelated implementations satisfy `ModelClient`, and no Commander or orchestration
code knows which one it holds:

| Implementation | Purpose |
|---|---|
| `DeterministicCommanderModel` | rule-based; the canonical offline path |
| `ScriptedCommanderModel` | replays pre-built decisions |
| `ReplayModelClient` | replays raw **text** through the real parser |
| `GeminiCommanderModel` / `GeminiSpecialistModel` | the live provider |

`ReplayModelClient` earns its place beside the scripted model: the scripted one hands over
objects that have already satisfied the contract, so it can only test what happens *after*
validation. The replay client takes strings, as a provider does, and runs them through
`parse_decision` — the same function `GeminiCommanderModel` calls. That is what makes an
adversarial provider response testable offline without pretending a network call happened,
and it also reads capture files, so one real run can be replayed deterministically forever.

`RecordingModelClient` wraps any of them and records call count, latency, request and
response digests, decision, tool and delegation sequences, failure category and — when a
provider reports them — token counts. It observes and cannot intervene: it returns the inner
value unchanged, re-raises the inner exception unchanged, and has no default decision
anywhere in the class. Content is never recorded, only digests.

Provider failures map onto the existing `ModelError` hierarchy, refined by a telemetry-only
category:

| Situation | Exception | Category |
|---|---|---|
| deadline exceeded (`httpx.TimeoutException` **or** builtin) | `ModelTimeout` | `TIMEOUT` |
| HTTP 429 | `ModelUnavailable` | `QUOTA` |
| HTTP 5xx | `ModelUnavailable` | `UNAVAILABLE` |
| HTTP 400/401/403/404 | `ModelUnavailable` | `CONFIGURATION` |
| connection failure | `ModelUnavailable` | `TRANSPORT` |
| safety block, no candidate | `ModelRefused` | `REFUSED` |
| unparseable, empty or oversized output | `MalformedModelOutput` | `MALFORMED` |

`ModelRefused` is new in this milestone. "The model would not speak" and "the model spoke
nonsense" are different facts about a run and an operator needs to tell them apart —
identical in consequence, since both are `ModelError` and every existing `except ModelError`
already catches it.

Classification is **structural**: by the presence of an integer HTTP `code` and by exception
class name, not by `isinstance` against imported SDK types. That makes the whole classifier
testable with the SDK uninstalled, and it fixed a real defect — `httpx.TimeoutException` is
not a subclass of the builtin `TimeoutError`, so the previous version silently filed every
real Gemini timeout as "unavailable".

### Delegation and the specialists

The Commander orchestrates; it no longer does specialist work itself, and it **cannot draft
a remediation**. `PROPOSAL_AUTHORITY` maps `production.rollback` to the Remediation agent
alone, so reaching a rollback means delegating — which is the point of having specialists.

| Agent | Reads | May propose |
| --- | --- | --- |
| Commander | health, metrics, deployments, dependencies | nothing |
| Diagnostic | health, metrics, deployments, dependencies | nothing |
| Security | security signals, deployments, health | nothing |
| Business Impact | health, dependencies | nothing |
| Remediation | health, deployments | `production.rollback` |

`DELEGATION_MATRIX` permits `Commander -> {Diagnostic, Security, BusinessImpact,
Remediation}` and nothing else. Every specialist row is empty: if a specialist could
delegate, an agent with no authority could reach one with proposal authority and build a
hidden chain ending in a production mutation.

**A finding is advisory.** An `AgentFinding` says "agent X concluded Y from evidence Z",
never "the enterprise is in state Y". `EvidenceType.AGENT_FINDING` remains outside the
verification engine's allowlist, so no specialist can conclude its own success. Findings
reach the Commander labelled `finding_summary` alongside `supporting_evidence` — the
observation ids behind them — so a synthesis cannot quietly promote a conclusion into a
measurement.

**Detection is not enforcement.** The Security agent finds injection markers in a hostile
payload and reports them. That finding blocks nothing, and a Security agent saying "safe"
authorises nothing: policy reaches the same decision either way. The two layers are
deliberately independent.

**Recovery.** A verification that does not establish recovery drives
`VERIFYING -> DEGRADED -> RECOVERING -> INVESTIGATING`, and the next attempt passes through
`POLICY_CHECK` and approval again. The transition table has no edge from either recovery
state to `EXECUTING`, so recovery cannot become a shortcut.

Still to come: lifecycle manager and circuit breaker.

### Lifecycle semantics as implemented

The transition table in [`transitions.py`](../src/aegis/core/incidents/transitions.py) is
written out edge by edge — no ordinal comparison, no wildcard, no fallback, and
transitivity is never implied. Three guarantees are structural:

- **RESOLVED only from VERIFYING, and only on proof.** A tool returning success is not
  evidence, so execution cannot resolve an incident on its own say-so — see the
  verification guard below.
- **POLICY_CHECK cannot be skipped.** Remove it from the graph and EXECUTING becomes
  unreachable from intake — including via the DEGRADED/RECOVERING recovery loop, because
  recovery re-enters at INVESTIGATING and never further along.
- **RESOLVED and ESCALATED are terminal.** Neither can re-enter active processing.

Guarded edges need an artifact, not just a legal predecessor: leaving POLICY_CHECK
requires the matching `PolicyDecision` (so a DENY reaches neither AWAITING_APPROVAL nor
EXECUTING), and leaving AWAITING_APPROVAL for EXECUTING requires an
`ExecutionAuthorization` from a consumed approval.

### Approval semantics as implemented

An approval authorises **one exact action, for a bounded time, under one policy context,
exactly once**:

- **One exact action** — `action_fingerprint`, a SHA-256 over the whole canonical
  serialization. Every field participates, so no field is free to edit after sign-off.
- **Bounded time** — `expires_at`, computed from the clock at consumption rather than a
  stored status. Lapsed approvals are never renewed; a new request is required.
- **One policy context** — policy is re-evaluated at creation *and* at consumption. A
  handed-in decision is treated as a claim, never as authority.
- **Exactly once** — the engine keeps a consumption ledger, so replaying a pre-consumption
  copy of the immutable record is refused.

A DENY can never become an approval request, so no amount of human sign-off converts a
denial into authorisation.

### Verification semantics as implemented

An `Observation` is not a tool return value. It embeds an `Evidence` for provenance and
adds the resource observed plus the measured attribute values. Four hard gates decide
whether one can contribute:

1. **Resource** — exact match on the action's target. A dependent service's health is
   context, never a substitute.
2. **Evidence type** — an allowlist (`OBSERVABLE_EVIDENCE_TYPES`). `TOOL_RESULT` is
   excluded, which is what stops "the rollback call returned 200" from resolving anything;
   so are `AGENT_FINDING`, `HUMAN_INPUT`, `MEMORY` and `VERIFICATION`.
3. **Source** — the expectation's `accepted_sources` allowlist. Anything else is ignored
   outright, so an untrusted payload cannot even force a conflict.
4. **Freshness** — no older than the expectation's `max_observation_age`.

Predicates are a closed system: three comparators (`EQUALS`, `AT_MOST`, `AT_LEAST`), two
value types, no expression language and nothing evaluated from strings. Every predicate is
required. Conflicting values for an attribute produce `MISMATCH` — the engine never picks a
winner, even when both readings would pass.

Five statuses, exactly one of which is success. When predicates fail differently,
`STATUS_PRECEDENCE` reports the most severe: `INSUFFICIENT_EVIDENCE > STALE > MISMATCH >
FAILED`.

**The resolution guard.** `VERIFYING -> RESOLVED` carries `TransitionGuard.VERIFICATION`
and requires both the `VerificationResult` and the action it verifies. It refuses unless
the result is `VERIFIED`, its incident matches, the action is one of the incident's
proposed actions, the result verifies *that* action, its resource is the action's target,
and its `action_fingerprint` still matches. A failed verification can only go to
`DEGRADED`.

### Audit semantics as implemented

The store is **append-only by construction**: there is no update or delete method, the
internal list is never handed out, and every record is a frozen model. A duplicate
`event_id` raises rather than overwriting.

Two kinds of time are kept apart. `AuditEvent.timestamp` is when the thing happened;
append order is when AEGIS recorded it. The store never reorders by timestamp, because the
gap between the two is itself evidence.

Each record is chained: `digest = SHA-256(canonical_json({correlation, event,
previous_digest, sequence}))`, with the first record linking to a fixed
`GENESIS_DIGEST`. `verify_chain` recomputes everything and reports the first bad index —
it never repairs. This gives **tamper evidence only**: not external immutability, trusted
hardware, non-repudiation or durability. An attacker who can rewrite the whole store can
also recompute every digest.

Recorders are translators. They copy what an engine already decided — a DENY stays a DENY,
a rejection stays a rejection, a failed verification stays a failure — and never re-run
policy, recompute risk or infer an outcome. A refused approval creation produces no
`Approval` to record; the DENY that caused it is what carries the record.

`reconstruct_incident_history` rebuilds the state sequence from `incident.state_changed`
events only, validates each edge against the real transition table, and reports gaps,
illegal transitions and resolutions not backed by a VERIFIED verification in the same
trail.

### Assessment semantics as implemented

- **Impact travels upstream.** Graph edges point from a resource to what it depends on;
  disruption propagates the other way, so blast radius is the target plus its transitive
  *dependents*.
- **Not every action disrupts.** A capability declared `risk_class = LOW` is treated as
  non-disruptive and reaches only its target, so a telemetry read does not inherit a
  rollback's reach. Anything above LOW propagates — the uncertainty errs towards
  over-stating reach.
- **Blast-radius impact** = `max(reach band, highest criticality among affected)`, where
  the reach bands are the published `REACH_THRESHOLDS` table (1 → LOW, 2–3 → MEDIUM,
  4–6 → HIGH, 7+ → CRITICAL).
- **Risk** = `max` of four independently-computed floors: capability risk class, blast
  radius impact, an irreversibility floor of HIGH, and a data-classification floor. Using
  a maximum is what makes the monotonicity invariants structural: no benign property can
  pull a dangerous one down. `approval_requirement` is deliberately *not* an input —
  approval is the response to risk, not evidence of it.
- **Unknown resources are unmeasured, not empty.** The graph raises rather than returning
  an empty dependent set, and the pipeline returns `INSUFFICIENT_INFORMATION` with no
  assessed action. The caller then has nothing authoritative to submit and the policy
  engine denies any privileged capability.
- **The proposal is never trusted and never lost.** `Action.risk` and
  `Action.blast_radius` are recomputed and overwritten in both directions; the original
  proposal is preserved on `Assessment.proposal` for audit.

### Policy semantics as implemented

- **Precedence is structural.** `DENY > REQUIRE_APPROVAL > ALLOW` is enforced by ordered
  gates that return immediately, not by ranking outcomes at the end. Approval can never
  repair an authorization failure.
- **Evaluation order.** agent known and matching the action's `requesting_agent` →
  lifecycle operational → capability registered → lifecycle permits *this* capability →
  capability held → resource in scope → risk assessed → approval → allow.
- **Ownership is two-sided.** `Agent.capabilities` must list the id *and*
  `Capability.allowed_agents` must list the agent. Either side alone revokes.
- **Scope matching is exact string equality.** No prefix, glob, wildcard, hierarchy or
  fuzzy matching. An empty `resource_scope` reaches nothing.
- **Privileged capability** = anything not unambiguously low-authority, i.e. unless
  `risk_class` is LOW *and* `reversible` *and* `approval_requirement` is NONE. The same
  predicate decides which capabilities require a risk assessment.
- **Lifecycle.** Operational states are an allowlist: ACTIVE, CANARY, RESTRICTED.
  RESTRICTED is reduced authority — unprivileged capabilities only. Every other state
  (REGISTERED, EVALUATING, SANDBOXED, APPROVED, QUARANTINED, RETIRED) permits nothing.
- **Unassessed risk denies.** `Action.risk is None` means UNASSESSED, never LOW. A
  privileged capability cannot be exercised on an unassessed action, so an agent cannot
  self-declare a low risk to bypass governance.
- **Time is not an authorization input.** The clock is injectable and read only to stamp
  `evaluated_at`, after the decision is already determined.

### Evaluation semantics as implemented

[`src/aegis/evaluation/`](../src/aegis/evaluation/) measures whether AEGIS makes correct
decisions. It is a **deterministic safety and governance benchmark**, not a model
evaluation: no model is scored, because no real model is involved. Every reasoning
component in it is rule-based.

**The oracle is hand-written.** A `Scenario` declares an arrangement and an
`ExpectedOutcome` that a person wrote down. The evaluator never derives what *should*
have happened — an oracle that reasoned about the incident would be a second
implementation of the system under test, and two implementations agreeing proves only
that they share a bug.

**Unspecified is not False.** Every expectation field defaults to `None`, meaning the
benchmark does not check it. An explicit `False` asserts that something must not happen.
A scenario asserting nothing at all is rejected at construction: it would measure only
that the run did not crash.

**Undefined is not zero.** `MetricValue` keeps its numerator and denominator and returns
`None` for a rate with an empty population. A suite with no security scenarios has an
*undefined* detection rate, never a perfect one. Reporting a number there would be
fabricating a measurement.

**Mismatches and violations are different things.** A mismatch means AEGIS did not do
what a scenario declared — possibly a bug, possibly a scenario written wrong. A
`CriticalViolation` means AEGIS did something it must never do. Any violation fails the
whole suite regardless of how the metrics look, and an empty suite reports `EMPTY`
rather than `PASS`.

**The evaluator is not a second policy engine.** It contains no risk thresholds and no
authorization logic. Each violation check reads two recorded artifacts against each
other and asks whether the record of permission exists — never whether permission was
deserved.

The single exception is deliberate and documented in
[`runner.py`](../src/aegis/evaluation/runner.py): the headline
`unauthorized_high_impact_actions` check does **not** consult the policy engine's own
verdict. A benchmark that asked policy whether policy had approved would report zero
unauthorized actions in exactly the case where policy is the broken component. It
instead states one invariant fixed by `claude.md` section 21 independently of any policy
configuration — a high-impact action never executes without a human authorization on
record — using the risk the assessment pipeline already computed.

### Reproducibility

Runs are byte-reproducible. The clock is injected, the enterprise is simulated, agent
models are rule-based, and scenario ordering is fixed. Two runs of the same suite
serialize identically apart from wall-clock runtime, which the reproducibility test
excludes explicitly rather than by ignoring timestamps generally.

### Memory semantics as implemented

[`src/aegis/memory/`](../src/aegis/memory/) is persistent organizational memory
(`claude.md` section 12). One sentence governs it:

> **Memory is context, not authority.**

It decides nothing. Risk, blast radius, policy, approval, execution, verification and
resolution are all determined by the deterministic control plane, and **not one of them
reads this package** — asserted structurally over parsed imports, in both directions.

**Only verified outcomes become authoritative.** `MemoryAdmission` runs nine named checks
against real artifacts: the incident is present, the action belongs to it, the verification
exists, its status is `VERIFIED`, and it is bound to the same incident, the same action and
the same *fingerprint*. A tool that reported success, an agent that is confident and a human
who wrote it down are recorded as what they are and can never be promoted.

**Agents cannot claim authority, structurally.** `MemoryCandidate` — the only memory type a
caller constructs — **has no status field**, and `MemoryStore` has no method that accepts a
pre-built record. `append()` always stores `CANDIDATE`; `admit()` runs admission. A record
built by hand with `status=AUTHORITATIVE` is a value nothing will take.

**Provenance is derived, never accepted.** What a candidate *claims* about its verification
is checked against the artifact and then discarded; the stored `MemoryProvenance` is built
from the artifact itself. It deliberately contains no confidence score, no model reasoning
and no agent assertion — a field that exists will eventually be read as if it mattered.

**Retrieval creates no authority.** Deterministic filtering on declared fields with exact
matching — no embeddings, no similarity, no relevance score. Results come back as
`RetrievedMemory`, a deliberately lossy projection that carries no status, digest or chain
position, labelled `historical context only; establishes no current state` and stamped with
the age of the knowledge. `age_seconds` is reported and **gates nothing**: a staleness
threshold would be a security mechanism built out of an estimate.

**Current state beats memory**, structurally rather than by rule. Verification reads
observations; nothing in its path can reach memory.

**Cross-incident isolation.** `for_incident()` excludes the incident's own memory, so a
conclusion cannot become its own supporting evidence. Memory from another incident is
retrievable as history, labelled with the incident it came from, and can satisfy no
verification, policy, approval or resolution for the current one.

**Revocation is append-only.** The original record stays in the chain and a revocation entry
names it. Revoked memory is never returned as history, and the log still shows that it
existed and was withdrawn — the difference between a correction and a cover-up.

**Memory reaches a model only through `ModelRequest.data`.** `ModelRequest` was not widened;
it still has exactly `task`, `data`, `available_tools`, `step`, `max_steps`. History travels
as opaque JSON through `CommanderContext.historical_memory`, so neither the agent plane nor
the orchestrator imports `aegis.memory`. The Prompt 08 invariant is unchanged: untrusted
content has no route into the instruction channel.

### Memory integrity and persistence

The chain is the same construction as the audit log — a declared payload model, canonically
serialized and hashed, each record carrying the digest of the one before it. Covered fields
include `content`, `provenance`, `status` and `sequence`, which is what makes edited content,
altered provenance, silent promotion, deletion, reordering and insertion all detectable.

The boundary is **tamper evidence, not immutability**. The digest function lives in-process
alongside the data, so an attacker who can rewrite the whole store can recompute every digest
and rewrite the integrity module too. Nothing here makes memory immutable.

`JsonlMemoryPersistence` gives real cross-process durability: one canonical JSON document per
line, appended, flushed and `fsync`ed before the write returns, verified on load. Its honest
limits are that it is **single-writer with no locking**, that nothing at the filesystem level
prevents an operator with write access from truncating or editing the file (the chain makes
that *detectable* on the next load, not impossible), and that a truncation of the tail leaves
a self-consistent prefix which no in-process chain can detect on its own. The default
`InMemoryPersistence` is **not durable** and says so.

### Lifecycle and circuit-breaker semantics as implemented

[`src/aegis/lifecycle/`](../src/aegis/lifecycle/) holds two components with sharply
separated jobs (`claude.md` sections 8, 10):

    LifecycleManager  — "should the incident lifecycle continue?"
    CircuitBreaker    — "is this automation path allowed to keep operating?"

**Neither grants authority.** They can stop automation and can decline to stop it, and
declining to stop is not permission — proceeding still requires assessment, policy,
approval and an execution authorization, any of which can independently refuse.
`LifecycleAction` has no `EXECUTE` member for exactly that reason, and `BreakerDecision`
carries `allowed=True` meaning "no objection from this gate", never "you may proceed".

**IncidentState remains authoritative.** This package defines no competing lifecycle enum
and adds no terminal state. `TERMINAL_STATES` is read from the existing domain enum, and
an escalating lifecycle verdict transitions the incident through the real state machine.

**Every bound is explicit and immutable.** `LifecycleLimits` declares max steps,
remediation attempts, recovery attempts, consecutive failures, total executions,
per-fingerprint executions and an optional deadline. All are `ge=1` — a zero limit is a
configuration error, not a strict policy — and there is no "unlimited" sentinel. The models
are frozen and are constructed by the operator wiring the orchestrator; nothing a model
produces can name one.

**Counters only rise.** `LifecycleCounters` is frozen and every `after_*` method returns a
new value. Only `after_success` clears anything, only `consecutive_failures`, and only from
a *verified* remediation. A success never refunds an attempt, a recovery or an execution:
doing something successfully once does not buy back the budget for doing it again.

**Retries are bounded twice.** Each recovery must be earned by a recorded degrade, and the
manager caps how many may occur. Recovery re-enters at investigation, never at execution —
the transition table has no edge from `DEGRADED` or `RECOVERING` to `EXECUTING`, so a retry
walks `POLICY_CHECK` and approval exactly like the first attempt.

### The circuit breaker

`CLOSED → OPEN → HALF_OPEN → CLOSED`, with a single bounded probe as the only route back.

Failure classes are counted and thresholded **separately**: execution failure, verification
failure, stale verification, insufficient evidence, verification mismatch and governance
anomaly. Collapsing them would destroy the diagnostic value — "three execution failures"
and "three stale telemetry readings" call for very different responses.

**A policy DENY never opens the breaker.** A refusal is the control plane working; a
breaker that opened on it would turn correct governance into a self-inflicted outage the
first time AEGIS said no. `GOVERNANCE_ANOMALIES` is a closed vocabulary of six conditions
that should be *unreachable* — execution without authorization, execution after a deny, an
approval bound to a different action, a verification of a different action, execution with
no policy evaluation, a broken audit chain — and its threshold defaults to one.

**Scope** defaults to `capability@resource`, the smallest key that still accumulates.
Repeated rollback failures against payment-api open the breaker for that pairing; a
rollback of order-service and a scale of payment-api are untouched. Counters persist across
incidents, which is the point: three incidents each failing once against the same
capability is exactly the pattern a per-incident scope would miss. `CAPABILITY`, `RESOURCE`,
`INCIDENT` and `GLOBAL` are available and documented, and `GLOBAL` is never the default
because it is the blast radius of a mistake.

**There is no `reset()`.** The only route from OPEN to CLOSED is `record_probe_success`,
which requires a real governed execution that a real verification confirmed. A failed probe
returns to OPEN directly — the probe failing is itself the evidence. `HALF_OPEN` permits
exactly one probe; `half_open_probes` is typed `le=1`, so "allow two probes" is not a
configuration a deployment can express.

**The breaker is asked twice per remediation**: before approval is requested, so a blocked
path never spends a human approval it cannot use; and immediately before execution, so a
breaker that opens in between still stops the action. A consumed approval is evidence a
human agreed — never a token that outranks a stop.

**Fail-closed.** While OPEN, production execution, new remediation attempts and delegation
toward remediation are refused. Observation, audit, reporting and escalation continue: the
point of stopping is to find out what is wrong, which requires still being able to look.

**Structural boundaries.** The breaker imports no `PolicyEngine`, `ApprovalEngine`,
`VerificationEngine` or `ActionExecutor`, and neither component imports `aegis.memory` —
all asserted over parsed imports. The breaker is handed a `FailureClass` someone else
computed and is never given the artifacts to re-derive one.

### Durable, tamper-evident lifecycle state

Prompt 12 left the breaker correct but ephemeral. Three hardenings close that.

**Durable.** Every state-affecting event appends a `LifecycleStateRecord` through a
`LifecycleStatePersistence` — two methods, `load` and `append`, so no backend can offer the
breaker a way to rewrite history. `InMemoryLifecycleState` is the hermetic default and says
it is not durable; `JsonlLifecycleState` writes one canonical JSON line per record, flushed
and `fsync`ed before returning. A restart restores circuit state, per-class failure counts,
scope, trip class, trip time, probe bookkeeping, and per-incident counters including
execution and per-fingerprint counts. **A restart never re-closes a breaker.**

**Tamper-evident.** Records chain by SHA-256 over canonical JSON, the same construction the
audit and memory logs use. Modification, insertion, deletion and reordering are all
detected, and `verify_state_chain` reports `valid`, `checked`, `first_invalid_index`,
`reason` and `trusted_prefix` — it reports, never repairs.

**Monotonic — and this is the part that is easy to miss.** A chain can be
cryptographically perfect and still describe a history that could not have happened.
Appending an old `CLOSED` snapshot after an `OPEN` one, with the digest correctly
recomputed, is a blind reset smuggled in through storage. So every record names the
`BreakerTransition` that produced it, and load checks each against an explicit edge table.
Exactly one edge results in `CLOSED` from a non-closed state:
`(PROBE_SUCCEEDED, HALF_OPEN, CLOSED)`.

The table is written one edge at a time on purpose. An earlier version paired a set of
permitted starting states with a set of permitted results, which quietly made
`OPEN → CLOSED` legal under `FAILURE_RECORDED` — the exact hole it exists to close. A cross
product is not a state machine.

**Failing closed on corruption.** `CorruptionPolicy.RAISE` (default) refuses to construct:
a process that cannot trust its record of which breakers are open must not start as though
none were. `CorruptionPolicy.QUARANTINE` constructs but refuses *every* scope, for
deployments that must keep observing. Neither can turn an open breaker closed.

### Automatic HALF_OPEN recovery

`probe_cooldown_seconds` (300s default) makes an open breaker eligible for one probe. The
transition happens when someone asks rather than on a timer, so it is always attributable
and always auditable. `None` means never automatically eligible — a legitimate setting for
a capability nobody wants retried unattended — and an operator can still call `allow_probe`.

The probe is a real governed execution: full assessment, policy, approval and verification.
HALF_OPEN is permission to try once, never permission to skip anything.

The breaker is asked twice per remediation, and in HALF_OPEN the first ask *consumes* the
probe. The lifecycle manager therefore remembers which scope's probe it holds, so the second
ask does not refuse the attempt the first authorised. That is bookkeeping, not a bypass: the
second gate still checks state and still refuses if the breaker has reopened since, and a
held probe is cleared at `begin`, so it cannot leak into the next incident.

### Governed agent-to-agent communication

[`src/aegis/a2a/`](../src/aegis/a2a/) is the transport and identity boundary between agents.
It is **not** a second control plane: it decides nothing about whether an action is
permitted, because it holds nothing that could.

```text
issue -> seal -> send -> admit -> deliver -> respond
```

`admit` checks, in this order and all failing closed: integrity, origin, replay, identity,
permission to communicate, task, incident/conversation/task binding, freshness, ordering,
bounds. Order matters — integrity comes first because nothing the message says can be
believed until the message is known to be the one that was issued.

Two distinctions worth keeping straight:

- **Integrity is not authentication.** The seal proves the message was not modified. Origin
  comes from the issuer's ledger, exactly as gate authenticity comes from `GateRegister`.
- **Admission is not authorization.** Admitting a message means it may be delivered. A
  specialist whose message was admitted has been allowed to *speak*.

The delegation matrix is **injected** rather than imported: `DELEGATION_MATRIX` lives in
`orchestration/delegation.py` and is passed into `AgentDirectory`. That is how Part 3's "one
delegation policy" and Part 20's "no A2A module imports orchestration" hold at the same
time — the dependency arrow points down, never up.

Identifiers use `ExactId`, which *rejects* surrounding whitespace instead of stripping it.
The domain `Identifier` alias strips, which is right for values AEGIS constructs and wrong
for values a model supplies.

Replay state is **durable** as of Prompt 16. `MessageLedger` takes an `A2APersistence`
backend — `load` and `append`, no update, no delete, no truncate — and rebuilds itself by
*replaying* the log rather than by trusting a summary, because a summary is a place for a
lie to hide.

```text
issue → append(MESSAGE_ISSUED) → fsync → in-memory view moves
admit → append(STATUS_CHANGED) → fsync → in-memory view moves
```

The append comes first deliberately: a failed write leaves the ledger where it was rather
than one step ahead of its own record.

`InMemoryA2APersistence` is the default and says **NOT DURABLE** in its own docstring;
`JsonlA2APersistence` is the one that survives a restart. `MessageLedger.durable` reports
the backend's answer rather than an assumption.

### The remote security boundary

[`src/aegis/a2a/remote/`](../src/aegis/a2a/remote/) builds the boundary that has to exist
*before* a network transport could be trusted. It does not build the network, and the
package structurally cannot: `socket`, `http`, `httpx`, `requests`, `urllib`, `aiohttp` and
`ssl` are all unimportable there, asserted over parsed imports.

```text
threats.py        the threat model as data -- 30 classes, each mapped to a layer
keys.py           SigningKey / VerifyingKey / KeyProvider protocols, HMAC-SHA256, KeyRing
ed25519.py        the ONLY module in AEGIS that imports `cryptography`
identity.py       RemoteAgentIdentity, IdentityStatus, RemoteAgentRegistry
envelope.py       SIGNED_FIELDS, RemoteEnvelope, RemoteFrame, encode/decode
verdicts.py       RemoteRejection (30 members), RemoteVerdict
authenticator.py  who sent this -- and nothing else. Pure; changes no state
gateway.py        addressing, binding, replay, then the *existing* local broker
channel.py        the one seam the orchestrator sees: sign, carry, deliver
transport.py      RemoteTransport protocol, RemoteFault, InMemoryRemoteTransport
```

The layering is the design. `authenticator.py` cannot import a ledger, a broker or a
transport, so authentication cannot consume, admit or mark anything — a bug there cannot
make something look delivered. `gateway.py` composes it with `A2ABroker.admit`, passing the
cryptographically established identity as `accountable_sender`. That single argument is the
integration; nothing else about the local boundary changes.

**Wiring is not a claim.** `RemoteGateway` takes `hosted_agents` (the agents this process
actually runs) and each `deliver` names one of them as `as_agent`. The message's *signed*
recipient is compared against that. A frame's address is unsigned — it legitimately changes
between hops — so an intermediary that readdresses one has changed a routing hint and not a
destination.

**Signing is bound to wiring too.** `RemoteChannel.sign_as` takes an agent id from the
application's own record of which agent it is, and looks the key up in a mapping the
application built. An agent with no key signs nothing: no default key, no shared key, no
fallback, because each of those is a way for one agent to sign as another.

Two things to keep straight, on top of the two above:

- **A valid hash is not an authenticated sender.** The envelope seal is a public formula, so
  anything that can build a message can produce a perfect one. That is why `RemoteEnvelope`
  exists.
- **A valid signature is not an authorization.** A compromised peer with genuine key material
  authenticates perfectly on every malicious message it sends, and that is the *correct*
  answer to the question authentication asks.

`RemoteDelivery` keeps the authentication verdict separately from the outcome, so "we could
not tell who sent this" and "we knew exactly who sent it and refused it anyway" stay
distinguishable. Folding them together would erase the distinction the class exists for.

Attack code lives in [`src/aegis/evaluation/remote_stage.py`](../src/aegis/evaluation/remote_stage.py),
not in the product. The transport ships genuine network conditions — delay, duplication,
reordering, loss, timeouts — because a network really does those on its own. It does not
ship a `tamper()` method, because a network does not tamper: an attacker does, and an
attacker is a control group. `MaliciousIntermediary` reaches frames through one reviewable
seam, the transport's `relay` hook, and holds no signing key.

The benchmark pins **HMAC-SHA256** so the safety benchmark needs no third-party package.
That is a symmetric MAC, which authenticates against a party without the key — the
intermediary threat — and does not give a receiver evidence it could show to somebody else.
The test suite parametrises every cryptographic property over
`available_algorithms()`, so Ed25519 is proven too wherever `cryptography` is installed:

```bash
uv sync --extra crypto
uv run pytest tests/a2a/remote        # 663 tests, both algorithms
```

The evaluator does its **own** cryptography.
`remote_admissions_are_authentic()` decodes the frames the transport actually carried,
rebuilds a verifier from the registry's stored material, and checks the signature and the
identity status itself. An authenticator that had stopped checking signatures would still
report success on every message; it could not make that function return `True`. Seventh
application of the lesson: **the evaluator must never trust the component it audits.**



A chain that does not verify makes the ledger refuse to exist. A failed append raises, and
the orchestrator turns that into a *recorded refusal* — a crash would skip the audit record
the refusal was supposed to leave.

Full detail, including the atomicity and concurrent-writer limitations: [`docs/A2A.md`](A2A.md).

### The operator control center

[`src/aegis/control_center/`](../src/aegis/control_center/) makes the governed control
plane understandable by a human, and **creates no authority doing it**.

```text
live orchestrator -> capture_incident() -> ControlCenterInput (frozen)
                                              |
                                              v
                                       project_incident()
                                              |
                                              v
                                       IncidentProjection -> export_incident()
```

`capture.py` is the only module that touches a live object. Everything downstream works on a
frozen value, so the read model **cannot** create authority — there is no object left to
ask. That is the Part 20 invariant implemented by construction rather than by discipline,
and four structural test layers hold it: no engine importable, no mutating call, nothing
held that could act, and — measured rather than asserted — building a projection moves
neither the audit head, nor the world's deployment, nor the gate register's counts.

`capture.py` reads through two helpers, and every call site passes a **literal** name, so
the reachable operation set is seven read-only methods written down in one place.

**The vocabulary is the design.** `Tri` is a boolean with a third value, and almost every
operator question needs it:

```text
missing evidence -> UNKNOWN
```

Never `FALSE`. AEGIS fails closed, so an unreadable source produces silence, and silence
rendered as `FALSE` looks exactly like a system with nothing wrong. An unreadable breaker is
not a closed one. A crashed run did not "not execute". Absent lifecycle counters are `None`,
because `0` is a claim and a crashed run used steps nobody counted.

`Fact` pairs a value with how it was arrived at — `OBSERVED`, `DERIVED` or `UNAVAILABLE` —
and refuses to be constructed inconsistently: a stated fact must have a value, and an
unavailable one must not.

`Provenance` travels with every view and is deliberately **not** flattened. Two views from
two sources are two observations; merging them would assert a "current state" that was never
true all at once.

**Two things the read model is careful about, and one it cannot do.**

The audit vocabulary has no `execution.*` event, so `Phase.EXECUTION` is answered by the
run's `ExecutionResult` and is `UNKNOWN` without one — even when the trail shows the state
machine reaching `EXECUTING` and a gate being consumed. Those are facts about the state
machine and about authorization, not about production.

A valid chain proves no *tampering*, not *completeness*: a truncated prefix verifies
perfectly. Truncation is caught separately, by comparing the last record's digest against
the store's own head digest, and when it is detected absence stops being evidence.

What it cannot do is detect a compromised orchestrator. It reads what that process recorded,
so a lying process produces lying artifacts and a faithful display of them — which is
exactly why the benchmark's oracle reads the **enterprise world** rather than the
projection. `capture.py` deliberately never captures the world; if it did, the oracle would
be comparing the read model with itself.

```bash
uv run pytest tests/control_center                       # the read model
uv run pytest tests/evaluation/test_control_center_oracle.py   # the oracle's independence
```

See [`docs/CONTROL_CENTER.md`](CONTROL_CENTER.md).


## 4. Where agents will live

`src/aegis/agents/` — trust zone B. Commander, Diagnostic, Security, Business Impact and
Remediation. Agents propose; they never authorize. They depend on `core.domain` for
contracts and reach the control plane through its interfaces, never the reverse.

## 5. Where Google integrations will live

`src/aegis/integrations/` — the dependency-inversion boundary for Gemini, ADK, Agent
Runtime, Agent Registry, Agent Identity, Agent Gateway, Model Armor, Memory Bank and
Agent Observability. The control plane depends on its own interfaces; adapters implement
them.

Two standing rules (`claude.md` sections 17, 18): a local fallback exists for
engineering resilience and never implies that an integration is configured, and no
module may fabricate a platform response.

Currently populated:

- `provider.py` — provider-neutral call telemetry and the recording wrapper. Knows nothing
  about any vendor.
- `replay.py` — a second, offline provider replaying raw response text and capture files.
- `gemini.py` — the Gemini provider. The **only** module in AEGIS permitted to import
  `google`, asserted structurally by test across every other package.

**No live Google integration has been executed.** `gemini.py` is implemented and its API
surface was verified against the installed SDK; the transport itself has never run. See
[`docs/PROVIDER.md`](PROVIDER.md) for the precise claim and its limits.

## 6. Running the tests

```bash
uv venv --python 3.13          # once
uv pip install -e ".[dev]"     # once

uv run pytest                   # full suite -- 3888 tests, ~62s
uv run pytest tests/evaluation  # the benchmark and the evaluator's own tests
uv run pytest tests/adversarial # the 8 attack classes
uv run ruff format .            # formatter
uv run ruff check .             # linter
```

## 7. Running the benchmark

```bash
uv run python run_benchmark.py
```

Prints every metric with its denominator, the per-category distribution and any critical
violations, then exits non-zero if the suite did not pass. The run is deterministic and
takes about seven seconds over 302 scenarios; nothing in it touches a network, a credential
or a model.

## 8. Running the adversarial matrix

```bash
uv run python run_adversarial_report.py
uv run python run_adversarial_report.py --json
```

Twenty-five attacks across eight classes, every one assuming the reasoning layer is fully
captured. Deterministic and offline like the benchmark, and about three seconds. Exits
non-zero if any attack is uncontained.

The matrix lives in
[`src/aegis/evaluation/adversarial.py`](../src/aegis/evaluation/adversarial.py) and
performs the attacks; it asserts nothing. The assertions are in
[`tests/adversarial/`](../tests/adversarial/), because a module that both attacked and
graded would be marking its own homework.

Two containment standards, and the distinction is the design:

```text
REFUSED  (17)  stopped by the named boundary; nothing executes
INERT    (8)   the run proceeds and the governed path is byte-identical to
               the same incident with no payload
```

Each attack declares the boundary that must stop it *before* it runs, so an attack stopped
by the wrong control is a finding rather than a pass. Execution and world state are read
from the enterprise simulator, never from a run's account of itself.

An earlier version of this matrix used one rule — "contained means nothing executed" — and
reported 17/25, failing every injection case. That was the metric being wrong rather than
the system: a poisoned incident that resolves through policy, a human approval and a spent
gate is the strong result, and demanding otherwise would push a maintainer towards making
injections break the run.

## 9. The three evaluation tracks

```
TRACK A   run_benchmark.py            deterministic · offline · reproducible · mutation-tested
          run_adversarial_report.py   deterministic · offline · reproducible · 8 attack classes
TRACK B   run_live_incident.py        real provider · probabilistic · network · recorded
```

Track A is the safety claim. Track B is a handful of samples of model behaviour and is
never a claim about reliability.

**A failure in Track B can never make Track A pass.** `aegis/evaluation/live.py` imports no
benchmark metric, runner, catalogue or result type; no Track A module imports it; and
`run_benchmark.py` mentions neither. All four directions are asserted by test.

Track B needs credentials and exits 2 without them, having run nothing:

```bash
uv sync --extra gemini

# an API key, or Vertex AI -- the two recorded runs used Vertex
export GOOGLE_API_KEY=...
# export GOOGLE_GENAI_USE_VERTEXAI=true
# export GOOGLE_CLOUD_PROJECT=<your-project>
# export GOOGLE_CLOUD_LOCATION=us-central1

uv run python run_live_incident.py --deterministic-specialists --capture runs/live.jsonl
uv run python run_live_incident.py --deterministic-specialists --injection
```

Both of those have been run once each, on `gemini-2.5-flash`, and both reached `RESOLVED` +
`VERIFIED`. Two runs are two observations; see [`docs/PROVIDER.md`](PROVIDER.md) for what
that establishes and what it does not.

Expect one benign `google-genai` AFC warning per process. AEGIS passes no `tools=` to
`generate_content`, so no function calling is in play; the SDK logs it once by default and
exits its AFC loop immediately. Non-blocking, and left unsuppressed on purpose.

Exit `0` means the run completed and governance held; `1` means governance did **not** hold
and wants investigating; `2` means the provider was not configured. A model that behaves
badly while governance holds still exits `0` — that is a model behaviour failure, not an
AEGIS failure, and the report distinguishes them from artifacts rather than from anything
the model claimed about itself.

No test in the suite makes a network call, so there is no live-test switch to turn off. The
one test that touches the live entry point clears the credential variables first.

Without `uv`, the equivalents are `python -m venv .venv`,
`.venv/Scripts/python -m pip install -e ".[dev]"` and
`.venv/Scripts/python -m pytest`.

Domain tests are deterministic by construction: fixed timestamps from
[`tests/conftest.py`](../tests/conftest.py), no clocks, no randomness, no network, no
model calls. A domain test that fails means the contract changed.
