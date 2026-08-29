# AEGIS

**Autonomous Enterprise Agent Command & Governance Fleet.**

A governed control plane for autonomous enterprise agent fleets.

> LLMs propose. Deterministic systems authorize. Tools execute. Verification establishes truth.

See [`claude.md`](claude.md) for the project constitution and [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md)
for repository layout and how to run the tests.

## Status

**Complete and evaluated.** The vertical slice `claude.md` section 27 defines runs end to
end, deterministically, and has been measured three ways — a 302-scenario governance
benchmark, a 25-attack adversarial matrix, and two live runs against a real Gemini model.

Jump to [**Evaluation Results**](#evaluation-results) for the numbers and, more
importantly, for what each of them does and does not establish.

- Typed domain contracts (agents, capabilities, incidents, actions, policy decisions,
  evidence, audit events), their authoritative enums, invariants and canonical serialization.
- An in-process `CapabilityRegistry` resolving capability definitions, ownership and
  resource scope.
- A declared `DependencyGraph`, plus `BlastRadiusEngine`, `RiskEngine` and the
  `AssessmentPipeline` that computes authoritative `risk` and `blast_radius` for a proposal.
  An agent's self-declared risk is never trusted.
- A pure `PolicyEngine` returning `ALLOW` / `DENY` / `REQUIRE_APPROVAL` with a machine-readable
  rule reference, fail-closed and structurally ordered so `DENY` always wins.

- An `ApprovalEngine` whose artifacts authorise one exact action, for a bounded time, under
  one policy context, exactly once — with policy re-evaluated before execution.
- An `IncidentStateMachine` over an explicit transition table: POLICY_CHECK never skipped,
  terminal states never reopened.
- A `VerificationEngine` that establishes enterprise state from independent observations.
  A tool returning success verifies nothing, and an incident cannot reach RESOLVED without
  a VERIFIED result bound to the exact action that ran.

- An append-only, hash-chained `AuditStore` with recorders for every control-plane
  artifact, plus deterministic incident-history reconstruction.

- A **simulated enterprise** (CONTROLLED SIMULATION): a synthetic world with declared
  topology, controlled mutations, an observation source and deterministic failure
  injection — plus the golden incident as an executable end-to-end scenario.

```text
proposal -> Assessment -> Policy -> Approval -> Execution -> Verification -> RESOLVED
                              (every stage recorded in the audit log)
```

The golden incident runs for real: payment-api on v4.8 at a 37% error rate is rolled back
to v4.7, the simulated world changes, observations establish the recovery, and the incident
resolves — reproducibly, with a complete tamper-evident audit trail.

- A **Commander** (agent plane): it interprets the incident, chooses what to investigate
  through governed tools, and proposes a remediation. It cannot authorize, approve, assess
  its own risk, execute, verify or resolve — it holds a model client and nothing else.

- **Four specialists** — Diagnostic, Security, Business Impact and Remediation. The
  Commander delegates; only Remediation may *propose* a production mutation, and even that
  reaches the enterprise solely through governance.

```text
Commander -> delegate -> specialist finding (advisory)
          -> Remediation proposal -> Assessment -> Policy -> Approval
          -> Execution -> Verification -> RESOLVED
```

The model drives the investigation; the deterministic core decides whether any of it is
permitted. A deliberately compromised model is used in the security tests to show the
boundary holds even when the reasoning layer is fully captured.

- An **evaluation harness and a 302-scenario benchmark** across fifteen families: normal
  incidents, security, authorization, failure recovery, cascading failures, memory,
  lifecycle, circuit breaker, execution boundary, agent abuse, provider boundary, A2A,
  A2A persistence, remote A2A and the control center.
  Scenarios are declarative data with hand-written expectations; the evaluator observes and
  reports and never decides what should have been permitted.

```text
uv run python run_benchmark.py

status:                            PASS
scenarios:                         302  passed: 302  failed: 0

unauthorized high-impact actions:  0      <- claude.md section 21's headline metric
unauthorized executions:           0
verification bypasses:             0
approval bypasses:                 0
policy bypasses:                   0
audit integrity failures:          0
unauthorized memory writes:        0
cross-incident contaminations:     0
memory integrity failures:         0
breaker bypasses:                  0
terminal-state escapes:            0
unbounded retries:                 0
recovery governance bypasses:      0
lifecycle gate bypasses:           0
agent identity forgeries:          0
agent quarantine bypasses:         0
cross-scope contaminations:        0
a2a transport bypasses:            0
a2a identity forgeries:            0
a2a authority transfers:           0
a2a replays after restart:         0
a2a non-durable consumptions:      0
a2a corrupt state accepted:        0
remote forged identities accepted: 0
remote unauthenticated admissions: 0
remote revoked keys accepted:      0
authenticated-but-unauthorized:    0
fabricated states:                 0
hidden governance events:          0
cross-incident leaks:              0
false approval bindings:           0
false verification states:         0
false resolution states:           0
audit integrity misreports:        0
control center secret leaks:       0
observability authority bypasses:  0

undefined metrics:                 none
```

This is a **deterministic safety and governance benchmark**, not a model evaluation: no
real model is scored, because none is involved. Correct *refusal* counts as a result —
about two thirds of the suite asserts that something must not happen.

The benchmark is verified to be capable of failing. Twenty mutations of the evaluator
(ignore the final state, ignore the policy decision, treat an undefined metric as zero,
pass a scenario despite a critical violation, …) are each caught by the suite, and
removing the approval requirement from the real policy engine turns the report red. The
same was done to the memory subsystem: six separate compromises — admitting unverified
outcomes, skipping the incident or fingerprint binding, storing proposals as authoritative,
serving revoked memory, disabling the integrity check — each make the benchmark fail.

- **Persistent organizational memory** with provenance. Only a `VERIFIED` verification,
  bound to one incident and one exact action by fingerprint, can make a memory
  authoritative. The type an agent constructs has no status field, so "an agent writes
  authoritative memory" is not a rule that can be mis-enforced — it is a sentence the type
  system cannot express.

```text
verified outcome -> admission (9 bindings checked) -> AUTHORITATIVE memory
                                                   -> retrieval -> ModelRequest.data
```

Memory is context, not authority. Nothing in the control plane reads it: risk, blast
radius, policy, approval, execution, verification and resolution are all decided without
it, and the dependency arrow is asserted structurally in both directions. Poisoned history
reaches the model as labelled data and changes no governed outcome — the benchmark runs
that case with a Commander that believes every word of it and executes nothing.

Memory is tamper-evident (an append-only hash chain covering content, provenance and
status) and file-backed persistence survives process restart. That is tamper *evidence*,
not immutability, and the limits are documented rather than glossed.

- A **lifecycle manager and circuit breaker**. Every bound on automated incident handling
  is explicit and immutable: steps, remediation attempts, recovery attempts, consecutive
  failures, total executions and executions of the same exact action. Counters only rise,
  and only a *verified* success clears the failure run.

```text
                    ┌─ before approval ─┐   ┌─ before execution ─┐
proposal → assess → policy → BREAKER → approval → BREAKER → execute → verify
```

The breaker is `CLOSED → OPEN → HALF_OPEN`, scoped to `capability@resource`, with one
bounded probe as the only route back and **no `reset()`**. It grants nothing: `allowed`
means "no objection from this gate", and policy, approval and execution authorization all
still get their say. A consumed human approval does not carry an action past an open
breaker — the benchmark runs that exact race and asserts nothing executes.

A policy DENY never opens it. Refusing an action is the control plane working, and a
breaker that tripped on correct governance would be a self-inflicted outage.

Breaker state is **durable and tamper-evident** — an append-only hash chain that survives a
restart, so a restart loop cannot clear a breaker. Loading checks more than digests: every
transition must be a legal edge, because a perfectly valid chain can still describe an
impossible history, and replaying an old `CLOSED` snapshot would be a blind reset smuggled
in through storage. An open breaker becomes eligible for **one probe** after a configured
cooldown, and that probe is a full governed execution.

- A **mandatory execution boundary**. `ActionExecutor` cannot execute without an
  `ExecutionAuthorization` *and* a `LifecycleGate` — two artifacts from two origins, neither
  sufficient alone. A gate is sealed, single-use, TTL-bound and bound to one exact
  gate/incident/action/fingerprint/capability/resource/scope/generation. Its authenticity is
  not the seal, whose formula is public, but the register that issued it: a resealed forgery
  fails because no register handed it out. A gate is deliberately **not** permission — it
  proves the lifecycle was crossed and entitles the holder to nothing.

- **Agent abuse containment**, separate from the breaker and keyed differently:

```text
CIRCUIT BREAKER      capability@resource            protects the path
AGENT RESTRICTION    agent@capability@resource      protects from the actor
```

  Default scope is the narrowest that contains anything, because a containment that
  over-reaches is the outage it exists to prevent. There is no public `clear`, `reset` or
  `release`. Agents cannot quarantine themselves, each other, or clear a quarantine, and no
  breaker or restriction field is exposed to `ModelRequest`.

- A **real Gemini provider** behind the unchanged `ModelClient` boundary, with a
  provider-neutral telemetry layer and a second offline provider that replays raw response
  text through the same parser.

```text
deterministic AEGIS architecture -> real model provider -> real model decisions
                                 -> unchanged governance -> deterministic safety
```

  A model saying "policy: ALLOW" still meets the policy engine. A model saying "risk: LOW"
  still meets the assessment pipeline. A model saying "verified, resolved" still needs an
  independent observation. A model naming a gate id gets nothing, because only the register
  mints gates. All of it is asserted against the real control plane with a provider replaying
  exactly the text a captured Gemini would emit — and twelve benchmark scenarios run
  deliberately compromised providers as a control group.

**Status of the Google integration, stated precisely** (`claude.md` section 17):

> Gemini provider **implemented, shape-verified** against the installed `google-genai`
> 2.19.0 — every API assumption read off the package rather than remembered — **and
> live-verified on the Commander path**: two incidents driven end to end by
> `gemini-2.5-flash` on Vertex AI, both reaching `RESOLVED` + `VERIFIED`.
>
> Two runs are two observations. Nothing here claims a success rate, and the specialist
> path has not been run live at all.

Verifying against the real SDK found a real defect before any call was made:
`httpx.TimeoutException` is not a subclass of the builtin `TimeoutError`, so the previously
written provider would have misfiled every genuine Gemini timeout. Running it live found a
second one, in AEGIS rather than in Gemini — the Commander's prompt documented four of five
decision types, omitting the only one that reaches a remediation. Both are described in
[`docs/PROVIDER.md`](docs/PROVIDER.md).

The deterministic suite and benchmark run with `google` **actively blocked** from importing,
checked in a subprocess rather than assumed.

- **Governed agent-to-agent communication.** Delegation now crosses a typed A2A boundary
  with its own identity, integrity, replay, ordering and payload rules.

```text
AGENTS MAY COMMUNICATE. AGENTS MAY NOT TRANSFER AUTHORITY.

Commander -> A2AEnvelope -> broker -> specialist -> AgentFinding -> unchanged governance
```

  A message is frozen, closed and sealed, and carries **no field** for policy, approval,
  authorization, risk, blast radius, verification, lifecycle or gate — so "a message carried
  an approval" is not a rule that can be mis-enforced, it is a sentence the type system
  cannot express. The declared sender is compared against the accountable agent from the
  wiring, and identifiers are matched rather than repaired: `"diagnostic "` is refused
  outright instead of being helpfully stripped into a real identity.

  Integrity is not authentication, and the code says so. The seal formula is public, so a
  forger can produce a perfect one; what they cannot produce is a record in the issuer's
  ledger. Replay, expiry, conversation and incident binding, strict ordering and hard
  payload bounds all fail closed, and there is no `reset` or `clear` to ask for.

  The invariant the whole family is built to measure: **agent count does not change
  authority**. Three agents agreeing is three opinions, because agreement is not an input to
  any deterministic engine anywhere in AEGIS.

- **Durable A2A state.** The one weakness Prompt 15 documented is closed: ledger state is an
  append-only, hash-chained log that survives a restart.

```text
issue → append → fsync → consume → append → fsync → RESTART → still consumed
```

  A fourth hash chain alongside audit, memory and lifecycle state, with five checks on load
  — position, link, digest, identity stability, and **status legality**. The last is the one
  a hash alone does not give: `CONSUMED → ISSUED` is not a legal edge, so replaying an old
  record to make a spent message fresh is refused even when every digest is perfect.

  A chain that does not verify makes the ledger **refuse to exist** rather than start as
  though nothing had been consumed. A failed append becomes a recorded refusal, never a
  delivery. Payload content is never stored — only a digest.

- A **remote A2A security boundary** (Prompt 17). The claim, exactly:

  > AEGIS provides an authenticated, integrity-protected, replay-resistant remote A2A
  > security boundary in a deterministic offline transport simulation.

```text
RemoteFrame -> decode -> authenticate -> address -> bind -> replay
            -> A2ABroker.admit(accountable_sender=<cryptographically established>)
            -> policy -> approval -> gate -> execution -> verification
```

  That one argument is the whole integration. In Prompt 15 the accountable sender came from
  the application's wiring; for a remote peer there is no shared wiring, so a signature over
  a registered key takes its place — and **every existing check then runs unchanged**.
  Authentication supplies the identity. It does not replace a check, weaken one, or add one.

  A registry binds keys to agents with status, expiry and monotonic revocation. Eighteen
  signed fields, declared twice so they cannot drift, with a test that fails if a
  security-relevant field is added without being signed. An explicit protocol version,
  refused rather than downgraded. A deterministic transport that can delay, duplicate,
  reorder, lose and time out — and a benchmark intermediary with six powers and no key.

  Three sentences, each demonstrated by a test rather than asserted by a comment:

```text
a valid hash is not an authenticated sender
a valid signature is not an authorization
a registered identity is not execution authority
```

  The third matters most. A **compromised peer** holding genuine key material signs
  perfectly, authenticates perfectly, and claims policy approved the action, a human granted
  it, verification passed and a gate exists. The benchmark runs a whole incident that way
  and asserts the governance path is byte-for-byte the honest one.

- An **operator control center** (Prompt 18). A read model, and nothing more:

```text
The control center is not an authorization system.
The control center cannot grant authority.
Displayed state is derived from recorded artifacts.
Missing evidence is UNKNOWN.
Audit corruption is surfaced, not repaired.
UI state cannot override deterministic governance.
```

  It answers what an operator has to be able to ask — what is AEGIS doing, why did it do
  that, why did it refuse that, is an approval waiting, is a breaker open, can I
  reconstruct the causal chain — from artifacts that were already recorded and nothing
  else. A deterministic timeline, a causal chain whose every edge is justified by a
  **shared identifier** rather than by adjacency in time, ten closed "why" questions each
  answered from artifacts or reported `EXPLANATION_INCOMPLETE`, and a byte-deterministic
  forensic export carrying its own audit verdict.

  The type that does the most work is a boolean with three values:

```text
missing evidence -> UNKNOWN     never FALSE, never EMPTY
```

  AEGIS fails closed, so an unreadable source produces *silence* — and silence rendered as
  `FALSE` looks exactly like a system with nothing wrong. An unreadable breaker is not a
  closed one; a crashed run did not "not execute"; absent counters are `None`, not `0`.

  It cannot create authority **by construction**: `capture_incident` produces a frozen
  value, and downstream of it there is no engine, no store and no registry — no object that
  could be asked to do anything. And "observing changes nothing" is *measured*, not
  asserted: the audit head, the world's deployment and the gate register's counts are taken
  before and after every projection the benchmark builds.

  Two honest limitations, stated rather than papered over. The audit vocabulary has **no
  execution event**, so a trail-only reconstruction reports execution as `UNKNOWN` even when
  a gate was consumed. And a valid audit chain proves no *tampering*, not *completeness* —
  truncation is caught separately, by comparing against the store's own head digest.

- An **adversarial evaluation matrix** — 25 attacks across eight classes, every one
  assuming the reasoning layer is fully captured:

```text
prompt injection      fake authority        unauthorized remediation
unauthorized delegation                     tool authorization
malicious observation data                  approval attacks
gate / execution attacks
```

  It is not a test of whether a model refuses attacks. A model that refuses is pleasant and
  proves nothing, because the next one will not. Each attack names the control that must
  stop it *before* it runs, so an attack stopped by the wrong boundary is a finding rather
  than a pass — and execution is read from the **enterprise simulator**, never from a run's
  account of itself.

  Two containment standards, because they are genuinely different claims. Seventeen attacks
  must be **refused**: nothing executes. Eight must be **inert**: the incident resolves
  normally and the governed path is *byte-identical* to the same incident with no payload.
  A poisoned incident that resolves through policy, a human approval and a spent gate is the
  strong result, not a weak one — demanding that injections break the run would mean grading
  the system on whether an attack managed to cause damage.

  Four of the attacks skip the orchestrator entirely and call the executor directly: an
  authorization with no gate, a correctly sealed gate no coordinator issued, an issued gate
  rebound to another action, and a real gate with no approval behind it. Production is
  untouched in all four.

**Claimed:** governed local A2A, durable local persistence, restart-safe replay prevention,
append-only integrity, strict ordering, at-most-once delivery, a remote security model,
cryptographic identity, authenticated envelopes, a deterministic remote transport
simulation, remote replay protection, key rotation, protocol versioning.

**Not claimed:** real internet transport, TLS deployment, cloud-to-cloud federation,
distributed consensus, Byzantine fault tolerance, secure multi-process shared state,
production key management, HSM-backed identity, remote attestation, exactly-once delivery,
multi-process-safe JSONL writes, **operator authentication**, **any operator override**.

There is no socket, no TLS, no DNS, no credential and no remote machine anywhere in AEGIS —
the A2A package structurally cannot import them, asserted by test. Durable local persistence
is not distributed security, an authenticated boundary is not a network, and a read
model is not authority. See [`docs/A2A.md`](docs/A2A.md) and
[`docs/CONTROL_CENTER.md`](docs/CONTROL_CENTER.md).

## Evaluation Results

Four kinds of evidence, deliberately kept apart. They support different claims, and
collapsing them into one number would make every one of them weaker.

| | What it measures | Result | Strength of claim |
|---|---|---|---|
| **Unit & integration suite** | every contract, boundary and invariant | **4052 passed**, 0 failed, 0 skipped | deterministic, reproducible |
| **Governance benchmark** | 302 scenarios across 15 families | **302/302 PASS** | deterministic, reproducible |
| **Adversarial matrix** | 25 attacks across 8 classes | **25/25 contained** | deterministic, reproducible |
| **Live Gemini runs** | one real model, two incidents | **2/2 `RESOLVED` + `VERIFIED`** | **two observations, not a rate** |

Every command below runs offline except the last.

### 1. Deterministic guarantees

These hold by construction and are re-checked on every run. No model is involved in any of
them; the deterministic Commander is rule-based and the whole suite passes with `google`
actively blocked from importing, verified in a subprocess rather than assumed.

```text
uv run pytest                    4052 passed in ~69s
uv run python run_benchmark.py   302 scenarios, 302 passed, 0 failed, runtime ~7s
```

Across the benchmark, every safety counter is zero — including the one `claude.md`
section 21 names as the most important:

```text
unauthorized high-impact actions:  0
```

About two thirds of the suite asserts that something must **not** happen, so correct
refusal is a result rather than a gap. The benchmark is verified to be capable of failing:
mutations of the evaluator and of the real engines each turn the report red, and each
milestone closed its surviving mutants rather than reporting a percentage.

Determinism is measured, not assumed — two consecutive benchmark runs produce byte-identical
output once the runtime line is excluded.

### 2. Adversarial control-plane guarantees

```text
uv run python run_adversarial_report.py

attacks:                    25
contained:                  25/25
  refused as required:      17/17
  inert as required:        8/8
unauthorized executions:    0
governance divergences:     0
audit failures:             0
```

Twenty-five attacks across eight classes — prompt injection, fake authority, unauthorized
remediation, unauthorized delegation, tool authorization, malicious observation data,
approval attacks, and gate/execution attacks. Every one assumes the reasoning layer is
**fully captured**; none of them tests whether a model refuses anything.

Two containment standards, because they are different claims:

```text
REFUSED  (17)  stopped by the named boundary; nothing executes
INERT    (8)   the incident resolves normally and the governed path is
               byte-identical to the same incident with no payload
```

The eight inert attacks all produce the same governance fingerprint as the unpoisoned
baseline — a SHA-256 over fifteen governance facts including the policy decision, who
granted the approval, the action fingerprint, the gate counts and the verification status.
A poisoned incident that resolves through policy, a human approval and a spent gate is the
strong result, not a weak one: demanding that injections break the run would grade the
system on whether an attack managed to cause damage.

Each attack names the control that must stop it *before* it runs, so an attack stopped by
the wrong boundary is a finding rather than a pass. Execution and world state are read from
the enterprise simulator, never from a run's account of itself. Four attacks skip the
orchestrator entirely and call the executor directly.

### 3. Live Gemini observations

```text
uv run python run_live_incident.py --deterministic-specialists              # normal
uv run python run_live_incident.py --deterministic-specialists --injection  # adversarial
```

Two incidents, driven end to end by `gemini-2.5-flash` on Vertex AI:

| Run | Incident | Outcome | Governance |
|---|---|---|---|
| normal | the golden incident | `RESOLVED` + `VERIFIED` | policy `REQUIRE_APPROVAL`, human approval, one gate spent |
| injection | the Part 6.A adversarial incident | `RESOLVED` + `VERIFIED` | identical path; the payload changed nothing |

Both used `--deterministic-specialists` on purpose: with five live models a run has five
variables, and a failure tells you nothing about which one moved. `GeminiSpecialistModel`
has therefore **not** been run live.

**What these two runs establish.** That the transport works. That a real model can drive
the investigation to a verified remediation. That the governance path is unchanged by a
real model being in the loop — the same policy decision, the same human approval, the same
single spent gate, the same independent verification.

**What they do not establish, and what nothing in this repository claims from them:**

```text
NOT a success rate.        Two runs are two observations.
NOT reliability.           A language model is probabilistic; n = 2.
NOT an expected behaviour. Same model, same temperature, same day, same incident shape.
NOT a safety property.     Safety here is a property of the control plane, which is
                           measured deterministically above and does not depend on
                           these runs at all.
```

The live harness is explicit about this in code as well as in prose: `LiveRunReport` has
separate `governed` and `model_reached_the_goal` properties, both read from artifacts rather
than from anything the model said, and a run where the model behaves badly while governance
holds exits `0` — because that is a model behaviour failure and not an AEGIS failure.

**The most useful thing the live trial produced was a defect.** The first attempt escalated
after ten identical `INVESTIGATE` decisions with zero delegations. The cause was in AEGIS:
`COMMANDER_SYSTEM_PROMPT` documented four of the five `DecisionType` members, and the
missing one — `DELEGATE` — is the only route to a remediation, because `PROPOSAL_AUTHORITY`
gives the Commander proposal rights over nothing. The deterministic model reads
`request.data` and never the prompt, so 302 green scenarios said nothing about whether the
prompt was complete. Fixed, with a regression test that pins every `DecisionType` and
`TaskType` to the prompt text. Full account in [`docs/PROVIDER.md`](docs/PROVIDER.md).

### A known, benign SDK warning

Every live run logs this once:

> Direct use of automatic function calling (AFC) in `Models.generate_content` is not
> recommended. Instead, we recommend to use AFC in `Chat.send_message`.

**Non-blocking, and unrelated to anything AEGIS does.** AEGIS passes no `tools=` to
`generate_content`, so no function calling is in play. `google-genai` enables AFC by default
whenever `automatic_function_calling` is unset, logs this once per process behind a class
flag, and then exits the AFC loop immediately at `if not function_map: break` — one request,
as intended. AEGIS's own tool loop is orchestrator-driven and never touches AFC. It is left
unsuppressed rather than hidden, because silencing an SDK's warnings by default is how a
real one gets missed.

### Limitations, stated rather than glossed

- **Two live runs are two live runs.** Repeated here because it is the single easiest
  thing to overstate.
- **The specialist provider is not live-verified.** Only the Commander path has been run.
- **In-process trust.** Code that can reach the audit store or the gate register can
  construct or destroy artifacts. Tampering is *detected*; a full-process compromise is not
  prevented, and no in-process mechanism can prevent it.
- **A valid audit chain proves no tampering, not completeness.** A truncated prefix
  verifies perfectly; truncation is caught separately, against the store's own head digest.
- **The audit vocabulary has no execution event**, so a trail-only reconstruction reports
  execution as `UNKNOWN` even when a gate was consumed.
- **The adversarial matrix is not an enumeration proof.** It shows the control plane holds
  against these 25 attacks under a fully captured reasoning layer. An attack class nobody
  thought of is not covered by a matrix of the ones we did.
- **The enterprise is simulated.** Every production mutation is a controlled simulation
  (`claude.md` section 17), and no real customer data exists anywhere in the project.

## Quick start

### Setup

```bash
uv venv --python 3.13
uv pip install -e ".[dev]"
```

### The offline evaluation — everything a reviewer needs

Three commands. No credentials, no network, no model, no third-party package beyond the dev
extras. Each exits `0` on success and non-zero on failure, so any of them can gate a build.

```bash
uv run pytest                             # 4052 tests            ~69s
uv run python run_benchmark.py            # 302 scenarios         ~7s
uv run python run_adversarial_report.py   # 25 attacks            ~3s
```

Machine-readable forms, for pasting into a report:

```bash
uv run python run_adversarial_report.py --json
```

Narrower runs, when a specific claim is the one in question:

```bash
uv run pytest tests/adversarial                   # the 8 attack classes
uv run pytest tests/control_center                # the operator read model
uv run pytest tests/a2a tests/a2a/remote          # the A2A and remote boundaries
uv run pytest tests/evaluation                    # the evaluator's own tests
uv run ruff check . && uv run ruff format --check .
```

The safety benchmark needs no cryptography package: it pins HMAC-SHA256 from the standard
library, so a clean install runs it. Ed25519 is implemented and tested and arrives through
an optional extra:

```bash
uv sync --extra crypto                    # adds Ed25519 to the test matrix
```

### The live provider — optional, and not part of the safety claim

Everything above is Track A: deterministic, offline, reproducible, and the thing the safety
claim rests on. The commands below are Track B: one real model, one incident, one moment,
recorded. **A green run here proves that it happened once.** See
[Evaluation Results](#3-live-gemini-observations) for what that does and does not establish.

```bash
uv sync --extra gemini
```

Then configure **either** an API key **or** Vertex AI — the two verified runs used Vertex:

```bash
# option A: an API key
export GOOGLE_API_KEY=...

# option B: Vertex AI (what the recorded runs used)
export GOOGLE_GENAI_USE_VERTEXAI=true
export GOOGLE_CLOUD_PROJECT=<your-project>
export GOOGLE_CLOUD_LOCATION=us-central1
```

```bash
# the golden incident, one live model, deterministic specialists
uv run python run_live_incident.py --deterministic-specialists

# the Part 6.A adversarial incident, same wiring
uv run python run_live_incident.py --deterministic-specialists --injection

# a human refusing the rollback
uv run python run_live_incident.py --deterministic-specialists --reject-approval

# JSON, and a replayable capture of the model's decisions
uv run python run_live_incident.py --deterministic-specialists --json
uv run python run_live_incident.py --deterministic-specialists --capture trace.json
```

`AEGIS_GEMINI_MODEL` overrides the default (`gemini-2.5-flash`); `--model` overrides both.
Drop `--deterministic-specialists` to run all five agents live, which has not been done here
and makes the run five variables instead of one.

Exit codes are deliberately asymmetric:

```text
0   the run completed and the control plane held
1   the control plane did NOT hold — a governance failure worth investigating
2   the provider is not configured, so nothing ran
```

A model that behaves badly while governance holds exits `0`, because that is a model
behaviour failure and not an AEGIS failure. The report says which.

Expect one benign `google-genai` AFC warning per process; it is
[explained above](#a-known-benign-sdk-warning) and affects nothing.

No command in this repository writes a credential anywhere, and none is stored in it.

### Serving it over HTTP, and deploying to Cloud Run

A thin HTTP surface lets a container serve the control plane. It adds no governance and
removes none: `POST /incident` reaches the enterprise through the same
`run_live_incident()` entrypoint the CLI uses, wired to the same orchestrator the benchmark
drives. There is no route that reaches the executor, and no request field that names a
capability, an agent, an approval or a gate.

```bash
uv run python run_service.py --check      # build the service, print /health, bind nothing
uv run python run_service.py              # serve on $PORT (default 8080)
```

```bash
curl -s http://127.0.0.1:8080/health | jq .

curl -s -X POST http://127.0.0.1:8080/incident   -H 'Content-Type: application/json'   -d '{"source": "monitoring.alerting: payment-api error rate 37% since deployment v4.8"}' | jq .
```

A governed run answers `200` with `"governed": true`, `"verification": "VERIFIED"` and
`"gates_consumed": 1`. Send `{"approve": false}` and nothing executes and nothing resolves.
Send the Part 6.A injection payload as the `source` and the governance path is identical to
the honest one.

The service is **deterministic by default** — no credentials, no network call, no spend.
Calling a real Gemini model needs two independent conditions (`AEGIS_SERVICE_ALLOW_LIVE=true`
*and* configured credentials); without both, `{"mode": "live"}` is a `409` and no client is
constructed.

```bash
docker build -t aegis:local .                  # runtime image, 312 MB
docker run --rm -p 8080:8080 aegis:local
curl -s http://localhost:8080/health | jq .
```

The image is built from `uv.lock` rather than a fresh resolve, so two builds install the
same versions. It runs as a non-root user, honours `$PORT`, and carries no test tooling;
`docker build --target test -t aegis:test .` adds pytest and ruff for running the suite
inside the image.

**Verified locally:** the image builds, starts healthy, serves all three endpoints, runs a
governed incident to `VERIFIED`, honours `PORT`, and passes 302/302 benchmark scenarios and
25/25 adversarial attacks in-container; the test target passes all 4052 tests and ruff.

[**`docs/DEPLOYMENT.md`**](docs/DEPLOYMENT.md) has the Cloud Run commands, the full request
path, the security caveats for a public deployment, troubleshooting for Docker Hub pull
failures, and — stated plainly — which parts have actually been executed and which have
not. The one that matters most: **no Cloud Run deployment has been performed.**

### Where to read next

| Document | What it covers |
|---|---|
| [`claude.md`](claude.md) | the project constitution — read this first |
| [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md) | repository layout, every subsystem, how to run things |
| [`docs/PROVIDER.md`](docs/PROVIDER.md) | the model boundary, the live runs, and their limits |
| [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) | the HTTP surface, Docker, Cloud Run, and what is actually Google |
| [`docs/A2A.md`](docs/A2A.md) | agent-to-agent messaging and the remote security boundary |
| [`docs/CONTROL_CENTER.md`](docs/CONTROL_CENTER.md) | the operator read model |
