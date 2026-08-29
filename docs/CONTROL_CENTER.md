# The operator control center

> **The control center is not an authorization system.**
> **The control center cannot grant authority.**
> **Displayed state is derived from recorded artifacts.**
> **Missing evidence is UNKNOWN.**
> **Audit corruption is surfaced, not repaired.**
> **UI state cannot override deterministic governance.**

Those six lines are the whole contract. Everything below serves them.

---

## 0. What this is, and what it is not

A **read model**. It answers the questions an operator has to be able to ask — what is
AEGIS doing, why did it do that, why did it refuse that, which agent caused the proposal,
which policy caused the decision, is an approval waiting, is a breaker open, is an agent
restricted, can I reconstruct the causal chain — from artifacts that were already recorded,
and from nothing else.

### Claimed

- deterministic incident timeline, causal chain and governance explanation
- an approval always displayed with the exact action it authorises
- three-way separation of capability, proposal authority and current restriction
- lifecycle counters, stop reason and breaker state, displayed and unadjustable
- memory labelled `HISTORICAL CONTEXT ONLY`, with revocations resolved
- A2A messages with five separate statuses and no key material
- security events that distinguish `DETECTED` from `REFUSED` from `CONTAINED`
- per-view provenance and freshness, never flattened into one "current state"
- audit-chain re-verification, **including truncation detection**
- strict cross-incident isolation
- deterministic, secret-free forensic export

### Not claimed

- **any authority whatsoever.** No operator action, no override, no approval, no execution
- operator authentication or authorization — out of scope (Part 31), and absent
- a web UI, a dashboard server, or any external service
- that "read-only" means safe to expose: incident contents can be sensitive
- completeness of a source the control center could not read
- that a valid audit chain proves a *complete* history (see §7)

---

## 1. Architecture

```
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
errors.py        one error, for a caller mistake
```

```
live orchestrator
      |  capture_incident()      <- the only place a live object is touched
      v
ControlCenterInput               <- frozen. Nothing downstream can act.
      |  project_incident()
      v
IncidentProjection               <- frozen, canonically serializable
      |  export_incident()
      v
IncidentExport                   <- deterministic forensic document
```

---

## 2. The read-only boundary

Enforced in four layers, each strictly stronger than the last.

**1. No engine is importable.** The package cannot name `PolicyEngine`, `ApprovalEngine`,
`ActionExecutor`, `VerificationEngine`, `AssessmentPipeline`, `CircuitBreaker`,
`AgentRestrictionRegistry`, `GateRegister`, `A2ABroker`, `MemoryStore`, `AuditStore`,
`AuditRecorder`, `EnterpriseWorld`, `IncidentOrchestrator` or their kin — asserted by test
over parsed imports. Only the `from X import name` form is permitted for AEGIS packages, so
what is reachable is exactly what is listed.

**2. No mutating call exists.** No `execute`, `approve`, `authorize`, `issue`, `consume`,
`revoke`, `admit`, `record_failure`, `request_gate`, `persist` anywhere in the package.

**3. Nothing it holds could act.** Downstream of `capture.py` there is no engine, no store
and no registry — `ControlCenterInput` holds frozen domain models, strings, booleans,
integers and timestamps. **There is no object here that could be asked to do anything.**

**4. Observing changes nothing — measured, not asserted.** The audit head digest, the
world's deployment and the gate register's counts are taken *before* and *after* every
projection the benchmark builds. A projection that moved any of them is a projection that
acted, whatever its imports say. That figure is
`observability_authority_bypasses`, and it is a measurement rather than a constant.

`capture.py` is the one module that touches a live object. It is duck-typed, reads through
two helpers (`_read`, `_call`), and every call site passes a **literal** method or attribute
name — asserted by test — so the set of reachable operations is:

```
records  verify_integrity  conversation_ids  messages_for  snapshot  check  key_for
```

Seven read-only methods, written down.

---

## 3. The read model's vocabulary

### `Tri` — a boolean that can also be "we do not know"

The most important type in the package. Almost every operator question is answered from
artifacts that may not exist, and the honest third answer has to be *representable* or it
will be rounded to the convenient one.

```
missing evidence -> UNKNOWN
```

Never `FALSE`, never `EMPTY`, never a default that happens to look reassuring. AEGIS is
built to fail closed, so an unreadable source produces **silence** — and silence rendered as
`FALSE` looks exactly like a system with nothing wrong.

`Tri.of(None)` is `UNKNOWN`. The conversion lives in one place precisely so it cannot be
done wrong in several.

### `Certainty` — observed, derived, or unavailable

`OBSERVED` is read off an artifact. `DERIVED` is computed from artifacts by a rule stated in
the view's docstring — deliberately not called "inferred", which would invite a reader to
imagine judgement. `UNAVAILABLE` carries no value, enforced at construction: a `Fact` that
is observed or derived **must** have one, and one that is unavailable **must not**.

### `Provenance` — which source, as of when, how complete

Attached to every view, and **not flattened**. Two views captured from different sources are
two observations; presenting them as a single "current state" would assert something that
was never true all at once.

---

## 4. Data sources

| View | Source | Notes |
|---|---|---|
| timeline | `AUDIT` (+ `RUN` for execution) | see §5 |
| causal chain | `RUN` + `AUDIT` | edges joined on identifiers only |
| governance | `RUN` | policy, assessment, approval, gate |
| approvals | `RUN`, falling back to `AUDIT` | fingerprint required |
| verification | `RUN` | three separate tri-states |
| agents | `RESTRICTION_REGISTRY` + `REGISTRY` | three fields, three sources |
| lifecycle / breaker | `LIFECYCLE_STATE` / `BREAKER` | counters `None`, never `0` |
| memory | `MEMORY` | historical context only |
| A2A | `A2A_LEDGER` + `AUDIT` | ledger owns routing; audit owns authentication |
| security | `AUDIT` | detection ≠ prevention |

**The enterprise world is deliberately absent.** If the control center could read it, the
projection could report "the deployment changed" as an execution — and the benchmark's
oracle, which reads the world precisely to check the projection against something it cannot
see, would be comparing the read model with itself.

---

## 5. The one phase the audit trail cannot answer

**Execution.** The audit vocabulary has no `execution.*` member. A consumed lifecycle gate
says authorization was *spent*, which is not the same as production being *changed*.

So `Phase.EXECUTION` is answered by the run's own `ExecutionResult`, and reports `UNKNOWN`
when no run was captured — **even when the trail shows the state machine reaching
`EXECUTING`, and even when a gate was consumed**. Those are observations about the state
machine and about authorization; neither is an observation about production.

This is a real limitation of the trail rather than of the read model, and it is not papered
over. Adding an `execution.*` audit event would close it and was deliberately left out of
scope for this milestone (Part 31).

---

## 6. Freshness and UNKNOWN semantics

Every view declares `AS_OF`, `SOURCE` and `COMPLETE` / `PARTIAL` / `UNKNOWN`.

| Situation | Reported as | Never |
|---|---|---|
| audit store unreadable | `trust = UNAVAILABLE`, every phase `UNKNOWN` | `EMPTY` |
| audit chain invalid | `trust = UNTRUSTED`, entries shown, claim withdrawn | repaired |
| trail truncated | `truncated = TRUE`, projection `PARTIAL` | `COMPLETE` |
| no run captured | execution/verification/resolution `UNKNOWN` | `FALSE` |
| lifecycle unreadable | counters `None`, breaker `UNKNOWN` | `0`, `CLOSED` |
| restriction registry unreadable | restriction `UNKNOWN` | `ACTIVE` |
| memory store unreadable | `provenance.source = NONE` | "no memories" |
| A2A ledger unreadable | `provenance.source = NONE` | "no messages" |

`ProjectionStatus` is the **worst** of what the sources reported, never the average and
never the best. A projection is only as trustworthy as its least trustworthy input.

---

## 7. Audit integrity

Every view derived from the trail re-verifies the chain. Three outcomes:

- `TRUSTED` — the chain verifies
- `UNTRUSTED` — it does not; `first_invalid_index`, `reason` and `trusted_prefix` are all
  reported, entries are still shown, and **nothing is repaired**
- `UNAVAILABLE` — the store could not be read, which is a missing source rather than
  evidence of tampering

Plus a fourth fact, kept separate: **`truncated`**.

> A valid chain proves no *tampering*. It says nothing about *completeness*.

A truncated prefix verifies perfectly and looks exactly like a shorter history. It is caught
by comparing the last record's digest against the **store's own head digest** — the only
thing that can distinguish a short history from a docked one. When the trail is truncated,
absence stops being evidence: every missing phase becomes `UNKNOWN` rather than `FALSE`.

A corrupted audit chain does **not** invalidate the run's own artifacts. `Phase.EXECUTION`
still stands on the `ExecutionResult`, because a damaged trail is not a reason to withdraw a
separate fact an operator still has.

---

## 8. Incident isolation

Every view filters by incident id **before** reading anything, so filtering is a property of
how data is gathered rather than a step somebody could forget after assembling it.

Tested against the hardest arrangement: two runs, same resource, same fleet, same
capability, one shared audit store, different outcomes. The strongest assertion is that the
projection built over both histories is **equal** to the one built over its own alone.

Isolation does not relax when a source breaks. A view that stopped filtering when it stopped
trusting would leak precisely when an operator is least able to notice.

---

## 9. The distinctions each view refuses to collapse

| View | Refuses to collapse |
|---|---|
| timeline | "the state machine entered EXECUTING" vs "production changed" |
| timeline | a specialist *result* vs a specialist *finding* |
| causal chain | a shared identifier vs adjacency in time |
| approvals | "approved" vs "approved **this exact action**" |
| verification | `EXECUTED` vs `VERIFIED` vs `RESOLVED` |
| agents | capability grant vs proposal authority vs current restriction |
| breaker | `CLOSED` vs `OPEN` vs `HALF_OPEN`; open vs quarantined |
| memory | historical context vs current enterprise state; held vs authoritative |
| A2A | authentication, identity, integrity, replay, consumption — five statuses |
| security | `DETECTED` vs `REFUSED` vs `CONTAINED` |

The security vocabulary has **no `BLOCKED` member**. It is the word an operator would read
as "we are safe" and the one this package is least able to justify: a detection stopped
nothing, and what stopped the action was policy, whose refusal is recorded separately.

---

## 10. "Why did AEGIS do this?"

Ten closed questions, each answered from artifacts by a fixed function. Three outcomes:

- `EXPLAINED` — with the artifact ids it rests on
- `NOT_APPLICABLE` — the thing asked about did not happen, which is not a gap
- `EXPLANATION_INCOMPLETE` — the artifacts are missing, **and it names which**

No LLM-generated explanation. No free-form interpretation. No "probably" — asserted by a
test that sweeps every answer for hedging language.

---

## 11. The export format

`aegis.control-center.export/v1`. Deterministic to the byte through the project's one
canonical serializer, so two exports of the same projection are identical and an export
round-trips.

The audit verdict travels **inside** the document. An export of a corrupted trail says so,
in the artifact, where a reader cannot miss it.

Contains: incident, timeline, causal chain, governance, approvals, lifecycle, breakers,
agents, memory, A2A, security events, audit integrity and every source's provenance.

Contains no credentials, private keys, HMAC material, API keys, prompts or model responses —
not because they are stripped, but because the projection it is built from never held them.
`model.decision` records a request digest and a response digest, never text, so there is
nothing to reconstruct from and Part 23 forbids inventing it.

---

## 12. The operator action boundary

**There is no admin override.** No force-approve, no force-execute, no bypass-policy, no
breaker reset, no agent release, no mark-verified, no mark-resolved. Not guarded — absent.
A test sweeps every public function name in the package for `force`, `override`, `reset`,
`approve`, `authorize`, `execute`, `release`, `grant` and `bypass`.

`ControlCenter` exposes exactly four operations: `add`, `incident`, `incidents`,
`incident_ids`. `add` stores a frozen projection — it adds an observation and grants
nothing.

If an operator interaction is necessary it must map onto an existing governed capability and
go through the engine that owns it. **A view is where you see that an approval is waiting;
it is not where you grant one.**

---

## 13. Caching

There is none, and a test asserts it structurally: no identifier in the package contains
`cache`. A cached projection is a stale one, and stale governance state on an operator's
screen is the failure this package exists to avoid. `capture_incident` is a pure function of
its sources, which makes caching unnecessary as well as forbidden.

---

## 14. Known limitations

**Truncation is detected, not prevented.** The head digest tells you the tail is missing; it
does not tell you what was in it.

**The audit vocabulary has no execution event** (§5). A trail-only reconstruction reports
`Phase.EXECUTION` as `UNKNOWN`.

**"Read-only" is not "safe to expose".** This package renders identifiers, decisions,
reasons and resource names, and an incident's contents can be sensitive. There is **no
operator authentication** and none is claimed — Part 31 rules it out of scope.

**A projection is a snapshot.** It is as of its `captured_at` and does not update. An
operator reading a stale projection is reading history, and the `as_of` on every view says
which history.

**The control center cannot detect a compromised orchestrator.** It reads what that process
recorded. If the process itself is lying, the artifacts are lying, and the read model will
faithfully display a lie — which is why the benchmark's oracle reads the *enterprise world*
rather than trusting the projection.

**Restriction state is per-scope.** An agent shown as `ACTIVE` is unrestricted *for the
scope this incident used*, not globally.

---

## 15. Evaluation

`CONTROL_CENTER` is a 32-scenario benchmark family. Eleven deliberately hand the read model
broken or incomplete evidence — an unreadable audit store, a corrupted chain, a truncated
trail, a crashed run, an unreadable containment registry, a foreign incident's records — and
require it to report `UNKNOWN` rather than invent state. A further nine keep every source
readable and make what those sources *say* hostile or disappointing: a prompt injection, a
tampered payload, a replayed message, a forged remote identity, a compromised peer,
malformed model output, an unavailable provider, a failed rollback, a refused verification.

The oracle reconstructs expected facts from artifacts the projection cannot see:

| Fact | Independent source |
|---|---|
| execution | the **enterprise world's** deployment |
| approval | the raw `approval.*` audit events |
| verification | the run's `VerificationResult` |
| gate | the gate register's own consumption count |
| restriction | the raw `agent.restriction_applied` events |
| breaker | the breaker's live `state_of` |

Two of those rules are deliberately **one-directional**, because only one direction is a
lie: "the world changed and the view does not show it" is a hidden execution, while an
execution that ran and failed leaves an artifact and an unchanged world. Likewise an agent
restricted by an event must be shown restricted, while an agent shown restricted with no
event in *this* incident's trail is a quarantine that predates the incident and is still in
force.
