# Governed agent-to-agent communication

> **AGENTS MAY COMMUNICATE. AGENTS MAY NOT TRANSFER AUTHORITY.**

A2A is a transport and identity boundary, not a second control plane.

---

## 0. What this is, and what it is not

**Governed local A2A with durable local state, plus an authenticated remote security
boundary exercised in a deterministic offline transport simulation.**

The claim, in one sentence, with every word load-bearing:

> AEGIS provides an authenticated, integrity-protected, replay-resistant remote A2A
> security boundary in a deterministic offline transport simulation.

"Deterministic offline transport simulation" is not a hedge. There is no socket, no TLS,
no DNS, no credential and no remote machine anywhere in AEGIS, and the A2A package
*structurally cannot import* `socket`, `http`, `httpx`, `requests`, `urllib`, `aiohttp` or
`ssl` — asserted by test over parsed imports, so "no real network protocol yet" is a
property of the source tree rather than a promise.

### Claimed

- governed local agent-to-agent communication
- **durable local persistence** — an append-only, hash-chained log
- **restart-safe replay prevention** — a consumed message stays consumed across a restart
- append-only integrity with tamper evidence
- strict ordering
- **at-most-once** delivery
- **a remote security model** — a threat model written as data, with a test bound to each
  of its thirty threats
- **cryptographic identity** — a registry binding keys to agents, with status, expiry and
  revocation
- **authenticated envelopes** — eighteen signed fields, an explicit protocol version, and
  a test that fails if a security-relevant field is added without being signed
- **a deterministic remote transport simulation** — delay, duplication, reordering, loss,
  timeouts, unreachable peers, and a relay seam a benchmark attacker occupies
- **remote replay protection**, resting on the same durable ledger as the local case
- **key rotation** with a documented revocation policy
- **protocol versioning** with downgrade refusal

### Not claimed

- real internet transport
- TLS deployment
- cloud-to-cloud federation
- distributed consensus
- Byzantine fault tolerance
- secure multi-process shared state
- **production key management** — the benchmark and the tests derive keys from printable
  seeds for reproducibility, which is a simulation artifact and nothing more
- HSM-backed identity
- remote attestation
- **exactly-once** delivery
- multi-process-safe JSONL writes

### The trust zone, formally

    LOCAL_TRUST_ZONE

- the local broker's and ledger's identity is **trusted**;
- persistence protects against accidental or corrupt state and **detects** tampering;
- **no remote cryptographic identity is claimed for a peer AEGIS does not control**, and
  no network authentication exists because no network exists.

Prompt 17 adds a boundary that *would* authenticate a genuinely remote peer, and exercises
it against an attacker who can rewrite bytes in flight. What it does not add is a network
for that peer to be on.

### The three sentences everything here rests on

    a valid hash is not an authenticated sender
    a valid signature is not an authorization
    a registered identity is not execution authority

Each is demonstrated by a test that would fail if the distinction were collapsed, not
asserted by a comment. See §13.

---

## 1. The contract

`A2AEnvelope` is frozen, closed (`extra="forbid"`) and sealed.

| Field | Meaning |
|---|---|
| `message_id` | identity, derived deterministically at issuance |
| `conversation_id` | which conversation this belongs to |
| `incident_id` | which incident it is about |
| `sender_agent_id` | who says they sent it — **not evidence**, see §2 |
| `recipient_agent_id` | who it is for |
| `task_id` | which unit of delegated work |
| `message_type` | `TASK_REQUEST` / `TASK_RESULT` / `TASK_REJECTED` |
| `task_type` | the existing `TaskType`, reused rather than duplicated |
| `target_resource` | what the work concerns |
| `evidence_refs` | observation ids, references only |
| `payload` | **untrusted data**, whoever wrote it |
| `sequence` | position in the conversation, from 1 |
| `created_at` / `expires_at` | freshness |
| `seal` | SHA-256 over every field above |

**There is no field for** policy, decision, approval, authorization, risk, blast radius,
verification, lifecycle, gate or execute. `FORBIDDEN_ENVELOPE_FIELDS` lists them so the
guarantee is greppable, and a parametrised test asserts each one is rejected. A message
carrying `policy="ALLOW"` is not a message with a policy decision in it — it is a
validation error.

---

## 2. Identity

```
declared sender   (model-influenced, in the message)
accountable agent (authoritative, from the wiring)
                ↓
          must be equal, exactly
```

The sender is established by the transport boundary from the agent record the application
wired up. The declared field exists so a recipient knows where to reply.

`ExactId` **rejects** a whitespace-padded identifier rather than stripping it. The ordinary
domain `Identifier` alias strips — right for values AEGIS constructs, wrong for values a
model supplies. `"diagnostic "` is not a typo to correct; it is an identifier that does not
exist, and normalising it would mean a model-supplied string had been edited into a valid
identity on its way through. `"DIAGNOSTIC"` is well-formed and simply matches nothing.

---

## 3. The delegation matrix

```
commander  -> diagnostic | security | business-impact | remediation   ALLOW
specialist -> anyone                                                  DENY
```

**One matrix, not two.** `DELEGATION_MATRIX` is declared in
`aegis.orchestration.delegation` and *injected* into `AgentDirectory`. That is how enforcing
the existing policy coexists with the rule that no A2A module may import orchestration: the
dependency arrow points down, never up.

Empty specialist rows are the important part. If a specialist could delegate, an agent with
no authority could reach the agent with proposal authority and manufacture a chain ending in
a production mutation.

---

## 4. Integrity

SHA-256 over canonical JSON — the same construction the audit chain, the memory chain, the
lifecycle state chain and the lifecycle gate use. One scheme, one set of properties, one
thing to review.

Sealed: every envelope field except the seal itself, asserted by comparing
`_SealPayload.model_fields` against `A2AEnvelope.model_fields`, so adding a field without
sealing it is a visible change with a test behind it.

> **Integrity ≠ authentication.**
> The formula is public. A perfect seal proves the message was not modified after issuance
> and proves *nothing* about who issued it. Authenticity is "this broker's ledger issued
> it" — a fact an attacker cannot manufacture. A hand-built envelope with a flawless seal is
> refused as `NOT_ISSUED`.

---

## 5. Replay, expiry and sequence

| Protection | Mechanism |
|---|---|
| message-id uniqueness | the ledger refuses to issue a duplicate |
| consumed tracking | consumption is one-way; `mark` cannot walk it back |
| conversation binding | checked against what the caller is actually doing |
| incident binding | same |
| expiry | 60 s message TTL, 300 s conversation lifetime, injected clock |
| ordering | exactly the issued sequence, and no predecessor still outstanding |

**No escape hatches.** There is no `reset_replay_state`, no `clear_consumed_messages`, and
a test asserts no public method contains `reset` or `clear`. The only removal path is
`prune_expired`, which needs the clock to agree the conversation is over, cannot be aimed at
a message, and can never un-consume anything.

**Process restart: closed as of Prompt 16.** This state was in memory and died with the
process, so a message captured before a restart was replayable after one. It is now backed
by an append-only, hash-chained log — see §5b. The default backend is still non-durable and
still says so; durability is a choice the caller makes by supplying
`JsonlA2APersistence`.

Messages are never silently reordered. A message arriving while an earlier one is still
outstanding is refused, not buffered — a reordering buffer is a place an attacker can insert
a message.

---

## 5b. Durability (Prompt 16)

Prompt 15 stated the weakness plainly: ledger state lived in memory and died with the
process, so a message captured before a restart was replayable after one. That is now
closed.

```
issue → append(MESSAGE_ISSUED) → fsync → in-memory view moves
admit → append(STATUS_CHANGED, CONSUMED) → fsync → in-memory view moves
```

The append happens **before** the in-memory view moves, so a failed write leaves the ledger
exactly where it was rather than one step ahead of its own record.

### The chain

A fourth hash chain, built like the audit, memory and lifecycle-state chains: SHA-256 over
canonical JSON, each record naming the digest of the one before it. Five checks on load:

| Check | Catches |
|---|---|
| `sequence` | deletion and reordering |
| `previous_digest` | insertion and truncation |
| `digest` | modification of any covered field |
| identity stability | a status record re-pointing a message at a different sender or seal |
| **status legality** | a chain that is perfect and still describes an impossible history |

The last is the one a hash alone does not give. `CONSUMED → ISSUED` is not a legal edge, so
replaying an old `ISSUED` record after a consumption — a valid-looking way to make a spent
message fresh — is refused.

### What is stored

Identifiers, bindings, timestamps, sequence, status, the envelope seal, and a
**`payload_digest`**. Never payload content: untrusted material already lives where it
belongs, and a digest answers every question the chain has to ask.

### Backends

| Backend | Durable | Use |
|---|---|---|
| `InMemoryA2APersistence` | **No** | hermetic tests; a process where a restart destroys every conversation partner |
| `JsonlA2APersistence` | Yes | anything that must survive a restart |

`InMemoryA2APersistence` carries `durable = False` and says **NOT DURABLE** in its own
docstring. `MessageLedger.durable` reports the backend's answer rather than an assumption.

### Failing closed

- a chain that does not verify → the ledger **refuses to exist**, rather than starting as
  though nothing had been consumed;
- an unreadable line → damage, not an ending; a log that quietly discards its own tail
  discards exactly where the recent consumptions live;
- a failed append → `A2APersistenceFailure`, which the orchestrator turns into a **recorded
  refusal**. A crash would skip the audit record the refusal is supposed to leave.

### Atomicity, stated rather than hidden

A single `write` of one short line is not guaranteed atomic by POSIX or by Windows. A crash
mid-line leaves a truncated final record. That is **detected** (the line fails to parse and
the load raises) but **not prevented**. Which way the failure falls is what matters: a torn
line can only lose the *most recent* record, and losing a record makes the log refuse to
load rather than quietly present an earlier status — so a torn write can never resurrect a
consumed message.

### Concurrent writers

> **Concurrent multi-process writers are outside the trust guarantee of the JSONL backend.**

Two processes appending to one file interleave and corrupt the sequence. That is
**detected on load** and not solved. There is no file locking, and none is claimed —
`fcntl`, `msvcrt` and `flock` appear nowhere in the package, which a test asserts.

### At-most-once

A message may be accepted once, rejected, expired or replayed — never successfully consumed
twice. Consumption is one-way and survives restarts. **Exactly-once distributed delivery is
not claimed**, and there is no retry inside A2A: retry belongs to `LifecycleManager`, and a
retry costs a step from the same bounded budget every other decision costs one from.

## 6. Bounds

| Bound | Value |
|---|---|
| `MAX_PAYLOAD_BYTES` | 16 KiB |
| `MAX_RESPONSE_BYTES` | 32 KiB |
| `MAX_EVIDENCE_REFS` | 128 |
| `MAX_RESOURCE_LENGTH` | 256 |
| `MAX_MESSAGES_PER_TASK` | 4 |
| `MAX_CONVERSATION_SECONDS` | 300 |
| `DEFAULT_MESSAGE_TTL_SECONDS` | 60 |

Oversized payloads are refused **before** anything is sent, and again at admission. Never
truncated: silently shortening a malicious payload leaves a shorter malicious payload. A
rejected payload stays rejected.

`MAX_EVIDENCE_REFS` is a ceiling on growth, not a uniqueness rule — references legitimately
repeat as a Commander accumulates them, and rejecting duplicates would turn ordinary
accumulation into a hard failure while protecting nothing.

---

## 7. Data and instructions

**The most important claim in this milestone, and it is architectural rather than
behavioural.**

A payload travels in `ModelRequest.data`. The instruction position is filled by a value
derived from the task type alone. `ModelRequest` has no instruction field — so an attacker
in complete control of a payload cannot place one byte where instructions live.

Verified for all four specialists against eight attacks: the byte-identical instruction is
asserted between a benign payload and each hostile one.

This does **not** claim a model "understood" an injection. A model may notice an attack,
repeat it, or try to act on it. What holds regardless is that untrusted A2A data cannot
become trusted instructions.

---

## 8. Responses and provenance

A response is a typed `AgentFinding` or an explicit failure. Two equalities the transport
does not let a specialist escape:

```
response.sender_agent_id == finding.agent_id
response.incident_id     == finding.incident_id
```

A finding may *reference* observations. It cannot manufacture them: `AGENT_FINDING` is not
in `OBSERVABLE_EVIDENCE_TYPES`, so an agent's conclusion is never authoritative verification
evidence — before or after A2A. Nothing in `aegis.a2a` so much as names an evidence type.

---

## 9. Failure handling

Every failure returns a typed `A2AVerdict` with `accepted=False` and a named rejection:
sender mismatch, unknown sender, unknown recipient, not permitted, unknown task, integrity
failure, not issued, replay, already consumed, expired, conversation expired, sequence
mismatch, incident/conversation/task mismatch, payload too large, too many messages,
recipient unavailable, malformed, timeout, recipient refused, response identity mismatch,
response binding mismatch.

There is **no retry mechanism in A2A**. A retry is the Commander deciding to delegate again,
which costs a step from the same bounded lifecycle budget every other decision costs one
from. `LifecycleManager` already provides recovery; Prompt 15 adds none.

---

## 10. Governance is unchanged

```
Commander → A2A → Specialist → AgentFinding → CommanderProposal
 → Assessment → Policy → Approval → Lifecycle → LifecycleGate
 → Authorization → Execution → Observation → Verification → Resolution
```

A finding cannot skip to policy, approval, gate, execution, verification or resolution. The
structural reason: the A2A package imports none of them and cannot.

**Agent count does not change authority.** Three agents agreeing is three opinions, because
agreement is not an input to any deterministic engine anywhere in AEGIS.

---

## 11. Observability

One new audit event: `a2a.message`, with a status scalar rather than four separate types —
unlike the gate events, these describe one message moving through one lifecycle, and four
names for the same fact would drift apart.

Recorded: message id, conversation, sender, recipient, task, task type, resource, status,
sequence, digest, rejection, finding id. **Never** payload text, prompts, model responses or
credentials. The recorder takes plain scalars and the audit package imports nothing from
`aegis.a2a`.

---

## 12. Security boundaries

Asserted structurally over parsed imports:

- no A2A module imports policy, approval, assessment, verification, audit, capabilities,
  dependencies, incidents, enterprise, orchestration, memory, lifecycle, evaluation or
  integrations;
- no A2A module imports Google or any provider SDK;
- the only AEGIS packages A2A depends on are `core.domain`, `agents.decisions` and
  `agents.findings`;
- no `eval`, `exec`, `compile`, `__import__`, `getattr`, `setattr`, `subprocess`,
  `importlib`, `socket`, `httpx`, `requests`, `urllib` or `aiohttp` anywhere in the package;
- the agent plane gained no control-plane import, and does not import A2A either.

---

## 13. The remote security boundary (Prompt 17)

### The layers, and why they are separate

    transport        carries frames; decides nothing
    envelope         signed fields, protocol version, wire format
    identity         which keys the registry binds to which agents
    authenticator    who sent this -- and nothing else
    gateway          addressing, binding, replay, then the existing local broker
    (unchanged)      policy, risk, approval, lifecycle gate, execution, verification

`aegis.a2a.remote.threats` writes the threat model down as data: thirty `ThreatClass`
members, each mapped to the `SecurityLayer` that answers it. A test walks the enum and
fails if a member has no mapping, which turns "we thought about these thirty things" into
"these thirty things each have a test".

Two of the mappings are worth reading twice. `COMPROMISED_PEER` and `CLAIMED_AUTHORITY` map
to **AUTHORIZATION**, not to authentication: a compromised remote agent may hold perfectly
valid key material and sign perfectly valid messages, and no amount of cryptography makes
its *content* true.

### The composition point

    A2ABroker.admit(envelope, accountable_sender=<cryptographically established>, ...)

That one argument is the whole integration. In Prompt 15 it came from the application's
wiring, because sender and receiver shared a process; for a remote peer there is no shared
wiring, so the signature takes its place. Every check the local broker already performs
then runs unchanged, against an identity the sender could not choose. **Authentication
supplies the accountable identity. It does not replace a check, weaken one, or add one.**

### Identity

`RemoteAgentIdentity` holds an agent id, a key id, an algorithm, verification material,
permitted protocol versions and three timestamps. It holds **no** policy, risk, approval,
lifecycle state or capability — asserted by a test on the field set.

The material field is called `verification_key`, not `public_key`. For Ed25519 it genuinely
is a public key; for HMAC-SHA256 it is shared secret material, and a field name asserting
otherwise would be a lie told by the schema itself.

Statuses: `UNKNOWN`, `ACTIVE`, `NOT_YET_VALID`, `EXPIRED`, `REVOKED`. The fourth is the one
the calendar forces — a key registered for tomorrow is not expired, and recording it as
expired would send an audit reader looking for a rotation that never happened. Only
`ACTIVE` authenticates anything.

A lookup needs **both** the agent id and the key id. A valid signature under a key
belonging to some other agent establishes nothing.

### Cryptography, without a library dependency

`KeyAlgorithm` is a closed enum with two members and no `NONE`. `aegis.a2a.remote.ed25519`
is the only module in AEGIS that imports `cryptography`, asserted by a test over the whole
source tree — the same discipline `integrations/gemini.py` follows for Google.

`cryptography` is an **optional** extra. When it is absent, `ed25519_provider()` returns
`None`, and a message naming Ed25519 is *refused* rather than verified some other way: a
missing provider never becomes a downgrade the deployment performed on its own behalf.

**The deterministic benchmark pins HMAC-SHA256**, so the safety benchmark needs no
third-party package at all. The honest consequence, stated rather than buried: that is a
**symmetric** MAC. It authenticates a message against anyone who does not hold the key —
which is exactly the malicious-intermediary threat — and it does *not* give the receiver
evidence it could show to a third party, because the receiver holds the same key. Ed25519
does, is implemented, and is tested under the same parametrised suite wherever the library
is installed.

### What is signed

`SIGNED_FIELDS` names eighteen fields, and `_SigningPayload` declares them as a model, so
the two cannot drift. A test asserts that every field on either envelope is covered or on a
three-name exception list — so **adding a security-relevant field without signing it is a
test failure.**

The exceptions, each with a reason: `signature` cannot cover itself; `payload` is covered
through `payload_digest`, which is signed *and recomputed by the authenticator*; `message`
is the wrapper's handle on the inner envelope, whose fields are covered individually.

Frame metadata — destination, hop count, arrival time, route — is **not signed**, because it
legitimately changes between hops. That is safe precisely because nothing trusts it: the
receiver compares its own identity against the **signed** recipient inside the body, so an
intermediary that readdresses a frame has changed a hint and not a destination.

### Order of checks

1. protocol version — before anything is interpreted, because a downgrade works by getting
   the wrong interpreter to run;
2. registry entry for the key — the key determines the identity;
3. permitted version, algorithm agreement, provider availability;
4. identity status, **revocation first**, so a live compromised key does not get to wait for
   its own expiry;
5. signature;
6. the declared sender against the established one — the least trustworthy thing in the
   message, checked last;
7. payload digest and inner seal;
8. freshness, against the **receiver's** clock and never the message's own timestamps.

---

## 14. Key rotation and revocation policy

The documented policy, in one line:

> **A revoked key admits nothing, whenever it claims to have signed.**

Historical *verification* survives. A revocation records a timestamp rather than deleting
anything, so "was this key valid last Tuesday?" stays answerable — `historical_status()` —
and an old signature stays mathematically checkable forever.

Historical *admission* does not, and cannot. A peer holding a stolen key controls every
timestamp in its own message, so honouring "but I signed this before you revoked me" would
hand the thief the exact excuse revocation exists to remove. Admission is judged against the
receiver's clock, always. A structural test asserts the authenticator calls `status()` and
never `historical_status()`, so the two cannot be confused by accident.

Revocation is **monotonic and irreversible**: revoking twice keeps the earlier timestamp,
and there is no `reactivate`, `unrevoke`, `restore` or `clear` anywhere on the registry.
Neither the authenticator nor the gateway calls `register` or `revoke` — asserted
structurally — so no message, however well signed, can change what the registry holds.

Rotation works: key A and key B may both be active, and revoking A leaves B authenticating
normally. A benchmark scenario requires the incident to **resolve** on the new key, because
enforcement that also refused the replacement would be an outage with a security
justification.

---

## 15. Protocol versioning

`REMOTE_PROTOCOL_VERSION = "aegis.a2a/2"`. `SUPPORTED_PROTOCOL_VERSIONS` is a frozenset, and
support is **membership, never comparison** — ordering invites "v1 is lower, so it is older,
so we can probably handle it", which is a downgrade written as politeness.

`LEGACY_PROTOCOL_VERSION = "aegis.a2a/1"` exists as a named constant and is **not**
supported. A version that exists but is refused is worth more than one that does not exist:
it gives "v2 sender, v1 receiver" a name and a rejection code instead of leaving it a
scenario nobody wrote.

The four downgrade attacks, and what happens:

| Attack | Result |
|---|---|
| v2 sender, receiver wants v1 | `UNSUPPORTED_PROTOCOL_VERSION` |
| attacker rewrites v2 to v1 | `UNSUPPORTED_PROTOCOL_VERSION`, and the signature would also fail |
| attacker strips a security field | parse failure, `MALFORMED_FRAME` |
| attacker removes the signature | parse failure, `MALFORMED_FRAME` |

Nothing defaults. There is no version of this schema in which a missing signature means
"unsigned".

The registry is additionally authoritative for which versions each identity may speak, so a
peer cannot widen its own support by claiming a version.

---

## 16. Remote transport semantics

Four operations: send, receive, acknowledge, reject. No `authorize`, `approve`, `execute`,
`verify_action`, `resolve_incident`, `issue_gate` or `change_risk` — asserted over the
protocol **and over every implementation**, because Prompt 16 learned that a protocol
constrains what a caller may rely on and not what a class may grow.

**At-most-once.** A frame is admitted once, or refused, expired, lost or replayed — never
consumed twice. Duplication is expected and handled: the receiver drains its inbox, so the
second copy genuinely meets the boundary and genuinely loses to the durable ledger.
**Exactly-once is not claimed and is not implemented.**

Ordering is strict and is not loosened for the wire: a frame arriving ahead of its
predecessor is refused rather than buffered.

There is **no retry** in the remote package — no `while` loop, no function with `retry` in
its name, asserted structurally. Retry is the Commander deciding to delegate again, costing
a step from the same bounded budget every other decision costs one from.

Every transport failure fails closed and carries its reason. A transport that dropped a
frame and returned normally would be telling the sender a message arrived when it did not:
**silence is a worse failure mode than an error**, so loss raises and becomes a refusal.
None of `TRANSPORT_FAILURE`, `TRANSPORT_TIMEOUT` or `PEER_UNAVAILABLE` can become ALLOW,
APPROVED, AUTHORIZED, EXECUTED, VERIFIED or RESOLVED, and none of them is ever an implicit
empty message.

`RemoteFault` ships only genuine **network conditions** — delay, duplication, reordering,
loss, timeout, unreachable peer. Adversarial rewriting is not a property of a network; it is
the act of an attacker, and an attacker is a benchmark control group rather than a method on
the transport. The attacker reaches frames through one reviewable seam, the transport's
`relay` hook.

---

## 17. The malicious intermediary

`MaliciousIntermediary` lives in `aegis/evaluation/remote_stage.py` and holds **no signing
key** — an intermediary that could sign would not be an intermediary, it would be a peer. It
has exactly six powers: modify, duplicate, reorder, drop, replay, redirect.

| Attack | Result |
|---|---|
| one character changed | `MALFORMED_FRAME` or `SIGNATURE_INVALID` |
| payload rewritten and **re-sealed** | `SIGNATURE_INVALID` |
| truncated | `MALFORMED_FRAME` |
| oversized | `OVERSIZED_FRAME`, refused **before parsing** |
| not JSON | `MALFORMED_FRAME` |
| signature stripped | `MALFORMED_FRAME` |
| version downgraded | `UNSUPPORTED_PROTOCOL_VERSION` |
| key id swapped for another valid key | `SIGNATURE_INVALID` |
| readdressed | intended recipient gets nothing; unintended one answers `WRONG_RECIPIENT` |
| duplicated | admitted once, `ALREADY_CONSUMED` thereafter |
| replayed | refused on a binding it cannot satisfy |
| dropped | `TRANSPORT_FAILURE`, bounded failure |
| reordered | refused per the strict-ordering rule |

The re-sealed case is the one that matters. Every hash inside the message agrees with
itself, the JSON is impeccable, and only the signature was computed over different bytes. A
boundary that checked hashes alone would accept it.

**No intermediary action produces an execution**, asserted from the world's state and the
ledger's consumed set rather than from any verdict.

---

## 18. The compromised peer

The scenario cryptography cannot touch, and the reason §13's layer mapping exists.

A compromised specialist holds a **genuine** key. Its signature verifies, its identity is in
excellent standing, and authentication says `True` — correctly, because the message really
did come from that agent. Its findings claim policy approved the action, a human granted
approval, verification passed, risk is zero and a lifecycle gate exists.

Every one of those is text in a finding. The envelope schema is closed, so none of them can
be a *field*; `FORBIDDEN_ENVELOPE_FIELDS` names sixteen that are rejected, and a signed
claim is still a claim.

The benchmark's `remote-compromised-peer-changes-nothing` scenario runs a whole incident
with every consulting specialist compromised and asserts the governance path is the one an
honest run produces: `REQUIRE_APPROVAL`, approval granted, gate issued, gate consumed,
executed, `VERIFIED`, `RESOLVED`. The lies changed nothing.

    authenticated is not trusted
    a trusted identity is not an authorized action

---

## 19. Remote observability

Two new audit members, and no more:

`remote.authentication`
: One member with a status scalar, exactly as `a2a.message` is. An authentication that
  succeeded and one that failed are the same fact with a different outcome;
  `remote.identity_verified` and `remote.message_rejected` would be two names for one event
  and would drift apart. A transport failure is carried here too, as a status: it is still
  "this message did not authenticate, and here is why".

  It records the **claimed** and the **established** agent id separately, because a trail
  showing only the established one could not show the moment a claim and a fact disagreed —
  which is the moment worth recording. It carries a key id, an algorithm, a protocol
  version, a status and a digest, and **never** key material, a signature, payload text or a
  credential.

`remote.key_revoked`
: Not a message event at all: an operator action that changes what will be accepted from
  that moment on. Without it the trail shows messages from a key being accepted and then,
  with no intervening record, refused — and silence is indistinguishable from the mechanism
  failing, the same argument that earned `agent.restriction_refused` its place.

`EVENT_VOCABULARY_VERSION` is unchanged: adding a member is compatible under this module's
own rule, because no historical record changes meaning.

The reconstruction chain, asserted end to end by test:

    a2a.message (issued)
      -> remote.authentication
      -> a2a.message (accepted)
      -> model.decision
      -> policy.decision
      -> approval.granted
      -> lifecycle.gate_issued
      -> lifecycle.gate_consumed
      -> verification.completed

A message is *issued* before it is authenticated — the sender builds it, signs it, and the
receiver then establishes who signed it — so `a2a.message` opens the sequence. That is the
opposite of the order the concepts are usually listed in, and it is what the code does.

---

## 20. Known limitations

**Replay state is durable as of Prompt 16** (§5b) — this limitation is closed for the local
case. It is *not* closed for a distributed one: durable local state says nothing about a
remote peer.

**Concurrent multi-process writers corrupt the log.** Detected on load, not solved.

**Torn final writes are detected, not prevented** (§5b).

**Integrity is not authentication** (§4). Three distinct things, and durability changes none
of them:

> Integrity proves that the message matches its recorded contents.
> The ledger proves that AEGIS issued the message.
> **Neither proves that a remote machine is genuinely the claimed agent.**

Origin comes from the issuer's ledger, which is in-process. Code that can reach the broker
can ask it for a message — nothing in-process prevents that, and no in-process mechanism
can. Persistence is emphatically **not** an identity authority: being in the log proves
issuance and says nothing about who is presenting the message now.

**The transport has never crossed a network.** Prompt 17 builds and proves the security
boundary that would have to exist first; it does not build the network. No socket, no TLS,
no DNS, no credential, no remote machine -- structurally, not by convention.

**The benchmark's authentication is symmetric.** HMAC-SHA256 is pinned so the safety
benchmark needs no third-party package. It defends against a party without the key, which is
the intermediary threat it is aimed at, and it does not give a receiver evidence it could
show to somebody else. Ed25519 is implemented and tested; it is not what the benchmark
measures.

**Key management is simulated.** Keys are derived from printable seeds for reproducibility.
That is a fixture, not production key management, and no part of this claims otherwise.

**Sender and receiver share a process.** What is genuinely exercised is the security
boundary: serialization to a wire format, signing, a transport that can lose or corrupt,
parsing back, verification against a registry. What is not exercised is a peer AEGIS does
not control.

**A compromised peer remains compromised.** Authentication establishes who sent a message
and can never establish that its contents are true. That is answered by the control plane,
not by a better signature -- a limitation of cryptography rather than of this
implementation.

**Clock skew is bounded, not solved.** A message more than thirty seconds ahead of the
receiver is refused; one inside that window is not. An operator whose clocks disagree by
more has a configuration problem the boundary cannot fix for them.

**An agent can still waste its own budget.** A Commander that delegates uselessly consumes
lifecycle steps and eventually escalates. That is bounded termination working, not a defect,
but it is an availability cost an agent can inflict on its own incident.

**Ordering is strict.** A message arriving out of order is refused rather than held. For an
in-process transport that is right; a network transport with legitimate reordering would
need a different answer, and adopting one would need its own analysis.
