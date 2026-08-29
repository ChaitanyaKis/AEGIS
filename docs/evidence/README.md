# Live-provider evidence

Two files, both produced by one real run of the production CLI against a real Gemini model
on Vertex AI. Nothing here was hand-authored, edited or synthesized; both are byte-for-byte
what `run_live_incident.py` wrote.

They exist because `docs/PROVIDER.md` previously asserted that live runs had happened and
the repository contained nothing a reader could check. An unverifiable claim is exactly
what `claude.md` section 17 forbids, and the fix for it is an artifact, not a sentence.

## The command

```bash
GOOGLE_GENAI_USE_VERTEXAI=true \
GOOGLE_CLOUD_PROJECT=<redacted> \
GOOGLE_CLOUD_LOCATION=us-central1 \
uv run python run_live_incident.py \
  --deterministic-specialists \
  --json \
  --capture docs/evidence/live-gemini-commander-decisions.jsonl \
  > docs/evidence/live-gemini-commander-report.json
```

Exit code `0`: the run completed and the control plane held.

`--deterministic-specialists` keeps the Commander as the single live variable. The four
specialists are the rule-based stand-ins, so a result says something about one model rather
than five. `GeminiSpecialistModel` has still never been run live.

## The files

### `live-gemini-commander-report.json`

`LiveRunReport.as_json()` — the run reduced to measured facts. Every field is a number, an
enum value, an identifier or a digest. There is no field for prompt text, response text,
credentials, endpoints or project identity, which is why it is safe to commit.

Selected values from this run:

| Field | Value |
|---|---|
| `provider` | `gemini-commander` |
| `model_id` | `gemini-2.5-flash` |
| `outcome` / `final_state` | `RESOLVED` / `RESOLVED` |
| `policy_decision` | `REQUIRE_APPROVAL` |
| `approval_granted` | `true` |
| `gates_issued` / `gates_consumed` | `1` / `1` |
| `execution_occurred` / `world_changed` | `true` / `true` |
| `verification` | `VERIFIED` |
| `audit_valid` | `true` |
| `model_calls` | `6` |
| `total_tokens` | `12821` |
| `model_latency_ms` | `24999.9` |
| `failure_categories` / `error` | `[]` / `null` |
| `governed` / `model_reached_the_goal` | `true` / `true` |

`provider_calls` holds one record per call: provider, model id, call index, request and
response **digests**, decision type, latency, token counts and finish reason. Digests, never
content.

### `live-gemini-commander-decisions.jsonl`

The `--capture` file: one JSON object per line, `{note, request_digest, response_text}`.

`write_capture` records **response text only**. A request carries the incident payload and
the organizational history, so it is represented by a SHA-256 digest and never by its
content — the docstring in `src/aegis/integrations/replay.py` says so, and the six entries
here have exactly those three keys and nothing else.

It replays offline through the production `load_capture()`, and every entry parses through
the real `parse_decision` validator into a valid `CommanderDecision`.

## What this proves

- A real Gemini model was called. `total_tokens: 12821` is reported by the provider; there
  is no way to obtain it without a real response. `model_latency_ms: 24999.9` over six calls
  is wall-clock time against a real endpoint.
- The governance path was unchanged by a real model being in the loop: policy required
  approval, a human granted it, one gate was issued and spent, execution happened,
  verification independently established the recovered state, and only then did the
  incident resolve. The hash-chained audit verified.
- The model chose its own route. It called four tools and then delegated to `diagnostic`
  and `remediation`, skipping `security` and `business-impact` — a path the deterministic
  model does not take. A scripted or fabricated run would not have produced it.

## What this does not prove

**One run is one observation.** It is not a success rate, not a reliability claim, and not
evidence about a second run. The model is probabilistic and the sample size is one.

It also says nothing about `GeminiSpecialistModel`, which has never been run live, and
nothing about a deployed Cloud Run service, which has never been deployed.

## Reproducing it

Configure credentials (see `../PROVIDER.md` §3) and run the command above. The output will
differ — a different model run produces different reasoning, possibly a different route,
and different digests. What should not differ is the governance column: policy, approval,
gate, execution, verification and audit.
