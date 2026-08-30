/* The AEGIS HTTP surface, typed.
 *
 * These interfaces mirror `src/aegis/service/app.py` and the `LiveRunReport` it embeds
 * (`src/aegis/evaluation/live.py`). They are hand-written rather than generated, so they
 * can drift; every field the dashboard renders is therefore treated as possibly absent
 * and nothing is asserted non-null.
 *
 * The dashboard is a *viewer*. It sends an incident and displays what the control plane
 * decided. It holds no authority of its own: there is no endpoint here that approves,
 * grants a capability or executes anything, because the service exposes none — approval
 * travels as one bounded boolean inside the incident request and is consumed by the
 * governance path, not by this file.
 */

const RAW_BASE = import.meta.env.VITE_API_BASE ?? '/api'

/** Normalised to exactly one trailing slash, so `${API_BASE}health` is always right. */
export const API_BASE = RAW_BASE.endsWith('/') ? RAW_BASE : `${RAW_BASE}/`

// --- health ------------------------------------------------------------------------

export interface EnterpriseInfo {
  /** Always true for the shipped service. Rendered prominently; see PART 13 of claude.md. */
  simulated: boolean
  note: string
  resources?: string[]
}

export interface GovernanceInfo {
  rule: string
  commander_tools: string[]
  /** agent id -> the agent ids it may delegate to. */
  delegation_matrix: Record<string, string[]>
  /** capability id -> the agent ids that may propose it. */
  proposal_authority: Record<string, string[]>
}

export interface LiveModeInfo {
  enabled: boolean
  credentials_present: boolean
  available: boolean
}

export interface Limits {
  max_body_bytes: number
  max_source_chars: number
  max_steps: number
  min_steps: number
}

export interface HealthResponse {
  status: string
  service: string
  version: string
  modes: Record<string, boolean>
  live_mode: LiveModeInfo
  enterprise: EnterpriseInfo
  governance: GovernanceInfo
  limits: Limits
}

// --- incident ----------------------------------------------------------------------

export type IncidentMode = 'deterministic' | 'live'

export interface IncidentRequest {
  source: string
  affected_resource?: string
  mode?: IncidentMode
  approve?: boolean
  max_steps?: number
}

/** One recorded model call. Digests, never prompt or response content. */
export interface ProviderCall {
  call_index: number
  provider: string
  model_id: string
  decision_type: string | null
  delegate_to: string | null
  tool_id: string | null
  proposed_capability: string | null
  failure_category: string | null
  failure_type: string | null
  finish_reason: string | null
  latency_ms: number | null
  prompt_tokens: number | null
  response_tokens: number | null
  total_tokens: number | null
  request_digest: string
  response_digest: string
}

export interface IncidentReport {
  incident_id: string
  outcome: string
  final_state: string
  provider: string
  model_id: string
  policy_decision: string | null
  approval_granted: boolean
  gates_issued: number
  gates_consumed: number
  execution_occurred: boolean
  world_changed: boolean
  verification: string | null
  audit_valid: boolean
  audit_head_digest: string
  governed: boolean
  model_reached_the_goal: boolean
  steps_used: number
  tool_calls: number
  specialist_calls: number
  model_calls: number
  model_latency_ms: number
  wall_clock_seconds: number
  total_tokens: number | null
  decision_sequence: string[]
  tool_sequence: string[]
  delegation_sequence: string[]
  failure_categories: string[]
  started_at: string
  error: string | null
  provider_calls: ProviderCall[]
}

export interface IncidentResponse {
  governed: boolean
  mode: string
  model_reached_the_goal: boolean
  models: { commander: string; specialists: string }
  enterprise: EnterpriseInfo
  report: IncidentReport
  request: Required<Pick<IncidentRequest, 'source' | 'affected_resource' | 'approve' | 'max_steps'>>
}

// --- transport ---------------------------------------------------------------------

/** An error carrying the HTTP status, so a 409 can be told from a 400 or a dead server. */
export class ApiError extends Error {
  readonly status: number
  readonly body: unknown

  constructor(message: string, status: number, body: unknown) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.body = body
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response
  try {
    response = await fetch(`${API_BASE}${path}`, init)
  } catch {
    // A network-level failure is the common case in development: the dashboard is up and
    // the Python service is not. Saying so beats surfacing "Failed to fetch".
    throw new ApiError(
      `Cannot reach the AEGIS service at ${API_BASE}. Start it with ` +
        `\`python run_service.py\` and reload.`,
      0,
      null,
    )
  }

  const text = await response.text()
  let body: unknown = null
  if (text) {
    try {
      body = JSON.parse(text)
    } catch {
      body = text
    }
  }

  if (!response.ok) {
    // The service refuses with both a machine code (`error`) and a sentence (`detail`),
    // e.g. `unknown_resource` alongside "'service:x' is not declared in the simulated
    // enterprise." The sentence is what a person needs; the code is kept on `body` for
    // anything that wants to branch on it.
    const payload = (body ?? {}) as Record<string, unknown>
    const message =
      typeof payload.detail === 'string'
        ? payload.detail
        : typeof payload.error === 'string'
          ? payload.error
          : `${response.status} ${response.statusText}`
    throw new ApiError(message, response.status, body)
  }
  return body as T
}

export function fetchHealth(): Promise<HealthResponse> {
  return request<HealthResponse>('health')
}

export function postIncident(body: IncidentRequest): Promise<IncidentResponse> {
  return request<IncidentResponse>('incident', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
}
