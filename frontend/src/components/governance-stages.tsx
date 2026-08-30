/* Turning one incident report into the ordered list of boundaries it met.
 *
 * Separate from the component that draws it so each file has one job, and so React Fast
 * Refresh keeps working — a module exporting both a component and a helper invalidates
 * the component on every edit to the helper.
 *
 * Nothing here computes a verdict. Every tone is read off a field the control plane
 * already decided; this module chooses a colour, never an outcome.
 */

import type { ReactNode } from 'react'
import type { IncidentReport } from '../api/client'
import { Sequence } from './ui'
import type { Tone } from './ui'

export type StageState = 'passed' | 'blocked' | 'unreached'

export interface Stage {
  key: string
  title: string
  caption: string
  state: StageState
  verdict: ReactNode
  tone: Tone
  facts: Array<[string, ReactNode]>
}

function policyTone(decision: string | null): Tone {
  if (decision === 'ALLOW') return 'good'
  if (decision === 'DENY') return 'bad'
  if (decision === 'REQUIRE_APPROVAL') return 'gov'
  return 'neutral'
}

export function buildStages(report: IncidentReport): Stage[] {
  const executed = report.execution_occurred
  const policy = report.policy_decision
  const approvalNeeded = policy === 'REQUIRE_APPROVAL'
  const approvalSettled = approvalNeeded || report.approval_granted

  return [
    {
      key: 'input',
      title: 'Untrusted input',
      caption: 'The incident report arrives as data, never as instructions.',
      state: 'passed',
      verdict: 'ACCEPTED',
      tone: 'neutral',
      facts: [
        ['Incident', report.incident_id],
        ['Steps used', `${report.steps_used} of the declared budget`],
      ],
    },
    {
      key: 'reasoning',
      title: 'Agent reasoning',
      caption: 'The model proposes. It holds no authority over anything below.',
      state: 'passed',
      verdict: `${report.model_calls} MODEL CALL${report.model_calls === 1 ? '' : 'S'}`,
      tone: 'neutral',
      facts: [
        ['Provider', report.provider],
        ['Model', report.model_id],
        ['Decisions', <Sequence key="d" items={report.decision_sequence} />],
      ],
    },
    {
      key: 'investigation',
      title: 'Investigation',
      caption: 'Governed tool calls against the simulated enterprise.',
      state: report.tool_calls > 0 ? 'passed' : 'unreached',
      verdict: `${report.tool_calls} TOOL CALL${report.tool_calls === 1 ? '' : 'S'}`,
      tone: 'neutral',
      facts: [['Tools', <Sequence key="t" items={report.tool_sequence} empty="no tool call" />]],
    },
    {
      key: 'delegation',
      title: 'Delegation',
      caption: 'Only the Commander may delegate, and only along declared edges.',
      state: report.specialist_calls > 0 ? 'passed' : 'unreached',
      verdict: `${report.specialist_calls} SPECIALIST${report.specialist_calls === 1 ? '' : 'S'}`,
      tone: 'neutral',
      facts: [
        [
          'Specialists',
          <Sequence key="s" items={report.delegation_sequence} empty="no delegation" />,
        ],
      ],
    },
    {
      key: 'policy',
      title: 'Deterministic policy',
      caption: 'Capability, scope, lifecycle and risk, decided outside the model.',
      state: policy ? 'passed' : 'unreached',
      verdict: policy ?? 'NOT EVALUATED',
      tone: policyTone(policy),
      facts: [['Decision', policy ?? '—']],
    },
    {
      key: 'approval',
      title: 'Human approval',
      caption: 'A gate a model cannot open and an approval cannot widen.',
      state: !approvalSettled ? 'unreached' : report.approval_granted ? 'passed' : 'blocked',
      verdict: !approvalSettled ? 'NOT REQUIRED' : report.approval_granted ? 'GRANTED' : 'REFUSED',
      tone: !approvalSettled ? 'neutral' : report.approval_granted ? 'good' : 'bad',
      facts: [['Required', approvalNeeded ? 'yes' : 'no']],
    },
    {
      key: 'gate',
      title: 'Execution gate',
      caption: 'Single-use authorization. Issued by the control plane, spent once.',
      state: report.gates_issued > 0 ? 'passed' : 'unreached',
      verdict:
        report.gates_issued > 0
          ? `${report.gates_consumed} / ${report.gates_issued} SPENT`
          : 'NONE ISSUED',
      tone: report.gates_issued > 0 ? 'gov' : 'neutral',
      facts: [
        ['Issued', String(report.gates_issued)],
        ['Consumed', String(report.gates_consumed)],
      ],
    },
    {
      key: 'execution',
      title: 'Execution',
      caption: 'The only stage that changes the enterprise.',
      state: executed ? 'passed' : 'unreached',
      verdict: executed ? 'EXECUTED' : 'NOT REACHED',
      tone: executed ? 'good' : 'neutral',
      facts: [['World changed', report.world_changed ? 'yes' : 'no']],
    },
    {
      key: 'verification',
      title: 'Verification',
      caption: 'Independent observation. A tool reporting success is not success.',
      state: report.verification
        ? report.verification === 'VERIFIED'
          ? 'passed'
          : 'blocked'
        : 'unreached',
      verdict: report.verification ?? 'NOT REACHED',
      tone: report.verification === 'VERIFIED' ? 'good' : report.verification ? 'bad' : 'neutral',
      facts: [['Result', report.verification ?? '—']],
    },
    {
      key: 'audit',
      title: 'Audit chain',
      caption: 'Hash-chained record of every decision above.',
      state: report.audit_valid ? 'passed' : 'blocked',
      verdict: report.audit_valid ? 'CHAIN VALID' : 'CHAIN BROKEN',
      tone: report.audit_valid ? 'good' : 'bad',
      facts: [
        [
          'Head digest',
          <span key="h" title={report.audit_head_digest}>
            {report.audit_head_digest.slice(0, 16)}…
          </span>,
        ],
      ],
    },
  ]
}
