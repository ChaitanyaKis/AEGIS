/* One incident report, drawn as the chain of boundaries it actually passed through.
 *
 * This is the view the dashboard exists for. A JSON dump proves a run happened; it does
 * not let anyone *see* that execution sat behind an approval and a spent gate, or that a
 * refused approval left execution and verification unreached.
 *
 * So every stage is always drawn, including the ones that did not happen. A rejected run
 * that simply omitted "Execution" would look like a shorter run rather than a blocked
 * one; drawing it dashed and labelled NOT REACHED is the difference between showing a
 * result and showing an enforcement boundary.
 */

import type { IncidentReport } from '../api/client'
import { buildStages } from './governance-stages'
import type { StageState } from './governance-stages'
import { Badge, Dot } from './ui'

const STATE_RAIL: Record<StageState, string> = {
  passed: 'border-line bg-surface',
  blocked: 'border-danger/30 bg-danger/5',
  unreached: 'border-dashed border-line-soft bg-transparent opacity-55',
}

export default function GovernanceChain({ report }: { report: IncidentReport }) {
  const stages = buildStages(report)

  return (
    <ol className="relative space-y-2">
      {stages.map((stage, index) => (
        <li key={stage.key} className="relative">
          {index < stages.length - 1 && (
            <span
              aria-hidden
              className="absolute top-11 bottom-[-0.5rem] left-[1.4375rem] w-px bg-line-soft"
            />
          )}
          <div className={`flex gap-4 rounded-lg border px-4 py-3.5 ${STATE_RAIL[stage.state]}`}>
            <div className="tnum mt-0.5 flex size-8 shrink-0 items-center justify-center rounded-full border border-line bg-surface-2 text-xs font-semibold text-muted">
              {index + 1}
            </div>

            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <h3 className="flex items-center gap-2 text-sm font-semibold text-text">
                  <Dot tone={stage.tone} />
                  {stage.title}
                </h3>
                <Badge tone={stage.tone} mono>
                  {stage.verdict}
                </Badge>
              </div>
              <p className="mt-1 text-xs leading-relaxed text-muted">{stage.caption}</p>

              <dl className="mt-2.5 flex flex-col gap-1.5">
                {stage.facts.map(([label, value]) => (
                  <div key={label} className="flex flex-wrap items-baseline gap-x-2.5 gap-y-1">
                    <dt className="text-[11px] tracking-widest text-faint uppercase">{label}</dt>
                    <dd className="tnum min-w-0 font-mono text-xs break-all text-text">{value}</dd>
                  </div>
                ))}
              </dl>
            </div>
          </div>
        </li>
      ))}
    </ol>
  )
}
