import { Link } from 'react-router-dom'
import {
  Badge,
  Card,
  ErrorNote,
  PageHeader,
  SimulationNotice,
  Spinner,
  StatTile,
} from '../components/ui'
import { useShell } from '../shell-context'

/* The stages the control plane actually enforces, in order.
 *
 * Static text, and labelled as such below: this is the architecture the service
 * implements, not a live reading of one run. The live reading is on the incident page,
 * where every stage is filled in from a real report.
 */
const PIPELINE = [
  ['Untrusted input', 'External incident content is carried as data, never as instructions.'],
  ['Agent reasoning', 'Models propose. They hold no authority over anything downstream.'],
  ['Deterministic policy', 'Capability, scope, lifecycle and risk are decided outside the model.'],
  ['Human approval', 'Required for high-impact actions. A model cannot open this gate.'],
  ['Execution gate', 'Single-use authorization, issued by the control plane and spent once.'],
  ['Execution', 'The only stage that changes the enterprise.'],
  ['Verification', 'Independent observation. A tool reporting success is not success.'],
  ['Audit', 'Hash-chained record of every decision above.'],
] as const

export default function OverviewPage() {
  const { health, error, loading, refresh } = useShell()

  if (loading && !health) return <Spinner label="Reading service health" />

  if (error) {
    return (
      <div className="space-y-6">
        <PageHeader title="Overview" />
        <ErrorNote title="Cannot reach the AEGIS service" detail={error} />
        <button
          type="button"
          onClick={refresh}
          className="rounded-md border border-line bg-surface px-4 py-2 text-sm text-text hover:bg-surface-2"
        >
          Retry
        </button>
      </div>
    )
  }

  if (!health) return null

  const operational = health.status.toLowerCase() === 'ok'
  const resources = health.enterprise.resources ?? []
  const agents = Object.keys(health.governance.delegation_matrix)

  return (
    <div className="space-y-6">
      <PageHeader
        title="Overview"
        lede="A governed control plane for autonomous enterprise agent fleets. This surface runs incidents through the same governance path as the command-line runners and decides nothing itself."
        actions={
          <Link
            to="/incidents"
            className="rounded-md bg-primary px-4 py-2 text-sm font-medium text-bg hover:bg-primary/85"
          >
            Run an incident
          </Link>
        }
      />

      <SimulationNotice note={health.enterprise.note} />

      <section className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <StatTile
          label="Status"
          value={operational ? 'OPERATIONAL' : health.status.toUpperCase()}
          tone={operational ? 'good' : 'warn'}
          hint={`${health.service} v${health.version}`}
        />
        <StatTile
          label="Execution mode"
          value={health.live_mode.available ? 'DETERMINISTIC + LIVE' : 'DETERMINISTIC'}
          tone={health.live_mode.available ? 'gov' : 'neutral'}
          hint={
            health.live_mode.available
              ? 'A real provider may be selected per request'
              : 'No credentials, no network call, no spend'
          }
        />
        <StatTile
          label="Fleet"
          value={agents.length}
          hint={`${agents.length} governed agents`}
        />
        <StatTile
          label="Resources"
          value={resources.length}
          hint="Declared in the simulated topology"
        />
      </section>

      <Card
        title="Governance pipeline"
        subtitle="The architecture the service implements. Run an incident to see each stage filled in from a real report."
      >
        <ol className="grid gap-2 sm:grid-cols-2">
          {PIPELINE.map(([title, description], index) => (
            <li
              key={title}
              className="flex gap-3 rounded-md border border-line-soft bg-surface-2 px-3.5 py-3"
            >
              <span className="tnum mt-0.5 text-xs font-semibold text-faint">
                {String(index + 1).padStart(2, '0')}
              </span>
              <div>
                <div className="text-sm font-medium text-text">{title}</div>
                <p className="mt-0.5 text-xs leading-relaxed text-muted">{description}</p>
              </div>
            </li>
          ))}
        </ol>
      </Card>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card title="Operating rule">
          <p className="text-sm leading-relaxed text-muted">{health.governance.rule}</p>
          <div className="mt-4 flex flex-wrap gap-2">
            <Badge tone="gov">Reasoning ≠ authorization</Badge>
            <Badge tone="gov">Authorization ≠ execution</Badge>
            <Badge tone="gov">Execution ≠ success</Badge>
          </div>
        </Card>

        <Card
          title="Declared resources"
          subtitle="An incident may only target a resource that exists in the topology."
        >
          {resources.length ? (
            <ul className="flex flex-wrap gap-1.5">
              {resources.map((resource) => (
                <li
                  key={resource}
                  className="rounded border border-line bg-surface-2 px-2 py-1 font-mono text-xs text-text"
                >
                  {resource}
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-sm text-faint">The service reported no resource list.</p>
          )}
        </Card>
      </div>

      <Card title="Operational limits" subtitle="Bounds enforced by the service, not by a model.">
        <dl className="grid gap-x-8 sm:grid-cols-2">
          {Object.entries(health.limits).map(([key, value]) => (
            <div
              key={key}
              className="flex items-baseline justify-between gap-4 border-b border-line-soft py-2"
            >
              <dt className="text-xs tracking-wide text-muted uppercase">
                {key.replace(/_/g, ' ')}
              </dt>
              <dd className="tnum font-mono text-sm text-text">{value.toLocaleString()}</dd>
            </div>
          ))}
        </dl>
      </Card>
    </div>
  )
}
