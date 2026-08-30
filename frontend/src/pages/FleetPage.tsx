import { Badge, Card, ErrorNote, PageHeader, Spinner } from '../components/ui'
import { useShell } from '../shell-context'

/* The agent fleet, derived from the delegation matrix and proposal authority in /health.
 *
 * Deliberately derived rather than hard-coded. The service does not currently expose a
 * per-agent registration document, so what can honestly be shown is what it does expose:
 * who may delegate to whom, and who may propose what. Inventing an owner, a version or a
 * lifecycle status here would be describing a registry the running service does not have.
 */

interface AgentRow {
  id: string
  delegatesTo: string[]
  receivesFrom: string[]
  proposes: string[]
}

export default function FleetPage() {
  const { health, error, loading } = useShell()

  if (loading && !health) return <Spinner label="Reading agent fleet" />
  if (error) return <ErrorNote title="Cannot reach the AEGIS service" detail={error} />
  if (!health) return null

  const matrix = health.governance.delegation_matrix
  const authority = health.governance.proposal_authority

  const rows: AgentRow[] = Object.keys(matrix)
    .sort()
    .map((id) => ({
      id,
      delegatesTo: matrix[id] ?? [],
      receivesFrom: Object.entries(matrix)
        .filter(([, targets]) => targets.includes(id))
        .map(([source]) => source),
      proposes: Object.entries(authority)
        .filter(([, agents]) => agents.includes(id))
        .map(([capability]) => capability),
    }))

  return (
    <div className="space-y-6">
      <PageHeader
        title="Agent fleet"
        lede="Derived from the delegation matrix and proposal authority the service reports. An agent's position here constrains what it may attempt; it grants nothing."
      />

      <div className="grid gap-3 sm:grid-cols-2">
        {rows.map((agent) => {
          const privileged = agent.proposes.length > 0
          return (
            <Card
              key={agent.id}
              title={agent.id}
              actions={
                privileged ? (
                  <Badge tone="gov">PROPOSAL AUTHORITY</Badge>
                ) : (
                  <Badge>NO MUTATION AUTHORITY</Badge>
                )
              }
            >
              <dl className="space-y-3 text-xs">
                <div>
                  <dt className="mb-1.5 tracking-widest text-faint uppercase">May delegate to</dt>
                  <dd className="flex flex-wrap gap-1.5">
                    {agent.delegatesTo.length ? (
                      agent.delegatesTo.map((target) => (
                        <Badge key={target} mono>
                          {target}
                        </Badge>
                      ))
                    ) : (
                      <span className="text-faint italic">nobody</span>
                    )}
                  </dd>
                </div>
                <div>
                  <dt className="mb-1.5 tracking-widest text-faint uppercase">
                    Receives work from
                  </dt>
                  <dd className="flex flex-wrap gap-1.5">
                    {agent.receivesFrom.length ? (
                      agent.receivesFrom.map((source) => (
                        <Badge key={source} mono>
                          {source}
                        </Badge>
                      ))
                    ) : (
                      <span className="text-faint italic">nobody</span>
                    )}
                  </dd>
                </div>
                <div>
                  <dt className="mb-1.5 tracking-widest text-faint uppercase">May propose</dt>
                  <dd className="flex flex-wrap gap-1.5">
                    {agent.proposes.length ? (
                      agent.proposes.map((capability) => (
                        <Badge key={capability} tone="gov" mono>
                          {capability}
                        </Badge>
                      ))
                    ) : (
                      <span className="text-faint italic">no production mutation</span>
                    )}
                  </dd>
                </div>
              </dl>
            </Card>
          )
        })}
      </div>

      <Card title="What this page does not show">
        <p className="text-sm leading-relaxed text-muted">
          The running service exposes delegation edges and proposal authority. It does not
          yet expose a per-agent registration document — owner, department, version,
          lifecycle status or approval record — so none of those are shown here. A fleet
          view that displayed them would be describing a registry this deployment does not
          have.
        </p>
      </Card>
    </div>
  )
}
