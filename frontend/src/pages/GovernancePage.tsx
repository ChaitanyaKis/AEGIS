import { Badge, Card, ErrorNote, PageHeader, Spinner } from '../components/ui'
import { useShell } from '../shell-context'

/* The authority configuration in force, read from `/health`.
 *
 * Every table on this page is served by the control plane from the same constants the
 * orchestrator enforces (`PROPOSAL_AUTHORITY`, `COMMANDER_TOOLS`, `DELEGATION_MATRIX`).
 * It is a projection of the running configuration, not a copy maintained here — a copy
 * would eventually disagree with the thing it describes, and a governance page that
 * disagrees with the governance is worse than no page.
 */

export default function GovernancePage() {
  const { health, error, loading } = useShell()

  if (loading && !health) return <Spinner label="Reading governance configuration" />
  if (error) return <ErrorNote title="Cannot reach the AEGIS service" detail={error} />
  if (!health) return null

  const { proposal_authority, delegation_matrix, commander_tools, rule } = health.governance
  const capabilities = Object.entries(proposal_authority)
  const edges = Object.entries(delegation_matrix)

  return (
    <div className="space-y-6">
      <PageHeader
        title="Governance"
        lede="The authority configuration the running service enforces, projected from /health. Nothing on this page is editable — configuration is not reachable from a request."
      />

      <Card title="Operating rule">
        <p className="font-mono text-sm leading-relaxed text-primary">{rule}</p>
      </Card>

      <Card
        title="Proposal authority"
        subtitle="Which agents may even propose a capability. Proposing is not performing: a proposal still passes policy, approval, a gate, execution and verification."
      >
        {capabilities.length ? (
          <div className="divide-y divide-line-soft">
            {capabilities.map(([capability, agents]) => (
              <div
                key={capability}
                className="flex flex-wrap items-center justify-between gap-3 py-3 first:pt-0 last:pb-0"
              >
                <code className="font-mono text-sm text-text">{capability}</code>
                <div className="flex flex-wrap gap-1.5">
                  {agents.length ? (
                    agents.map((agent) => (
                      <Badge key={agent} tone="gov" mono>
                        {agent}
                      </Badge>
                    ))
                  ) : (
                    <span className="text-xs text-faint italic">no agent</span>
                  )}
                </div>
              </div>
            ))}
          </div>
        ) : (
          <p className="text-sm text-faint">No proposal authority is declared.</p>
        )}
      </Card>

      <Card
        title="Delegation matrix"
        subtitle="Every permitted delegation edge. An agent with no targets may delegate to nobody — which is what stops a specialist from reaching an agent that holds proposal authority."
      >
        <div className="divide-y divide-line-soft">
          {edges.map(([agent, targets]) => (
            <div
              key={agent}
              className="flex flex-wrap items-center gap-3 py-3 first:pt-0 last:pb-0"
            >
              <code className="w-36 shrink-0 font-mono text-sm text-text">{agent}</code>
              <span className="text-faint">→</span>
              <div className="flex flex-wrap gap-1.5">
                {targets.length ? (
                  targets.map((target) => (
                    <Badge key={target} mono>
                      {target}
                    </Badge>
                  ))
                ) : (
                  <Badge tone="bad">may delegate to nobody</Badge>
                )}
              </div>
            </div>
          ))}
        </div>
      </Card>

      <Card
        title="Commander tools"
        subtitle="The complete set of tools the Commander may call. A name outside this set is not a tool that fails — it is a tool that does not exist."
      >
        <ul className="flex flex-wrap gap-1.5">
          {commander_tools.map((tool) => (
            <li
              key={tool}
              className="rounded border border-line bg-surface-2 px-2.5 py-1 font-mono text-xs text-text"
            >
              {tool}
            </li>
          ))}
        </ul>
      </Card>
    </div>
  )
}
