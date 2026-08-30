import { NavLink } from 'react-router-dom'

const NAV = [
  { to: '/overview', label: 'Overview', hint: 'Posture and configuration' },
  { to: '/incidents', label: 'Run incident', hint: 'Drive the governed path' },
  { to: '/governance', label: 'Governance', hint: 'Authority and delegation' },
  { to: '/fleet', label: 'Agent fleet', hint: 'Who may do what' },
] as const

export default function SideBar() {
  return (
    <nav
      aria-label="Primary"
      className="flex w-60 shrink-0 flex-col gap-6 border-r border-line bg-surface px-4 py-5"
    >
      <div className="px-2">
        <div className="flex items-center gap-2">
          <span className="size-2.5 rounded-sm bg-primary" />
          <span className="text-sm font-semibold tracking-[0.2em] text-text">AEGIS</span>
        </div>
        <p className="mt-1.5 text-[11px] leading-snug text-faint">
          Autonomous Enterprise Agent Command &amp; Governance Fleet
        </p>
      </div>

      <ul className="flex flex-col gap-1">
        {NAV.map((item) => (
          <li key={item.to}>
            <NavLink
              to={item.to}
              className={({ isActive }) =>
                `block rounded-md px-3 py-2 transition-colors ${
                  isActive
                    ? 'bg-primary/10 text-primary'
                    : 'text-muted hover:bg-surface-2 hover:text-text'
                }`
              }
            >
              {({ isActive }) => (
                <>
                  <span className="block text-sm font-medium">{item.label}</span>
                  <span
                    className={`block text-[11px] ${isActive ? 'text-primary/70' : 'text-faint'}`}
                  >
                    {item.hint}
                  </span>
                </>
              )}
            </NavLink>
          </li>
        ))}
      </ul>

      <p className="mt-auto px-2 text-[11px] leading-relaxed text-faint">
        LLMs propose. Deterministic systems authorize. Tools execute. Verification
        establishes truth.
      </p>
    </nav>
  )
}
