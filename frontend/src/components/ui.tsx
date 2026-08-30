/* Shared presentation primitives.
 *
 * Small on purpose. Every component here is a layout or emphasis decision — none of them
 * interprets a governance value, because a component that decided what "VERIFIED" means
 * would be a second opinion competing with the control plane's own.
 */

import type { ReactNode } from 'react'

// --- tone -------------------------------------------------------------------------

/** The four things colour is allowed to mean in this dashboard, plus a neutral. */
export type Tone = 'neutral' | 'good' | 'warn' | 'bad' | 'gov'

const TONE_TEXT: Record<Tone, string> = {
  neutral: 'text-muted',
  good: 'text-success',
  warn: 'text-warning',
  bad: 'text-danger',
  gov: 'text-governance',
}

const TONE_CHIP: Record<Tone, string> = {
  neutral: 'bg-line-soft text-muted border-line',
  good: 'bg-success/10 text-success border-success/30',
  warn: 'bg-warning/10 text-warning border-warning/30',
  bad: 'bg-danger/10 text-danger border-danger/30',
  gov: 'bg-governance/10 text-governance border-governance/30',
}

const TONE_DOT: Record<Tone, string> = {
  neutral: 'bg-faint',
  good: 'bg-success',
  warn: 'bg-warning',
  bad: 'bg-danger',
  gov: 'bg-governance',
}

// --- primitives -------------------------------------------------------------------

export function Card({
  title,
  subtitle,
  actions,
  children,
  className = '',
}: {
  title?: ReactNode
  subtitle?: ReactNode
  actions?: ReactNode
  children: ReactNode
  className?: string
}) {
  return (
    <section
      className={`rounded-lg border border-line bg-surface ${className}`}
    >
      {(title || actions) && (
        <header className="flex items-start justify-between gap-4 border-b border-line-soft px-5 py-3.5">
          <div>
            {title && (
              <h2 className="text-sm font-semibold tracking-wide text-text uppercase">
                {title}
              </h2>
            )}
            {subtitle && <p className="mt-1 text-xs text-muted">{subtitle}</p>}
          </div>
          {actions}
        </header>
      )}
      <div className="p-5">{children}</div>
    </section>
  )
}

export function Badge({
  tone = 'neutral',
  children,
  mono = false,
}: {
  tone?: Tone
  children: ReactNode
  mono?: boolean
}) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded border px-2 py-0.5 text-xs font-medium ${
        TONE_CHIP[tone]
      } ${mono ? 'font-mono' : ''}`}
    >
      {children}
    </span>
  )
}

export function Dot({ tone = 'neutral' }: { tone?: Tone }) {
  return <span className={`inline-block size-2 shrink-0 rounded-full ${TONE_DOT[tone]}`} />
}

export function StatTile({
  label,
  value,
  hint,
  tone = 'neutral',
}: {
  label: string
  value: ReactNode
  hint?: ReactNode
  tone?: Tone
}) {
  return (
    <div className="rounded-lg border border-line bg-surface px-4 py-3.5">
      <div className="text-[11px] font-medium tracking-widest text-faint uppercase">{label}</div>
      <div className={`tnum mt-1.5 text-lg font-semibold ${TONE_TEXT[tone]}`}>{value}</div>
      {hint && <div className="mt-1 text-xs text-muted">{hint}</div>}
    </div>
  )
}

/** A label/value row. Values are monospaced by default because most of them are ids. */
export function Field({
  label,
  children,
  mono = true,
}: {
  label: string
  children: ReactNode
  mono?: boolean
}) {
  return (
    <div className="flex items-baseline justify-between gap-4 border-b border-line-soft py-2 last:border-b-0">
      <dt className="shrink-0 text-xs tracking-wide text-muted uppercase">{label}</dt>
      <dd
        className={`tnum min-w-0 truncate text-right text-sm text-text ${mono ? 'font-mono' : ''}`}
      >
        {children}
      </dd>
    </div>
  )
}

/** An ordered list of short tokens — a decision, tool or delegation sequence. */
export function Sequence({ items, empty = 'none' }: { items: string[]; empty?: string }) {
  if (!items.length) return <span className="text-sm text-faint italic">{empty}</span>
  return (
    <ol className="flex flex-wrap items-center gap-1.5">
      {items.map((item, i) => (
        <li key={`${item}-${i}`} className="flex items-center gap-1.5">
          <span className="rounded border border-line bg-surface-2 px-2 py-0.5 font-mono text-xs text-text">
            {item}
          </span>
          {i < items.length - 1 && <span className="text-faint">→</span>}
        </li>
      ))}
    </ol>
  )
}

export function Spinner({ label = 'Loading' }: { label?: string }) {
  return (
    <div className="flex items-center justify-center gap-3 py-16 text-muted" role="status">
      <span className="size-4 animate-spin rounded-full border-2 border-line border-t-primary" />
      <span className="text-sm">{label}…</span>
    </div>
  )
}

export function ErrorNote({ title, detail }: { title: string; detail?: ReactNode }) {
  return (
    <div
      role="alert"
      className="rounded-lg border border-danger/30 bg-danger/10 px-5 py-4 text-sm"
    >
      <p className="font-semibold text-danger">{title}</p>
      {detail && <p className="mt-1.5 leading-relaxed text-muted">{detail}</p>}
    </div>
  )
}

export function EmptyState({ title, detail }: { title: string; detail?: ReactNode }) {
  return (
    <div className="rounded-lg border border-dashed border-line px-6 py-12 text-center">
      <p className="text-sm font-medium text-muted">{title}</p>
      {detail && <p className="mx-auto mt-2 max-w-lg text-xs text-faint">{detail}</p>}
    </div>
  )
}

/** The standing reminder that nothing here touches real infrastructure. */
export function SimulationNotice({ note }: { note?: string }) {
  return (
    <p className="rounded-md border border-warning/25 bg-warning/8 px-4 py-2.5 text-xs leading-relaxed text-warning/90">
      <span className="font-semibold">Simulated enterprise.</span>{' '}
      {note ??
        'Every resource, deployment, metric and mutation is synthetic and deterministic. Nothing here is real infrastructure, real telemetry or real customer data.'}
    </p>
  )
}

export function PageHeader({
  title,
  lede,
  actions,
}: {
  title: string
  lede?: ReactNode
  actions?: ReactNode
}) {
  return (
    <div className="flex flex-wrap items-end justify-between gap-4">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight text-text">{title}</h1>
        {lede && <p className="mt-1.5 max-w-2xl text-sm text-muted">{lede}</p>}
      </div>
      {actions}
    </div>
  )
}
