const DOT_COLOR = {
  neutral: 'text-[var(--text-secondary)]',
  ok: 'text-[var(--ok)]',
  danger: 'text-[var(--danger)]',
  warn: 'text-[var(--warn)]',
}

const STRIPE_COLOR = {
  neutral: 'via-[var(--accent)]',
  ok: 'via-[var(--ok)]',
  danger: 'via-[var(--danger)]',
  warn: 'via-[var(--warn)]',
}

export default function MetricCard({ label, value, sub, tone = 'neutral' }) {
  const hasValue = value !== null && value !== undefined
  return (
    <div className="card group flex flex-col gap-3 overflow-hidden">
      <div className={`absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent ${STRIPE_COLOR[tone]} to-transparent opacity-55`} />
      <div className="flex items-center gap-2">
        <span className={`inline-block w-2 h-2 rounded-full bg-current shadow-[0_0_8px_currentColor] ${DOT_COLOR[tone]}`} />
        <span className="text-xs font-medium uppercase tracking-[.06em] text-[var(--text-secondary)]">{label}</span>
      </div>
      <div className="text-[2rem] leading-none font-semibold tracking-[-.035em] text-[var(--text-primary)]">
        {hasValue ? value : <span className="text-[var(--text-muted)]">—</span>}
      </div>
      <div className="text-xs text-[var(--text-muted)]">{sub}</div>
    </div>
  )
}
