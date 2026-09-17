export default function Placeholder({ title }) {
  return (
    <div className="card py-16 text-center">
      <h1 className="text-xl font-semibold text-[var(--text-primary)] mb-2">{title}</h1>
      <p className="text-sm text-[var(--text-muted)]">This screen is next up — not built yet.</p>
    </div>
  )
}
