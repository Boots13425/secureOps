export default function EmptyState({ icon: Icon, title, description, action }) {
  return (
    <div className="flex flex-col items-center justify-center text-center py-14 px-6">
      <div className="flex items-center justify-center w-11 h-11 rounded-[var(--radius-sm)] bg-[var(--accent-bg)] text-[var(--accent)] mb-4">
        <Icon size={20} />
      </div>
      <div className="text-sm font-semibold text-[var(--text-primary)] mb-1">{title}</div>
      <div className="text-xs text-[var(--text-muted)] max-w-xs mb-5">{description}</div>
      {action}
    </div>
  )
}
