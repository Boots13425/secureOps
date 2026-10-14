import { AlertTriangle } from 'lucide-react'

/**
 * Explicit confirmation before an action that touches a network other than the
 * one the scanner sits on.
 *
 * Scanning another network is only ever started from inside this dialog, never
 * from the click that opened it. Declining is a normal outcome and leaves
 * everything untouched - no session is created, no probe is sent.
 */
export default function ConfirmDialog({
  open,
  title,
  body,
  detail,
  confirmLabel = 'Scan this network',
  cancelLabel = 'Not now',
  busy = false,
  error = null,
  onConfirm,
  onCancel,
}) {
  if (!open) return null

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      style={{ background: 'rgba(0,0,0,0.6)' }}
      onClick={onCancel}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-label={title}
        className="card w-full max-w-md flex flex-col gap-4"
        onClick={(event) => event.stopPropagation()}
      >
        <div className="flex items-start gap-3">
          <AlertTriangle size={18} className="text-[var(--warn)] shrink-0 mt-0.5" />
          <div className="min-w-0">
            <h2 className="text-sm font-semibold text-[var(--text-primary)]">{title}</h2>
            <p className="text-xs text-[var(--text-secondary)] mt-1">{body}</p>
          </div>
        </div>

        {detail && (
          <div className="rounded-[var(--radius-sm)] border border-[var(--border)] bg-[var(--bg-surface)] px-3 py-2 text-xs text-[var(--text-muted)]">
            {detail}
          </div>
        )}

        {error && (
          <div
            role="alert"
            className="rounded-[var(--radius-sm)] border border-[var(--danger)] bg-[var(--danger-bg)] px-3 py-2 text-xs text-[var(--danger-text)]"
          >
            {error}
          </div>
        )}

        <div className="flex items-center justify-end gap-2">
          <button
            type="button"
            onClick={onCancel}
            disabled={busy}
            className="text-sm font-medium px-4 py-2 rounded-[var(--radius-sm)] border border-[var(--border)] text-[var(--text-secondary)] hover:text-[var(--text-primary)] transition-colors disabled:opacity-60"
          >
            {cancelLabel}
          </button>
          <button
            type="button"
            onClick={onConfirm}
            disabled={busy}
            className="flex items-center gap-2 bg-[var(--accent)] hover:bg-[var(--accent-hover)] disabled:opacity-60 text-white text-sm font-medium px-4 py-2 rounded-[var(--radius-sm)] transition-colors"
          >
            {busy ? 'Starting…' : confirmLabel}
          </button>
        </div>
      </div>
    </div>
  )
}
