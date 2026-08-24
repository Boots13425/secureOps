import { useScanSessions } from '../hooks/useScanSessions'
import { timeAgo } from '../utils/time'

export default function NextScanWidget() {
  const { data: sessions } = useScanSessions()
  const latest = sessions?.[0]
  const running = (sessions || []).find((s) => s.status === 'RUNNING')

  return (
    <div className="rounded-[var(--radius-sm)] border border-[var(--border)] bg-[var(--bg-surface)] px-3 py-3 text-xs">
      <div className="text-[var(--text-muted)]">Monitoring</div>

      {!latest ? (
        <div className="text-[var(--text-primary)] font-medium mt-0.5">Never started</div>
      ) : running ? (
        <>
          <div className="text-[var(--ok)] font-medium mt-0.5">● Active</div>
          <div className="text-[var(--text-muted)] mt-1.5">
            {running.mode === 'bounded' ? `${running.duration_minutes}-minute session` : 'Continuous session'} · {running.subnet}
          </div>
        </>
      ) : (
        <>
          <div className="text-[var(--text-primary)] font-medium mt-0.5">Stopped</div>
          <div className="text-[var(--text-muted)] mt-1.5">last active {timeAgo(latest.finished_at)}</div>
        </>
      )}
    </div>
  )
}
