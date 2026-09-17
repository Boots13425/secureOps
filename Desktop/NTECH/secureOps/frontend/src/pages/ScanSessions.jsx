import { useState } from 'react'
import { RefreshCw, Square, RotateCcw, Radar } from 'lucide-react'
import { useScanNetwork, useScanSessions, useStartSession, useStopSession, useResumeSession } from '../hooks/useScanSessions'
import EmptyState from '../components/EmptyState'
import { timeAgo } from '../utils/time'

const DURATION_OPTIONS = [5, 6, 7, 8, 9, 10]

const STATUS_BADGE = {
  RUNNING: 'pill--ok',
  STOPPED: 'pill--info',
  COMPLETED: 'pill--info',
  FAILED: 'pill--danger',
}

function modeLabel(session) {
  if (!session.mode) return 'One-time scan'
  return session.mode === 'bounded' ? `Bounded · ${session.duration_minutes} min` : 'Continuous'
}

export default function ScanSessions() {
  const { data: sessions, isLoading } = useScanSessions()
  const { data: network } = useScanNetwork()
  const startMutation = useStartSession()
  const stopMutation = useStopSession()
  const resumeMutation = useResumeSession()

  const [subnet, setSubnet] = useState('')
  const [duration, setDuration] = useState('')

  function handleStart() {
    startMutation.mutate({
      subnet: subnet.trim() || undefined,
      durationMinutes: duration ? Number(duration) : undefined,
    })
  }

  return (
    <div className="flex flex-col gap-5">
      <div>
        <h1 className="text-2xl font-semibold text-[var(--text-primary)]">Scan Sessions</h1>
        <p className="text-sm text-[var(--text-muted)]">
          {isLoading ? 'Loading…' : `${sessions?.length ?? 0} session${sessions?.length === 1 ? '' : 's'}`}
        </p>
      </div>

      <div className="card flex items-end gap-3 flex-wrap">
        <div className="flex flex-col gap-1">
          <label className="text-xs text-[var(--text-muted)]">Subnet (auto-detected)</label>
          <input
            type="text"
            value={subnet}
            onChange={(e) => setSubnet(e.target.value)}
            placeholder={network?.selected ? `Auto: ${network.selected}` : 'Detecting active network…'}
            className="bg-[var(--bg-surface-2)] border border-[var(--border)] rounded-[var(--radius-sm)] px-3 py-2 text-sm text-[var(--text-primary)] placeholder:text-[var(--text-muted)] outline-none focus:border-[var(--accent)] w-56"
          />
        </div>
        <div className="flex flex-col gap-1">
          <label className="text-xs text-[var(--text-muted)]">Duration</label>
          <select
            value={duration}
            onChange={(e) => setDuration(e.target.value)}
            className="bg-[var(--bg-surface-2)] border border-[var(--border)] rounded-[var(--radius-sm)] px-3 py-2 text-sm text-[var(--text-primary)]"
          >
            <option value="">Continuous (default)</option>
            {DURATION_OPTIONS.map((m) => (
              <option key={m} value={m}>{m} minutes</option>
            ))}
          </select>
        </div>
        <button
          onClick={handleStart}
          disabled={startMutation.isPending}
          className="flex items-center gap-2 bg-[var(--accent)] hover:bg-[var(--accent-hover)] disabled:opacity-60 text-white text-sm font-medium px-4 py-2 rounded-[var(--radius-sm)] transition-colors"
        >
          <RefreshCw size={14} className={startMutation.isPending ? 'animate-spin' : ''} />
          Start new session
        </button>
      </div>

      <div className="card">
        {!sessions || sessions.length === 0 ? (
          <EmptyState icon={Radar} title="No sessions yet" description="Start a session above to begin monitoring the network." />
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-[10px] uppercase tracking-wide text-[var(--text-muted)] border-b border-[var(--border)]">
                <th className="pb-2 font-medium">Subnet</th>
                <th className="pb-2 font-medium">Mode</th>
                <th className="pb-2 font-medium">Source</th>
                <th className="pb-2 font-medium">Status</th>
                <th className="pb-2 font-medium">Devices</th>
                <th className="pb-2 font-medium">Started</th>
                <th className="pb-2 font-medium">Ended</th>
                <th className="pb-2 font-medium">Actions</th>
              </tr>
            </thead>
            <tbody>
              {sessions.map((s) => (
                <tr key={s.id} className="border-b border-[var(--border)] last:border-0">
                  <td className="py-2.5 mono">{s.subnet}</td>
                  <td className="py-2.5 text-[var(--text-secondary)]">{modeLabel(s)}</td>
                  <td className="py-2.5 text-[var(--text-secondary)] capitalize">{s.source || 'manual'}</td>
                  <td className="py-2.5">
                    <span className={`pill ${STATUS_BADGE[s.status] || 'pill--info'}`}>{s.status}</span>
                  </td>
                  <td className="py-2.5">{s.devices_found ?? '—'}</td>
                  <td className="py-2.5 text-[var(--text-secondary)]">{timeAgo(s.started_at)}</td>
                  <td className="py-2.5 text-[var(--text-secondary)]">{s.finished_at ? timeAgo(s.finished_at) : '—'}</td>
                  <td className="py-2.5">
                    {s.status === 'RUNNING' ? (
                      <button
                        onClick={() => stopMutation.mutate(s.id)}
                        disabled={stopMutation.isPending}
                        className="flex items-center gap-1.5 text-xs px-2.5 py-1.5 rounded-[var(--radius-sm)] border border-[var(--border)] text-[var(--text-secondary)] hover:bg-[var(--bg-hover)] hover:text-[var(--text-primary)] disabled:opacity-60"
                      >
                        <Square size={12} fill="currentColor" />
                        Stop
                      </button>
                    ) : (
                      <button
                        onClick={() => resumeMutation.mutate(s.id)}
                        disabled={resumeMutation.isPending}
                        className="flex items-center gap-1.5 text-xs px-2.5 py-1.5 rounded-[var(--radius-sm)] border border-[var(--border)] text-[var(--text-secondary)] hover:bg-[var(--bg-hover)] hover:text-[var(--text-primary)] disabled:opacity-60"
                      >
                        <RotateCcw size={12} />
                        Resume
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}
