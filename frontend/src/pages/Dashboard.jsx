import { useState } from 'react'
import { RefreshCw, Square, Cpu, HardDrive, TrendingUp, Boxes } from 'lucide-react'
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts'
import { format } from 'date-fns'
import { useDevices, useScanActivity, useScanHistory } from '../hooks/useDevices'
import { useScanSessions, useStartSession, useStopSession } from '../hooks/useScanSessions'
import MetricCard from '../components/MetricCard'
import StatusPill from '../components/StatusPill'
import OsCell from '../components/OsCell'
import EmptyState from '../components/EmptyState'
import { timeAgo } from '../utils/time'

const WEEK_MS = 7 * 24 * 60 * 60 * 1000

function computeMetrics(devices) {
  if (!devices || devices.length === 0) return null
  const total = devices.length
  const present = devices.filter((d) => !['missing', 'offline'].includes(d.status)).length
  const missing = devices.filter((d) => ['missing', 'offline'].includes(d.status)).length
  const unknown = devices.filter((d) => d.status === 'unknown').length
  const approved = devices.filter((d) => d.status === 'approved').length
  const newThisWeek = devices.filter((d) => d.first_seen && Date.now() - new Date(d.first_seen).getTime() < WEEK_MS).length
  const sources = [...new Set(devices.flatMap((d) => d.discovery_sources || []))]
  return { total, present, missing, unknown, approved, newThisWeek, sources }
}

function computeBreakdown(devices, keyFn, fallback) {
  const counts = {}
  for (const d of devices) {
    const key = keyFn(d) || fallback
    counts[key] = (counts[key] || 0) + 1
  }
  return Object.entries(counts).sort((a, b) => b[1] - a[1])
}

function BreakdownBars({ data }) {
  const max = data.length ? data[0][1] : 1
  return (
    <div className="flex flex-col gap-3 mt-4">
      {data.map(([name, count]) => (
        <div key={name} className="flex items-center gap-3">
          <div className="w-36 text-sm text-[var(--text-secondary)] truncate">{name}</div>
          <div className="flex-1 h-2 rounded-full bg-[var(--bg-surface-2)] overflow-hidden">
            <div className="h-full rounded-full bg-[var(--chart-1)]" style={{ width: `${(count / max) * 100}%` }} />
          </div>
          <div className="w-6 text-sm text-[var(--text-primary)] text-right">{count}</div>
        </div>
      ))}
    </div>
  )
}

const DURATION_OPTIONS = [5, 6, 7, 8, 9, 10]

export default function Dashboard() {
  const { data: devices, isLoading } = useDevices()
  const { data: activity } = useScanActivity()
  const { data: history } = useScanHistory()
  const { data: sessions } = useScanSessions()
  const startMutation = useStartSession()
  const stopMutation = useStopSession()
  const [duration, setDuration] = useState('')

  const manualSession = (sessions || []).find((s) => s.source === 'manual' && s.status === 'RUNNING')
  const scanning = !!manualSession || startMutation.isPending || stopMutation.isPending

  function handleScanClick() {
    if (manualSession) {
      stopMutation.mutate(manualSession.id)
    } else {
      startMutation.mutate({ durationMinutes: duration ? Number(duration) : undefined })
    }
  }

  const metrics = computeMetrics(devices)
  const osBreakdown = devices ? computeBreakdown(devices, (d) => d.os_name, 'Not identified') : []
  const deviceTypeBreakdown = devices ? computeBreakdown(devices, (d) => d.device_type, 'Unknown') : []
  const recentDevices = devices ? [...devices].sort((a, b) => new Date(b.last_seen) - new Date(a.last_seen)).slice(0, 7) : []
  const historyChartData = (history || []).map((h) => ({
    time: format(new Date(h.ts), 'HH:mm'),
    Responding: h.devices_found,
    Discovered: h.known_total,
  }))

  return (
    <div className="flex flex-col gap-5">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-[var(--text-primary)]">Dashboard</h1>
          <p className="text-sm text-[var(--text-muted)]">Network discovery and device information</p>
        </div>
        <div className="flex items-center gap-2">
          <select
            value={duration}
            onChange={(e) => setDuration(e.target.value)}
            disabled={!!manualSession}
            className="bg-[var(--bg-surface)] border border-[var(--border)] rounded-[var(--radius-sm)] px-3 py-2.5 text-sm text-[var(--text-primary)] disabled:opacity-60"
          >
            <option value="">Continuous (default)</option>
            {DURATION_OPTIONS.map((m) => (
              <option key={m} value={m}>{m} minutes</option>
            ))}
          </select>
          <button
            onClick={handleScanClick}
            disabled={startMutation.isPending || stopMutation.isPending}
            className="flex items-center gap-2 bg-[var(--accent)] hover:bg-[var(--accent-hover)] disabled:opacity-60 text-white text-sm font-medium px-4 py-2.5 rounded-[var(--radius-sm)] transition-colors"
          >
            {manualSession ? (
              <>
                <Square size={13} fill="currentColor" />
                Stop Session
              </>
            ) : (
              <>
                <RefreshCw size={15} className={startMutation.isPending ? 'animate-spin' : ''} />
                Start Scan Session
              </>
            )}
          </button>
        </div>
      </div>

      <div className="grid grid-cols-5 gap-4">
        <MetricCard
          label="Total Devices"
          value={metrics?.total}
          sub={metrics ? (metrics.newThisWeek ? `+${metrics.newThisWeek} this week` : '') : 'Not scanned yet'}
        />
        <MetricCard label="Observed" value={metrics?.present} sub={metrics ? 'present in latest state' : 'Not scanned yet'} tone="ok" />
        <MetricCard
          label="Missing / offline"
          value={metrics?.missing}
          sub={metrics ? 'not observed in current state' : 'Not scanned yet'}
          tone="danger"
        />
        <MetricCard
          label="Unknown"
          value={metrics?.unknown}
          sub={metrics ? 'requires classification' : 'Not scanned yet'}
          tone="warn"
        />
        <MetricCard
          label="Approved"
          value={metrics?.approved}
          sub={metrics ? 'organizationally approved' : 'Not scanned yet'}
        />
      </div>

      <div className="grid grid-cols-3 gap-4">
        <div className="card col-span-2">
          <div className="mb-2">
            <h2 className="text-sm font-semibold text-[var(--text-primary)]">Devices seen over time</h2>
            <p className="text-xs text-[var(--text-muted)]">Devices responding vs. known total, per scan</p>
          </div>
          {historyChartData.length === 0 ? (
            <EmptyState icon={TrendingUp} title="No scan history yet" description="Run a network scan to start building history." />
          ) : (
            <ResponsiveContainer width="100%" height={220}>
              <LineChart data={historyChartData} margin={{ top: 8, right: 8, left: -20, bottom: 0 }}>
                <CartesianGrid stroke="var(--chart-grid)" strokeDasharray="3 3" vertical={false} />
                <XAxis dataKey="time" tick={{ fill: 'var(--text-muted)', fontSize: 11 }} axisLine={false} tickLine={false} />
                <YAxis tick={{ fill: 'var(--text-muted)', fontSize: 11 }} axisLine={false} tickLine={false} allowDecimals={false} />
                <Tooltip contentStyle={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', fontSize: 12 }} />
                <Line type="monotone" dataKey="Discovered" stroke="var(--chart-1)" strokeWidth={2} dot={false} />
                <Line type="monotone" dataKey="Responding" stroke="var(--chart-2)" strokeWidth={2} dot={false} />
              </LineChart>
            </ResponsiveContainer>
          )}
        </div>

        <div className="card">
          <div className="mb-2">
            <h2 className="text-sm font-semibold text-[var(--text-primary)]">Device types</h2>
            <p className="text-xs text-[var(--text-muted)]">Breakdown by discovered device type</p>
          </div>
          {deviceTypeBreakdown.length === 0 ? (
            <EmptyState icon={Boxes} title="No devices yet" description="Run a network scan to see device types." />
          ) : (
            <BreakdownBars data={deviceTypeBreakdown} />
          )}
        </div>
      </div>

      <div className="card">
        <div className="mb-2">
          <h2 className="text-sm font-semibold text-[var(--text-primary)]">Operating Systems</h2>
          <p className="text-xs text-[var(--text-muted)]">Operating system information from discovered devices</p>
        </div>
        {osBreakdown.length === 0 ? (
          <EmptyState
            icon={Cpu}
            title="No operating systems detected"
            description="Run a network scan to identify the operating systems connected to the network."
          />
        ) : (
          <BreakdownBars data={osBreakdown} />
        )}
      </div>

      <div className="card">
        <div className="flex items-center justify-between mb-2">
          <div>
            <h2 className="text-sm font-semibold text-[var(--text-primary)]">Devices</h2>
            <p className="text-xs text-[var(--text-muted)]">Discovered computers, servers and network devices</p>
          </div>
          {recentDevices.length > 0 && (
            <a href="/devices" className="text-xs text-[var(--accent)] hover:underline">View all</a>
          )}
        </div>

        {recentDevices.length === 0 ? (
          <EmptyState
            icon={HardDrive}
            title="No devices discovered yet"
            description="Connect to the company network and run a network scan to discover devices."
            action={
              <button
                onClick={() => startMutation.mutate({})}
                disabled={scanning}
                className="flex items-center gap-2 bg-[var(--accent)] hover:bg-[var(--accent-hover)] disabled:opacity-60 text-white text-sm font-medium px-4 py-2 rounded-[var(--radius-sm)] transition-colors"
              >
                <RefreshCw size={14} className={scanning ? 'animate-spin' : ''} />
                {scanning ? 'Scanning…' : 'Start Network Discovery'}
              </button>
            }
          />
        ) : (
          <table className="w-full text-sm mt-3">
            <thead>
              <tr className="text-left text-[10px] uppercase tracking-wide text-[var(--text-muted)] border-b border-[var(--border)]">
                <th className="pb-2 font-medium">Device</th>
                <th className="pb-2 font-medium">IP address</th>
                <th className="pb-2 font-medium">Operating system</th>
                <th className="pb-2 font-medium">Seen via</th>
                <th className="pb-2 font-medium">Status</th>
                <th className="pb-2 font-medium">Last seen</th>
              </tr>
            </thead>
            <tbody>
              {recentDevices.map((d) => (
                <tr key={d.id} className="border-b border-[var(--border)] last:border-0">
                  <td className="py-2.5">
                    <div className="text-[var(--text-primary)]">{d.hostname || 'Unknown'}</div>
                    <div className="text-[11px] text-[var(--text-muted)] capitalize">{d.device_type}</div>
                  </td>
                  <td className="py-2.5 mono">{d.ip}</td>
                  <td className="py-2.5"><OsCell osName={d.os_name} osSource={d.os_source} /></td>
                  <td className="py-2.5">
                    <span className="pill pill--info">{d.discovery_sources.join(' · ')}</span>
                  </td>
                  <td className="py-2.5"><StatusPill status={d.status} /></td>
                  <td className="py-2.5 text-[var(--text-secondary)]">{timeAgo(d.last_seen)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <div className="card">
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-sm font-semibold text-[var(--text-primary)]">Scan activity</h2>
          {activity && activity.length > 0 && (
            <a href="/discovery" className="text-xs text-[var(--accent)] hover:underline">View all</a>
          )}
        </div>
        {!activity || activity.length === 0 ? (
          <EmptyState icon={TrendingUp} title="No scan activity yet" description="Activity will appear here once a scan runs." />
        ) : (
          <div className="flex flex-col gap-3">
            {activity.map((event) => (
              <div key={event.id} className="flex items-start justify-between gap-3 text-sm">
                <div>
                  <div className="text-[var(--text-primary)]">{event.message}</div>
                  <div className="text-xs text-[var(--text-muted)] mono">{event.detail}</div>
                </div>
                <div className="text-xs text-[var(--text-muted)] whitespace-nowrap">{timeAgo(event.timestamp)}</div>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="grid grid-cols-3 gap-4 text-sm">
        <div className="card">
          <div className="text-xs text-[var(--text-muted)] mb-1">Last Network Scan</div>
          <div className="text-[var(--text-primary)] font-medium">
            {isLoading ? '…' : recentDevices[0] ? timeAgo(recentDevices[0].last_seen) : 'Never'}
          </div>
        </div>
        <div className="card">
          <div className="text-xs text-[var(--text-muted)] mb-1">Discovery Method</div>
          <div className="text-[var(--text-primary)] font-medium">Nmap</div>
        </div>
        <div className="card">
          <div className="text-xs text-[var(--text-muted)] mb-1">Network Status</div>
          <div className={`font-medium ${recentDevices.length ? 'text-[var(--ok)]' : 'text-[var(--warn)]'}`}>
            {recentDevices.length ? 'Active' : 'Not Started'}
          </div>
        </div>
      </div>
    </div>
  )
}
