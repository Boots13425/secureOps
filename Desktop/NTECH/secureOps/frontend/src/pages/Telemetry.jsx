import { useState } from 'react'
import { GitCompare, PlusCircle, MinusCircle, ArrowUpRight, ArrowDownRight, RefreshCw, Settings2, ShieldAlert, ShieldCheck, History as HistoryIcon } from 'lucide-react'
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from 'recharts'
import EmptyState from '../components/EmptyState'
import MetricCard from '../components/MetricCard'
import SeverityPill from '../components/SeverityPill'
import { useTelemetryChanges, useTelemetryTrend } from '../hooks/useTelemetry'
import { useScanSessions } from '../hooks/useScanSessions'
import { timeAgo } from '../utils/time'

const FIELD_LABELS = { os: 'OS', vendor: 'Vendor', mac_address: 'MAC address', hostname: 'Hostname' }

function ChangeGroup({ icon: Icon, title, tone, items, renderItem, emptyLabel }) {
  return (
    <div className="card">
      <div className="flex items-center gap-2 mb-3">
        <Icon size={16} className={tone} />
        <h2 className="text-sm font-semibold text-[var(--text-primary)]">{title}</h2>
        <span className="pill pill--info">{items.length}</span>
      </div>
      {items.length === 0 ? (
        <p className="text-xs text-[var(--text-muted)]">{emptyLabel}</p>
      ) : (
        <div className="flex flex-col gap-2">{items.map(renderItem)}</div>
      )}
    </div>
  )
}

export default function Telemetry() {
  const [fromScanId, setFromScanId] = useState('')
  const [toScanId, setToScanId] = useState('')
  const { data: sessions } = useScanSessions()
  const completedSessions = (sessions || []).filter((s) => s.status === 'COMPLETED')

  const { data: changes, isLoading } = useTelemetryChanges({ toScanId: toScanId || undefined, fromScanId: fromScanId || undefined })
  const { data: trend } = useTelemetryTrend(10)

  const trendData = (trend || []).map((row) => ({
    time: new Date(row.started_at).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }),
    Devices: row.device_count,
    'Open ports': row.open_port_count,
    'Avg risk score': row.avg_risk_score,
    'Highest risk score': row.max_risk_score,
  }))

  return (
    <div className="flex flex-col gap-5">
      <div>
        <h1 className="text-2xl font-semibold text-[var(--text-primary)]">Network changes & trends</h1>
        <p className="text-sm text-[var(--text-muted)]">What changed between two scans, and how your network has trended over recent scans</p>
      </div>

      <div className="card border-[var(--accent-border)] bg-[linear-gradient(135deg,var(--accent-bg),var(--bg-surface))]">
        <div className="flex gap-3">
          <GitCompare size={19} className="text-[var(--accent)] shrink-0 mt-0.5" />
          <div>
            <div className="text-sm font-semibold text-[var(--text-primary)]">How to read this layer</div>
            <p className="text-xs text-[var(--text-secondary)] leading-relaxed mt-1">
              Every other page shows what's true right now. This page compares two completed scans directly —
              devices that appeared or disappeared, ports that opened, closed, or had their service version change,
              OS/vendor/MAC/hostname changes, and security findings that newly appeared or got resolved — plus a
              trend of device count, open ports, and Layer 8 risk score across your last several scans. By default
              it compares your two most recent scans; use the pickers below to compare any two instead.
            </p>
          </div>
        </div>
      </div>

      <div className="card flex items-end gap-3 flex-wrap">
        <div>
          <label className="block text-xs text-[var(--text-muted)] mb-1.5">Baseline scan (from)</label>
          <select value={fromScanId} onChange={(event) => setFromScanId(event.target.value)} className="bg-[var(--bg-surface-2)] border border-[var(--border)] rounded-[var(--radius-sm)] px-3 py-2 text-sm text-[var(--text-primary)] min-w-64">
            <option value="">Auto — scan right before "to"</option>
            {completedSessions.map((s) => <option key={s.id} value={s.id}>{new Date(s.started_at).toLocaleString()}</option>)}
          </select>
        </div>
        <div>
          <label className="block text-xs text-[var(--text-muted)] mb-1.5">Compare scan (to)</label>
          <select value={toScanId} onChange={(event) => setToScanId(event.target.value)} className="bg-[var(--bg-surface-2)] border border-[var(--border)] rounded-[var(--radius-sm)] px-3 py-2 text-sm text-[var(--text-primary)] min-w-64">
            <option value="">Auto — most recent scan</option>
            {completedSessions.map((s) => <option key={s.id} value={s.id}>{new Date(s.started_at).toLocaleString()}</option>)}
          </select>
        </div>
        {(fromScanId || toScanId) && (
          <button onClick={() => { setFromScanId(''); setToScanId('') }} className="text-xs text-[var(--accent)] hover:underline pb-2.5">Reset to latest two</button>
        )}
      </div>

      {isLoading ? null : !changes?.to_scan ? (
        <div className="card"><EmptyState icon={HistoryIcon} title="No completed scan yet" description="Run a network scan to start building change history." /></div>
      ) : changes.baseline ? (
        <div className="card"><EmptyState icon={HistoryIcon} title="Only one scan so far" description="This is your first completed scan — there's nothing to compare it against yet. Run another scan to see what changed." /></div>
      ) : (
        <>
          <div className="text-xs text-[var(--text-muted)] flex items-center gap-1.5">
            <GitCompare size={13} />
            <span>Comparing scan from {timeAgo(changes.from_scan.started_at)} to scan from {timeAgo(changes.to_scan.started_at)}</span>
          </div>

          <div className="grid grid-cols-5 gap-4">
            <MetricCard label="New devices" value={changes.new_devices.length} sub="appeared since baseline" tone={changes.new_devices.length ? 'warn' : 'ok'} />
            <MetricCard label="Missing devices" value={changes.missing_devices.length} sub="not seen in compare scan" tone={changes.missing_devices.length ? 'warn' : 'ok'} />
            <MetricCard label="Port changes" value={changes.port_changes.length} sub="opened, closed, or updated" tone={changes.port_changes.length ? 'warn' : 'ok'} />
            <MetricCard label="Config changes" value={changes.config_changes.length} sub="OS, vendor, MAC, hostname" tone={changes.config_changes.length ? 'warn' : 'ok'} />
            <MetricCard label="Finding changes" value={changes.finding_changes.length} sub="security findings appeared/resolved" tone={changes.finding_changes.length ? 'warn' : 'ok'} />
          </div>

          <div className="grid grid-cols-3 gap-4">
            <ChangeGroup
              icon={PlusCircle} title="New devices" tone="text-[var(--ok)]"
              items={changes.new_devices} emptyLabel="No new devices between these scans."
              renderItem={(d) => (
                <div key={d.asset_id} className="flex items-center justify-between text-xs border-b border-[var(--border)] last:border-0 pb-2 last:pb-0">
                  <span className="text-[var(--text-primary)]">{d.hostname || 'Unknown'}</span>
                  <span className="mono text-[var(--text-muted)]">{d.ip_address}</span>
                </div>
              )}
            />
            <ChangeGroup
              icon={MinusCircle} title="Missing devices" tone="text-[var(--danger)]"
              items={changes.missing_devices} emptyLabel="No devices dropped off between these scans."
              renderItem={(d) => (
                <div key={d.asset_id} className="flex items-center justify-between text-xs border-b border-[var(--border)] last:border-0 pb-2 last:pb-0">
                  <span className="text-[var(--text-primary)]">{d.hostname || 'Unknown'}</span>
                  <span className="mono text-[var(--text-muted)]">{d.ip_address}</span>
                </div>
              )}
            />
            <ChangeGroup
              icon={ArrowUpRight} title="Port & service changes" tone="text-[var(--warn)]"
              items={changes.port_changes} emptyLabel="No ports opened, closed, or updated between these scans."
              renderItem={(p) => (
                <div key={`${p.asset_id}-${p.port}-${p.protocol}-${p.change}`} className="flex items-center justify-between text-xs border-b border-[var(--border)] last:border-0 pb-2 last:pb-0 gap-2">
                  <span className="flex items-center gap-1.5 min-w-0">
                    {p.change === 'opened' && <ArrowUpRight size={12} className="text-[var(--warn)] shrink-0" />}
                    {p.change === 'closed' && <ArrowDownRight size={12} className="text-[var(--ok)] shrink-0" />}
                    {p.change === 'updated' && <RefreshCw size={12} className="text-[var(--info)] shrink-0" />}
                    <span className="text-[var(--text-primary)] truncate">{p.hostname || p.ip_address}</span>
                    <span className="text-[var(--text-muted)] shrink-0">{p.port}/{p.protocol}</span>
                  </span>
                  <span className="text-[var(--text-muted)] text-right shrink-0">
                    {p.change === 'updated' ? `${p.old_version || 'unknown'} → ${p.new_version || 'unknown'}` : p.change}
                  </span>
                </div>
              )}
            />
            <ChangeGroup
              icon={Settings2} title="Config changes" tone="text-[var(--info)]"
              items={changes.config_changes} emptyLabel="No OS, vendor, MAC, or hostname changes between these scans."
              renderItem={(c) => (
                <div key={`${c.asset_id}-${c.field}`} className="flex items-center justify-between text-xs border-b border-[var(--border)] last:border-0 pb-2 last:pb-0 gap-2">
                  <span className="flex items-center gap-1.5 min-w-0">
                    <span className="text-[var(--text-primary)] truncate">{c.hostname || c.ip_address}</span>
                    <span className="pill pill--info shrink-0">{FIELD_LABELS[c.field] || c.field}</span>
                  </span>
                  <span className="text-[var(--text-muted)] text-right shrink-0">{c.old_value || 'unknown'} → {c.new_value || 'unknown'}</span>
                </div>
              )}
            />
            <ChangeGroup
              icon={ShieldAlert} title="Finding changes" tone="text-[var(--warn)]"
              items={changes.finding_changes} emptyLabel="No security findings appeared or got resolved between these scans."
              renderItem={(f) => (
                <div key={`${f.finding_id}-${f.change}`} className="flex items-center justify-between text-xs border-b border-[var(--border)] last:border-0 pb-2 last:pb-0 gap-2">
                  <span className="flex items-center gap-1.5 min-w-0">
                    {f.change === 'new' ? <ShieldAlert size={12} className="text-[var(--warn)] shrink-0" /> : <ShieldCheck size={12} className="text-[var(--ok)] shrink-0" />}
                    <span className="text-[var(--text-primary)] truncate">{f.title}</span>
                    <SeverityPill severity={f.severity} />
                  </span>
                  <span className="text-[var(--text-muted)] text-right shrink-0">{f.hostname || f.ip_address} · {f.change}</span>
                </div>
              )}
            />
          </div>
        </>
      )}

      <div className="card">
        <div className="mb-2">
          <h2 className="text-sm font-semibold text-[var(--text-primary)]">Trend over recent scans</h2>
          <p className="text-xs text-[var(--text-muted)]">
            Device count, open ports, and Layer 8 risk score (average and highest) across your last {trendData.length || 0} completed
            scans. Risk scores use current CVSS/EPSS/KEV/criticality data applied to the assets seen in each scan — not a
            point-in-time snapshot of what the score was back then, since those inputs aren't stored per scan.
          </p>
        </div>
        {trendData.length === 0 ? (
          <EmptyState icon={GitCompare} title="No scan history yet" description="Run a few scans to start building a trend." />
        ) : (
          <ResponsiveContainer width="100%" height={240}>
            <LineChart data={trendData} margin={{ top: 8, right: 8, left: -20, bottom: 0 }}>
              <CartesianGrid stroke="var(--chart-grid)" strokeDasharray="3 3" vertical={false} />
              <XAxis dataKey="time" tick={{ fill: 'var(--text-muted)', fontSize: 11 }} axisLine={false} tickLine={false} />
              <YAxis tick={{ fill: 'var(--text-muted)', fontSize: 11 }} axisLine={false} tickLine={false} allowDecimals={false} />
              <Tooltip contentStyle={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', fontSize: 12 }} />
              <Legend wrapperStyle={{ fontSize: 11 }} />
              <Line type="monotone" dataKey="Devices" stroke="var(--chart-1)" strokeWidth={2} dot={false} />
              <Line type="monotone" dataKey="Open ports" stroke="var(--chart-2)" strokeWidth={2} dot={false} />
              <Line type="monotone" dataKey="Avg risk score" stroke="var(--chart-3)" strokeWidth={2} dot={false} />
              <Line type="monotone" dataKey="Highest risk score" stroke="var(--danger)" strokeWidth={2} dot={false} />
            </LineChart>
          </ResponsiveContainer>
        )}
      </div>
    </div>
  )
}
