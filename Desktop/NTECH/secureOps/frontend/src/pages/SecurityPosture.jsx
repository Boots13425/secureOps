import { Target, Flame, TrendingUp, GitCompare, ArrowRight } from 'lucide-react'
import { Link } from 'react-router-dom'
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts'
import EmptyState from '../components/EmptyState'
import MetricCard from '../components/MetricCard'
import { useRiskAssets, useRiskSummary } from '../hooks/useRisk'
import { useTelemetryChanges, useTelemetryTrend } from '../hooks/useTelemetry'

const BAND_TONE = { critical: 'pill--danger', high: 'pill--danger', medium: 'pill--warn', low: 'pill--ok' }

// A short, transparent reason per asset, picking whichever factor actually
// drove the score highest — same underlying numbers already shown on the
// Risk Engine page, just summarized into one sentence for a decision-maker.
function topReason(a) {
  if (a.has_kev) return 'Confirmed actively exploited (CISA KEV)'
  if (a.max_cvss >= 9) return `Critical severity vulnerability (CVSS ${a.max_cvss})`
  if (a.max_epss >= 0.5) return `High exploitation probability (EPSS ${Math.round(a.max_epss * 100)}%)`
  if (a.exposure_score >= 40) return 'Multiple significant security findings open'
  if (a.criticality === 'critical' || a.criticality === 'high') return 'Tagged as a high-importance asset'
  return 'Elevated from combined risk factors'
}

export default function SecurityPosture() {
  const { data: assets, isLoading } = useRiskAssets()
  const { data: riskSummary } = useRiskSummary()
  const { data: changes } = useTelemetryChanges()
  const { data: trend } = useTelemetryTrend(10)

  const topActions = (assets || []).slice(0, 5)
  const overallBand = riskSummary?.critical > 0 ? 'critical' : riskSummary?.high > 0 ? 'high' : riskSummary?.medium > 0 ? 'medium' : 'low'

  const trendData = (trend || []).map((row) => ({
    time: new Date(row.started_at).toLocaleDateString(undefined, { month: 'short', day: 'numeric' }),
    'Avg risk': row.avg_risk_score,
  }))

  return (
    <div className="flex flex-col gap-5">
      <div>
        <h1 className="text-2xl font-semibold text-[var(--text-primary)]">Security posture & decision dashboard</h1>
        <p className="text-sm text-[var(--text-muted)]">The single big-picture view — pulling risk scores, recent changes, and top priorities from every layer into one screen</p>
      </div>

      <div className="card border-[var(--accent-border)] bg-[linear-gradient(135deg,var(--accent-bg),var(--bg-surface))]">
        <div className="flex gap-3">
          <Target size={19} className="text-[var(--accent)] shrink-0 mt-0.5" />
          <div>
            <div className="text-sm font-semibold text-[var(--text-primary)]">How to read this layer</div>
            <p className="text-xs text-[var(--text-secondary)] leading-relaxed mt-1">
              Every other page answers one narrow question. This page answers "what should we do today?" by combining the
              Risk Engine's scores (Layer 8) with the most recent network changes (Layer 7) into one prioritized view. It
              does not compute anything new itself — everything here is drawn directly from those two layers.
            </p>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div className="card flex items-center gap-4">
          <div className={`pill ${BAND_TONE[overallBand] || 'pill--ok'} text-sm px-4 py-2`}>{overallBand.toUpperCase()}</div>
          <div>
            <div className="text-sm font-semibold text-[var(--text-primary)]">Overall network posture</div>
            <div className="text-xs text-[var(--text-muted)]">Driven by the highest-risk band present across {riskSummary?.assets_scored ?? 0} scored assets</div>
          </div>
        </div>
        <div className="card flex items-center gap-4">
          <Flame size={28} className={riskSummary?.kev_matches ? 'text-[var(--danger)]' : 'text-[var(--ok)]'} />
          <div>
            <div className="text-sm font-semibold text-[var(--text-primary)]">{riskSummary?.kev_matches ?? 0} confirmed exploited (KEV)</div>
            <div className="text-xs text-[var(--text-muted)]">{riskSummary?.kev_matches ? 'Requires immediate attention' : 'Nothing confirmed exploited right now'}</div>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-4 gap-4">
        <MetricCard label="Critical" value={riskSummary?.critical} sub="assets" tone="danger" />
        <MetricCard label="High" value={riskSummary?.high} sub="assets" tone="danger" />
        <MetricCard label="Medium" value={riskSummary?.medium} sub="assets" tone="warn" />
        <MetricCard label="Low" value={riskSummary?.low} sub="assets" tone="ok" />
      </div>

      <div className="grid grid-cols-2 gap-4 items-start">
        <div className="card">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              <Target size={16} className="text-[var(--danger)]" />
              <h2 className="text-sm font-semibold text-[var(--text-primary)]">Top priority actions</h2>
            </div>
            <Link to="/risk" className="text-xs text-[var(--accent)] hover:underline flex items-center gap-1">Full ranking <ArrowRight size={12} /></Link>
          </div>
          {!isLoading && topActions.length === 0 ? (
            <EmptyState icon={Target} title="No assets scored yet" description="Run a scan first." />
          ) : (
            <div className="flex flex-col gap-3">
              {topActions.map((a) => (
                <div key={a.asset_id} className="flex items-start justify-between gap-3 text-xs border-b border-[var(--border)] last:border-0 pb-3 last:pb-0">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="pill pill--info">#{a.priority_rank}</span>
                      <span className="text-[var(--text-primary)] font-medium truncate">{a.hostname || a.ip_address}</span>
                      <span className={`pill ${BAND_TONE[a.risk_band] || 'pill--info'}`}>{a.risk_band}</span>
                    </div>
                    <div className="text-[var(--text-muted)] mt-1">{topReason(a)}</div>
                  </div>
                  <div className="text-right shrink-0">
                    <div className="text-base font-semibold text-[var(--text-primary)]">{a.risk_score}</div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="card">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              <GitCompare size={16} className="text-[var(--info)]" />
              <h2 className="text-sm font-semibold text-[var(--text-primary)]">What changed recently</h2>
            </div>
            <Link to="/telemetry" className="text-xs text-[var(--accent)] hover:underline flex items-center gap-1">Full detail <ArrowRight size={12} /></Link>
          </div>
          {!changes?.to_scan ? (
            <EmptyState icon={GitCompare} title="No completed scan yet" description="Run a network scan to start building change history." />
          ) : changes.baseline ? (
            <EmptyState icon={GitCompare} title="Only one scan so far" description="Run another scan to see what changed." />
          ) : (
            <div className="grid grid-cols-2 gap-3 text-xs">
              <div className="rounded-[var(--radius-sm)] border border-[var(--border)] bg-[var(--bg-surface-2)] p-3">
                <div className="text-[10px] uppercase text-[var(--text-muted)]">New devices</div>
                <div className="text-lg font-semibold text-[var(--text-primary)]">{changes.new_devices.length}</div>
              </div>
              <div className="rounded-[var(--radius-sm)] border border-[var(--border)] bg-[var(--bg-surface-2)] p-3">
                <div className="text-[10px] uppercase text-[var(--text-muted)]">Missing devices</div>
                <div className="text-lg font-semibold text-[var(--text-primary)]">{changes.missing_devices.length}</div>
              </div>
              <div className="rounded-[var(--radius-sm)] border border-[var(--border)] bg-[var(--bg-surface-2)] p-3">
                <div className="text-[10px] uppercase text-[var(--text-muted)]">Port/service changes</div>
                <div className="text-lg font-semibold text-[var(--text-primary)]">{changes.port_changes.length}</div>
              </div>
              <div className="rounded-[var(--radius-sm)] border border-[var(--border)] bg-[var(--bg-surface-2)] p-3">
                <div className="text-[10px] uppercase text-[var(--text-muted)]">Finding changes</div>
                <div className="text-lg font-semibold text-[var(--text-primary)]">{changes.finding_changes.length}</div>
              </div>
            </div>
          )}
        </div>
      </div>

      <div className="card">
        <div className="flex items-center gap-2 mb-2">
          <TrendingUp size={16} className="text-[var(--accent)]" />
          <h2 className="text-sm font-semibold text-[var(--text-primary)]">Risk trend</h2>
        </div>
        {trendData.length === 0 ? (
          <EmptyState icon={TrendingUp} title="No scan history yet" description="Run a few scans to start building a trend." />
        ) : (
          <ResponsiveContainer width="100%" height={180}>
            <LineChart data={trendData} margin={{ top: 8, right: 8, left: -20, bottom: 0 }}>
              <CartesianGrid stroke="var(--chart-grid)" strokeDasharray="3 3" vertical={false} />
              <XAxis dataKey="time" tick={{ fill: 'var(--text-muted)', fontSize: 11 }} axisLine={false} tickLine={false} />
              <YAxis tick={{ fill: 'var(--text-muted)', fontSize: 11 }} axisLine={false} tickLine={false} domain={[0, 100]} />
              <Tooltip contentStyle={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', fontSize: 12 }} />
              <Line type="monotone" dataKey="Avg risk" stroke="var(--chart-3)" strokeWidth={2} dot={false} />
            </LineChart>
          </ResponsiveContainer>
        )}
      </div>
    </div>
  )
}
