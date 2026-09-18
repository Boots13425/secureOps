import { Target, TrendingUp, TrendingDown, Minus, GitCompare, ArrowRight } from 'lucide-react'
import { Link } from 'react-router-dom'
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts'
import EmptyState from '../components/EmptyState'
import MetricCard from '../components/MetricCard'
import { useRiskAssets, useRiskSummary } from '../hooks/useRisk'
import { useTelemetryChanges, useTelemetryTrend } from '../hooks/useTelemetry'
import { useCurrentDevices } from '../hooks/useDevices'
import { useFindingsSummary } from '../hooks/useFindings'
import { useKevSummary } from '../hooks/useKev'

const BAND_TONE = { critical: 'pill--danger', high: 'pill--danger', elevated: 'pill--warn', moderate: 'pill--warn', low: 'pill--ok' }

// Project guide §13.2's priority queue lists every concrete driver behind an
// asset's score as its own bullet (e.g. "CISA KEV match", "SMBv1 enabled",
// "New RDP exposure"), not one vague sentence — a manager needs to see WHY,
// plural, not a single summarized reason. Same underlying numbers already
// shown on the Risk Engine page; this just itemizes them the way §13.2 does.
function riskDrivers(a) {
  const drivers = []
  if (a.has_kev) drivers.push('Confirmed actively exploited (CISA KEV)')
  if (a.max_cvss >= 9) drivers.push(`Critical severity vulnerability (CVSS ${a.max_cvss})`)
  else if (a.max_cvss >= 7) drivers.push(`High severity vulnerability (CVSS ${a.max_cvss})`)
  if (a.max_epss >= 0.5) drivers.push(`High exploitation probability (EPSS ${Math.round(a.max_epss * 100)}%)`)
  if (a.has_smbv1_finding) drivers.push('Legacy SMBv1 protocol enabled')
  if (a.has_anon_ftp_finding) drivers.push('Anonymous FTP access accepted')
  if (a.has_rdp_exposure_finding) drivers.push('RDP broadly exposed')
  if (a.has_cert_finding) drivers.push('TLS certificate expired or expiring soon')
  if (a.critical_finding_count) drivers.push(`${a.critical_finding_count} critical exposure finding${a.critical_finding_count === 1 ? '' : 's'} open`)
  if (a.high_finding_count) drivers.push(`${a.high_finding_count} high-severity exposure finding${a.high_finding_count === 1 ? '' : 's'} open`)
  if (a.criticality === 'critical_service' || a.criticality === 'business_server') drivers.push('Tagged as a high-importance asset')
  if (a.exposure === 'internet_facing' || a.exposure === 'guest_network') drivers.push('Sits on a broadly reachable network segment')
  if (drivers.length === 0) drivers.push('Elevated from combined risk factors')
  return drivers
}

// Project guide §13.1: "Posture trend — Improving / stable / deteriorating
// based on previous scan." Compares the average EARI score of the last two
// completed scans; a falling average risk score means posture is improving.
function posturePhrase(trend) {
  if (!trend || trend.length < 2) return { label: 'Not enough history', Icon: Minus, tone: 'text-[var(--text-muted)]' }
  const prev = trend[trend.length - 2].avg_risk_score
  const latest = trend[trend.length - 1].avg_risk_score
  if (prev == null || latest == null) return { label: 'Not enough history', Icon: Minus, tone: 'text-[var(--text-muted)]' }
  const delta = latest - prev
  if (delta <= -2) return { label: 'Improving', Icon: TrendingDown, tone: 'text-[var(--ok)]' }
  if (delta >= 2) return { label: 'Deteriorating', Icon: TrendingUp, tone: 'text-[var(--danger)]' }
  return { label: 'Stable', Icon: Minus, tone: 'text-[var(--text-secondary)]' }
}

export default function SecurityPosture() {
  const { data: assets, isLoading } = useRiskAssets()
  const { data: riskSummary } = useRiskSummary()
  const { data: changes } = useTelemetryChanges()
  const { data: trend } = useTelemetryTrend(10)
  const { data: currentDevices } = useCurrentDevices()
  const { data: findingsSummary } = useFindingsSummary()
  const { data: kevSummary } = useKevSummary()

  const topActions = (assets || []).slice(0, 5)
  const overallBand = riskSummary?.critical > 0 ? 'critical' : riskSummary?.high > 0 ? 'high' : riskSummary?.elevated > 0 ? 'elevated' : riskSummary?.moderate > 0 ? 'moderate' : 'low'

  const trendData = (trend || []).map((row) => ({
    time: new Date(row.started_at).toLocaleDateString(undefined, { month: 'short', day: 'numeric' }),
    'Avg risk': row.avg_risk_score,
  }))

  // Project guide §13.1 required top-level cards.
  const discoveredAssets = currentDevices?.length ?? null
  const unknownAssets = currentDevices ? currentDevices.filter((d) => d.status === 'unknown').length : null
  const highCriticalAssets = riskSummary ? (riskSummary.critical ?? 0) + (riskSummary.high ?? 0) : null
  const newExposures = changes?.baseline === false ? (changes.port_changes || []).filter((c) => c.change === 'opened').length : (changes?.baseline ? 0 : null)
  const posture = posturePhrase(trend)

  return (
    <div className="flex flex-col gap-5">
      <div>
        <h1 className="text-2xl font-semibold text-[var(--text-primary)]">Security posture & decision dashboard</h1>
        <p className="text-sm text-[var(--text-muted)]">The single big-picture view — pulling risk scores, recent changes, and top priorities from every layer into one screen</p>
      </div>

      <div className="card flex items-center gap-4">
        <div className={`pill ${BAND_TONE[overallBand] || 'pill--ok'} text-sm px-4 py-2`}>{overallBand.toUpperCase()}</div>
        <div>
          <div className="text-sm font-semibold text-[var(--text-primary)]">Overall network posture</div>
          <div className="text-xs text-[var(--text-muted)]">Driven by the highest-risk band present across {riskSummary?.assets_scored ?? 0} scored assets · {riskSummary?.index_label || 'ETSNTECH prototype prioritization index'}</div>
        </div>
      </div>

      {/* Project guide §13.1 — the seven required top-level cards, in the spec's own order. */}
      <div className="grid grid-cols-4 gap-4">
        <MetricCard label="Discovered assets" value={discoveredAssets} sub="in the latest scan" />
        <MetricCard label="Unknown/new assets" value={unknownAssets} sub="not yet approved" tone="warn" />
        <MetricCard label="High/Critical assets" value={highCriticalAssets} sub="EARI score 70+" tone="danger" />
        <MetricCard label="Open findings" value={findingsSummary?.open} sub="unresolved exposures" tone={findingsSummary?.open ? 'warn' : 'ok'} />
      </div>
      <div className="grid grid-cols-3 gap-4">
        <MetricCard label="KEV matches" value={kevSummary?.active_matches} sub="confirmed exploited in the wild" tone={kevSummary?.active_matches ? 'danger' : 'ok'} />
        <MetricCard label="New exposures" value={newExposures} sub="new ports/services since prior scan" tone={newExposures ? 'warn' : 'ok'} />
        <div className="card flex items-center gap-3">
          <posture.Icon size={22} className={posture.tone} />
          <div>
            <div className="text-xs font-medium uppercase tracking-[.06em] text-[var(--text-secondary)]">Posture trend</div>
            <div className={`text-lg font-semibold ${posture.tone}`}>{posture.label}</div>
          </div>
        </div>
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
            <div className="flex flex-col gap-4">
              {topActions.map((a) => (
                <div key={a.asset_id} className="flex items-start justify-between gap-3 text-xs border-b border-[var(--border)] last:border-0 pb-4 last:pb-0">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="pill pill--info">#{a.priority_rank}</span>
                      <span className="text-[var(--text-primary)] font-medium truncate">{a.hostname || a.ip_address}</span>
                      <span className={`pill ${BAND_TONE[a.risk_band] || 'pill--info'}`}>{a.label} · {a.risk_score}</span>
                    </div>
                    <ul className="mt-1.5 space-y-0.5 text-[var(--text-muted)] list-disc list-inside">
                      {riskDrivers(a).map((driver) => <li key={driver}>{driver}</li>)}
                    </ul>
                    <div className="mt-1.5 text-[var(--text-secondary)]">
                      <span className="font-medium text-[var(--text-primary)]">Actions: </span>{a.recommendations?.join(' ') || 'Continue routine monitoring.'}
                    </div>
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
              <div className="rounded-[var(--radius-sm)] border border-[var(--border)] bg-[var(--bg-surface-2)] p-3">
                <div className="text-[10px] uppercase text-[var(--text-muted)]">CVE changes</div>
                <div className="text-lg font-semibold text-[var(--text-primary)]">{changes.cve_changes.length}</div>
              </div>
              <div className="rounded-[var(--radius-sm)] border border-[var(--border)] bg-[var(--bg-surface-2)] p-3">
                <div className="text-[10px] uppercase text-[var(--text-muted)]">Risk changes</div>
                <div className="text-lg font-semibold text-[var(--text-primary)]">{changes.risk_changes.length}</div>
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
