import { useState } from 'react'
import { Activity, CalendarClock, RefreshCw, Search, TrendingUp } from 'lucide-react'
import EmptyState from '../components/EmptyState'
import MetricCard from '../components/MetricCard'
import SeverityPill from '../components/SeverityPill'
import { useEpssIntelligence, useEpssRuns, useEpssSummary, useRefreshEpss } from '../hooks/useEpss'
import { timeAgo } from '../utils/time'

function percentage(value, digits = 1) {
  return value === null || value === undefined ? 'Not scored' : `${(Number(value) * 100).toFixed(digits)}%`
}

function riskTone(band) {
  return band === 'critical' || band === 'high' ? 'pill--danger' : band === 'medium' ? 'pill--warn' : 'pill--ok'
}

export default function EpssIntelligence() {
  const [status, setStatus] = useState('active')
  const [query, setQuery] = useState('')
  const filters = { status, query: query.trim() }
  const { data: intelligence, isLoading } = useEpssIntelligence(filters)
  const { data: summary } = useEpssSummary()
  const { data: runs } = useEpssRuns()
  const refresh = useRefreshEpss()
  const latestRun = runs?.[0]
  const working = refresh.isPending || ['queued', 'running'].includes(latestRun?.status)

  return (
    <div className="flex flex-col gap-5">
      <div className="flex items-end justify-between gap-4 flex-wrap">
        <div><h1 className="text-2xl font-semibold text-[var(--text-primary)]">EPSS exploitation probability</h1><p className="text-sm text-[var(--text-muted)]">Daily FIRST probability scores joined locally to discovered CVEs</p></div>
        <div className="flex items-center gap-3">
          <div className="text-right"><div className="text-xs text-[var(--text-secondary)]">Daily download {latestRun?.status || 'not run'}</div><div className="text-[11px] text-[var(--text-muted)]">Scheduled 14:45 Africa/Douala{latestRun?.status === 'failed' && latestRun.next_retry_at ? ` · retry ${timeAgo(latestRun.next_retry_at)}` : ''}</div></div>
          <button onClick={() => refresh.mutate()} disabled={working} className="flex items-center gap-2 bg-[var(--accent)] hover:bg-[var(--accent-hover)] disabled:opacity-60 text-[var(--on-accent)] text-sm font-semibold px-4 py-2.5 rounded-[var(--radius-sm)] transition-colors"><RefreshCw size={15} className={working ? 'animate-spin' : ''} />{working ? 'Downloading…' : 'Download today’s EPSS'}</button>
        </div>
      </div>

      <div className="grid grid-cols-5 gap-4">
        <MetricCard label="Discovered CVEs" value={summary?.discovered_cves} sub="active CVE candidates" />
        <MetricCard label="EPSS scored" value={summary?.scored_cves} sub="joined by CVE identifier" tone="ok" />
        <MetricCard label="Highest probability" value={summary?.highest_epss_score == null ? null : percentage(summary.highest_epss_score)} sub="exploitation in next 30 days" tone="danger" />
        <MetricCard label="Top percentile" value={summary?.highest_percentile == null ? null : percentage(summary.highest_percentile)} sub="relative EPSS position" tone="warn" />
        <MetricCard label="High org risk" value={summary?.high_risk_matches} sub="high or critical risk links" tone="danger" />
      </div>

      <div className="card border-[var(--accent-border)] bg-[linear-gradient(135deg,var(--accent-bg),var(--bg-surface))]">
        <div className="flex gap-3"><TrendingUp size={19} className="text-[var(--accent)] shrink-0 mt-0.5" /><div><div className="text-sm font-semibold text-[var(--text-primary)]">How to read this layer</div><p className="text-xs text-[var(--text-secondary)] leading-relaxed mt-1">EPSS estimates the probability that exploitation activity for a CVE will be observed in the wild during the next 30 days. It complements CVSS technical severity; it does not replace it or prove that this asset has been exploited.</p></div></div>
      </div>

      <div className="card flex items-end gap-3 flex-wrap">
        <div className="relative flex-1 min-w-64"><label className="block text-xs text-[var(--text-muted)] mb-1.5">Search risk intelligence</label><Search size={15} className="absolute left-3 bottom-2.5 text-[var(--text-muted)]" /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="CVE, product, asset or IP" className="w-full bg-[var(--bg-surface-2)] border border-[var(--border)] rounded-[var(--radius-sm)] pl-9 pr-3 py-2 text-sm text-[var(--text-primary)] outline-none" /></div>
        <div><label className="block text-xs text-[var(--text-muted)] mb-1.5">CVE status</label><select value={status} onChange={(event) => setStatus(event.target.value)} className="bg-[var(--bg-surface-2)] border border-[var(--border)] rounded-[var(--radius-sm)] px-3 py-2 text-sm text-[var(--text-primary)]"><option value="">All</option><option value="active">Active</option><option value="dismissed">Dismissed</option><option value="resolved">Resolved</option></select></div>
      </div>

      {!isLoading && (!intelligence || intelligence.length === 0) ? (
        <div className="card"><EmptyState icon={Activity} title="No CVEs have EPSS context in this view" description="Complete NVD enrichment first, then allow the daily EPSS snapshot to join scores by CVE identifier." /></div>
      ) : (
        <div className="flex flex-col gap-3">{(intelligence || []).map((item) => (
          <article className="card" key={item.service_vulnerability_id}>
            <div className="flex items-start justify-between gap-4 flex-wrap">
              <div><div className="flex items-center gap-2 flex-wrap"><span className="text-base font-semibold text-[var(--accent)]">{item.cve_id}</span><SeverityPill severity={(item.cvss_base_severity || 'informational').toLowerCase()} /><span className={`pill ${riskTone(item.organization_risk_band)}`}>{item.organization_risk_band || 'unrated'} organization risk</span></div><div className="text-xs text-[var(--text-muted)] mt-1.5">{item.hostname || 'Unresolved asset'} · <span className="mono">{item.ip_address}</span> · {item.port}/{item.protocol} · {item.product || item.service_name || 'Unidentified product'} {item.version || ''}</div></div>
              <div className="grid grid-cols-3 gap-2 text-center"><div className="rounded-[var(--radius-sm)] border border-[var(--border)] bg-[var(--bg-surface-2)] px-4 py-2"><div className="text-[10px] uppercase text-[var(--text-muted)]">EPSS</div><div className="text-lg font-semibold text-[var(--text-primary)]">{percentage(item.epss_score)}</div></div><div className="rounded-[var(--radius-sm)] border border-[var(--border)] bg-[var(--bg-surface-2)] px-4 py-2"><div className="text-[10px] uppercase text-[var(--text-muted)]">Percentile</div><div className="text-lg font-semibold text-[var(--text-primary)]">{percentage(item.epss_percentile)}</div></div><div className="rounded-[var(--radius-sm)] border border-[var(--border)] bg-[var(--bg-surface-2)] px-4 py-2"><div className="text-[10px] uppercase text-[var(--text-muted)]">Org risk</div><div className="text-lg font-semibold text-[var(--text-primary)]">{item.organization_risk_score ?? '—'}</div></div></div>
            </div>
            <p className="text-sm text-[var(--text-secondary)] leading-relaxed mt-4">{item.description}</p>
            <div className="epss-detail-grid grid grid-cols-3 gap-3 mt-4 text-xs"><div className="rounded-[var(--radius-sm)] border border-[var(--border)] bg-[var(--bg-surface-2)] p-3"><div className="text-[10px] uppercase tracking-wider text-[var(--text-muted)] mb-1">CVSS severity</div><div className="text-[var(--text-secondary)]">{item.cvss_base_score ?? 'Not scored'} / 10 · {(item.cvss_base_severity || 'unknown').toLowerCase()}</div></div><div className="rounded-[var(--radius-sm)] border border-[var(--border)] bg-[var(--bg-surface-2)] p-3"><div className="text-[10px] uppercase tracking-wider text-[var(--text-muted)] mb-1">EPSS freshness</div><div className="text-[var(--text-secondary)]">{item.epss_date || 'No daily score available'}</div></div><div className="rounded-[var(--radius-sm)] border border-[var(--border)] bg-[var(--bg-surface-2)] p-3"><div className="text-[10px] uppercase tracking-wider text-[var(--text-muted)] mb-1">Organizational context</div><div className="text-[var(--text-secondary)]">{item.device_type || 'unknown'} · {item.asset_status} · {item.match_confidence} evidence</div></div></div>
          </article>
        ))}</div>
      )}

      <div className="card flex gap-3"><CalendarClock size={18} className="text-[var(--info)] shrink-0" /><div className="text-xs text-[var(--text-secondary)] leading-relaxed"><strong className="text-[var(--text-primary)]">Risk formula:</strong> CVSS contributes 50%, EPSS 35%, match confidence 10%, and asset type/status 5%. The score is a transparent prototype prioritization aid, not proof of compromise. Latest stored EPSS snapshot: {summary?.latest_epss_date || 'none'}.</div></div>
    </div>
  )
}
