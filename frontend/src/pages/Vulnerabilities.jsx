import { useState } from 'react'
import { DatabaseZap, ExternalLink, Filter, RefreshCw, Search } from 'lucide-react'
import { useEnrichmentRuns, useRefreshEnrichment, useUpdateVulnerabilityStatus, useVulnerabilities, useVulnerabilitiesSummary } from '../hooks/useVulnerabilities'
import ConfidencePill from '../components/ConfidencePill'
import EmptyState from '../components/EmptyState'
import MetricCard from '../components/MetricCard'
import SeverityPill from '../components/SeverityPill'
import { timeAgo } from '../utils/time'

export default function Vulnerabilities() {
  const [status, setStatus] = useState('active')
  const [severity, setSeverity] = useState('')
  const [confidence, setConfidence] = useState('')
  const [query, setQuery] = useState('')
  const filters = { status, severity, confidence, query: query.trim() }
  const { data: matches, isLoading } = useVulnerabilities(filters)
  const { data: summary } = useVulnerabilitiesSummary()
  const { data: runs } = useEnrichmentRuns()
  const refresh = useRefreshEnrichment()
  const updateStatus = useUpdateVulnerabilityStatus()
  const latestRun = runs?.[0]
  const working = refresh.isPending || ['queued', 'running'].includes(latestRun?.status)

  return (
    <div className="flex flex-col gap-5">
      <div className="flex items-end justify-between gap-4 flex-wrap">
        <div><h1 className="text-2xl font-semibold text-[var(--text-primary)]">Vulnerability intelligence</h1><p className="text-sm text-[var(--text-muted)]">Cached NVD CVE and CVSS candidates linked through observed CPE evidence</p></div>
        <div className="flex items-center gap-3">
          <div className="text-right"><div className="text-xs text-[var(--text-secondary)]">NVD data {latestRun?.status || 'not refreshed'}</div><div className="text-[11px] text-[var(--text-muted)]">{summary?.last_refreshed_at ? `Last refreshed ${timeAgo(summary.last_refreshed_at)}` : 'No vulnerability data stored yet'}</div></div>
          <button onClick={() => refresh.mutate()} disabled={working} className="flex items-center gap-2 bg-[var(--accent)] hover:bg-[var(--accent-hover)] disabled:opacity-60 text-[var(--on-accent)] text-sm font-semibold px-4 py-2.5 rounded-[var(--radius-sm)] transition-colors"><RefreshCw size={15} className={working ? 'animate-spin' : ''} />{working ? 'Enriching…' : 'Refresh NVD data'}</button>
        </div>
      </div>

      <div className="grid grid-cols-5 gap-4">
        <MetricCard label="Active matches" value={summary?.active_matches} sub="candidate service links" />
        <MetricCard label="Critical CVSS" value={summary?.critical} sub="NVD base severity" tone="danger" />
        <MetricCard label="High CVSS" value={summary?.high} sub="NVD base severity" tone="danger" />
        <MetricCard label="High confidence" value={summary?.high_confidence} sub="exact CPE/version matches" tone="ok" />
        <MetricCard label="Affected assets" value={summary?.affected_assets} sub="assets requiring validation" />
      </div>

      <div className="card flex items-end gap-3 flex-wrap">
        <div className="relative flex-1 min-w-64"><label className="block text-xs text-[var(--text-muted)] mb-1.5">Search intelligence</label><Search size={15} className="absolute left-3 bottom-2.5 text-[var(--text-muted)]" /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="CVE, description, product, asset or IP" className="w-full bg-[var(--bg-surface-2)] border border-[var(--border)] rounded-[var(--radius-sm)] pl-9 pr-3 py-2 text-sm text-[var(--text-primary)] outline-none" /></div>
        <Filter size={15} className="text-[var(--text-muted)] mb-2.5" />
        <div><label className="block text-xs text-[var(--text-muted)] mb-1.5">Status</label><select value={status} onChange={(event) => setStatus(event.target.value)} className="bg-[var(--bg-surface-2)] border border-[var(--border)] rounded-[var(--radius-sm)] px-3 py-2 text-sm text-[var(--text-primary)]"><option value="">All</option><option value="active">Active</option><option value="dismissed">Dismissed</option><option value="resolved">Resolved</option></select></div>
        <div><label className="block text-xs text-[var(--text-muted)] mb-1.5">CVSS severity</label><select value={severity} onChange={(event) => setSeverity(event.target.value)} className="bg-[var(--bg-surface-2)] border border-[var(--border)] rounded-[var(--radius-sm)] px-3 py-2 text-sm text-[var(--text-primary)]"><option value="">All</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select></div>
        <div><label className="block text-xs text-[var(--text-muted)] mb-1.5">Match confidence</label><select value={confidence} onChange={(event) => setConfidence(event.target.value)} className="bg-[var(--bg-surface-2)] border border-[var(--border)] rounded-[var(--radius-sm)] px-3 py-2 text-sm text-[var(--text-primary)]"><option value="">All</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option><option value="confirmed">Confirmed</option></select></div>
      </div>

      {!isLoading && (!matches || matches.length === 0) ? (
        <div className="card"><EmptyState icon={DatabaseZap} title="No vulnerability candidates match this view" description="Only sufficiently specific CPE evidence is submitted to NVD. Run a scan or refresh cached NVD data." /></div>
      ) : (
        <div className="flex flex-col gap-3">{(matches || []).map((match) => (
          <article key={match.service_vulnerability_id} className="card">
            <div className="flex items-start justify-between gap-4">
              <div className="flex gap-4 min-w-0">
                <div className="w-16 h-16 shrink-0 rounded-[var(--radius-sm)] bg-[var(--bg-surface-2)] border border-[var(--border)] flex flex-col items-center justify-center"><span className="text-[10px] text-[var(--text-muted)]">CVSS</span><span className="text-xl font-semibold text-[var(--text-primary)]">{match.cvss_base_score ?? '—'}</span><span className="text-[9px] text-[var(--text-muted)]">v{match.cvss_version || 'N/A'}</span></div>
                <div className="min-w-0"><div className="flex items-center gap-2 flex-wrap mb-1.5"><a href={`https://nvd.nist.gov/vuln/detail/${match.cve_id}`} target="_blank" rel="noreferrer" className="text-base font-semibold text-[var(--accent)] hover:underline inline-flex items-center gap-1">{match.cve_id}<ExternalLink size={13} /></a><SeverityPill severity={(match.cvss_base_severity || 'informational').toLowerCase()} /><ConfidencePill confidence={match.match_confidence === 'confirmed' ? 'high' : match.match_confidence} /></div><div className="text-xs font-medium text-[var(--text-secondary)]">{match.match_wording}</div><div className="text-xs text-[var(--text-muted)] mt-1">{match.hostname || 'Unresolved asset'} · <span className="mono">{match.ip_address}</span> · {match.port}/{match.protocol} · {match.product || match.service_name || 'Unidentified product'} {match.version || ''}</div></div>
              </div>
              <select aria-label={`Update status for ${match.cve_id}`} value={match.status} disabled={updateStatus.isPending} onChange={(event) => updateStatus.mutate({ matchId: match.service_vulnerability_id, status: event.target.value })} className="bg-[var(--bg-surface-2)] border border-[var(--border)] rounded-[var(--radius-sm)] px-3 py-2 text-xs text-[var(--text-primary)]"><option value="active">Active</option><option value="dismissed">Dismiss</option><option value="resolved">Resolved</option></select>
            </div>
            <p className="text-sm text-[var(--text-secondary)] leading-relaxed mt-4">{match.description}</p>
            <div className="vulnerability-detail-grid grid grid-cols-3 gap-3 mt-4 text-xs"><div className="rounded-[var(--radius-sm)] border border-[var(--border)] bg-[var(--bg-surface-2)] p-3"><div className="text-[10px] uppercase tracking-wider text-[var(--text-muted)] mb-1">Matched CPE</div><div className="mono break-all text-[var(--text-secondary)]">{match.matched_cpe}</div></div><div className="rounded-[var(--radius-sm)] border border-[var(--border)] bg-[var(--bg-surface-2)] p-3"><div className="text-[10px] uppercase tracking-wider text-[var(--text-muted)] mb-1">Match rationale</div><div className="text-[var(--text-secondary)]">{match.match_reason}</div></div><div className="rounded-[var(--radius-sm)] border border-[var(--border)] bg-[var(--bg-surface-2)] p-3"><div className="text-[10px] uppercase tracking-wider text-[var(--text-muted)] mb-1">CVSS vector</div><div className="mono break-all text-[var(--text-secondary)]">{match.cvss_vector || 'Not supplied by NVD'}</div></div></div>
            <div className="flex justify-between mt-3 text-[11px] text-[var(--text-muted)]"><span>Candidate applicability: {match.applicability_status} · NVD status: {match.vuln_status || 'unknown'}</span><span>Checked {timeAgo(match.last_checked_at)}</span></div>
          </article>
        ))}</div>
      )}

      <div className="text-xs text-[var(--text-muted)]">Remote product/version matches are candidates until validated. This layer does not present an NVD CPE match as confirmed exploitation or a confirmed vulnerability.</div>
    </div>
  )
}
