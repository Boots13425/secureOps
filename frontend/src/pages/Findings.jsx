import { useState } from 'react'
import { Filter, Search, ShieldAlert } from 'lucide-react'
import { useFindings, useFindingsSummary, useUpdateFindingStatus } from '../hooks/useFindings'
import ConfidencePill from '../components/ConfidencePill'
import EmptyState from '../components/EmptyState'
import MetricCard from '../components/MetricCard'
import SeverityPill from '../components/SeverityPill'
import { timeAgo } from '../utils/time'

const CHECKS = ['smb-protocols', 'ftp-anon', 'ssl-cert', 'rdp-enum-encryption', 'service-observation', 'historical-comparison']

export default function Findings() {
  const [status, setStatus] = useState('open')
  const [severity, setSeverity] = useState('')
  const [confidence, setConfidence] = useState('')
  const [checkId, setCheckId] = useState('')
  const [query, setQuery] = useState('')
  const filters = { status, severity, confidence, checkId, query: query.trim() }
  const { data: findings, isLoading } = useFindings(filters)
  const { data: summary } = useFindingsSummary()
  const updateStatus = useUpdateFindingStatus()

  return (
    <div className="flex flex-col gap-5">
      <div>
        <h1 className="text-2xl font-semibold text-[var(--text-primary)]">Security exposure findings</h1>
        <p className="text-sm text-[var(--text-muted)]">Decision-oriented findings from approved network checks and observable configuration</p>
      </div>

      <div className="grid grid-cols-5 gap-4">
        <MetricCard label="Open findings" value={summary?.open} sub="requires review" />
        <MetricCard label="Critical" value={summary?.critical} sub="immediate attention" tone="danger" />
        <MetricCard label="High" value={summary?.high} sub="priority remediation" tone="danger" />
        <MetricCard label="Medium" value={summary?.medium} sub="planned remediation" tone="warn" />
        <MetricCard label="Affected assets" value={summary?.affected_assets} sub="assets with open findings" />
      </div>

      <div className="card flex items-end gap-3 flex-wrap">
        <div className="relative flex-1 min-w-64">
          <label className="block text-xs text-[var(--text-muted)] mb-1.5">Search findings</label>
          <Search size={15} className="absolute left-3 bottom-2.5 text-[var(--text-muted)]" />
          <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Title, evidence, asset or IP" className="w-full bg-[var(--bg-surface-2)] border border-[var(--border)] rounded-[var(--radius-sm)] pl-9 pr-3 py-2 text-sm text-[var(--text-primary)] outline-none" />
        </div>
        <Filter size={15} className="text-[var(--text-muted)] mb-2.5" />
        <div><label className="block text-xs text-[var(--text-muted)] mb-1.5">Status</label><select value={status} onChange={(event) => setStatus(event.target.value)} className="bg-[var(--bg-surface-2)] border border-[var(--border)] rounded-[var(--radius-sm)] px-3 py-2 text-sm text-[var(--text-primary)]"><option value="">All</option><option value="open">Open</option><option value="accepted">Accepted</option><option value="resolved">Resolved</option></select></div>
        <div><label className="block text-xs text-[var(--text-muted)] mb-1.5">Severity</label><select value={severity} onChange={(event) => setSeverity(event.target.value)} className="bg-[var(--bg-surface-2)] border border-[var(--border)] rounded-[var(--radius-sm)] px-3 py-2 text-sm text-[var(--text-primary)]"><option value="">All</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option><option value="informational">Informational</option></select></div>
        <div><label className="block text-xs text-[var(--text-muted)] mb-1.5">Confidence</label><select value={confidence} onChange={(event) => setConfidence(event.target.value)} className="bg-[var(--bg-surface-2)] border border-[var(--border)] rounded-[var(--radius-sm)] px-3 py-2 text-sm text-[var(--text-primary)]"><option value="">All</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select></div>
        <div><label className="block text-xs text-[var(--text-muted)] mb-1.5">Check</label><select value={checkId} onChange={(event) => setCheckId(event.target.value)} className="bg-[var(--bg-surface-2)] border border-[var(--border)] rounded-[var(--radius-sm)] px-3 py-2 text-sm text-[var(--text-primary)]"><option value="">All checks</option>{CHECKS.map((check) => <option key={check} value={check}>{check}</option>)}</select></div>
      </div>

      {!isLoading && (!findings || findings.length === 0) ? (
        <div className="card"><EmptyState icon={ShieldAlert} title="No findings match this view" description="Run a scan or adjust the filters to review exposure findings." /></div>
      ) : (
        <div className="flex flex-col gap-3">
          {(findings || []).map((finding) => (
            <article key={finding.finding_id} className="card">
              <div className="flex items-start justify-between gap-4 mb-4">
                <div><div className="flex items-center gap-2 mb-1.5"><SeverityPill severity={finding.severity} /><ConfidencePill confidence={finding.confidence} /><span className="pill pill--info">{finding.status}</span></div><h2 className="text-base font-semibold text-[var(--text-primary)]">{finding.title}</h2><div className="text-xs text-[var(--text-muted)] mt-1"><span className="text-[var(--text-secondary)]">{finding.hostname || 'Unresolved asset'}</span> · <span className="mono">{finding.ip_address}</span>{finding.port ? ` · ${finding.port}/${finding.protocol}` : ''}</div></div>
                <select aria-label={`Update status for ${finding.title}`} value={finding.status} disabled={updateStatus.isPending} onChange={(event) => updateStatus.mutate({ findingId: finding.finding_id, status: event.target.value })} className="bg-[var(--bg-surface-2)] border border-[var(--border)] rounded-[var(--radius-sm)] px-3 py-2 text-xs text-[var(--text-primary)]"><option value="open">Open</option><option value="accepted">Accept risk</option><option value="resolved">Resolved</option></select>
              </div>
              <div className="finding-detail-grid grid grid-cols-3 gap-4 text-sm">
                <div className="rounded-[var(--radius-sm)] border border-[var(--border)] bg-[var(--bg-surface-2)] p-3"><div className="text-[10px] uppercase tracking-wider text-[var(--text-muted)] mb-1.5">Evidence</div><p className="text-[var(--text-secondary)] whitespace-pre-wrap">{finding.evidence}</p></div>
                <div className="rounded-[var(--radius-sm)] border border-[var(--border)] bg-[var(--bg-surface-2)] p-3"><div className="text-[10px] uppercase tracking-wider text-[var(--text-muted)] mb-1.5">Why it matters</div><p className="text-[var(--text-secondary)]">{finding.why_it_matters}</p></div>
                <div className="rounded-[var(--radius-sm)] border border-[var(--border)] bg-[var(--bg-surface-2)] p-3"><div className="text-[10px] uppercase tracking-wider text-[var(--text-muted)] mb-1.5">Recommendation</div><p className="text-[var(--text-secondary)]">{finding.recommendation}</p></div>
              </div>
              <div className="flex items-center justify-between mt-3 text-[11px] text-[var(--text-muted)]"><span>Source: {finding.source?.replaceAll('_', ' ')} · Check: {finding.check_id}</span><span>First seen {timeAgo(finding.first_seen)} · Last seen {timeAgo(finding.last_seen)}</span></div>
            </article>
          ))}
        </div>
      )}

      <div className="text-xs text-[var(--text-muted)]">Default checks are restricted to smb-protocols, ftp-anon, ssl-cert and rdp-enum-encryption. Intrusive cipher enumeration is not enabled.</div>
    </div>
  )
}
