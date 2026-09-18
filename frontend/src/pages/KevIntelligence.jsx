import { useState } from 'react'
import { AlertOctagon, CalendarClock, ExternalLink, Flame, RefreshCw, Search, ShieldAlert } from 'lucide-react'
import EmptyState from '../components/EmptyState'
import MetricCard from '../components/MetricCard'
import ConfidencePill from '../components/ConfidencePill'
import { useKevIntelligence, useKevRuns, useRefreshKev } from '../hooks/useKev'
import { useLatestCompletedSession } from '../hooks/useScanSessions'
import { timeAgo } from '../utils/time'

function daysUntil(dateStr) {
  if (!dateStr) return null
  return Math.ceil((new Date(dateStr) - new Date()) / (1000 * 60 * 60 * 24))
}

function dueTone(dateStr) {
  const days = daysUntil(dateStr)
  if (days === null) return 'text-[var(--text-muted)]'
  if (days < 0) return 'text-[var(--danger)]'
  if (days <= 14) return 'text-[var(--warn)]'
  return 'text-[var(--text-secondary)]'
}

function dueLabel(dateStr) {
  const days = daysUntil(dateStr)
  if (days === null) return 'No remediation deadline published'
  if (days < 0) return `Overdue by ${Math.abs(days)} day${Math.abs(days) === 1 ? '' : 's'}`
  if (days === 0) return 'Due today'
  return `Due in ${days} day${days === 1 ? '' : 's'}`
}

// Computed from whatever the list is actually showing, so the cards and the
// matches below them always agree, and stay correct whichever scope is picked.
function summarize(matches) {
  const list = matches || []
  return {
    active_matches: list.length,
    distinct_cves: new Set(list.map((item) => item.cve_id)).size,
    due_soon: list.filter((item) => { const d = daysUntil(item.kev_due_date); return d !== null && d >= 0 && d <= 14 }).length,
    affected_assets: new Set(list.map((item) => item.asset_id)).size,
  }
}

export default function KevIntelligence() {
  const [scope, setScope] = useState('current')
  const [status, setStatus] = useState('active')
  const [query, setQuery] = useState('')
  const { session: latestScan, isLoading: sessionLoading } = useLatestCompletedSession()
  const scanId = scope === 'current' ? latestScan?.id : undefined
  const { data: matches, isLoading: matchesLoading } = useKevIntelligence({ status, query: query.trim(), scanId })
  const summary = summarize(matches)
  const isLoading = sessionLoading || matchesLoading
  const blockedByNoScan = scope === 'current' && !sessionLoading && !latestScan
  const { data: runs } = useKevRuns()
  const refresh = useRefreshKev()
  const latestRun = runs?.[0]
  const working = refresh.isPending || latestRun?.status === 'running'

  return (
    <div className="flex flex-col gap-5">
      <div className="flex items-end justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-2xl font-semibold text-[var(--text-primary)]">Known exploited vulnerabilities</h1>
          <p className="text-sm text-[var(--text-muted)]">
            {scope === 'current' ? "CISA's confirmed-exploited catalog, cross-checked against CVEs found in the last scan." : "CISA's confirmed-exploited catalog, cross-checked against every CVE ever discovered, across every scan."}
          </p>
        </div>
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1 bg-[var(--bg-surface)] border border-[var(--border)] rounded-[var(--radius-sm)] p-1">
            <button onClick={() => setScope('current')} className={`px-3 py-1.5 text-xs font-medium rounded-[var(--radius-sm)] transition-colors ${scope === 'current' ? 'bg-[var(--accent)] text-white' : 'text-[var(--text-muted)] hover:text-[var(--text-primary)]'}`}>Current scan</button>
            <button onClick={() => setScope('all')} className={`px-3 py-1.5 text-xs font-medium rounded-[var(--radius-sm)] transition-colors ${scope === 'all' ? 'bg-[var(--accent)] text-white' : 'text-[var(--text-muted)] hover:text-[var(--text-primary)]'}`}>All time</button>
          </div>
          <div className="text-right">
            <div className="text-xs text-[var(--text-secondary)]">Catalog check {latestRun?.status || 'not run yet'}</div>
            <div className="text-[11px] text-[var(--text-muted)]">{latestRun?.finished_at ? `Last checked ${timeAgo(latestRun.finished_at)}` : 'Runs automatically after every scan'}</div>
          </div>
          <button onClick={() => refresh.mutate()} disabled={working} className="flex items-center gap-2 bg-[var(--accent)] hover:bg-[var(--accent-hover)] disabled:opacity-60 text-[var(--on-accent)] text-sm font-semibold px-4 py-2.5 rounded-[var(--radius-sm)] transition-colors">
            <RefreshCw size={15} className={working ? 'animate-spin' : ''} />{working ? 'Checking…' : 'Re-check CISA KEV'}
          </button>
        </div>
      </div>

      <div className="grid grid-cols-4 gap-4">
        <MetricCard label="Known exploited" value={summary.active_matches} sub="confirmed by CISA" tone="danger" />
        <MetricCard label="Distinct CVEs" value={summary.distinct_cves} sub="unique confirmed vulnerabilities" tone="danger" />
        <MetricCard label="Due soon" value={summary.due_soon} sub="remediation due within 14 days" tone="warn" />
        <MetricCard label="Affected assets" value={summary.affected_assets} sub="devices requiring action" />
      </div>

      <div className="card border-[var(--accent-border)] bg-[linear-gradient(135deg,var(--accent-bg),var(--bg-surface))]">
        <div className="flex gap-3">
          <ShieldAlert size={19} className="text-[var(--accent)] shrink-0 mt-0.5" />
          <div>
            <div className="text-sm font-semibold text-[var(--text-primary)]">How to read this layer</div>
            <p className="text-xs text-[var(--text-secondary)] leading-relaxed mt-1">
              Everything on this page is confirmed, not predicted — CISA only adds a CVE here once there is real evidence it has
              been exploited in the wild. Because of that, a match here outranks CVSS severity and EPSS probability everywhere
              else in the app: this is the strongest signal the system has.
            </p>
          </div>
        </div>
      </div>

      <div className="card flex items-end gap-3 flex-wrap">
        <div className="relative flex-1 min-w-64">
          <label className="block text-xs text-[var(--text-muted)] mb-1.5">Search known-exploited intelligence</label>
          <Search size={15} className="absolute left-3 bottom-2.5 text-[var(--text-muted)]" />
          <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="CVE, product, asset or IP" className="w-full bg-[var(--bg-surface-2)] border border-[var(--border)] rounded-[var(--radius-sm)] pl-9 pr-3 py-2 text-sm text-[var(--text-primary)] outline-none" />
        </div>
        <div>
          <label className="block text-xs text-[var(--text-muted)] mb-1.5">Status</label>
          <select value={status} onChange={(event) => setStatus(event.target.value)} className="bg-[var(--bg-surface-2)] border border-[var(--border)] rounded-[var(--radius-sm)] px-3 py-2 text-sm text-[var(--text-primary)]">
            <option value="">All</option><option value="active">Active</option><option value="dismissed">Dismissed</option><option value="resolved">Resolved</option>
          </select>
        </div>
      </div>

      {blockedByNoScan ? (
        <div className="card">
          <EmptyState icon={AlertOctagon} title="No completed scan yet" description="Start a scan from the Discovery page, or switch to All time to see historical data." />
        </div>
      ) : !isLoading && (!matches || matches.length === 0) ? (
        <div className="card">
          <EmptyState icon={AlertOctagon} title="Nothing confirmed exploited right now" description="That's a good result — none of the CVEs found on your network are currently on CISA's confirmed-exploited list. This is checked automatically after every scan." />
        </div>
      ) : (
        <div className="flex flex-col gap-3">
          {(matches || []).map((match) => (
            <article className="card border-l-4 border-l-[var(--danger)]" key={match.service_vulnerability_id}>
              <div className="flex items-start justify-between gap-4 flex-wrap">
                <div>
                  <div className="flex items-center gap-2 flex-wrap mb-1.5">
                    <a href={`https://nvd.nist.gov/vuln/detail/${match.cve_id}`} target="_blank" rel="noreferrer" className="text-base font-semibold text-[var(--accent)] hover:underline inline-flex items-center gap-1">{match.cve_id}<ExternalLink size={13} /></a>
                    <span className="pill pill--danger inline-flex items-center gap-1"><Flame size={11} />Known Exploited</span>
                    {match.kev_known_ransomware_use && <span className="pill pill--danger">Ransomware use</span>}
                    <ConfidencePill confidence={match.match_confidence} />
                  </div>
                  <div className="text-xs text-[var(--text-muted)]">{match.hostname || 'Unresolved asset'} · <span className="mono">{match.ip_address}</span> · {match.port}/{match.protocol} · {match.product || match.service_name || 'Unidentified product'} {match.version || ''}</div>
                </div>
                <div className={`text-right text-xs font-semibold ${dueTone(match.kev_due_date)}`}>
                  <div className="flex items-center gap-1.5 justify-end"><CalendarClock size={13} />{dueLabel(match.kev_due_date)}</div>
                  {match.kev_due_date && <div className="text-[var(--text-muted)] font-normal mt-0.5">{match.kev_due_date}</div>}
                </div>
              </div>

              <p className="text-sm text-[var(--text-secondary)] leading-relaxed mt-4">{match.description}</p>

              <div className="grid grid-cols-3 gap-3 mt-4 text-xs">
                <div className="rounded-[var(--radius-sm)] border border-[var(--border)] bg-[var(--bg-surface-2)] p-3">
                  <div className="text-[10px] uppercase tracking-wider text-[var(--text-muted)] mb-1">CISA required action</div>
                  <div className="text-[var(--text-secondary)]">{match.kev_required_action || 'Not specified by CISA'}</div>
                </div>
                <div className="rounded-[var(--radius-sm)] border border-[var(--border)] bg-[var(--bg-surface-2)] p-3">
                  <div className="text-[10px] uppercase tracking-wider text-[var(--text-muted)] mb-1">Added to CISA catalog</div>
                  <div className="text-[var(--text-secondary)]">{match.kev_date_added || 'Unknown'}</div>
                </div>
                <div className="rounded-[var(--radius-sm)] border border-[var(--border)] bg-[var(--bg-surface-2)] p-3">
                  <div className="text-[10px] uppercase tracking-wider text-[var(--text-muted)] mb-1">CVSS severity</div>
                  <div className="text-[var(--text-secondary)]">{match.cvss_base_score ?? 'Not scored'} / 10 · {(match.cvss_base_severity || 'unknown').toLowerCase()}</div>
                </div>
              </div>

              <div className="flex justify-between mt-3 text-[11px] text-[var(--text-muted)]">
                <span>{match.device_type || 'unknown'} · {match.asset_status}</span>
                <span>Status: {match.status}</span>
              </div>
            </article>
          ))}
        </div>
      )}

      <div className="text-xs text-[var(--text-muted)]">This list only ever contains vulnerabilities CISA has explicitly confirmed as exploited — nothing here is a probability or a guess.</div>
    </div>
  )
}
