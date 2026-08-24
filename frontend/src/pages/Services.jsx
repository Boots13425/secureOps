import { useState } from 'react'
import { Binary, Filter, Search, ServerCog } from 'lucide-react'
import { useServices, useServicesSummary } from '../hooks/useServices'
import ConfidencePill from '../components/ConfidencePill'
import EmptyState from '../components/EmptyState'
import MetricCard from '../components/MetricCard'
import { timeAgo } from '../utils/time'

function EnrichmentPill({ service }) {
  if (service.enrichment_status === 'enriched') return <span className="pill pill--ok">Enriched</span>
  if (service.enrichment_status === 'cpe_ready') return <span className="pill pill--info">CPE ready</span>
  return <span className="pill pill--warn">Not enriched</span>
}

export default function Services() {
  const [confidence, setConfidence] = useState('')
  const [enrichmentStatus, setEnrichmentStatus] = useState('')
  const [query, setQuery] = useState('')
  const [port, setPort] = useState('')
  const filters = { confidence, enrichmentStatus, query: query.trim(), port }
  const { data: services, isLoading } = useServices(filters)
  const { data: summary } = useServicesSummary()

  return (
    <div className="flex flex-col gap-5">
      <div>
        <h1 className="text-2xl font-semibold text-[var(--text-primary)]">Service exposure</h1>
        <p className="text-sm text-[var(--text-muted)]">Products, versions and CPE evidence observed on discovered assets</p>
      </div>

      <div className="grid grid-cols-5 gap-4">
        <MetricCard label="Open services" value={summary?.total} sub="persistent exposures" />
        <MetricCard label="Exposed assets" value={summary?.exposed_assets} sub="assets with open ports" />
        <MetricCard label="High confidence" value={summary?.high_confidence} sub="strong fingerprint evidence" tone="ok" />
        <MetricCard label="CPE ready" value={summary?.cpe_ready} sub="eligible for intelligence" />
        <MetricCard label="Not enriched" value={summary?.not_enriched} sub="no trusted CPE match" tone="warn" />
      </div>

      <div className="card flex items-end gap-3 flex-wrap">
        <div className="relative flex-1 min-w-64">
          <label className="block text-xs text-[var(--text-muted)] mb-1.5">Search evidence</label>
          <Search size={15} className="absolute left-3 bottom-2.5 text-[var(--text-muted)]" />
          <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Asset, service, product, version or CPE" className="w-full bg-[var(--bg-surface-2)] border border-[var(--border)] rounded-[var(--radius-sm)] pl-9 pr-3 py-2 text-sm text-[var(--text-primary)] outline-none" />
        </div>
        <div>
          <label className="block text-xs text-[var(--text-muted)] mb-1.5">Port</label>
          <input type="number" min="1" max="65535" value={port} onChange={(event) => setPort(event.target.value)} placeholder="Any" className="w-24 bg-[var(--bg-surface-2)] border border-[var(--border)] rounded-[var(--radius-sm)] px-3 py-2 text-sm text-[var(--text-primary)] outline-none" />
        </div>
        <Filter size={15} className="text-[var(--text-muted)] mb-2.5" />
        <div>
          <label className="block text-xs text-[var(--text-muted)] mb-1.5">Confidence</label>
          <select value={confidence} onChange={(event) => setConfidence(event.target.value)} className="bg-[var(--bg-surface-2)] border border-[var(--border)] rounded-[var(--radius-sm)] px-3 py-2 text-sm text-[var(--text-primary)] outline-none">
            <option value="">All confidence</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option>
          </select>
        </div>
        <div>
          <label className="block text-xs text-[var(--text-muted)] mb-1.5">Intelligence state</label>
          <select value={enrichmentStatus} onChange={(event) => setEnrichmentStatus(event.target.value)} className="bg-[var(--bg-surface-2)] border border-[var(--border)] rounded-[var(--radius-sm)] px-3 py-2 text-sm text-[var(--text-primary)] outline-none">
            <option value="">All states</option><option value="cpe_ready">CPE ready</option><option value="not_enriched">Not enriched</option><option value="enriched">Enriched</option>
          </select>
        </div>
      </div>

      <div className="card">
        {!isLoading && (!services || services.length === 0) ? (
          <EmptyState icon={ServerCog} title="No service fingerprints yet" description="Run a scan to fingerprint exposed services on discovered assets." />
        ) : (
          <table className="w-full text-sm">
            <thead><tr className="text-left text-[10px] uppercase tracking-wide text-[var(--text-muted)] border-b border-[var(--border)]">
              <th className="pb-2 font-medium">Asset</th><th className="pb-2 font-medium">Exposure</th><th className="pb-2 font-medium">Service</th><th className="pb-2 font-medium">Product / version</th><th className="pb-2 font-medium">CPE evidence</th><th className="pb-2 font-medium">Confidence</th><th className="pb-2 font-medium">First / last seen</th>
            </tr></thead>
            <tbody>{(services || []).map((service) => (
              <tr key={service.service_id} className="border-b border-[var(--border)] last:border-0 align-top">
                <td className="py-3 pr-4"><div className="text-[var(--text-primary)]">{service.hostname || 'Unresolved asset'}</div><div className="mono text-[var(--text-muted)]">{service.ip_address}</div></td>
                <td className="py-3 pr-4"><span className="mono text-[var(--accent)]">{service.port}/{service.protocol}</span><div className="text-[11px] text-[var(--ok)] mt-1">Open</div></td>
                <td className="py-3 pr-4 text-[var(--text-primary)]">{service.service_name || 'Unknown service'}</td>
                <td className="py-3 pr-4"><div className="text-[var(--text-primary)]">{service.product || 'Product not identified'}</div><div className="text-xs text-[var(--text-muted)]">{service.version || 'Version unavailable'}</div></td>
                <td className="py-3 pr-4 max-w-72"><EnrichmentPill service={service} />{service.cpe ? <div className="mono text-[11px] text-[var(--text-secondary)] break-all mt-1.5">{service.cpe}</div> : <div className="text-[11px] text-[var(--text-muted)] mt-1.5">No CPE returned; CVE matching withheld</div>}</td>
                <td className="py-3 pr-4"><ConfidencePill confidence={service.confidence} /><div className="text-[10px] text-[var(--text-muted)] mt-1.5">{service.detection_source?.replaceAll('_', ' ')}</div></td>
                <td className="py-3 whitespace-nowrap"><div className="text-[var(--text-secondary)]">{timeAgo(service.first_seen)}</div><div className="text-xs text-[var(--text-muted)]">{timeAgo(service.last_seen)}</div></td>
              </tr>
            ))}</tbody>
          </table>
        )}
      </div>

      <div className="flex items-center gap-2 text-xs text-[var(--text-muted)]"><Binary size={14} /><span>Raw product and version strings are retained even when no CPE is available.</span></div>
    </div>
  )
}
