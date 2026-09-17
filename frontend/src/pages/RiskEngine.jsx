import { useState } from 'react'
import { BrainCircuit, Flame } from 'lucide-react'
import EmptyState from '../components/EmptyState'
import { uploadRiskPolicy } from '../api/client'
import MetricCard from '../components/MetricCard'
import { useRiskAssets, useRiskSummary, useUpdateCriticality } from '../hooks/useRisk'

const BAND_TONE = { critical: 'pill--danger', high: 'pill--danger', elevated: 'pill--warn', moderate: 'pill--warn', low: 'pill--ok' }
const CRITICALITY_OPTIONS = ['low', 'normal', 'high', 'critical']

function ScoreBar({ label, value, max = 100 }) {
  const pct = Math.max(0, Math.min(100, (value / max) * 100))
  return (
    <div>
      <div className="flex justify-between text-[10px] text-[var(--text-muted)] mb-0.5">
        <span>{label}</span>
        <span>{value}</span>
      </div>
      <div className="h-1.5 rounded-full bg-[var(--bg-surface-2)] overflow-hidden">
        <div className="h-full bg-[var(--accent)]" style={{ width: `${pct}%` }} />
      </div>
    </div>
  )
}

export default function RiskEngine() {
  const { data: assets, isLoading, refetch: refetchAssets } = useRiskAssets()
  const { data: summary, refetch: refetchSummary } = useRiskSummary()
  const updateCriticality = useUpdateCriticality()

  const [files, setFiles] = useState({ criticality: null, network: null })
  const [uploadStatus, setUploadStatus] = useState({ criticality: null, network: null })

  async function handlePolicyUpload(kind) {
    const file = files[kind]
    if (!file) return
    setUploadStatus((current) => ({ ...current, [kind]: { state: 'uploading', message: 'Uploading...' } }))
    try {
      const endpoint = kind === 'criticality' ? '/risk/policy/device-criticality' : '/risk/policy/network-context'
      const data = await uploadRiskPolicy(endpoint, file)
      await Promise.all([refetchAssets(), refetchSummary()])
      setUploadStatus((current) => ({ ...current, [kind]: { state: 'success', message: `${data.rows_uploaded} row(s) uploaded at ${new Date(data.updated_at).toLocaleString()}.` } }))
    } catch (err) {
      const detail = err.response?.data?.detail
      const errors = detail?.errors?.map((item) => `Row ${item.row}: ${item.message}`).join(' ') || detail?.message || err.message
      setUploadStatus((current) => ({ ...current, [kind]: { state: 'error', message: errors } }))
    }
  }

  function PolicyCard({ kind, title, description }) {
    const status = uploadStatus[kind]
    return (
      <div className="card border-[var(--border)] bg-[var(--bg-surface)] p-4">
        <div className="text-sm font-semibold text-[var(--text-primary)] mb-1">{title}</div>
        <p className="text-xs text-[var(--text-secondary)] mb-3">{description}</p>
        <div className="flex items-center gap-3 flex-wrap">
          <input type="file" accept=".csv" onChange={(event) => setFiles((current) => ({ ...current, [kind]: event.target.files[0] || null }))} className="text-xs text-[var(--text-secondary)]" />
          <button type="button" onClick={() => handlePolicyUpload(kind)} disabled={!files[kind] || status?.state === 'uploading'} className="bg-[var(--accent)] hover:bg-[var(--accent-hover)] disabled:opacity-50 text-white text-xs font-medium px-3 py-2 rounded-[var(--radius-sm)]">
            {status?.state === 'uploading' ? 'Uploading...' : 'Upload policy'}
          </button>
        </div>
        {status && <p role={status.state === 'error' ? 'alert' : undefined} className={`text-xs mt-2 ${status.state === 'error' ? 'text-[var(--danger)]' : 'text-[var(--text-primary)]'}`}>{status.message}</p>}
      </div>
    )
  }

  return (
    <div className="flex flex-col gap-5">
      <div>
        <h1 className="text-2xl font-semibold text-[var(--text-primary)]">Risk & interpretation engine</h1>
        <p className="text-sm text-[var(--text-muted)]">ETSNTECH prototype prioritization index for each asset</p>
      </div>

      <div className="card border-[var(--accent-border)] bg-[linear-gradient(135deg,var(--accent-bg),var(--bg-surface))]">
        <div className="flex gap-3">
          <BrainCircuit size={19} className="text-[var(--accent)] shrink-0 mt-0.5" />
          <div>
            <div className="text-sm font-semibold text-[var(--text-primary)]">How this score is built</div>
            <p className="text-xs text-[var(--text-secondary)] leading-relaxed mt-1">
              The ETSNTECH prototype prioritization index combines severity, EPSS likelihood, KEV status, network exposure, and asset criticality. It is a prioritization index, not a probability or universal risk standard.
            </p>
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-3 mt-4">
              <PolicyCard kind="criticality" title="Device criticality policy" description="CSV columns: device_identifier, criticality" />
              <PolicyCard kind="network" title="Network context policy" description="CSV columns: subnet_cidr, context_label, notes" />
            </div>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-5 gap-4">
        <MetricCard label="Critical" value={summary?.critical} sub="fix immediately" tone="danger" />
        <MetricCard label="High" value={summary?.high} sub="fix soon" tone="danger" />
        <MetricCard label="Elevated" value={summary?.elevated} sub="monitor" tone="warn" />
        <MetricCard label="Low" value={summary?.low} sub="acceptable for now" tone="ok" />
        <MetricCard label="KEV matches" value={summary?.kev_matches} sub="confirmed exploited" tone="danger" />
      </div>

      {!isLoading && (!assets || assets.length === 0) ? (
        <div className="card"><EmptyState icon={BrainCircuit} title="No assets to score yet" description="Run a network scan first — this layer scores every known asset once it exists." /></div>
      ) : (
        <div className="flex flex-col gap-3">
          {(assets || []).map((a) => (
            <article key={a.asset_id} className="card">
              <div className="flex items-start justify-between gap-4 flex-wrap">
                <div>
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="pill pill--info">Priority #{a.priority_rank} of {a.priority_total}</span>
                    <span className="text-base font-semibold text-[var(--text-primary)]">{a.hostname || 'Unknown'}</span>
                    <span className={`pill ${BAND_TONE[a.risk_band] || 'pill--info'}`}>{a.label}</span>
                    {a.has_kev && <span className="pill pill--danger inline-flex items-center gap-1"><Flame size={11} />Known Exploited</span>}
                  </div>
                  <div className="text-xs text-[var(--text-muted)] mt-1.5 mono">{a.ip_address} · {a.device_type}</div>
                </div>
                <div className="text-right">
                  <div className="text-2xl font-semibold text-[var(--text-primary)]">{a.risk_score}</div>
                  <div className="text-[10px] uppercase text-[var(--text-muted)]">prioritization index / 100</div>
                </div>
              </div>

              <div className="grid grid-cols-4 gap-4 mt-4">
                <ScoreBar label="Max CVSS" value={a.max_cvss} max={10} />
                <ScoreBar label="Max EPSS %" value={Math.round((a.max_epss || 0) * 100)} />
                <ScoreBar label={`Exposure${a.exposure_unmapped ? ' (unmapped)' : ''}`} value={a.exposure} />
                <div>
                  <label className="block text-[10px] text-[var(--text-muted)] mb-0.5">Criticality (set by you)</label>
                  <select
                    value={a.criticality}
                    onChange={(event) => updateCriticality.mutate({ assetId: a.asset_id, criticality: event.target.value })}
                    className="w-full bg-[var(--bg-surface-2)] border border-[var(--border)] rounded-[var(--radius-sm)] px-2 py-1 text-xs text-[var(--text-primary)]"
                  >
                    {CRITICALITY_OPTIONS.map((c) => <option key={c} value={c}>{c[0].toUpperCase() + c.slice(1)}</option>)}
                  </select>
                </div>
              </div>

              <div className="flex justify-between mt-3 text-[11px] text-[var(--text-muted)]">
                <span>{a.active_vuln_count} active CVE{a.active_vuln_count === 1 ? '' : 's'}</span>
                <span>{a.open_finding_count} open finding{a.open_finding_count === 1 ? '' : 's'} ({a.critical_finding_count} critical, {a.high_finding_count} high, {a.medium_finding_count} medium)</span>
              </div>
            </article>
          ))}
        </div>
      )}
    </div>
  )
}
