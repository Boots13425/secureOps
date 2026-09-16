import { useState } from 'react'
import { BrainCircuit, Flame } from 'lucide-react'
import EmptyState from '../components/EmptyState'
import { API_BASE_URL } from '../api/client'
import MetricCard from '../components/MetricCard'
import { useRiskAssets, useRiskSummary, useUpdateCriticality } from '../hooks/useRisk'

const BAND_TONE = { critical: 'pill--danger', high: 'pill--danger', medium: 'pill--warn', low: 'pill--ok' }
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

  const [uploadStatus, setUploadStatus] = useState(null)

  async function handlePolicyUpload(event) {
    const file = event.target.files[0]
    if (!file) return
    setUploadStatus('Uploading...')
    const formData = new FormData()
    formData.append('file', file)
    try {
      const res = await fetch(`${API_BASE_URL}/assets/policy/upload`, {
        method: 'POST',
        body: formData,
      })
      const data = await res.json()
      if (!res.ok) throw new Error(data.detail || 'The policy upload failed.')
      await Promise.all([refetchAssets(), refetchSummary()])
      setUploadStatus(`Updated ${data.updated} device(s).${data.not_found.length ? ` Not found: ${data.not_found.join(', ')}` : ''}`)
    } catch (err) {
      setUploadStatus(`Upload failed: ${err.message}`)
    }
    event.target.value = ''
  }

  return (
    <div className="flex flex-col gap-5">
      <div>
        <h1 className="text-2xl font-semibold text-[var(--text-primary)]">Risk & interpretation engine</h1>
        <p className="text-sm text-[var(--text-muted)]">One risk score per asset, combining severity, likelihood, exposure, and how much it matters to you</p>
      </div>

      <div className="card border-[var(--accent-border)] bg-[linear-gradient(135deg,var(--accent-bg),var(--bg-surface))]">
        <div className="flex gap-3">
          <BrainCircuit size={19} className="text-[var(--accent)] shrink-0 mt-0.5" />
          <div>
            <div className="text-sm font-semibold text-[var(--text-primary)]">How this score is built</div>

        <div className="card border-[var(--border)] bg-[var(--bg-surface)] p-4">
          <div className="text-sm font-semibold text-[var(--text-primary)] mb-1">Upload asset criticality policy</div>
          <p className="text-xs text-[var(--text-secondary)] mb-3">
            CSV with columns: device_identifier, criticality (low, normal, high, critical)
          </p>
          <input
            type="file"
            accept=".csv"
            onChange={handlePolicyUpload}
            className="text-xs text-[var(--text-secondary)]"
          />
          {uploadStatus && (
            <p className="text-xs mt-2 text-[var(--text-primary)]">{uploadStatus}</p>
          )}
        </div>
            <p className="text-xs text-[var(--text-secondary)] leading-relaxed mt-1">
              Each asset gets a 0-100 score: <strong>severity</strong> (max CVSS of its active CVEs, 35%) + <strong>likelihood</strong> (EPSS
              exploitation probability, 30%) + <strong>exposure</strong> (open security findings on it, weighted — critical findings count
              more than high, high counts more than medium, 20%) + <strong>criticality</strong> (how much this asset matters to your
              organization, 15%). Criticality is set by you below — nothing in a scan can tell the system that a device is your file
              server rather than a spare printer. A confirmed CISA KEV match always forces the score to "critical", regardless of the
              math, matching how KEV outranks everything else in this app. Every asset also gets an explicit priority rank, so "single
              risk score and priority" is literal, not just an implied sort order.
            </p>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-5 gap-4">
        <MetricCard label="Critical" value={summary?.critical} sub="fix immediately" tone="danger" />
        <MetricCard label="High" value={summary?.high} sub="fix soon" tone="danger" />
        <MetricCard label="Medium" value={summary?.medium} sub="monitor" tone="warn" />
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
                    <span className={`pill ${BAND_TONE[a.risk_band] || 'pill--info'}`}>{a.risk_band} risk</span>
                    {a.has_kev && <span className="pill pill--danger inline-flex items-center gap-1"><Flame size={11} />Known Exploited</span>}
                  </div>
                  <div className="text-xs text-[var(--text-muted)] mt-1.5 mono">{a.ip_address} · {a.device_type}</div>
                </div>
                <div className="text-right">
                  <div className="text-2xl font-semibold text-[var(--text-primary)]">{a.risk_score}</div>
                  <div className="text-[10px] uppercase text-[var(--text-muted)]">risk score / 100</div>
                </div>
              </div>

              <div className="grid grid-cols-4 gap-4 mt-4">
                <ScoreBar label="Max CVSS" value={a.max_cvss} max={10} />
                <ScoreBar label="Max EPSS %" value={Math.round((a.max_epss || 0) * 100)} />
                <ScoreBar label="Exposure (weighted findings)" value={a.exposure_score} />
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
