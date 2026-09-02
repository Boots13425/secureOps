import { BrainCircuit, Flame, Wrench } from 'lucide-react'
import EmptyState from '../components/EmptyState'
import MetricCard from '../components/MetricCard'
import { useRiskAssets, useRiskSummary, useUpdateCriticality, useUpdateExposure } from '../hooks/useRisk'

const BAND_TONE = { critical: 'pill--danger', high: 'pill--danger', elevated: 'pill--warn', moderate: 'pill--warn', low: 'pill--ok' }

// Project guide §12.4 — organizational value of the asset (0-100).
const CRITICALITY_OPTIONS = [
  { value: 'test_temporary', label: 'Test/temporary device (20)' },
  { value: 'peripheral', label: 'Printer/non-critical peripheral (30)' },
  { value: 'standard_workstation', label: 'Standard staff workstation (50)' },
  { value: 'privileged_workstation', label: 'Admin/privileged workstation (70)' },
  { value: 'business_server', label: 'Business application/server (85)' },
  { value: 'critical_service', label: 'Identity/finance/critical core service (100)' },
]

// Project guide §12.3 — how reachable the asset's network segment is (0-100).
const EXPOSURE_OPTIONS = [
  { value: 'isolated_lab', label: 'Isolated lab/test network (20)' },
  { value: 'management_segment', label: 'Management-only/restricted segment (30)' },
  { value: 'server_vlan', label: 'Server/internal protected VLAN (50)' },
  { value: 'staff_network', label: 'General staff/user network (65)' },
  { value: 'guest_network', label: 'Guest or broadly reachable internal network (80)' },
  { value: 'internet_facing', label: 'Internet-facing/reachable (100)' },
]

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
  const { data: assets, isLoading } = useRiskAssets()
  const { data: summary } = useRiskSummary()
  const updateCriticality = useUpdateCriticality()
  const updateExposure = useUpdateExposure()

  return (
    <div className="flex flex-col gap-5">
      <div>
        <h1 className="text-2xl font-semibold text-[var(--text-primary)]">Risk & interpretation engine</h1>
        <p className="text-sm text-[var(--text-muted)]">{summary?.index_label || 'ETSNTECH prototype prioritization index'} — one score per asset, combining severity, likelihood, known exploitation, network exposure, and organizational criticality</p>
      </div>

      <div className="card border-[var(--accent-border)] bg-[linear-gradient(135deg,var(--accent-bg),var(--bg-surface))]">
        <div className="flex gap-3">
          <BrainCircuit size={19} className="text-[var(--accent)] shrink-0 mt-0.5" />
          <div>
            <div className="text-sm font-semibold text-[var(--text-primary)]">How this score is built</div>
            <p className="text-xs text-[var(--text-secondary)] leading-relaxed mt-1">
              Each asset gets a 0-100 <strong>{summary?.index_label || 'ETSNTECH prototype prioritization index'}</strong>: <strong>severity</strong> (max
              CVSS of its active CVEs x10, 30%) + <strong>exploit likelihood</strong> (max EPSS score x100, 20%) + <strong>known
              exploitation</strong> (100 if any active CVE is in CISA KEV, else 0, 20%) + <strong>network exposure</strong> (which
              segment it sits on, 15%) + <strong>asset criticality</strong> (how much it matters to your organization, 15%). Exposure and
              criticality are set by you below — nothing in a scan can tell the system that a device is your internet-facing file server
              rather than an isolated lab printer. A confirmed CISA KEV match always enforces a minimum score of 80, regardless of the
              math, matching how KEV outranks everything else in this app. This is a prioritization heuristic, not a probability of
              breach. Every asset also gets an explicit priority rank, so "single risk score and priority" is literal, not just an
              implied sort order.
            </p>
          </div>
        </div>
      </div>

      <div className="card">
        <div className="flex gap-3">
          <Wrench size={18} className="text-[var(--text-muted)] shrink-0 mt-0.5" />
          <div>
            <div className="text-sm font-semibold text-[var(--text-primary)]">What was fixed here</div>
            <p className="text-xs text-[var(--text-secondary)] leading-relaxed mt-1">
              <strong>Problem:</strong> this page's score used to mix "already exploited" and "likely to be exploited soon" into one
              number, faked the network-exposure input using an unrelated count of open findings, and used a generic low/medium/high
              scale instead of the guide's specific device categories. <strong>Fix:</strong> the five scoring inputs are now separated and
              weighted exactly as the project guide specifies, network exposure and criticality are now real settings you choose below,
              and a confirmed KEV match always enforces a minimum score of 80.
            </p>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-6 gap-4">
        <MetricCard label="Critical" value={summary?.critical} sub="85-100 · fix immediately" tone="danger" />
        <MetricCard label="High" value={summary?.high} sub="70-84 · fix soon" tone="danger" />
        <MetricCard label="Elevated" value={summary?.elevated} sub="50-69 · plan remediation" tone="warn" />
        <MetricCard label="Moderate" value={summary?.moderate} sub="30-49 · monitor" tone="warn" />
        <MetricCard label="Low" value={summary?.low} sub="0-29 · acceptable for now" tone="ok" />
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

              <div className="grid grid-cols-5 gap-4 mt-4">
                <ScoreBar label="Severity (30%)" value={a.severity_normalized} />
                <ScoreBar label="Exploit likelihood (20%)" value={a.epss_normalized} />
                <ScoreBar label="Known exploitation (20%)" value={a.kev_normalized} />
                <div>
                  <label className="block text-[10px] text-[var(--text-muted)] mb-0.5">Exposure (15%, set by you)</label>
                  <select
                    value={a.exposure}
                    onChange={(event) => updateExposure.mutate({ assetId: a.asset_id, exposure: event.target.value })}
                    className="w-full bg-[var(--bg-surface-2)] border border-[var(--border)] rounded-[var(--radius-sm)] px-2 py-1 text-xs text-[var(--text-primary)]"
                  >
                    {EXPOSURE_OPTIONS.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
                  </select>
                </div>
                <div>
                  <label className="block text-[10px] text-[var(--text-muted)] mb-0.5">Criticality (15%, set by you)</label>
                  <select
                    value={a.criticality}
                    onChange={(event) => updateCriticality.mutate({ assetId: a.asset_id, criticality: event.target.value })}
                    className="w-full bg-[var(--bg-surface-2)] border border-[var(--border)] rounded-[var(--radius-sm)] px-2 py-1 text-xs text-[var(--text-primary)]"
                  >
                    {CRITICALITY_OPTIONS.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
                  </select>
                </div>
              </div>

              <div className="flex justify-between mt-3 text-[11px] text-[var(--text-muted)]">
                <span>{a.active_vuln_count} active CVE{a.active_vuln_count === 1 ? '' : 's'}</span>
                <span>{a.open_finding_count} open finding{a.open_finding_count === 1 ? '' : 's'} ({a.critical_finding_count} critical, {a.high_finding_count} high, {a.medium_finding_count} medium)</span>
              </div>
              <div className="mt-3 pt-3 border-t border-[var(--border)] text-xs text-[var(--text-secondary)]">
                <span className="font-medium text-[var(--text-primary)]">Recommendation: </span>{a.recommended_action}
              </div>
            </article>
          ))}
        </div>
      )}
    </div>
  )
}
