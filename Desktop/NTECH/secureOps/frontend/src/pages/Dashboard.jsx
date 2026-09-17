import { useState } from 'react'
import { Link } from 'react-router-dom'
import { RefreshCw, Square, ShieldAlert, AlertTriangle, Activity, ArrowRight } from 'lucide-react'
import { useCurrentDevices } from '../hooks/useDevices'
import { useRiskAssets, useRiskSummary } from '../hooks/useRisk'
import { useFindingsSummary } from '../hooks/useFindings'
import { useTelemetryChanges } from '../hooks/useTelemetry'
import { useScanSessions, useStartSession, useStopSession } from '../hooks/useScanSessions'
import MetricCard from '../components/MetricCard'
import EmptyState from '../components/EmptyState'

function getActionableAdvice(asset) {
  if (asset.has_kev) {
    return {
      title: 'Actively Exploited Threat Detected',
      reason: 'Software running on this machine matches a known active cyberattack vector in CISA KEV.',
      action: 'Apply vendor security patch immediately or disconnect device from the local network.',
    }
  }

  if (asset.critical_finding_count > 0 || asset.high_finding_count > 0) {
    return {
      title: 'Insecure Network Configuration',
      reason: 'Legacy, unencrypted, or broadly exposed services (SMBv1, FTP, or unshielded RDP) detected.',
      action: 'Turn off unnecessary legacy services and restrict remote management behind a VPN.',
    }
  }

  if (asset.max_epss > 0.3) {
    return {
      title: 'Elevated Exploitation Likelihood',
      reason: 'Threat intelligence models predict a high likelihood of near-term exploitation.',
      action: 'Verify installed version and confirm patch readiness with the product vendor.',
    }
  }

  return {
    title: 'Routine Maintenance',
    reason: 'No critical external vulnerabilities or severe configuration risks flagged.',
    action: 'Maintain automated system updates and monitor for baseline configuration drift.',
  }
}

const DURATION_OPTIONS = [5, 6, 7, 8, 9, 10]

export default function Dashboard() {
  const { data: devices, isLoading: devicesLoading, hasCompletedScan } = useCurrentDevices()
  const { data: riskSummary } = useRiskSummary()
  const { data: riskRanking } = useRiskAssets()
  const { data: findingsSummary } = useFindingsSummary()
  const { data: telemetryChanges } = useTelemetryChanges()
  const { data: sessions } = useScanSessions()
  const startMutation = useStartSession()
  const stopMutation = useStopSession()
  const [duration, setDuration] = useState('')

  const manualSession = (sessions || []).find((s) => s.source === 'manual' && s.status === 'RUNNING')
  const scanning = !!manualSession || startMutation.isPending || stopMutation.isPending

  function handleScanClick() {
    if (manualSession) {
      stopMutation.mutate(manualSession.id)
    } else {
      startMutation.mutate({ durationMinutes: duration ? Number(duration) : undefined })
    }
  }

  const activeDevices = devices?.length || 0
  const criticalAndHigh = (riskSummary?.critical || 0) + (riskSummary?.high || 0)
  const kevCount = riskSummary?.kev_matches || 0
  const openFindingsCount = findingsSummary?.open || 0
  const newDevicesCount = telemetryChanges?.new_devices?.length || 0
  const missingDevicesCount = telemetryChanges?.missing_devices?.length || 0
  const portChangesCount = telemetryChanges?.port_changes?.length || 0

  const topRisks = (riskRanking || []).slice(0, 4)

  return (
    <div className="flex flex-col gap-6">
      {/* 1. Header & Scan Controller */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-[var(--text-primary)]">Security Posture Dashboard</h1>
          <p className="text-sm text-[var(--text-muted)]">
            Network discovery, vulnerability intelligence, and prioritized actions
          </p>
        </div>
        <div className="flex items-center gap-2">
          <select
            value={duration}
            onChange={(e) => setDuration(e.target.value)}
            disabled={!!manualSession}
            className="bg-[var(--bg-surface)] border border-[var(--border)] rounded-[var(--radius-sm)] px-3 py-2 text-sm text-[var(--text-primary)] disabled:opacity-60"
          >
            <option value="">Continuous scan</option>
            {DURATION_OPTIONS.map((m) => (
              <option key={m} value={m}>{m} minutes</option>
            ))}
          </select>
          <button
            onClick={handleScanClick}
            disabled={startMutation.isPending || stopMutation.isPending}
            className="flex items-center gap-2 bg-[var(--accent)] hover:bg-[var(--accent-hover)] disabled:opacity-60 text-white text-sm font-medium px-4 py-2 rounded-[var(--radius-sm)] transition-colors"
          >
            {manualSession ? (
              <>
                <Square size={13} fill="currentColor" />
                Stop Scan
              </>
            ) : (
              <>
                <RefreshCw size={15} className={startMutation.isPending ? 'animate-spin' : ''} />
                {scanning ? 'Scanning…' : 'Run Security Scan'}
              </>
            )}
          </button>
        </div>
      </div>

      {/* 2. Top Metric Cards */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
        <MetricCard
          label="Active Devices"
          value={devicesLoading ? '…' : activeDevices}
          sub={hasCompletedScan ? 'reachable on network' : 'Awaiting first scan'}
        />
        <MetricCard
          label="New Devices"
          value={newDevicesCount}
          sub="since previous scan"
          tone={newDevicesCount > 0 ? 'warn' : undefined}
        />
        <MetricCard
          label="High Priority"
          value={criticalAndHigh}
          sub="require attention"
          tone={criticalAndHigh > 0 ? 'danger' : 'ok'}
        />
        <MetricCard
          label="CISA KEV Threats"
          value={kevCount}
          sub="actively exploited"
          tone={kevCount > 0 ? 'danger' : 'ok'}
        />
        <MetricCard
          label="Open Weaknesses"
          value={openFindingsCount}
          sub="configuration checks"
          tone={openFindingsCount > 0 ? 'warn' : undefined}
        />
        <MetricCard
          label="Overall Posture"
          value={criticalAndHigh === 0 && kevCount === 0 ? 'Protected' : 'Action Needed'}
          sub="based on EARI index"
          tone={criticalAndHigh === 0 && kevCount === 0 ? 'ok' : 'danger'}
        />
      </div>

      {/* 3. Priority Action Queue */}
      <div className="card">
        <div className="flex items-center justify-between mb-3 border-b border-[var(--border)] pb-3">
          <div>
            <h2 className="text-sm font-semibold text-[var(--text-primary)]">Priority Action Queue</h2>
            <p className="text-xs text-[var(--text-muted)]">
              Ranked by the ETSNTECH Asset Risk Index (EARI). Review and remediate top assets first.
            </p>
          </div>
          <Link to="/risk" className="text-xs text-[var(--accent)] hover:underline flex items-center gap-1 font-medium">
            View All Scored Assets <ArrowRight size={12} />
          </Link>
        </div>

        {topRisks.length === 0 ? (
          <EmptyState
            icon={Activity}
            title="No elevated risk items detected"
            description="All connected devices are currently operating within acceptable risk baselines."
          />
        ) : (
          <div className="flex flex-col gap-3">
            {topRisks.map((asset, idx) => {
              const advice = getActionableAdvice(asset)
              const badgeTone =
                asset.risk_band === 'critical'
                  ? 'badge--danger'
                  : asset.risk_band === 'high'
                  ? 'badge--warn'
                  : 'badge--info'

              return (
                <div
                  key={asset.asset_id || idx}
                  className="p-3.5 rounded-[var(--radius-sm)] border border-[var(--border)] bg-[var(--bg-surface-2)] flex flex-col md:flex-row md:items-center justify-between gap-4"
                >
                  <div className="flex items-start gap-3">
                    <div className="w-6 h-6 rounded-full bg-[var(--bg-surface)] border border-[var(--border)] flex items-center justify-center font-bold text-xs text-[var(--text-primary)] shrink-0">
                      {idx + 1}
                    </div>
                    <div>
                      <div className="flex items-center gap-2 flex-wrap">
                        <Link
                          to={`/devices/${asset.asset_id}`}
                          className="font-medium text-sm text-[var(--text-primary)] hover:text-[var(--accent)]"
                        >
                          {asset.hostname || asset.ip_address}
                        </Link>
                        <span className="text-xs text-[var(--text-muted)] mono">({asset.ip_address})</span>
                        <span className={`badge ${badgeTone} uppercase text-[10px] font-bold px-2 py-0.5 rounded`}>
                          {asset.risk_band} · Score {asset.risk_score}
                        </span>
                      </div>
                      <div className="text-xs font-medium text-[var(--text-primary)] mt-1">{advice.title}</div>
                      <div className="text-xs text-[var(--text-muted)] mt-0.5">{advice.reason}</div>
                    </div>
                  </div>

                  <div className="md:text-right shrink-0 border-t md:border-t-0 border-[var(--border)] pt-2 md:pt-0">
                    <div className="text-[11px] font-medium text-[var(--text-muted)]">Recommended Action:</div>
                    <div className="text-xs text-[var(--accent)] font-medium max-w-sm mt-0.5">{advice.action}</div>
                  </div>
                </div>
              )
            })}
          </div>
        )}
      </div>

      {/* 4. Recent Baseline Changes (Layer 7 Telemetry) */}
      <div className="card">
        <div className="flex items-center justify-between mb-3 border-b border-[var(--border)] pb-3">
          <div>
            <h2 className="text-sm font-semibold text-[var(--text-primary)]">Recent Network Changes</h2>
            <p className="text-xs text-[var(--text-muted)]">
              Differences detected between the current observation and the previous scan baseline
            </p>
          </div>
          <Link to="/telemetry" className="text-xs text-[var(--accent)] hover:underline flex items-center gap-1 font-medium">
            Full Change History <ArrowRight size={12} />
          </Link>
        </div>

        {newDevicesCount === 0 && missingDevicesCount === 0 && portChangesCount === 0 ? (
          <EmptyState
            icon={Activity}
            title="Network state is unchanged"
            description="No device additions, disconnections, or port state changes compared to the prior scan."
          />
        ) : (
          <div className="flex flex-col divide-y divide-[var(--border)] text-xs">
            {(telemetryChanges?.new_devices || []).map((dev, i) => (
              <div key={`new-dev-${i}`} className="py-2 flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-[var(--ok)]" />
                  <span className="font-medium text-[var(--text-primary)]">New Device Discovered:</span>
                  <span className="text-[var(--text-secondary)]">{dev.hostname || dev.ip_address}</span>
                </div>
                <span className="text-[var(--text-muted)]">First observed</span>
              </div>
            ))}

            {(telemetryChanges?.missing_devices || []).map((dev, i) => (
              <div key={`missing-dev-${i}`} className="py-2 flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-[var(--danger)]" />
                  <span className="font-medium text-[var(--text-primary)]">Device Not Observed:</span>
                  <span className="text-[var(--text-secondary)]">{dev.hostname || dev.ip_address}</span>
                </div>
                <span className="text-[var(--text-muted)]">Offline / unresponsive</span>
              </div>
            ))}

            {(telemetryChanges?.port_changes || []).map((ch, i) => (
              <div key={`port-${i}`} className="py-2 flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className={`w-2 h-2 rounded-full ${ch.change === 'opened' ? 'bg-[var(--warn)]' : 'bg-[var(--accent)]'}`} />
                  <span className="font-medium text-[var(--text-primary)]">
                    Port {ch.port} ({ch.service_name || 'service'}) {ch.change === 'opened' ? 'Opened' : 'Closed'}:
                  </span>
                  <span className="text-[var(--text-secondary)]">{ch.hostname || ch.ip_address}</span>
                </div>
                <span className="text-[var(--text-muted)] capitalize">{ch.change}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}