import { Link, useParams } from 'react-router-dom'
import { ArrowLeft, ServerCog, ShieldAlert, BrainCircuit, Flame } from 'lucide-react'
import { useDevice, useDeviceServices } from '../hooks/useDevices'
import { useDeviceFindings } from '../hooks/useFindings'
import { useRiskAssets } from '../hooks/useRisk'
import StatusPill from '../components/StatusPill'
import ConfidencePill from '../components/ConfidencePill'
import SeverityPill from '../components/SeverityPill'
import OsCell from '../components/OsCell'
import EmptyState from '../components/EmptyState'
import MetricCard from '../components/MetricCard'
import { findRiskAsset } from '../utils/riskAssets'
import { timeAgo } from '../utils/time'

const BAND_TONE = { critical: 'pill--danger', high: 'pill--danger', elevated: 'pill--warn', moderate: 'pill--warn', low: 'pill--ok' }

function EnrichmentPill({ service }) {
  if (service.enrichment_status === 'enriched') return <span className="pill pill--ok">Enriched</span>
  if (service.enrichment_status === 'cpe_ready') return <span className="pill pill--info">CPE ready</span>
  return <span className="pill pill--warn">Not enriched</span>
}

export default function AssetDetail() {
  const { assetId } = useParams()
  const { data: device, isLoading: deviceLoading, isError } = useDevice(assetId)
  const { data: services, isLoading: servicesLoading } = useDeviceServices(assetId)
  const { data: findings, isLoading: findingsLoading } = useDeviceFindings(assetId)
  const { data: riskAssets } = useRiskAssets()
  const openFindings = (findings || []).filter((f) => f.status === 'open')
  // The endpoint returns grouped arrays, not a flat list — searching it
  // directly threw "find is not a function". Also null (rather than undefined)
  // so `risk && ...` below is a real test.
  const risk = findRiskAsset(riskAssets, assetId)
  // Only claim "not ranked" once the response has actually arrived, otherwise
  // a freshly ranked device would flash the empty state during load.
  const rankingLoaded = Boolean(riskAssets)

  if (isError) {
    return (
      <div className="flex flex-col gap-5">
        <Link to="/devices" className="inline-flex items-center gap-1.5 text-sm text-[var(--text-muted)] hover:text-[var(--text-primary)]">
          <ArrowLeft size={14} /> Back to asset inventory
        </Link>
        <div className="card">
          <EmptyState icon={ServerCog} title="Device not found" description="This asset may have been removed, or the link is stale." />
        </div>
      </div>
    )
  }

  const cpeReady = (services || []).filter((s) => s.enrichment_status !== 'not_enriched').length
  const highConfidence = (services || []).filter((s) => s.confidence === 'high').length

  return (
    <div className="flex flex-col gap-5">
      <Link to="/devices" className="inline-flex items-center gap-1.5 text-sm text-[var(--text-muted)] hover:text-[var(--text-primary)] w-fit">
        <ArrowLeft size={14} /> Back to asset inventory
      </Link>

      {deviceLoading || !device ? (
        <div className="card"><p className="text-sm text-[var(--text-muted)]">Loading asset…</p></div>
      ) : (
        <>
          <div className="card flex flex-col gap-4">
            <div className="flex items-start justify-between flex-wrap gap-3">
              <div>
                <h1 className="text-2xl font-semibold text-[var(--text-primary)]">{device.hostname || 'Unknown device'}</h1>
                <p className="text-sm text-[var(--text-muted)] capitalize">{device.device_type} · discovered via {(device.discovery_sources || []).join(', ') || 'nmap'}</p>
              </div>
              <StatusPill status={device.status} />
            </div>

            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
              <div>
                <div className="text-[10px] uppercase tracking-wide text-[var(--text-muted)] mb-1">IP address</div>
                <div className="mono text-[var(--text-primary)]">{device.ip}</div>
              </div>
              <div>
                <div className="text-[10px] uppercase tracking-wide text-[var(--text-muted)] mb-1">MAC address</div>
                <div className="mono text-[var(--text-primary)]">{device.mac_address || '—'}</div>
              </div>
              <div>
                <div className="text-[10px] uppercase tracking-wide text-[var(--text-muted)] mb-1">Operating system</div>
                <OsCell osName={device.os_name} osSource={device.os_source} />
              </div>
              <div>
                <div className="text-[10px] uppercase tracking-wide text-[var(--text-muted)] mb-1">Vendor</div>
                <div className="text-[var(--text-primary)]">{device.vendor || 'Unknown'}</div>
              </div>
              <div>
                <div className="text-[10px] uppercase tracking-wide text-[var(--text-muted)] mb-1">First seen</div>
                <div className="text-[var(--text-secondary)]">{timeAgo(device.first_seen)}</div>
              </div>
              <div>
                <div className="text-[10px] uppercase tracking-wide text-[var(--text-muted)] mb-1">Last seen</div>
                <div className="text-[var(--text-secondary)]">{timeAgo(device.last_seen)}</div>
              </div>
            </div>
          </div>

          <div className="grid grid-cols-4 gap-4">
            <MetricCard label="Open services" value={services?.length} sub="exposed on this asset" />
            <MetricCard label="High confidence" value={highConfidence} sub="strong fingerprint evidence" tone="ok" />
            <MetricCard label="CPE ready" value={cpeReady} sub="eligible for CVE intelligence" />
            <MetricCard label="Open findings" value={openFindings.length} sub="security exposure checks" tone={openFindings.length ? 'danger' : 'neutral'} />
          </div>

          {risk && (
            <div>
              <h2 className="text-sm font-semibold text-[var(--text-primary)] mb-3">Security posture — ETSNTECH prototype prioritization index</h2>
              <div className="card flex flex-col gap-4">
                <div className="flex items-center gap-4 flex-wrap">
                  <div className="flex items-center gap-2">
                    <BrainCircuit size={18} className="text-[var(--accent)]" />
                    <span className="text-2xl font-semibold text-[var(--text-primary)]">{risk.risk_score}</span>
                    <span className="text-xs text-[var(--text-muted)]">/ 100</span>
                  </div>
                  <span className={`pill ${BAND_TONE[risk.risk_band] || 'pill--info'}`}>{risk.risk_band}</span>
                  <span className="pill pill--info">Priority #{risk.priority_rank} of {risk.priority_total}</span>
                  {risk.has_kev && <span className="pill pill--danger inline-flex items-center gap-1"><Flame size={11} />Known Exploited</span>}
                </div>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                  <div>
                    <div className="text-[10px] uppercase tracking-wide text-[var(--text-muted)] mb-1">Highest CVSS</div>
                    <div className="text-[var(--text-primary)]">{risk.max_cvss || '—'}</div>
                  </div>
                  <div>
                    <div className="text-[10px] uppercase tracking-wide text-[var(--text-muted)] mb-1">Highest EPSS</div>
                    <div className="text-[var(--text-primary)]">{risk.max_epss ? `${Math.round(risk.max_epss * 100)}%` : '—'}</div>
                  </div>
                  <div>
                    <div className="text-[10px] uppercase tracking-wide text-[var(--text-muted)] mb-1">Active CVEs</div>
                    <div className="text-[var(--text-primary)]">{risk.active_vuln_count}</div>
                  </div>
                  <div>
                    <div className="text-[10px] uppercase tracking-wide text-[var(--text-muted)] mb-1">KEV matches</div>
                    <div className="text-[var(--text-primary)]">{risk.has_kev ? 'Yes' : 'None'}</div>
                  </div>
                </div>
                <div className="pt-3 border-t border-[var(--border)] text-xs text-[var(--text-secondary)]">
                  <span className="font-medium text-[var(--text-primary)]">Recommendation: </span>{risk.recommended_action}
                </div>
              </div>
            </div>
          )}

          {rankingLoaded && !risk && (
            <div>
              <h2 className="text-sm font-semibold text-[var(--text-primary)] mb-3">Security posture — ETSNTECH prototype prioritization index</h2>
              <div className="card">
                <EmptyState
                  icon={BrainCircuit}
                  title="Device not yet ranked"
                  description={riskAssets?.last_ranked_at
                    ? 'This device was not in the most recent ranking. Re-run risk calculation to include newly discovered assets.'
                    : 'Risk ranking has not been run yet. Run risk calculation to score this device.'}
                />
              </div>
            </div>
          )}

          <div>
            <h2 className="text-sm font-semibold text-[var(--text-primary)] mb-3">Security findings</h2>
            <div className="card">
              {!findingsLoading && openFindings.length === 0 ? (
                <EmptyState icon={ShieldAlert} title="No open findings" description="No SMBv1, anonymous FTP, weak RDP security, expiring certificates, Telnet or unencrypted HTTP were observed on this asset." />
              ) : (
                <table className="w-full text-sm">
                  <thead>
                    <tr className="text-left text-[10px] uppercase tracking-wide text-[var(--text-muted)] border-b border-[var(--border)]">
                      <th className="pb-2 font-medium">Finding</th>
                      <th className="pb-2 font-medium">Severity</th>
                      <th className="pb-2 font-medium">Evidence</th>
                      <th className="pb-2 font-medium">Recommendation</th>
                      <th className="pb-2 font-medium">First / last seen</th>
                    </tr>
                  </thead>
                  <tbody>
                    {openFindings.map((finding) => (
                      <tr key={finding.finding_id} className="border-b border-[var(--border)] last:border-0 align-top">
                        <td className="py-3 pr-4 max-w-56"><div className="text-[var(--text-primary)]">{finding.title}</div><div className="text-[11px] text-[var(--text-muted)] mt-1">{finding.source}{finding.port ? ` · port ${finding.port}` : ''}</div></td>
                        <td className="py-3 pr-4"><SeverityPill severity={finding.severity} /><div className="mt-1.5"><ConfidencePill confidence={finding.confidence} /></div></td>
                        <td className="py-3 pr-4 max-w-72 text-[var(--text-secondary)] text-xs">{finding.evidence}</td>
                        <td className="py-3 pr-4 max-w-64 text-[var(--text-secondary)] text-xs">{finding.recommendation}</td>
                        <td className="py-3 whitespace-nowrap"><div className="text-[var(--text-secondary)]">{timeAgo(finding.first_seen)}</div><div className="text-xs text-[var(--text-muted)]">{timeAgo(finding.last_seen)}</div></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </div>

          <div>
            <h2 className="text-sm font-semibold text-[var(--text-primary)] mb-3">Exposure — ports and services</h2>
            <div className="card">
              {!servicesLoading && (!services || services.length === 0) ? (
                <EmptyState icon={ServerCog} title="No open services observed" description="This asset had no open ports on its last fingerprint pass." />
              ) : (
                <table className="w-full text-sm">
                  <thead>
                    <tr className="text-left text-[10px] uppercase tracking-wide text-[var(--text-muted)] border-b border-[var(--border)]">
                      <th className="pb-2 font-medium">Port</th>
                      <th className="pb-2 font-medium">Service</th>
                      <th className="pb-2 font-medium">Product / version</th>
                      <th className="pb-2 font-medium">CPE evidence</th>
                      <th className="pb-2 font-medium">Confidence</th>
                      <th className="pb-2 font-medium">First / last seen</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(services || []).map((service) => (
                      <tr key={service.service_id} className="border-b border-[var(--border)] last:border-0 align-top">
                        <td className="py-3 pr-4"><span className="mono text-[var(--accent)]">{service.port}/{service.protocol}</span><div className="text-[11px] text-[var(--ok)] mt-1">Open</div></td>
                        <td className="py-3 pr-4 text-[var(--text-primary)]">{service.service_name || 'Unknown service'}</td>
                        <td className="py-3 pr-4"><div className="text-[var(--text-primary)]">{service.product || 'Product not identified'}</div><div className="text-xs text-[var(--text-muted)]">{service.version || 'Version unavailable'}</div></td>
                        <td className="py-3 pr-4 max-w-72"><EnrichmentPill service={service} />{service.cpe ? <div className="mono text-[11px] text-[var(--text-secondary)] break-all mt-1.5">{service.cpe}</div> : <div className="text-[11px] text-[var(--text-muted)] mt-1.5">No CPE returned; CVE matching withheld</div>}</td>
                        <td className="py-3 pr-4"><ConfidencePill confidence={service.confidence} /><div className="text-[10px] text-[var(--text-muted)] mt-1.5">{service.detection_source?.replaceAll('_', ' ')}</div></td>
                        <td className="py-3 whitespace-nowrap"><div className="text-[var(--text-secondary)]">{timeAgo(service.first_seen)}</div><div className="text-xs text-[var(--text-muted)]">{timeAgo(service.last_seen)}</div></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </div>
        </>
      )}
    </div>
  )
}
