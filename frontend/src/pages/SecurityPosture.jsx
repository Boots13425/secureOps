import { useState, useMemo } from 'react'
import { Target, TrendingUp, TrendingDown, Minus, AlertTriangle, ShieldCheck, Search, ChevronRight, ChevronDown, Info, HelpCircle, ExternalLink } from 'lucide-react'
import { Link } from 'react-router-dom'
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts'
import { format } from 'date-fns'
import { useRiskAssets, useRiskSummary } from '../hooks/useRisk'
import { useTelemetryChanges, useTelemetryTrend } from '../hooks/useTelemetry'
import { useCurrentDevices } from '../hooks/useDevices'
import { useFindingsSummary } from '../hooks/useFindings'
import { useKevSummary } from '../hooks/useKev'
import { rankedAssets, notInDocumentAssets, missingFromScanAssets } from '../utils/riskAssets'
import MetricCard from '../components/MetricCard'
import EmptyState from '../components/EmptyState'
import SeverityPill from '../components/SeverityPill'
import StatusPill from '../components/StatusPill'

const BAND_TONE = { critical: 'pill--danger', high: 'pill--danger', elevated: 'pill--warn', moderate: 'pill--warn', low: 'pill--ok' }
const BAND_LABEL = { critical: 'Critical', high: 'High', elevated: 'Elevated', moderate: 'Moderate', low: 'Low' }

// --- Finding type to plain-English mapping (Simple view) ---
const FINDING_PLAIN = {
  'smb-protocols': { technical: 'Legacy SMBv1 protocol enabled', simple: 'Old file sharing (SMBv1) is turned on — attackers use this to spread ransomware' },
  'ftp-anon': { technical: 'Anonymous FTP access accepted', simple: 'FTP allows anonymous login — anyone can read or write files without a password' },
  'rdp-exposure': { technical: 'RDP broadly exposed', simple: 'Remote Desktop is open to the network — attackers brute-force this constantly' },
  'certificate': { technical: 'TLS certificate expired or expiring soon', simple: 'Security certificate is expired or about to expire — browsers will warn users' },
  'unexpected-port': { technical: 'New unexpected port since previous scan', simple: 'A new network port opened since last scan — could be unauthorized software' },
  'new-unexpected-port': { technical: 'New unexpected port since previous scan', simple: 'A new network port opened since last scan — could be unauthorized software' },
  'kev': { technical: 'CISA KEV match', simple: 'This vulnerability is actively exploited in the wild (per CISA Known Exploited list)' },
  'critical-finding': { technical: 'Critical exposure finding', simple: 'A critical security issue that needs immediate attention' },
  'high-finding': { technical: 'High-severity exposure finding', simple: 'A high-severity security issue that should be fixed soon' },
  'smbv1': { technical: 'Legacy SMBv1 protocol enabled', simple: 'Old file sharing (SMBv1) is turned on — attackers use this to spread ransomware' },
  'anon_ftp': { technical: 'Anonymous FTP access accepted', simple: 'FTP allows anonymous login — anyone can read or write files without a password' },
  'rdp': { technical: 'RDP broadly exposed', simple: 'Remote Desktop is open to the network — attackers brute-force this constantly' },
  'cert': { technical: 'TLS certificate expired or expiring soon', simple: 'Security certificate is expired or about to expire — browsers will warn users' },
}

function findingToPlain(finding) {
  const checkId = finding?.check_id || ''
  const title = (finding?.title || '').toLowerCase()
  const evidence = (finding?.evidence || '').toLowerCase()
  const combined = `${checkId} ${title} ${evidence}`

  if (combined.includes('smbv1') || combined.includes('smb-protocols') || combined.includes('nt lm 0.12')) return FINDING_PLAIN['smb-protocols'].simple
  if (combined.includes('anonymous ftp') || combined.includes('ftp-anon')) return FINDING_PLAIN['ftp-anon'].simple
  if (combined.includes('rdp') && (combined.includes('expos') || combined.includes('brute') || checkId === 'rdp-exposure')) return FINDING_PLAIN['rdp-exposure'].simple
  if (combined.includes('certificate') && (combined.includes('expired') || combined.includes('expir') || combined.includes('near expiry'))) return FINDING_PLAIN['certificate'].simple
  if (checkId === 'unexpected-port' || checkId === 'new-unexpected-port') return FINDING_PLAIN['unexpected-port'].simple
  if (finding?.kev) return FINDING_PLAIN['kev'].simple
  if (finding?.severity === 'critical') return FINDING_PLAIN['critical-finding'].simple
  if (finding?.severity === 'high') return FINDING_PLAIN['high-finding'].simple
  return finding?.title || 'Security finding'
}

function actionForFindings(findings, hasKev, services) {
  const actions = []
  const findingText = findings.map(f => `${f.check_id} ${f.title} ${f.evidence} ${f.why_it_matters}`).join(' ').toLowerCase()
  const serviceText = services.map(s => `${s.name} ${s.product} ${s.version}`).join(' ').toLowerCase()
  const combined = `${findingText} ${serviceText}`

  if (hasKev) actions.push('validate/patch KEV vulnerability')
  if (combined.includes('smbv1') || combined.includes('smb-protocols') || combined.includes('nt lm 0.12')) actions.push('disable SMBv1')
  if (combined.includes('anonymous ftp') || combined.includes('ftp-anon')) actions.push('disable anonymous FTP')
  if (combined.includes('rdp') && (combined.includes('expos') || combined.includes('3389'))) actions.push('restrict RDP to VPN/management sources')
  if (combined.includes('certificate') && (combined.includes('expired') || combined.includes('expir'))) actions.push('renew/replace certificate')
  if (combined.includes('unexpected-port') || combined.includes('new-unexpected-port')) actions.push('identify owner, validate need, close if unauthorized')

  if (actions.length === 0) {
    if (findingText.includes('critical') || findingText.includes('high')) actions.push('prioritize validation and vendor remediation')
    else actions.push('continue routine monitoring')
  }

  return actions.join('; ') + '.'
}

// --- Posture trend calculation ---
function posturePhrase(trend) {
  if (!trend || trend.length < 2) return { label: 'Not enough history', Icon: Minus, tone: 'text-[var(--text-muted)]' }
  const prev = trend[trend.length - 2].avg_risk_score
  const latest = trend[trend.length - 1].avg_risk_score
  if (prev == null || latest == null) return { label: 'Not enough history', Icon: Minus, tone: 'text-[var(--text-muted)]' }
  const delta = latest - prev
  if (delta <= -2) return { label: 'Improving', Icon: TrendingDown, tone: 'text-[var(--ok)]' }
  if (delta >= 2) return { label: 'Deteriorating', Icon: TrendingUp, tone: 'text-[var(--danger)]' }
  return { label: 'Stable', Icon: Minus, tone: 'text-[var(--text-secondary)]' }
}

// --- Deduplicate assets by MAC/hostname for accurate counts ---
function deduplicateAssets(assets) {
  const seen = new Map()
  for (const a of assets) {
    const mac = a.mac_address?.toLowerCase()
    const hostKey = a.hostname ? a.hostname.toLowerCase().split('.')[0] : null
    const key = mac || (hostKey ? `host:${hostKey}` : `ip:${a.ip_address}`)
    const existing = seen.get(key)
    if (!existing || (a.mac_address && !existing.mac_address) || (a.hostname && a.hostname.includes('.') && !existing.hostname?.includes('.'))) {
      seen.set(key, a)
    }
  }
  return Array.from(seen.values())
}

export default function SecurityPosture() {
  const { data: assetsRaw, isLoading } = useRiskAssets()
  const { data: riskSummary } = useRiskSummary()
  const { data: changes } = useTelemetryChanges()
  const { data: trend } = useTelemetryTrend(10)
  const { data: currentDevices } = useCurrentDevices()
  const { data: findingsSummary } = useFindingsSummary()
  const { data: kevSummary } = useKevSummary()

  // All ranked + not_in_document + missing_from_scan assets for this ranking
  const allRankedAssets = [
    ...(assetsRaw?.ranked || []),
    ...(assetsRaw?.not_in_document || []),
  ]

  // Deduplicate for accurate counts
  const dedupedAssets = useMemo(() => deduplicateAssets(allRankedAssets), [allRankedAssets])

  // Latest scan devices (from currentDevices which is latest scan)
  const latestScanDevices = currentDevices || []
  const dedupedLatestScan = useMemo(() => deduplicateAssets(latestScanDevices), [latestScanDevices])

  // Section 13.1 card values
  const discoveredAssets = dedupedLatestScan.length
  const unknownAssets = dedupedLatestScan.filter(d => d.status === 'unknown').length
  const highCriticalAssets = dedupedAssets.filter(a => {
    const score = a.risk_score ?? a.score
    return score >= 70
  }).length
  const openFindings = findingsSummary?.open ?? 0
  const kevMatches = kevSummary?.active_matches ?? 0
  const newExposures = changes?.baseline === false
    ? (changes.port_changes || []).filter(c => c.change === 'opened').length
    : (changes?.baseline ? 0 : null)
  const posture = posturePhrase(trend)

  const trendData = (trend || []).map(row => ({
    time: new Date(row.started_at).toLocaleDateString(undefined, { month: 'short', day: 'numeric' }),
    'Avg risk': row.avg_risk_score,
  }))

  // Priority queue data (top 5 from ranked assets)
  const priorityQueue = (assetsRaw?.ranked || []).slice(0, 5).map((a, idx) => ({
    rank: idx + 1,
    deviceName: a.hostname || a.device_identifier || a.ip_address,
    score: a.risk_score ?? a.score,
    label: a.risk_band ? BAND_LABEL[a.risk_band] : BAND_LABEL[a.label?.toLowerCase()],
    findings: (a.findings || []).filter(f => f.status === 'open'),
    hasKev: a.has_kev,
    services: a.services || [],
    recommendations: a.recommendations || [],
    ipAddress: a.ip_address,
    assetId: a.asset_id,
  }))

  const [simpleView, setSimpleView] = useState(false)

  return (
    <div className="flex flex-col gap-5">
      {/* Header with view toggle */}
      <div className="flex items-center justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-2xl font-semibold text-[var(--text-primary)]">Security posture & decision dashboard</h1>
          <p className="text-sm text-[var(--text-muted)]">The single big-picture view — pulling risk scores, recent changes, and top priorities from every layer into one screen</p>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-xs text-[var(--text-muted)]">View:</span>
          <button
            onClick={() => setSimpleView(false)}
            className={`px-3 py-1.5 text-xs font-medium rounded-[var(--radius-sm)] transition-colors ${!simpleView ? 'bg-[var(--accent)] text-white' : 'bg-[var(--bg-surface-2)] text-[var(--text-secondary)] hover:bg-[var(--bg-surface-3)]'}`}
          >
            Technical
          </button>
          <button
            onClick={() => setSimpleView(true)}
            className={`px-3 py-1.5 text-xs font-medium rounded-[var(--radius-sm)] transition-colors ${simpleView ? 'bg-[var(--accent)] text-white' : 'bg-[var(--bg-surface-2)] text-[var(--text-secondary)] hover:bg-[var(--bg-surface-3)]'}`}
          >
            Simple
          </button>
        </div>
      </div>

      {/* Overall posture badge */}
      <div className="card flex items-center gap-4">
        <div className={`pill ${BAND_TONE[riskSummary?.critical > 0 ? 'critical' : riskSummary?.high > 0 ? 'high' : riskSummary?.elevated > 0 ? 'elevated' : riskSummary?.moderate > 0 ? 'moderate' : 'low']} text-sm px-4 py-2`}>
          {(riskSummary?.critical > 0 ? 'Critical' : riskSummary?.high > 0 ? 'High' : riskSummary?.elevated > 0 ? 'Elevated' : riskSummary?.moderate > 0 ? 'Moderate' : 'Low').toUpperCase()}
        </div>
        <div>
          <div className="text-sm font-semibold text-[var(--text-primary)]">Overall network posture</div>
          <div className="text-xs text-[var(--text-muted)]">Driven by the highest-risk band present across {dedupedAssets.length} scored assets · {riskSummary?.index_label || 'ETSNTECH prototype prioritization index'}</div>
        </div>
      </div>

      {/* Section 13.1 - Seven required top-level cards */}
      <div className="grid grid-cols-4 gap-4">
        <MetricCard label="Discovered assets" value={discoveredAssets} sub="in the latest scan" />
        <MetricCard label="Unknown/new assets" value={unknownAssets} sub="not yet approved or first seen this scan" tone="warn" />
        <MetricCard label="High/Critical assets" value={highCriticalAssets} sub="EARI score ≥ 70" tone="danger" />
        <MetricCard label="Open findings" value={openFindings} sub="unresolved exposures" tone={openFindings ? 'warn' : 'ok'} />
      </div>
      <div className="grid grid-cols-4 gap-4">
        <MetricCard label="KEV matches" value={kevMatches} sub="confirmed exploited in the wild" tone={kevMatches ? 'danger' : 'ok'} />
        <MetricCard label="New exposures" value={newExposures} sub="new ports/services since prior scan" tone={newExposures ? 'warn' : 'ok'} />
        <div className="card flex items-center gap-3">
          <posture.Icon size={22} className={posture.tone} />
          <div>
            <div className="text-xs font-medium uppercase tracking-[.06em] text-[var(--text-secondary)]">Posture trend</div>
            <div className={`text-lg font-semibold ${posture.tone}`}>{posture.label}</div>
          </div>
        </div>
        {/* Spacer for 4-column grid */}
        <div className="hidden sm:block" />
      </div>

      {/* Section 13.2 - Priority Queue */}
      <div className="card">
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-2">
            <Target size={16} className="text-[var(--danger)]" />
            <h2 className="text-sm font-semibold text-[var(--text-primary)]">Top priority actions</h2>
          </div>
          <Link to="/risk" className="text-xs text-[var(--accent)] hover:underline flex items-center gap-1">Full ranking <ChevronRight size={12} /></Link>
        </div>
        {!isLoading && priorityQueue.length === 0 ? (
          <EmptyState icon={Target} title="No assets scored yet" description="Upload the asset document and run Calculate Ranking." />
        ) : (
          <div className="flex flex-col gap-4">
            {priorityQueue.map((item, idx) => {
              const drivers = []
              if (item.hasKev) drivers.push({ technical: 'CISA KEV match', simple: 'Actively exploited in the wild (CISA KEV)' })
              item.findings.forEach(f => drivers.push({ technical: f.title, simple: findingToPlain(f) }))
              if (item.services.some(s => s.port === 3389 || (s.name && s.name.toLowerCase().includes('rdp')))) {
                drivers.push({ technical: 'RDP broadly exposed', simple: 'Remote Desktop open to the network' })
              }
              if (item.services.some(s => (s.name && s.name.toLowerCase().includes('smb')) || (s.product && s.product.toLowerCase().includes('smb')))) {
                drivers.push({ technical: 'Legacy SMBv1 protocol enabled', simple: 'Old file sharing (SMBv1) turned on' })
              }
              if (item.services.some(s => (s.name && s.name.toLowerCase().includes('ftp')) && (s.product && s.product.toLowerCase().includes('anon')))) {
                drivers.push({ technical: 'Anonymous FTP access', simple: 'FTP allows anonymous login' })
              }

              const actionLine = actionForFindings(item.findings, item.hasKev, item.services)

              return (
                <div key={item.assetId} className="flex items-start justify-between gap-3 text-xs border-b border-[var(--border)] last:border-0 pb-4 last:pb-0">
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2 flex-wrap mb-1.5">
                      <span className="pill pill--info">#{item.rank}</span>
                      <span className="text-[var(--text-primary)] font-medium truncate">{item.deviceName}</span>
                      <span className={`pill ${BAND_TONE[item.label?.toLowerCase()] || 'pill--info'}`}>EARI {item.score} / {item.label}</span>
                    </div>
                    <ul className="mt-1.5 space-y-0.5 ml-4 list-disc">
                      {drivers.slice(0, 3).map((d, di) => (
                        <li key={di} className="text-[var(--text-muted)]">
                          {simpleView ? d.simple : d.technical}
                        </li>
                      ))}
                      {drivers.length > 3 && (
                        <li className="text-[var(--text-muted)] text-xs">+{drivers.length - 3} more</li>
                      )}
                    </ul>
                    <div className="mt-1.5 text-[var(--text-secondary)]">
                      <span className="font-medium text-[var(--text-primary)]">Action: </span>
                      {simpleView
                        ? actionLine.replace(/validate\/patch KEV vulnerability/, 'update the vulnerable software')
                          .replace(/disable SMBv1/, 'turn off old file sharing')
                          .replace(/disable anonymous FTP/, 'turn off anonymous FTP')
                          .replace(/restrict RDP to VPN\/management sources/, 'limit Remote Desktop to VPN only')
                          .replace(/renew\/replace certificate/, 'renew the security certificate')
                          .replace(/identify owner, validate need, close if unauthorized/, 'find who owns this and close it if not needed')
                        : actionLine}
                    </div>
                  </div>
                  <div className="text-right shrink-0">
                    <div className="text-base font-semibold text-[var(--text-primary)]">{item.score}</div>
                    <div className="text-[10px] uppercase text-[var(--text-muted)]">prioritization index</div>
                  </div>
                </div>
              )
            })}
          </div>
        )}
      </div>

      {/* What changed recently */}
      <div className="card">
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-2">
            <GitCompare size={16} className="text-[var(--info)]" />
            <h2 className="text-sm font-semibold text-[var(--text-primary)]">What changed recently</h2>
          </div>
          <Link to="/telemetry" className="text-xs text-[var(--accent)] hover:underline flex items-center gap-1">Full detail <ChevronRight size={12} /></Link>
        </div>
        {!changes?.to_scan ? (
          <EmptyState icon={GitCompare} title="No completed scan yet" description="Run a network scan to start building change history." />
        ) : changes.baseline ? (
          <EmptyState icon={GitCompare} title="Only one scan so far" description="Run another scan to see what changed." />
        ) : (
          <div className="grid grid-cols-2 gap-3 text-xs">
            <div className="rounded-[var(--radius-sm)] border border-[var(--border)] bg-[var(--bg-surface-2)] p-3">
              <div className="text-[10px] uppercase text-[var(--text-muted)]">New devices</div>
              <div className="text-lg font-semibold text-[var(--text-primary)]">{changes.new_devices.length}</div>
            </div>
            <div className="rounded-[var(--radius-sm)] border border-[var(--border)] bg-[var(--bg-surface-2)] p-3">
              <div className="text-[10px] uppercase text-[var(--text-muted)]">Missing devices</div>
              <div className="text-lg font-semibold text-[var(--text-primary)]">{changes.missing_devices.length}</div>
            </div>
            <div className="rounded-[var(--radius-sm)] border border-[var(--border)] bg-[var(--bg-surface-2)] p-3">
              <div className="text-[10px] uppercase text-[var(--text-muted)]">Port/service changes</div>
              <div className="text-lg font-semibold text-[var(--text-primary)]">{changes.port_changes.length}</div>
            </div>
            <div className="rounded-[var(--radius-sm)] border border-[var(--border)] bg-[var(--bg-surface-2)] p-3">
              <div className="text-[10px] uppercase text-[var(--text-muted)]">Finding changes</div>
              <div className="text-lg font-semibold text-[var(--text-primary)]">{changes.finding_changes.length}</div>
            </div>
            <div className="rounded-[var(--radius-sm)] border border-[var(--border)] bg-[var(--bg-surface-2)] p-3">
              <div className="text-[10px] uppercase text-[var(--text-muted)]">CVE changes</div>
              <div className="text-lg font-semibold text-[var(--text-primary)]">{changes.cve_changes.length}</div>
            </div>
            <div className="rounded-[var(--radius-sm)] border border-[var(--border)] bg-[var(--bg-surface-2)] p-3">
              <div className="text-[10px] uppercase text-[var(--text-muted)]">Risk changes</div>
              <div className="text-lg font-semibold text-[var(--text-primary)]">{changes.risk_changes.length}</div>
            </div>
          </div>
        )}
      </div>

      {/* Risk trend chart */}
      <div className="card">
        <div className="flex items-center gap-2 mb-2">
          <TrendingUp size={16} className="text-[var(--accent)]" />
          <h2 className="text-sm font-semibold text-[var(--text-primary)]">Risk trend</h2>
        </div>
        {trendData.length === 0 ? (
          <EmptyState icon={TrendingUp} title="No scan history yet" description="Run a few scans to start building a trend." />
        ) : (
          <ResponsiveContainer width="100%" height={180}>
            <LineChart data={trendData} margin={{ top: 8, right: 8, left: -20, bottom: 0 }}>
              <CartesianGrid stroke="var(--chart-grid)" strokeDasharray="3 3" vertical={false} />
              <XAxis dataKey="time" tick={{ fill: 'var(--text-muted)', fontSize: 11 }} axisLine={false} tickLine={false} />
              <YAxis tick={{ fill: 'var(--text-muted)', fontSize: 11 }} axisLine={false} tickLine={false} domain={[0, 100]} />
              <Tooltip contentStyle={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', fontSize: 12 }} />
              <Line type="monotone" dataKey="Avg risk" stroke="var(--chart-3)" strokeWidth={2} dot={false} />
            </LineChart>
          </ResponsiveContainer>
        )}
      </div>
    </div>
  )
}

// Need to import GitCompare
import { GitCompare } from 'lucide-react'