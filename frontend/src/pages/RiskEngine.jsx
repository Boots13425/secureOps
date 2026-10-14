import { useState } from 'react'
import { BrainCircuit, ChevronDown, ChevronRight, Flame } from 'lucide-react'
import EmptyState from '../components/EmptyState'
import MetricCard from '../components/MetricCard'
import { useCalculateRisk, useRiskAssets, useRiskReadiness, useRiskSummary, useUploadAssetDocument } from '../hooks/useRisk'
import { missingFromScanAssets, notInDocumentAssets, rankedAssets } from '../utils/riskAssets'

const BAND_TONE = { critical: 'pill--danger', high: 'pill--danger', elevated: 'pill--warn', moderate: 'pill--warn', low: 'pill--ok' }
const MATCH_FLAG_LABEL = { ip: 'matched by IP', hostname: 'matched by hostname', conflict: 'conflict — review this row' }

const REQUIRED_COLUMNS = ['device_name', 'ip_address', 'purpose', 'criticality_category']
const ALLOWED_CATEGORIES = [
  'Test/temporary device',
  'Printer/non-critical peripheral',
  'Standard staff workstation',
  'Administration/privileged workstation',
  'Business application/server',
  'Identity, finance, student/medical records, critical core service',
]

// Wording is fixed by the backend (READINESS_BLOCKED_MESSAGE) and repeated here
// so the tooltip, the inline line and a click on the disabled button all agree.
const BLOCKED_MESSAGE = 'Upload the asset document first. Ranking runs only after it is uploaded.'

function ScoreBar({ label, value, max = 100 }) {
  const displayValue = value == null ? '—' : value
  const pct = value == null ? 0 : Math.max(0, Math.min(100, (value / max) * 100))
  return (
    <div>
      <div className="flex justify-between text-[10px] text-[var(--text-muted)] mb-0.5">
        <span>{label}</span>
        <span>{displayValue}</span>
      </div>
      <div className="h-1.5 rounded-full bg-[var(--bg-surface-2)] overflow-hidden">
        <div className="h-full bg-[var(--accent)]" style={{ width: `${pct}%` }} />
      </div>
    </div>
  )
}

function AssetCard({ asset }) {
  return (
    <article className="card">
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <div className="flex items-center gap-2 flex-wrap">
            <span className="pill pill--info">
              {asset.priority_rank ? `Priority #${asset.priority_rank} of ${asset.priority_total}` : 'Not yet ranked'}
            </span>
            <span className="text-base font-semibold text-[var(--text-primary)]">
              {asset.hostname || asset.device_identifier || 'Unknown'}
            </span>
            {asset.label && <span className={`pill ${BAND_TONE[asset.risk_band] || 'pill--info'}`}>{asset.label}</span>}
            {asset.has_kev && <span className="pill pill--danger inline-flex items-center gap-1"><Flame size={11} />Known Exploited</span>}
            {asset.match_flag && <span className={`pill ${asset.match_flag === 'conflict' ? 'pill--warn' : 'pill--info'}`}>{MATCH_FLAG_LABEL[asset.match_flag]}</span>}
          </div>
          <div className="text-xs text-[var(--text-muted)] mt-1.5 mono">{asset.ip_address} · {asset.device_type}</div>
        </div>
        <div className="text-right">
          <div className="text-2xl font-semibold text-[var(--text-primary)]">{asset.risk_score ?? 'Not yet ranked'}</div>
          <div className="text-[10px] uppercase text-[var(--text-muted)]">prioritization index / 100</div>
        </div>
      </div>

      <div className="grid grid-cols-3 gap-4 mt-4">
        <ScoreBar label="Max CVSS" value={asset.max_cvss} max={10} />
        <ScoreBar label="Max EPSS %" value={Math.round((asset.max_epss || 0) * 100)} />
        <ScoreBar label="Exposure (network-wide)" value={asset.exposure} />
      </div>

      {/* Read-only: organizational criticality now comes from the uploaded
          asset document, never from a dropdown on this card. */}
      <div className="mt-3 grid grid-cols-2 gap-3 text-xs">
        <div>
          <span className="block text-[10px] uppercase tracking-wider text-[var(--text-muted)] mb-0.5">Criticality (15%, from your document)</span>
          <span className="text-[var(--text-secondary)]">{asset.criticality_label || '—'}</span>
        </div>
        <div>
          <span className="block text-[10px] uppercase tracking-wider text-[var(--text-muted)] mb-0.5">Purpose</span>
          <span className="text-[var(--text-secondary)]">{asset.purpose || '—'}</span>
        </div>
      </div>
      {asset.document_note && (
        <div className="mt-2 text-xs text-[var(--warning)]">{asset.document_note}</div>
      )}

      <div className="flex justify-between mt-3 text-[11px] text-[var(--text-muted)]">
        <span>{asset.active_vuln_count} active CVE{asset.active_vuln_count === 1 ? '' : 's'}</span>
        <span>{asset.recommendations?.length || 0} recommendation{asset.recommendations?.length === 1 ? '' : 's'}</span>
      </div>
      <div className="mt-3 pt-3 border-t border-[var(--border)] text-xs text-[var(--text-secondary)]">
        <span className="font-medium text-[var(--text-primary)]">Recommendations: </span>{asset.recommendations?.join(' ') || 'No urgent action required; continue routine monitoring.'}
      </div>
    </article>
  )
}

export default function RiskEngine() {
  const { data: assets, isLoading } = useRiskAssets()
  const { data: summary, refetch: refetchSummary } = useRiskSummary()
  const { data: readiness, refetch: refetchReadiness } = useRiskReadiness()
  const calculateRisk = useCalculateRisk()
  const uploadDocument = useUploadAssetDocument()

  const [file, setFile] = useState(null)
  const [uploadErrors, setUploadErrors] = useState([])
  const [uploadSuccess, setUploadSuccess] = useState(null)
  const [blockedNotice, setBlockedNotice] = useState(false)
  const [showMissing, setShowMissing] = useState(false)
  const [showExplanation, setShowExplanation] = useState(false)

  const ranked = rankedAssets(assets)
  const notInDocument = notInDocumentAssets(assets)
  const missingFromScan = missingFromScanAssets(assets)
  const readyToRank = Boolean(readiness?.ready_to_rank)
  const isPending = calculateRisk.isPending
  const calculateDisabled = !readyToRank || isPending

  async function handleUpload() {
    if (!file) return
    setUploadErrors([])
    setUploadSuccess(null)
    try {
      const result = await uploadDocument.mutateAsync(file)
      setUploadSuccess({
        rows: result.rows_uploaded,
        at: new Date(result.uploaded_at).toLocaleString(),
      })
      setFile(null)
      await Promise.all([refetchReadiness(), refetchSummary()])
    } catch (error) {
      // Never a generic "Upload failed": render the backend's per-row problems.
      setUploadErrors(error.validationErrors?.length
        ? error.validationErrors
        : [{ row: 0, column: '-', problem: error.validationMessage || error.message, expected: '-' }])
    }
  }

  // The button is genuinely disabled, so clicking it cannot fire; the wrapper
  // still surfaces the reason on click rather than leaving a dead control.
  function handleCalculateClick() {
    if (!readyToRank) {
      setBlockedNotice(true)
      return
    }
    if (isPending) return
    setBlockedNotice(false)
    calculateRisk.mutate()
  }

  return (
    <div className="flex flex-col gap-5">
      <div>
        <h1 className="text-2xl font-semibold text-[var(--text-primary)]">Risk & interpretation engine</h1>
        <p className="text-sm text-[var(--text-muted)]">{summary?.index_label || 'ETSNTECH prototype prioritization index'} — one score per asset, combining severity, likelihood, known exploitation, network exposure, and organizational criticality</p>
      </div>

      <div className="card flex flex-col gap-3">
        <div className="flex items-center justify-between gap-3 flex-wrap">
          <div className="flex items-center gap-2">
            <BrainCircuit size={16} className="text-[var(--accent)]" />
            <span className="text-sm font-semibold text-[var(--text-primary)]">Asset document</span>
          </div>
          <button
            type="button"
            onClick={() => setShowExplanation((open) => !open)}
            aria-expanded={showExplanation}
            className="text-xs text-[var(--accent)] hover:underline"
          >
            {showExplanation ? 'Hide how this is calculated' : 'Learn how this is calculated'}
          </button>
        </div>
        <p className="text-xs text-[var(--text-secondary)]">
          Upload one document listing every device. It replaces the previous document entirely, and it is the
          only source of organizational criticality — nothing is marked device-by-device.
        </p>
        <div className="text-xs text-[var(--text-secondary)]">
          <span className="block text-[10px] uppercase tracking-wider text-[var(--text-muted)] mb-1">Required columns</span>
          <span className="mono">{REQUIRED_COLUMNS.join(' · ')}</span>
          <span className="block mt-1 text-[10px] uppercase tracking-wider text-[var(--text-muted)]">Allowed criticality_category values</span>
          <ul className="list-disc pl-5 mt-0.5">
            {ALLOWED_CATEGORIES.map((value) => <li key={value}>{value}</li>)}
          </ul>
          <span className="block mt-1 text-[var(--text-muted)]">
            Accepts .csv or .xlsx (sheet “Device Criticality”, or the first sheet). Each row needs an ip_address or a device_name.
          </span>
        </div>
        <div className="flex items-center gap-3 flex-wrap">
          <label className="inline-flex items-center cursor-pointer bg-[var(--bg-surface-2)] border border-[var(--border)] hover:border-[var(--accent)] text-[var(--text-primary)] text-xs font-medium px-3 py-2 rounded-[var(--radius-sm)]">
            Choose file
            <input
              type="file"
              accept=".csv,.xlsx,text/csv,application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
              className="sr-only"
              onChange={(event) => { setFile(event.target.files?.[0] || null); setUploadErrors([]); setUploadSuccess(null) }}
            />
          </label>
          <span className="text-xs text-[var(--text-muted)] truncate max-w-64">{file?.name || 'No file selected'}</span>
          <button
            type="button"
            onClick={handleUpload}
            disabled={!file || uploadDocument.isPending}
            className="bg-[var(--accent)] hover:bg-[var(--accent-hover)] disabled:opacity-50 text-white text-xs font-medium px-3 py-2 rounded-[var(--radius-sm)]"
          >
            {uploadDocument.isPending ? 'Uploading...' : 'Upload asset document'}
          </button>
        </div>

        {uploadSuccess && (
          <p role="status" className="text-xs text-[var(--text-primary)]">
            Uploaded {uploadSuccess.rows} device row{uploadSuccess.rows === 1 ? '' : 's'} at {uploadSuccess.at}.
            Press Calculate Ranking to apply it — nothing is recalculated automatically.
          </p>
        )}
        {uploadErrors.length > 0 && (
          <div role="alert" className="text-xs text-[var(--danger)]">
            <p className="font-medium mb-1">The document was rejected — nothing was uploaded:</p>
            <ul className="list-disc pl-5 space-y-0.5">
              {uploadErrors.map((problem, index) => (
                <li key={`${problem.row}-${problem.column}-${index}`}>
                  {problem.row ? `Row ${problem.row}, ${problem.column}: ` : ''}
                  {problem.problem}
                  {problem.expected && problem.expected !== '-' ? <span className="text-[var(--text-muted)]"> Expected: {problem.expected}</span> : null}
                </li>
              ))}
            </ul>
          </div>
        )}

        <div className="pt-3 border-t border-[var(--border)] flex flex-col gap-2">
          <div className="text-xs text-[var(--text-secondary)]">
            {readiness
              ? readiness.asset_document_uploaded
                ? `✓ Asset document uploaded${readiness.uploaded_at ? ` at ${new Date(readiness.uploaded_at).toLocaleString()}` : ''}`
                : `⚠ ${BLOCKED_MESSAGE}`
              : 'Checking readiness...'}
          </div>
          <div className="w-fit" title={calculateDisabled && !isPending ? BLOCKED_MESSAGE : undefined}>
            <button
              type="button"
              disabled={calculateDisabled}
              onClick={handleCalculateClick}
              className="w-fit bg-[var(--accent)] hover:bg-[var(--accent-hover)] disabled:opacity-50 disabled:cursor-not-allowed text-white text-xs font-medium px-3 py-2 rounded-[var(--radius-sm)]"
            >
              {isPending ? 'Calculating...' : 'Calculate Ranking'}
            </button>
          </div>
          {calculateDisabled && !isPending && <div className="text-xs text-[var(--warning)]">{BLOCKED_MESSAGE}</div>}
          {blockedNotice && <div role="alert" className="text-xs text-[var(--warning)]">{BLOCKED_MESSAGE}</div>}
          {summary?.ranked_at
            ? <div className="text-xs text-[var(--text-muted)]">Last ranked: {new Date(summary.ranked_at).toLocaleString()}</div>
            : <div className="text-xs text-[var(--text-muted)]">Not yet ranked</div>}
          {summary?.ranking_stale && <div className="text-xs text-[var(--warning)]">Ranking may be outdated - recalculate</div>}
          {calculateRisk.isError && (
            <div role="alert" className="text-xs text-[var(--danger)]">
              {calculateRisk.error?.response?.data?.detail?.message || calculateRisk.error?.message}
            </div>
          )}
        </div>
      </div>

      <div className="grid grid-cols-5 gap-4">
        <MetricCard label="Critical" value={summary?.critical} sub="fix immediately" tone="danger" />
        <MetricCard label="High" value={summary?.high} sub="fix soon" tone="danger" />
        <MetricCard label="Elevated" value={summary?.elevated} sub="monitor" tone="warn" />
        <MetricCard label="Low" value={summary?.low} sub="acceptable for now" tone="ok" />
        <MetricCard label="KEV matches" value={summary?.kev_matches} sub="confirmed exploited" tone="danger" />
      </div>

      {!isLoading && ranked.length === 0 && notInDocument.length === 0 ? (
        <div className="card">
          <EmptyState
            icon={BrainCircuit}
            title="No ranking yet"
            description="Upload the asset document and press Calculate Ranking — this layer scores every device seen in the last 24 hours."
          />
        </div>
      ) : (
        <div className="flex flex-col gap-3">
          {missingFromScan.length > 0 && (
            <div role="status" className="card border-[var(--accent-border)] bg-[var(--accent-bg)]">
              <button
                type="button"
                onClick={() => setShowMissing((open) => !open)}
                aria-expanded={showMissing}
                className="flex items-center gap-2 text-xs font-medium text-[var(--text-primary)] w-full text-left"
              >
                {showMissing ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                {missingFromScan.length} device{missingFromScan.length === 1 ? '' : 's'} in your document were not found on the network
              </button>
              {showMissing && (
                <ul className="mt-2 pl-6 text-xs text-[var(--text-secondary)] list-disc space-y-0.5">
                  {missingFromScan.map((item) => (
                    <li key={`${item.device_name || ''}-${item.ip_address || ''}`}>
                      <span className="font-medium text-[var(--text-primary)]">{item.device_name || item.ip_address}</span>
                      {item.ip_address && item.device_name ? ` (${item.ip_address})` : ''}
                      {item.purpose ? ` — ${item.purpose}` : ''}
                      <span className="block text-[var(--text-muted)]">{item.note}</span>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          )}

          {ranked.map((asset) => <AssetCard key={asset.asset_id} asset={asset} />)}

          {notInDocument.length > 0 && (
            <>
              <h2 className="text-sm font-semibold text-[var(--text-primary)] mt-2">Scanned devices not in your document</h2>
              {notInDocument.map((asset) => <AssetCard key={asset.asset_id} asset={asset} />)}
            </>
          )}
        </div>
      )}
    </div>
  )
}
