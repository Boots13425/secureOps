import { useState, useMemo } from 'react'
import { Link } from 'react-router-dom'
import { HardDrive, Filter, Radar, Globe, AlertCircle, RefreshCw } from 'lucide-react'
import { useCurrentDevices } from '../hooks/useDevices'
import { useNetworks } from '../hooks/useNetworks'
import StatusPill from '../components/StatusPill'
import OsCell from '../components/OsCell'
import HostnameCell from '../components/HostnameCell'
import EmptyState from '../components/EmptyState'
import { timeAgo } from '../utils/time'

export default function Devices() {
  const [status, setStatus] = useState('')
  const [deviceType, setDeviceType] = useState('')
  const [networkFilter, setNetworkFilter] = useState('')
  const { data: devices, isLoading, latestScan, hasCompletedScan } = useCurrentDevices()
  const { data: networksData } = useNetworks()
  const networks = networksData?.networks || []

  const filtered = (devices || []).filter((d) => 
    (!status || d.status === status) && 
    (!deviceType || d.device_type === deviceType) &&
    (!networkFilter || d.network_cidr === networkFilter)
  )
  const sorted = [...filtered].sort((a, b) => new Date(b.last_seen) - new Date(a.last_seen))

  // Count unique networks among displayed devices
  const uniqueNetworks = new Set(sorted.map(d => d.network_cidr).filter(Boolean))
  const networkCount = uniqueNetworks.size

  // Identify stale networks (networks with no recent scan)
  const staleNetworks = useMemo(() => {
    if (!networks) return []
    return networks.filter(n => !n.is_local && n.is_stale)
  }, [networks])

  // Networks that have devices in the current view
  const networksWithDevices = useMemo(() => {
    const nets = new Set(sorted.map(d => d.network_cidr).filter(Boolean))
    return nets
  }, [sorted])

  // Networks that are scanned but not stale (have recent scan)
  const freshNetworks = useMemo(() => {
    if (!networks) return new Set()
    return new Set(networks.filter(n => !n.is_local && !n.is_stale && n.cidr_text).map(n => n.cidr_text))
  }, [networks])

  // Networks that are scanned and fresh but have no devices in current view (empty scan)
  const emptyFreshNetworks = useMemo(() => {
    return Array.from(freshNetworks).filter(n => !networksWithDevices.has(n))
  }, [freshNetworks, networksWithDevices])

  return (
    <div className="flex flex-col gap-5">
      <div className="flex items-end justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-2xl font-semibold text-[var(--text-primary)]">Devices — right now</h1>
          <p className="text-sm text-[var(--text-muted)]">
            {isLoading
              ? 'Loading…'
              : hasCompletedScan
                ? `${sorted.length} device${sorted.length === 1 ? '' : 's'} connected across ${networkCount} network${networkCount === 1 ? '' : 's'}`
                : 'No completed scan yet'}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Filter size={15} className="text-[var(--text-muted)]" />
          <select aria-label="Filter by asset status" value={status} onChange={(event) => setStatus(event.target.value)} className="bg-[var(--bg-surface)] border border-[var(--border)] rounded-[var(--radius-sm)] px-3 py-2 text-sm text-[var(--text-primary)] outline-none">
            <option value="">All statuses</option>
            {['unknown', 'known', 'approved', 'missing'].map((value) => <option key={value} value={value}>{value[0].toUpperCase() + value.slice(1)}</option>)}
          </select>
          <select aria-label="Filter by device type" value={deviceType} onChange={(event) => setDeviceType(event.target.value)} className="bg-[var(--bg-surface)] border border-[var(--border)] rounded-[var(--radius-sm)] px-3 py-2 text-sm text-[var(--text-primary)] outline-none">
            <option value="">All device types</option>
            {['PC', 'server', 'router', 'switch', 'network device', 'printer', 'phone', 'unknown'].map((value) => <option key={value} value={value}>{value[0].toUpperCase() + value.slice(1)}</option>)}
          </select>
          <select aria-label="Filter by network" value={networkFilter} onChange={(event) => setNetworkFilter(event.target.value)} className="bg-[var(--bg-surface)] border border-[var(--border)] rounded-[var(--radius-sm)] px-3 py-2 text-sm text-[var(--text-primary)] outline-none">
            <option value="">All networks</option>
            {networks?.map((n) => n.cidr_text || n.cidr).filter(Boolean).map((cidr) => <option key={cidr} value={cidr}>{cidr}</option>)}
          </select>
        </div>
      </div>

      <div className="text-xs text-[var(--text-muted)]">
        This only shows devices that answered a direct probe in the latest scan of their network. For the full permanent record of every device ever seen, see the <Link to="/history" className="text-[var(--accent)] hover:underline">History</Link> page.
      </div>

      <div className="card">
        {!isLoading && !hasCompletedScan ? (
          <EmptyState
            icon={Radar}
            title="No completed scan yet"
            description="Start a network scan from the Discovery page to see what's on the network right now."
          />
        ) : !isLoading && sorted.length === 0 && staleNetworks.length === 0 && emptyFreshNetworks.length === 0 ? (
          <EmptyState
            icon={HardDrive}
            title="No devices matched the last scan"
            description="Try clearing the filters above, or run a new scan."
          />
        ) : (
          <>
            {/* Stale network notices */}
            {staleNetworks.length > 0 && (
              <div className="p-4 border-b border-[var(--border)]">
                <div className="flex items-center gap-2 text-sm text-[var(--warning)] mb-2">
                  <AlertCircle size={16} />
                  <span className="font-medium">Networks not rescanned recently:</span>
                </div>
                <div className="flex flex-wrap gap-2">
                  {staleNetworks.map((net) => (
                    <div key={net.network_id} className="pill pill--warn flex items-center gap-1.5 text-xs">
                      <span>{net.cidr_text || net.cidr}</span>
                      <span className="text-[var(--text-muted)]">
                        ({timeAgo(net.last_scanned_at)} ago)
                      </span>
                      <RefreshCw size={10} className="text-[var(--text-secondary)]" />
                    </div>
                  ))}
                </div>
                <p className="text-xs text-[var(--text-muted)] mt-2">
                  These networks haven't been scanned in the last {networksData?.freshness_window_minutes || 30} minutes. 
                  Devices from these networks are not shown. Run a scan to update their status.
                </p>
              </div>
            )}

            {/* Empty fresh networks (scanned recently but no devices found) */}
            {emptyFreshNetworks.length > 0 && (
              <div className="p-4 border-b border-[var(--border)]">
                <div className="flex items-center gap-2 text-sm text-[var(--text-secondary)] mb-2">
                  <Globe size={16} />
                  <span className="font-medium">Recently scanned, no devices found:</span>
                </div>
                <div className="flex flex-wrap gap-2">
                  {emptyFreshNetworks.map((cidr) => (
                    <div key={cidr} className="pill pill--info text-xs">
                      {cidr}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Device table */}
            {sorted.length > 0 && (
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-left text-[10px] uppercase tracking-wide text-[var(--text-muted)] border-b border-[var(--border)]">
                    <th className="pb-2 font-medium">Device</th>
                    <th className="pb-2 font-medium">IP address</th>
                    <th className="pb-2 font-medium">MAC address</th>
                    <th className="pb-2 font-medium">Network</th>
                    <th className="pb-2 font-medium">Operating system</th>
                    <th className="pb-2 font-medium">Seen via</th>
                    <th className="pb-2 font-medium">Status</th>
                    <th className="pb-2 font-medium">Exposures</th>
                    <th className="pb-2 font-medium">First seen</th>
                    <th className="pb-2 font-medium">Last seen</th>
                  </tr>
                </thead>
                <tbody>
                  {sorted.map((d) => (
                    <tr key={d.id} className="border-b border-[var(--border)] last:border-0 hover:bg-[var(--bg-hover)] cursor-pointer">
                      <td className="py-2.5">
                        <Link to={`/devices/${d.id}`} className="block">
                          <HostnameCell hostname={d.hostname} provenance={d.identification_provenance} />
                          <div className="text-[11px] text-[var(--text-muted)] capitalize">{d.device_type}</div>
                        </Link>
                      </td>
                      <td className="py-2.5 mono">{d.ip}</td>
                      <td className="py-2.5 mono text-[var(--text-muted)]">{d.mac_address || '—'}</td>
                      <td className="py-2.5 mono text-[var(--text-secondary)]">{d.network_cidr || '—'}</td>
                      <td className="py-2.5"><OsCell osName={d.os_name} osSource={d.os_source} /></td>
                      <td className="py-2.5">
                        <span className="pill pill--info">{(d.discovery_sources || []).join(' · ') || '—'}</span>
                      </td>
                      <td className="py-2.5"><StatusPill status={d.status} /></td>
                      <td className="py-2.5"><span className="pill pill--info">{d.service_count || 0} open</span></td>
                      <td className="py-2.5 text-[var(--text-secondary)] whitespace-nowrap">{timeAgo(d.first_seen)}</td>
                      <td className="py-2.5 text-[var(--text-secondary)] whitespace-nowrap">{timeAgo(d.last_seen)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </>
        )}
      </div>
    </div>
  )
}
