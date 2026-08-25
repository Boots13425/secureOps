import { useState } from 'react'
import { Link } from 'react-router-dom'
import { HardDrive, Filter } from 'lucide-react'
import { useDevices } from '../hooks/useDevices'
import StatusPill from '../components/StatusPill'
import OsCell from '../components/OsCell'
import EmptyState from '../components/EmptyState'
import { timeAgo } from '../utils/time'

export default function Devices() {
  const [status, setStatus] = useState('')
  const [deviceType, setDeviceType] = useState('')
  const { data: devices, isLoading } = useDevices({ status, deviceType })
  const sorted = devices ? [...devices].sort((a, b) => new Date(b.last_seen) - new Date(a.last_seen)) : []

  return (
    <div className="flex flex-col gap-5">
      <div className="flex items-end justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-2xl font-semibold text-[var(--text-primary)]">Asset inventory</h1>
          <p className="text-sm text-[var(--text-muted)]">
            {isLoading ? 'Loading…' : `${sorted.length} persistent asset${sorted.length === 1 ? '' : 's'} in scope`}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Filter size={15} className="text-[var(--text-muted)]" />
          <select aria-label="Filter by asset status" value={status} onChange={(event) => setStatus(event.target.value)} className="bg-[var(--bg-surface)] border border-[var(--border)] rounded-[var(--radius-sm)] px-3 py-2 text-sm text-[var(--text-primary)] outline-none">
            <option value="">All statuses</option>
            {['unknown', 'known', 'approved', 'missing', 'offline'].map((value) => <option key={value} value={value}>{value[0].toUpperCase() + value.slice(1)}</option>)}
          </select>
          <select aria-label="Filter by device type" value={deviceType} onChange={(event) => setDeviceType(event.target.value)} className="bg-[var(--bg-surface)] border border-[var(--border)] rounded-[var(--radius-sm)] px-3 py-2 text-sm text-[var(--text-primary)] outline-none">
            <option value="">All device types</option>
            {['PC', 'server', 'router', 'printer', 'phone', 'unknown'].map((value) => <option key={value} value={value}>{value[0].toUpperCase() + value.slice(1)}</option>)}
          </select>
        </div>
      </div>

      <div className="card">
        {!isLoading && sorted.length === 0 ? (
          <EmptyState
            icon={HardDrive}
            title="No devices discovered yet"
            description="Connect to the company network and run a network scan to discover devices."
          />
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-[10px] uppercase tracking-wide text-[var(--text-muted)] border-b border-[var(--border)]">
                <th className="pb-2 font-medium">Device</th>
                <th className="pb-2 font-medium">IP address</th>
                <th className="pb-2 font-medium">MAC address</th>
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
                      <div className="text-[var(--text-primary)] hover:text-[var(--accent)]">{d.hostname || 'Unknown'}</div>
                      <div className="text-[11px] text-[var(--text-muted)] capitalize">{d.device_type}</div>
                    </Link>
                  </td>
                  <td className="py-2.5 mono">{d.ip}</td>
                  <td className="py-2.5 mono text-[var(--text-muted)]">{d.mac_address || '—'}</td>
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
      </div>
    </div>
  )
}
