import { Search, ChevronDown, Command } from 'lucide-react'
import { useScanSessions } from '../hooks/useScanSessions'

export default function Topbar() {
  const { data: sessions } = useScanSessions()
  const monitoring = (sessions || []).some((s) => s.status === 'RUNNING')

  return (
    <header
      className="app-topbar fixed top-0 right-0 z-20 flex items-center justify-between gap-6 border-b border-[var(--border)] bg-[rgba(7,17,31,.84)] backdrop-blur-xl px-7"
      style={{ height: 'var(--topbar-h)', left: 'var(--sidebar-w)' }}
    >
      <div className="topbar-search relative flex-1 max-w-lg">
        <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-[var(--text-muted)]" />
        <input
          type="text"
          placeholder="Search device, IP, MAC, hostname"
          className="w-full bg-[rgba(13,27,45,.8)] border border-[var(--border)] rounded-[var(--radius-sm)] pl-9 pr-12 py-2.5 text-sm text-[var(--text-primary)] placeholder:text-[var(--text-muted)] outline-none"
        />
        <div className="absolute right-3 top-1/2 -translate-y-1/2 flex items-center gap-1 text-[10px] text-[var(--text-muted)] border border-[var(--border)] rounded px-1.5 py-0.5">
          <Command size={10} /> K
        </div>
      </div>

      <div className="flex items-center gap-6">
        <div className="topbar-status flex items-center gap-2 text-xs font-medium text-[var(--text-secondary)] border border-[var(--border)] bg-[var(--bg-surface)] rounded-full px-3 py-1.5">
          <span className={`w-2 h-2 rounded-full ${monitoring ? 'bg-[var(--ok)] shadow-[0_0_8px_var(--ok)]' : 'bg-[var(--text-muted)]'}`} />
          {monitoring ? 'Monitoring active' : 'Scanner idle'}
        </div>

        <div className="flex items-center gap-2.5 cursor-pointer">
          <div className="flex items-center justify-center w-9 h-9 rounded-full border border-[var(--accent-border)] bg-[var(--accent-bg)] text-[var(--accent)] text-xs font-semibold">
            FL
          </div>
          <div className="topbar-profile-copy leading-tight">
            <div className="text-sm text-[var(--text-primary)]">Florence</div>
            <div className="text-[11px] text-[var(--text-muted)]">Administrator</div>
          </div>
          <ChevronDown size={16} className="topbar-chevron text-[var(--text-muted)]" />
        </div>
      </div>
    </header>
  )
}
