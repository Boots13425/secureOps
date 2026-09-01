import { NavLink } from 'react-router-dom'
import {
  LayoutDashboard,
  HardDrive,
  ScanLine,
  Radar,
  Settings,
  ShieldCheck,
  Network,
  Gauge,
  Bell,
  FileText,
  ScrollText,
  ServerCog,
  ShieldAlert,
  DatabaseZap,
    TrendingUp,
    History,
 } from 'lucide-react'
import NextScanWidget from './NextScanWidget'

const navItems = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard, end: true },
  { to: '/devices', label: 'Devices', icon: HardDrive },
  { to: '/history', label: 'History', icon: History },
  { to: '/services', label: 'Services & CPE', icon: ServerCog },
  { to: '/findings', label: 'Exposure Findings', icon: ShieldAlert },
  { to: '/vulnerabilities', label: 'CVE Intelligence', icon: DatabaseZap },
  { to: '/epss', label: 'EPSS Probability', icon: TrendingUp },
  { to: '/discovery', label: 'Discovery / Scan', icon: ScanLine },
  { to: '/sessions', label: 'Scan Sessions', icon: Radar },
  { to: '/settings', label: 'Settings', icon: Settings },
]

// Roadmap items with no real page behind them yet — shown for context, not
// clickable, matching how the mockup itself grays these out.
const laterPhaseItems = [
  { label: 'Network topology', icon: Network, tag: 'stretch' },
  { label: 'Performance', icon: Gauge, tag: 'stretch' },
  { label: 'Alerts and events', icon: Bell, tag: 'phase 2' },
  { label: 'Reports', icon: FileText, tag: 'phase 2' },
  { label: 'Logs', icon: ScrollText, tag: 'phase 2' },
]

function NavItem({ to, label, icon: Icon, end }) {
  return (
    <NavLink
      to={to}
      end={end}
      className={({ isActive }) =>
        `sidebar-nav-item group flex items-center gap-3 px-3 py-2.5 rounded-[var(--radius-sm)] text-sm font-medium transition-all duration-150 ${
          isActive
            ? 'bg-[var(--accent-bg)] text-[var(--accent)] shadow-[inset_3px_0_var(--accent)]'
            : 'text-[var(--text-secondary)] hover:bg-[var(--bg-hover)] hover:text-[var(--text-primary)]'
        }`
      }
    >
      <Icon size={17} strokeWidth={2} />
      <span className="sidebar-item-label">{label}</span>
    </NavLink>
  )
}

function LaterPhaseItem({ label, icon: Icon, tag }) {
  return (
    <div className="sidebar-nav-item flex items-center gap-3 px-3 py-2.5 rounded-[var(--radius-sm)] text-sm text-[var(--text-muted)] cursor-default">
      <Icon size={17} strokeWidth={2} />
      <span className="sidebar-item-label flex-1">{label}</span>
      <span className="sidebar-tag text-[9px] uppercase tracking-wider px-1.5 py-0.5 rounded border border-[var(--border)] text-[var(--text-muted)]">{tag}</span>
    </div>
  )
}

export default function Sidebar() {
  return (
    <aside
      className="app-sidebar fixed left-0 top-0 z-30 h-full flex flex-col overflow-y-auto border-r border-[var(--border)] bg-[linear-gradient(180deg,var(--bg-sidebar),#07111f)] px-3 py-5 shadow-[12px_0_40px_rgba(0,5,12,.14)]"
      style={{ width: 'var(--sidebar-w)' }}
    >
      <div className="flex items-center gap-3 px-2 mb-8">
        <div className="flex shrink-0 items-center justify-center w-9 h-9 rounded-[10px] bg-[var(--accent-bg)] border border-[var(--accent-border)] text-[var(--accent)] shadow-[0_0_24px_rgba(22,184,212,.12)]">
          <ShieldCheck size={18} strokeWidth={2.2} />
        </div>
        <div className="sidebar-brand-copy">
          <div className="text-[15px] font-semibold tracking-tight text-[var(--text-primary)] leading-tight">SecureOps Hub</div>
          <div className="text-[10px] uppercase tracking-[.12em] text-[var(--text-muted)] mt-0.5">Security operations</div>
        </div>
      </div>

      <div className="sidebar-section-label px-3 mb-2 text-[9px] font-semibold uppercase tracking-[.16em] text-[var(--text-muted)]">Operations</div>
      <nav className="flex flex-col gap-0.5 mb-5">
        {navItems.map((item) => (
          <NavItem key={item.to} {...item} />
        ))}
      </nav>

      <div className="sidebar-section-label px-3 mb-2 text-[9px] font-semibold uppercase tracking-[.16em] text-[var(--text-muted)]">Intelligence</div>
      <nav className="flex flex-col gap-0.5">
        {laterPhaseItems.map((item) => (
          <LaterPhaseItem key={item.label} {...item} />
        ))}
      </nav>

      <div className="sidebar-monitor mt-auto pt-4">
        <NextScanWidget />
      </div>
    </aside>
  )
}
