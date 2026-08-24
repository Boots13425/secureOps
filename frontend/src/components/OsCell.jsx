// os_source distinguishes confirmed OS (snmp/ssh) from a fingerprint guess
// (nmap_guess). CLAUDE.md requires these are never shown identically.
export default function OsCell({ osName, osSource }) {
  if (!osName) {
    return <span className="text-[var(--text-muted)]">Not identified</span>
  }
  return (
    <div className="leading-tight">
      <div className="text-[var(--text-primary)]">{osName}</div>
      {osSource === 'nmap_guess' && (
        <div className="text-[11px] text-[var(--text-muted)]">nmap guess, unconfirmed</div>
      )}
      {osSource === 'ttl_guess' && (
        <div className="text-[11px] text-[var(--text-muted)]">TTL-based guess, unconfirmed</div>
      )}
    </div>
  )
}
