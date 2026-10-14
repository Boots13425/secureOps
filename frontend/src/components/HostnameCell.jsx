// A device with no hostname is usually a network limitation rather than a
// scanning failure, so the reason is surfaced instead of a bare "Unknown".
// The backend records why in identification_provenance.hostname_unresolved_reason
// when a name could not be established - most commonly for devices on a remote
// network, where NetBIOS and mDNS are deliberately skipped because neither
// crosses a router.
export default function HostnameCell({ hostname, provenance }) {
  if (hostname) {
    return <div className="text-[var(--text-primary)]">{hostname}</div>
  }
  const reason = provenance?.hostname_unresolved_reason
  if (!reason) {
    return <div className="text-[var(--text-muted)]">Unknown</div>
  }
  return (
    <div className="leading-tight">
      <div
        className="text-[var(--text-muted)] underline decoration-dotted cursor-help"
        title={reason}
        aria-label={reason}
      >
        Unknown
      </div>
      <div className="text-[11px] text-[var(--text-muted)]">no name available</div>
    </div>
  )
}
