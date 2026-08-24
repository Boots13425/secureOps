const STATUS_MAP = {
  online: { cls: 'pill--ok', label: 'Online' },
  offline: { cls: 'pill--danger', label: 'Offline' },
  unmanaged: { cls: 'pill--warn', label: 'Unmanaged' },
  known: { cls: 'pill--info', label: 'Known' },
  unknown: { cls: 'pill--warn', label: 'Unknown' },
  approved: { cls: 'pill--ok', label: 'Approved' },
  missing: { cls: 'pill--danger', label: 'Missing' },
}

export default function StatusPill({ status }) {
  const entry = STATUS_MAP[status] ?? { cls: 'pill--info', label: status }
  return <span className={`pill ${entry.cls}`}>{entry.label}</span>
}
