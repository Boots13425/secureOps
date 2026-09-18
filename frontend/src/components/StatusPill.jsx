// Project guide §5.1's four organizational status values only — every
// caller here passes an asset's `status` field, which never holds anything else.
const STATUS_MAP = {
  known: { cls: 'pill--info', label: 'Known' },
  unknown: { cls: 'pill--warn', label: 'Unknown' },
  approved: { cls: 'pill--ok', label: 'Approved' },
  missing: { cls: 'pill--danger', label: 'Missing' },
}

export default function StatusPill({ status }) {
  const entry = STATUS_MAP[status] ?? { cls: 'pill--info', label: status }
  return <span className={`pill ${entry.cls}`}>{entry.label}</span>
}
