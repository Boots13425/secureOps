const SEVERITY = {
  critical: { cls: 'pill--danger', label: 'Critical' },
  high: { cls: 'pill--danger', label: 'High' },
  medium: { cls: 'pill--warn', label: 'Medium' },
  low: { cls: 'pill--info', label: 'Low' },
  informational: { cls: 'pill--info', label: 'Informational' },
}

export default function SeverityPill({ severity }) {
  const entry = SEVERITY[severity] || SEVERITY.informational
  return <span className={`pill ${entry.cls}`}>{entry.label}</span>
}
