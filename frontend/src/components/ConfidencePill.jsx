const CONFIDENCE = {
  high: { cls: 'pill--ok', label: 'High' },
  medium: { cls: 'pill--info', label: 'Medium' },
  low: { cls: 'pill--warn', label: 'Low' },
}

export default function ConfidencePill({ confidence }) {
  const entry = CONFIDENCE[confidence] || CONFIDENCE.low
  return <span className={`pill ${entry.cls}`}>{entry.label}</span>
}
