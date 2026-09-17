import { formatDistanceToNowStrict } from 'date-fns'

// Backend sends raw ISO 8601 UTC timestamps (per CLAUDE.md); this is the
// one place relative-time strings like "12s ago" get produced.
export function timeAgo(isoTimestamp) {
  if (!isoTimestamp) return '—'
  return formatDistanceToNowStrict(new Date(isoTimestamp), { addSuffix: true })
}
