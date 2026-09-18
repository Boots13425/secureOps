import { TrendingUp } from 'lucide-react'
import { useScanActivity } from '../hooks/useDevices'
import EmptyState from '../components/EmptyState'
import { timeAgo } from '../utils/time'

export default function ScanActivity() {
  const { data: activity, isLoading } = useScanActivity(50)

  return (
    <div className="flex flex-col gap-5">
      <div>
        <h1 className="text-2xl font-semibold text-[var(--text-primary)]">Discovery / Scan activity</h1>
        <p className="text-sm text-[var(--text-muted)]">
          {isLoading ? 'Loading…' : `${activity?.length ?? 0} recent event${activity?.length === 1 ? '' : 's'}`}
        </p>
      </div>

      <div className="card">
        {!activity || activity.length === 0 ? (
          <EmptyState icon={TrendingUp} title="No scan activity yet" description="Activity will appear here once a scan runs." />
        ) : (
          <div className="flex flex-col gap-3">
            {activity.map((event) => (
              <div key={event.id} className="flex items-start justify-between gap-3 text-sm border-b border-[var(--border)] last:border-0 pb-3 last:pb-0">
                <div>
                  <div className="text-[var(--text-primary)]">{event.message}</div>
                  <div className="text-xs text-[var(--text-muted)] mono">{event.detail}</div>
                </div>
                <div className="text-xs text-[var(--text-muted)] whitespace-nowrap">{timeAgo(event.timestamp)}</div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
