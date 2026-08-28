import { useQuery } from '@tanstack/react-query'
import { getTelemetryChanges, getTelemetryTrend } from '../api/client'

export function useTelemetryChanges({ toScanId, fromScanId } = {}) {
  return useQuery({
    queryKey: ['telemetry-changes', toScanId, fromScanId],
    queryFn: () => getTelemetryChanges({ toScanId, fromScanId }),
    refetchInterval: 15_000,
  })
}

export function useTelemetryTrend(limit = 10) {
  return useQuery({ queryKey: ['telemetry-trend', limit], queryFn: () => getTelemetryTrend(limit), refetchInterval: 15_000 })
}
