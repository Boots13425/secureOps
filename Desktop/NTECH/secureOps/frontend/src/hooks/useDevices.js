import { useQuery } from '@tanstack/react-query'
import { getDevice, getDeviceServices, getDevices, getScanActivity, getScanHistory } from '../api/client'
import { useLatestCompletedSession } from './useScanSessions'

export function useDevices(filters = {}) {
  return useQuery({ queryKey: ['devices', filters], queryFn: () => getDevices(filters) })
}

// "What's here right now" — devices seen in the most recently completed scan
// only, as opposed to the full historic inventory (see useDevices()/History page).
export function useCurrentDevices() {
  const { session: latestCompleted, isLoading: sessionsLoading } = useLatestCompletedSession()
  const devices = useQuery({
    queryKey: ['devices', { scanId: latestCompleted?.id }],
    queryFn: () => getDevices({ scanId: latestCompleted.id }),
    enabled: Boolean(latestCompleted?.id),
  })
  return {
    data: devices.data,
    latestScan: latestCompleted,
    isLoading: sessionsLoading || (Boolean(latestCompleted?.id) && devices.isLoading),
    hasCompletedScan: Boolean(latestCompleted),
  }
}

export function useDevice(assetId) {
  return useQuery({ queryKey: ['device', assetId], queryFn: () => getDevice(assetId), enabled: Boolean(assetId) })
}

export function useDeviceServices(assetId) {
  return useQuery({ queryKey: ['device-services', assetId], queryFn: () => getDeviceServices(assetId), enabled: Boolean(assetId) })
}

export function useScanActivity(limit = 8) {
  return useQuery({ queryKey: ['scan-activity', limit], queryFn: () => getScanActivity(limit) })
}

// Dashboard's activity feed — only events from the latest scan, not a mix of
// old and new. The full cross-scan feed still lives on the Discovery page.
export function useCurrentActivity(limit = 8) {
  const { session: latestCompleted, isLoading: sessionsLoading } = useLatestCompletedSession()
  const activity = useQuery({
    queryKey: ['scan-activity', { limit, scanId: latestCompleted?.id }],
    queryFn: () => getScanActivity(limit, latestCompleted.id),
    enabled: Boolean(latestCompleted?.id),
  })
  return {
    data: activity.data,
    latestScan: latestCompleted,
    isLoading: sessionsLoading || (Boolean(latestCompleted?.id) && activity.isLoading),
    hasCompletedScan: Boolean(latestCompleted),
  }
}

export function useScanHistory() {
  return useQuery({ queryKey: ['scan-history'], queryFn: getScanHistory })
}
