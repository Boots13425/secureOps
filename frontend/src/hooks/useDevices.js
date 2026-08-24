import { useQuery } from '@tanstack/react-query'
import { getDevices, getScanActivity, getScanHistory } from '../api/client'

export function useDevices(filters = {}) {
  return useQuery({ queryKey: ['devices', filters], queryFn: () => getDevices(filters) })
}

export function useScanActivity(limit = 8) {
  return useQuery({ queryKey: ['scan-activity', limit], queryFn: () => getScanActivity(limit) })
}

export function useScanHistory() {
  return useQuery({ queryKey: ['scan-history'], queryFn: getScanHistory })
}
