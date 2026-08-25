import { useQuery } from '@tanstack/react-query'
import { getDevice, getDeviceServices, getDevices, getScanActivity, getScanHistory } from '../api/client'

export function useDevices(filters = {}) {
  return useQuery({ queryKey: ['devices', filters], queryFn: () => getDevices(filters) })
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

export function useScanHistory() {
  return useQuery({ queryKey: ['scan-history'], queryFn: getScanHistory })
}
