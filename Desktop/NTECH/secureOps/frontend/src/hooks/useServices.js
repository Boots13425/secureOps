import { useQuery } from '@tanstack/react-query'
import { getServices, getServicesSummary } from '../api/client'

export function useServices(filters = {}) {
  return useQuery({ queryKey: ['services', filters], queryFn: () => getServices(filters) })
}

export function useServicesSummary() {
  return useQuery({ queryKey: ['services-summary'], queryFn: getServicesSummary })
}
