import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { getEpssIntelligence, getEpssRuns, getEpssSummary, refreshEpss } from '../api/client'

export function useEpssIntelligence(filters = {}) {
  return useQuery({ queryKey: ['epss-intelligence', filters], queryFn: () => getEpssIntelligence(filters), refetchInterval: 15_000 })
}

export function useEpssSummary() {
  return useQuery({ queryKey: ['epss-summary'], queryFn: getEpssSummary, refetchInterval: 15_000 })
}

export function useEpssRuns() {
  return useQuery({ queryKey: ['epss-runs'], queryFn: getEpssRuns, refetchInterval: 5_000 })
}

export function useRefreshEpss() {
  const queryClient = useQueryClient()
  return useMutation({ mutationFn: refreshEpss, onSuccess: () => {
    queryClient.invalidateQueries({ queryKey: ['epss-runs'] })
    queryClient.invalidateQueries({ queryKey: ['epss-intelligence'] })
    queryClient.invalidateQueries({ queryKey: ['epss-summary'] })
    queryClient.invalidateQueries({ queryKey: ['vulnerabilities'] })
  } })
}
