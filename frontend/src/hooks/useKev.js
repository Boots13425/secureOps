import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { getKevIntelligence, getKevRuns, getKevSummary, refreshKev } from '../api/client'

export function useKevIntelligence(filters = {}) {
  return useQuery({ queryKey: ['kev-intelligence', filters], queryFn: () => getKevIntelligence(filters), refetchInterval: 15_000 })
}

export function useKevSummary() {
  return useQuery({ queryKey: ['kev-summary'], queryFn: getKevSummary, refetchInterval: 15_000 })
}

export function useKevRuns() {
  return useQuery({ queryKey: ['kev-runs'], queryFn: getKevRuns, refetchInterval: 5_000 })
}

export function useRefreshKev() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: refreshKev,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['kev-runs'] })
      queryClient.invalidateQueries({ queryKey: ['kev-intelligence'] })
      queryClient.invalidateQueries({ queryKey: ['kev-summary'] })
      queryClient.invalidateQueries({ queryKey: ['vulnerabilities'] })
    },
  })
}
