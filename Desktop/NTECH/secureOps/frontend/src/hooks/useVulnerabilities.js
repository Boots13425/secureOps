import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { getEnrichmentRuns, getVulnerabilities, getVulnerabilitiesSummary, refreshEnrichment, updateVulnerabilityStatus } from '../api/client'

export function useVulnerabilities(filters = {}) {
  return useQuery({ queryKey: ['vulnerabilities', filters], queryFn: () => getVulnerabilities(filters), refetchInterval: 15_000 })
}

export function useVulnerabilitiesSummary() {
  return useQuery({ queryKey: ['vulnerabilities-summary'], queryFn: getVulnerabilitiesSummary, refetchInterval: 15_000 })
}

export function useEnrichmentRuns() {
  return useQuery({ queryKey: ['enrichment-runs'], queryFn: getEnrichmentRuns, refetchInterval: 5_000 })
}

function useVulnerabilityMutation(mutationFn) {
  const queryClient = useQueryClient()
  return useMutation({ mutationFn, onSuccess: () => {
    queryClient.invalidateQueries({ queryKey: ['vulnerabilities'] })
    queryClient.invalidateQueries({ queryKey: ['vulnerabilities-summary'] })
    queryClient.invalidateQueries({ queryKey: ['enrichment-runs'] })
  } })
}

export function useRefreshEnrichment() { return useVulnerabilityMutation(refreshEnrichment) }
export function useUpdateVulnerabilityStatus() { return useVulnerabilityMutation(updateVulnerabilityStatus) }
