import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { calculateRisk, getRiskAssets, getRiskReadiness, getRiskSummary, uploadAssetDocument } from '../api/client'

export function useRiskAssets() {
  return useQuery({ queryKey: ['risk-assets'], queryFn: getRiskAssets, refetchInterval: 15_000 })
}

export function useRiskSummary() {
  return useQuery({ queryKey: ['risk-summary'], queryFn: getRiskSummary, refetchInterval: 15_000 })
}

export function useRiskReadiness() {
  return useQuery({ queryKey: ['risk-readiness'], queryFn: getRiskReadiness, refetchInterval: 15_000 })
}

export function useCalculateRisk() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: calculateRisk,
    onSuccess: (data) => {
      // The calculate response already carries the three groups, so cache them
      // directly instead of waiting for a refetch to land.
      queryClient.setQueryData(['risk-assets'], data)
      queryClient.invalidateQueries({ queryKey: ['risk-summary'] })
      queryClient.invalidateQueries({ queryKey: ['risk-readiness'] })
    },
  })
}

// Uploading a new document does not recalculate anything: the stored ranking
// becomes stale and the UI asks the administrator to press Calculate Ranking.
export function useUploadAssetDocument() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: uploadAssetDocument,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['risk-readiness'] })
      queryClient.invalidateQueries({ queryKey: ['risk-assets'] })
      queryClient.invalidateQueries({ queryKey: ['risk-summary'] })
    },
  })
}
