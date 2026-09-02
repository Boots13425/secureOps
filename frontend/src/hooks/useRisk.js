import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { getRiskAssets, getRiskSummary, patchDevice } from '../api/client'

export function useRiskAssets() {
  return useQuery({ queryKey: ['risk-assets'], queryFn: getRiskAssets, refetchInterval: 15_000 })
}

export function useRiskSummary() {
  return useQuery({ queryKey: ['risk-summary'], queryFn: getRiskSummary, refetchInterval: 15_000 })
}

export function useUpdateCriticality() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ assetId, criticality }) => patchDevice(assetId, { criticality }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['risk-assets'] })
      queryClient.invalidateQueries({ queryKey: ['risk-summary'] })
      queryClient.invalidateQueries({ queryKey: ['devices'] })
    },
  })
}

export function useUpdateExposure() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ assetId, exposure }) => patchDevice(assetId, { exposure }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['risk-assets'] })
      queryClient.invalidateQueries({ queryKey: ['risk-summary'] })
      queryClient.invalidateQueries({ queryKey: ['devices'] })
    },
  })
}
