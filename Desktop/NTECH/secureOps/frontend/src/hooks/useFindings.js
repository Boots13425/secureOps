import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { getDeviceFindings, getFindings, getFindingsSummary, updateFindingStatus } from '../api/client'

export function useFindings(filters = {}) {
  return useQuery({ queryKey: ['findings', filters], queryFn: () => getFindings(filters) })
}

export function useDeviceFindings(assetId) {
  return useQuery({ queryKey: ['device-findings', assetId], queryFn: () => getDeviceFindings(assetId), enabled: Boolean(assetId) })
}

export function useFindingsSummary() {
  return useQuery({ queryKey: ['findings-summary'], queryFn: getFindingsSummary })
}

export function useUpdateFindingStatus() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: updateFindingStatus,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['findings'] })
      queryClient.invalidateQueries({ queryKey: ['findings-summary'] })
    },
  })
}
