import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { detectNetworks, getNetworks, scanNetworkById, scanAllNetworks } from '../api/client'

// GET /networks returns { networks, summary, targets }, so consumers must read
// the `networks` array rather than treating the payload as a list. The shared
// accessors live in utils/riskAssets-style helpers: see getOtherNetworks below.
export function useNetworks() {
  return useQuery({ queryKey: ['networks'], queryFn: getNetworks, refetchInterval: 30_000 })
}

export function useOtherNetworks() {
  const query = useNetworks()
  const data = query.data
  return {
    ...query,
    // The local network is already summarized by the Dashboard's Total
    // Devices / Observed / Missing cards, so it is excluded here rather than
    // counted twice in two different places.
    networks: (data?.networks || []).filter((network) => !network.is_local),
    summary: data?.summary,
    targets: data?.targets || [],
  }
}

export function useDetectNetworks() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: detectNetworks,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['networks'] })
    },
  })
}

export function useScanNetwork() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ networkId, ...payload }) => scanNetworkById(networkId, payload),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['networks'] })
      queryClient.invalidateQueries({ queryKey: ['scan-sessions'] })
      queryClient.invalidateQueries({ queryKey: ['scan-activity'] })
    },
  })
}

export function useScanAllNetworks() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: scanAllNetworks,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['networks'] })
      queryClient.invalidateQueries({ queryKey: ['scan-sessions'] })
      queryClient.invalidateQueries({ queryKey: ['scan-activity'] })
    },
  })
}
