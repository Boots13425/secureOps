import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { getScanNetwork, getScanSessions, getLatestCompletedSession, startScanSession, stopScanSession, resumeScanSession } from '../api/client'

// WebSocket push is the primary refresh path, but a socket can be closed by a
// backend restart, a sleeping laptop, or a proxy that drops idle connections.
// These intervals are a cheap safety net: without them the dashboard can sit on
// stale data indefinitely and look broken even though the API is healthy.
const SCAN_POLL_MS = 10_000

// Kept fresh by useScanSocket (WebSocket push) invalidating on every
// SESSION_* event, with polling as a fallback if that socket is down.
export function useScanSessions() {
  return useQuery({
    queryKey: ['scan-sessions'],
    queryFn: getScanSessions,
    refetchInterval: SCAN_POLL_MS,
    refetchOnWindowFocus: true,
  })
}

export function useScanNetwork() {
  return useQuery({ queryKey: ['scan-network'], queryFn: getScanNetwork, refetchInterval: 10_000 })
}

// Shared by any "what's happening right now" view (Devices, Dashboard activity)
// so they all agree on which scan counts as "the current one".
export function useLatestCompletedSession() {
  const sessions = useQuery({
    queryKey: ['scan-sessions', 'latest'],
    queryFn: getLatestCompletedSession,
    refetchInterval: SCAN_POLL_MS,
    refetchOnWindowFocus: true,
  })
  return {
    session: sessions.data,
    isLoading: sessions.isLoading,
  }
}

function useSessionMutation(mutationFn) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['devices'] })
      queryClient.invalidateQueries({ queryKey: ['scan-sessions'] })
      queryClient.invalidateQueries({ queryKey: ['scan-activity'] })
      queryClient.invalidateQueries({ queryKey: ['scan-history'] })
      queryClient.invalidateQueries({ queryKey: ['services'] })
      queryClient.invalidateQueries({ queryKey: ['services-summary'] })
      queryClient.invalidateQueries({ queryKey: ['findings'] })
      queryClient.invalidateQueries({ queryKey: ['findings-summary'] })
      queryClient.invalidateQueries({ queryKey: ['vulnerabilities'] })
      queryClient.invalidateQueries({ queryKey: ['vulnerabilities-summary'] })
      queryClient.invalidateQueries({ queryKey: ['enrichment-runs'] })
    },
  })
}

export function useStartSession() {
  return useSessionMutation(startScanSession)
}

export function useStopSession() {
  return useSessionMutation(stopScanSession)
}

export function useResumeSession() {
  return useSessionMutation(resumeScanSession)
}
