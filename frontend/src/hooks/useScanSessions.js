import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { getScanNetwork, getScanSessions, startScanSession, stopScanSession, resumeScanSession } from '../api/client'

// Kept fresh by useScanSocket (WebSocket push) invalidating on every
// SESSION_* event — no polling needed.
export function useScanSessions() {
  return useQuery({ queryKey: ['scan-sessions'], queryFn: getScanSessions })
}

export function useScanNetwork() {
  return useQuery({ queryKey: ['scan-network'], queryFn: getScanNetwork, refetchInterval: 10_000 })
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
