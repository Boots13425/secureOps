import { useEffect } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { API_BASE_URL } from '../api/client'

function wsUrl() {
  const apiUrl = new URL(API_BASE_URL)
  const protocol = apiUrl.protocol === 'https:' ? 'wss:' : 'ws:'
  return `${protocol}//${apiUrl.host}/ws/events`
}

const RECONNECT_DELAY_MS = 3000

/**
 * Keeps the dashboard live: every session lifecycle change (started/
 * stopped/completed/failed) or individual scan tick — from the Dashboard
 * button, the always-on default session, or another browser tab entirely —
 * refetches the relevant data on every connected client immediately,
 * instead of waiting for a manual reload.
 */
export function useScanSocket() {
  const queryClient = useQueryClient()

  useEffect(() => {
    let socket
    let reconnectTimer

    function connect() {
      socket = new WebSocket(wsUrl())

      socket.onmessage = (event) => {
        let data
        try {
          data = JSON.parse(event.data)
        } catch {
          return
        }

        if (['SESSION_STARTED', 'SESSION_STOPPED', 'SESSION_COMPLETED', 'SESSION_FAILED'].includes(data.event)) {
          queryClient.invalidateQueries({ queryKey: ['scan-sessions'] })
          queryClient.invalidateQueries({ queryKey: ['scan-activity'] })
          queryClient.invalidateQueries({ queryKey: ['devices'] })
          queryClient.invalidateQueries({ queryKey: ['services'] })
          queryClient.invalidateQueries({ queryKey: ['services-summary'] })
          queryClient.invalidateQueries({ queryKey: ['findings'] })
          queryClient.invalidateQueries({ queryKey: ['findings-summary'] })
          queryClient.invalidateQueries({ queryKey: ['vulnerabilities'] })
          queryClient.invalidateQueries({ queryKey: ['vulnerabilities-summary'] })
          queryClient.invalidateQueries({ queryKey: ['enrichment-runs'] })
        }

        if (data.event === 'SESSION_TICK') {
          queryClient.invalidateQueries({ queryKey: ['devices'] })
          queryClient.invalidateQueries({ queryKey: ['scan-history'] })
          queryClient.invalidateQueries({ queryKey: ['scan-sessions'] })
          queryClient.invalidateQueries({ queryKey: ['services'] })
          queryClient.invalidateQueries({ queryKey: ['services-summary'] })
          queryClient.invalidateQueries({ queryKey: ['findings'] })
          queryClient.invalidateQueries({ queryKey: ['findings-summary'] })
          queryClient.invalidateQueries({ queryKey: ['vulnerabilities'] })
          queryClient.invalidateQueries({ queryKey: ['vulnerabilities-summary'] })
          queryClient.invalidateQueries({ queryKey: ['enrichment-runs'] })
        }

        if (data.event === 'FINDING_UPDATED') {
          queryClient.invalidateQueries({ queryKey: ['findings'] })
          queryClient.invalidateQueries({ queryKey: ['findings-summary'] })
        }

        if (data.event === 'VULNERABILITY_UPDATED') {
          queryClient.invalidateQueries({ queryKey: ['vulnerabilities'] })
          queryClient.invalidateQueries({ queryKey: ['vulnerabilities-summary'] })
        }

        if (['EPSS_UPDATED', 'EPSS_FAILED'].includes(data.event)) {
          queryClient.invalidateQueries({ queryKey: ['epss-intelligence'] })
          queryClient.invalidateQueries({ queryKey: ['epss-summary'] })
          queryClient.invalidateQueries({ queryKey: ['epss-runs'] })
          queryClient.invalidateQueries({ queryKey: ['vulnerabilities'] })
        }
      }

      socket.onclose = () => {
        reconnectTimer = setTimeout(connect, RECONNECT_DELAY_MS)
      }

      socket.onerror = () => {
        socket.close()
      }
    }

    connect()

    return () => {
      clearTimeout(reconnectTimer)
      if (socket) {
        socket.onclose = null
        // Closing a socket that's still CONNECTING (e.g. React StrictMode's
        // dev-only double-mount) logs a browser warning — wait for it to
        // open first, then close immediately.
        if (socket.readyState === WebSocket.CONNECTING) {
          socket.addEventListener('open', () => socket.close())
        } else {
          socket.close()
        }
      }
    }
  }, [queryClient])
}
