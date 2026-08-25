import axios from 'axios'
import mockDevices from '../mocks/devices.json'
import mockScanActivity from '../mocks/scan-activity.json'

export const USE_MOCKS = false

export const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8007/api/v1'

const http = axios.create({
  baseURL: API_BASE_URL,
})

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

export async function getDevices(filters = {}) {
  if (USE_MOCKS) {
    await delay(200)
    return mockDevices
  }
  const params = {}
  if (filters.status) params.status = filters.status
  if (filters.deviceType) params.type = filters.deviceType
  const { data } = await http.get('/devices', { params })
  return data.data
}

export async function getScanActivity(limit = 8) {
  if (USE_MOCKS) {
    await delay(200)
    return mockScanActivity
  }
  const { data } = await http.get('/scan/activity', { params: { limit } })
  return data.data
}

export async function getScanHistory() {
  const { data } = await http.get('/scan/history')
  return data.data
}

export async function getScanSessions() {
  const { data } = await http.get('/scan/sessions')
  return data.data
}

export async function getServices(filters = {}) {
  const params = {}
  if (filters.confidence) params.confidence = filters.confidence
  if (filters.enrichmentStatus) params.enrichment_status = filters.enrichmentStatus
  if (filters.port) params.port = filters.port
  if (filters.query) params.q = filters.query
  const { data } = await http.get('/services', { params })
  return data.data
}

export async function getServicesSummary() {
  const { data } = await http.get('/services/summary')
  return data.data
}

export async function getFindings(filters = {}) {
  const params = {}
  if (filters.status) params.status = filters.status
  if (filters.severity) params.severity = filters.severity
  if (filters.confidence) params.confidence = filters.confidence
  if (filters.checkId) params.check_id = filters.checkId
  if (filters.query) params.q = filters.query
  const { data } = await http.get('/findings', { params })
  return data.data
}

export async function getFindingsSummary() {
  const { data } = await http.get('/findings/summary')
  return data.data
}

export async function updateFindingStatus({ findingId, status }) {
  const { data } = await http.patch(`/findings/${findingId}`, { status })
  return data.data
}

export async function getVulnerabilities(filters = {}) {
  const params = {}
  if (filters.status) params.status = filters.status
  if (filters.severity) params.severity = filters.severity
  if (filters.confidence) params.confidence = filters.confidence
  if (filters.query) params.q = filters.query
  const { data } = await http.get('/vulnerabilities', { params })
  return data.data
}

export async function getVulnerabilitiesSummary() {
  const { data } = await http.get('/vulnerabilities/summary')
  return data.data
}

export async function updateVulnerabilityStatus({ matchId, status }) {
  const { data } = await http.patch(`/vulnerabilities/${matchId}`, { status })
  return data.data
}

export async function getEnrichmentRuns() {
  const { data } = await http.get('/enrichment/runs', { params: { limit: 10 } })
  return data.data
}

export async function refreshEnrichment() {
  const { data } = await http.post('/enrichment/refresh')
  return data
}

export async function getScanNetwork() {
  const { data } = await http.get('/scan/network')
  return data.data
}

export async function startScanSession({ subnet, durationMinutes } = {}) {
  const body = {}
  if (subnet) body.subnet = subnet
  if (durationMinutes) body.durationMinutes = durationMinutes
  const { data } = await http.post('/scan/sessions', body)
  return data
}

export async function stopScanSession(id) {
  const { data } = await http.post(`/scan/sessions/${id}/stop`)
  return data
}

export async function resumeScanSession(id) {
  const { data } = await http.post(`/scan/sessions/${id}/resume`)
  return data
}
