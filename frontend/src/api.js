import axios from 'axios'

const BASE = 'http://localhost:5000/api'

const getHeaders = () => ({
  Authorization: `Bearer ${localStorage.getItem('token')}`
})

// ── Existing API ──────────────────────────────────────────
export const login    = (u, p) => axios.post(`${BASE}/login`, { username: u, password: p })
export const getStats   = ()  => axios.get(`${BASE}/stats`,   { headers: getHeaders() })
export const getThreats = ()  => axios.get(`${BASE}/threats`, { headers: getHeaders() })
export const getSHAP    = ()  => axios.get(`${BASE}/shap`,    { headers: getHeaders() })
export const predict    = (f) => axios.post(`${BASE}/predict`, { features: f }, { headers: getHeaders() })
export const getAuditLogs = () => axios.get(`${BASE}/audit-log`, { headers: getHeaders() })
export const getNetworkAuditLogs = (limit = 500) =>
  axios.get(`${BASE}/network/audit-log`, { params: { limit }, headers: getHeaders() })

export const uploadScan = (file) => {
  const form = new FormData()
  form.append('file', file)
  return axios.post(`${BASE}/upload-scan`, form, {
    headers: { ...getHeaders(), 'Content-Type': 'multipart/form-data' }
  })
}

export const exportThreatsCSV = () => {
  const a = document.createElement('a')
  a.href = `${BASE}/threats/export/csv`
  const token = localStorage.getItem('token')
  fetch(`${BASE}/threats/export/csv`, { headers: { Authorization: `Bearer ${token}` } })
    .then(r => r.blob())
    .then(blob => {
      const url = URL.createObjectURL(blob)
      a.href = url
      a.download = `threats_${Date.now()}.csv`
      a.click()
      URL.revokeObjectURL(url)
    })
}

// ── New: Security Events ──────────────────────────────────
export const getSecurityEvents = (params = {}) =>
  axios.get(`${BASE}/events`, { params, headers: getHeaders() })

// ── New: Incidents ────────────────────────────────────────
export const getIncidents = (params = {}) =>
  axios.get(`${BASE}/incidents`, { params, headers: getHeaders() })
export const getIncident = (id) =>
  axios.get(`${BASE}/incidents/${id}`, { headers: getHeaders() })
export const investigateIncident = (id) =>
  axios.get(`${BASE}/incidents/${id}/investigate`, { headers: getHeaders() })
export const getIncidentEvidence = (id) =>
  axios.get(`${BASE}/incidents/${id}/evidence`, { headers: getHeaders() })
export const replayIncident = (id) =>
  axios.get(`${BASE}/incidents/${id}/replay`, { headers: getHeaders() })
export const getAttackGraph = (id) =>
  axios.get(`${BASE}/incidents/${id}/attack-graph`, { headers: getHeaders() })

// ── New: Honeypot ─────────────────────────────────────────
export const getHoneypotFiles    = () => axios.get(`${BASE}/honeypot/files`,    { headers: getHeaders() })
export const getHoneypotTriggers = () => axios.get(`${BASE}/honeypot/triggers`, { headers: getHeaders() })
export const getHoneypotStatus   = () => axios.get(`${BASE}/honeypot/status`,   { headers: getHeaders() })

// ── New: Geolocation ──────────────────────────────────────
export const geolocateIP = (ip) =>
  axios.get(`${BASE}/geo/${encodeURIComponent(ip)}`, { headers: getHeaders() })

// ── New: Risk Score ───────────────────────────────────────
export const calculateRiskScore = (data) =>
  axios.post(`${BASE}/risk-score`, data, { headers: getHeaders() })

// ── New: Cyber Lab ────────────────────────────────────────
export const getLabMode   = ()       => axios.get(`${BASE}/lab/mode`,    { headers: getHeaders() })
export const setLabMode   = (enabled) => axios.post(`${BASE}/lab/mode`, { enabled }, { headers: getHeaders() })
export const getLabStatus = ()       => axios.get(`${BASE}/lab/status`,  { headers: getHeaders() })
export const startSimulation = (type) => axios.post(`${BASE}/lab/simulate`, { type }, { headers: getHeaders() })
export const stopSimulation  = ()    => axios.post(`${BASE}/lab/stop`,   {}, { headers: getHeaders() })
export const resetLab        = ()    => axios.post(`${BASE}/lab/reset`,  {}, { headers: getHeaders() })
export const getLabLogs = (scenarioId) =>
  axios.get(`${BASE}/lab/logs/${scenarioId}`, { headers: getHeaders() })

// ── New: Evidence ─────────────────────────────────────────
export const getEvidence       = ()           => axios.get(`${BASE}/evidence`, { headers: getHeaders() })
export const verifyEvidence    = (data)       => axios.post(`${BASE}/evidence/verify`, data, { headers: getHeaders() })