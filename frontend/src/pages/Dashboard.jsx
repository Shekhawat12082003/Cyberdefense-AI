import { useState, useEffect, useRef } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { io } from 'socket.io-client'
import {
  getStats, getThreats, getIncidents, getHoneypotStatus,
  getLabStatus, getSecurityEvents, getNetworkStats,
  getCaptureStatus,
  getVerifiedNetworkAlerts, getHoneypotTriggers, getHoneypotFiles,
  enrichIP, geolocateIP, getNetworkAuditLogs, getNetworkPackets, getNetworkConnections
} from '../api'
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, BarChart, Bar, PieChart, Pie, Cell, LineChart, Line } from 'recharts'
import ThreatIntelPanel from '../components/ThreatIntelPanel'
import WorkspaceSwitcher from '../components/WorkspaceSwitcher'

// ── Design tokens ──────────────────────────────────────────
const C = {
  bg: '#000010', card: '#05051a', border: '#00d4ff22',
  red: '#ff003c', orange: '#ff8c00', green: '#00ff88',
  blue: '#00d4ff', purple: '#a78bfa', yellow: '#ffe600',
  muted: '#444', dim: '#1a1a2e', text: '#ccc',
}
const SEV = { CRITICAL: C.red, HIGH: C.orange, MODERATE: C.yellow, LOW: C.green, MEDIUM: C.orange }
const m   = (sz = 12, c = C.text) => ({ fontFamily: 'monospace', fontSize: sz, color: c })
const cardStyle = (extra = {}) => ({
  background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, padding: 20, ...extra,
})
const sLabel = { ...m(9, C.muted), letterSpacing: 3, marginBottom: 12, textTransform: 'uppercase' }
const packetGridColumns = '54px minmax(190px, 1fr) minmax(190px, 1fr) 65px 58px 96px minmax(180px, 1.2fr)'

const formatEndpoint = (ip, port) => {
  if (!ip || ip === '—') return '—'
  const address = String(ip)
  if (port === undefined || port === null || port === '') return address
  return address.includes(':') ? `[${address}]:${port}` : `${address}:${port}`
}

const stripEndpointPort = (endpoint, port) => {
  if (!endpoint) return undefined
  const value = String(endpoint)
  if (value.startsWith('[')) {
    const closingBracket = value.indexOf(']')
    return closingBracket >= 0 ? value.slice(1, closingBracket) : value
  }
  if (port !== undefined && port !== null && port !== '') {
    const suffix = `:${port}`
    if (value.endsWith(suffix)) return value.slice(0, -suffix.length)
  }
  return value
}

// ── Status dot ─────────────────────────────────────────────
const Dot = ({ ok, pulse }) => (
  <span style={{
    display: 'inline-block', width: 8, height: 8, borderRadius: '50%', flexShrink: 0,
    background: ok ? C.green : C.red, boxShadow: `0 0 6px ${ok ? C.green : C.red}`,
    animation: pulse ? 'pulse 1.4s infinite' : 'none',
  }} />
)

// ── Metric Card ─────────────────────────────────────────────
const MetricCard = ({ label, value, change, color = C.blue, icon }) => (
  <div style={cardStyle({ textAlign: 'center' })}>
    <div style={{ fontSize: 20, marginBottom: 6 }}>{icon}</div>
    <div style={{ ...m(28, color), fontWeight: 'bold', lineHeight: 1, marginBottom: 8 }}>{value}</div>
    <div style={{ ...m(9, C.muted), letterSpacing: 2, marginBottom: 4 }}>{label}</div>
    {change !== undefined && (
      <div style={{ ...m(8, change >= 0 ? C.green : C.red) }}>
        {change >= 0 ? '↑' : '↓'} {Math.abs(change)}% from yesterday
      </div>
    )}
  </div>
)

// ── Network Flow Row ───────────────────────────────────────
const NetworkFlowRow = ({ flow, onClick }) => {
  const isSuspicious = flow.risk_score > 50 || flow.isSuspicious
  const color = isSuspicious ? C.orange : C.green
  const srcIP = flow.src_ip || flow.remote_ip || '—'
  const srcPort = flow.src_port || flow.remote_port || '—'
  const dstIP = flow.dst_ip || stripEndpointPort(flow.local, flow.local_port) || '—'
  const dstPort = flow.dst_port || flow.local_port || '—'
  const protocol = flow.protocol || flow.proto || 'TCP'
  const number = flow.number || '—'
  const status = flow.status || 'UNKNOWN'
  const timestamp = flow.timestamp ? new Date(flow.timestamp).toLocaleTimeString() : '—'
  const displayTime = flow.relative_time !== undefined
    ? Number(flow.relative_time).toFixed(6)
    : timestamp
  const info = flow.info || ''

  // Wireshark-like fields
  const flags = flow.flags || '—'
  const length = flow.length || flow.bytes || 0
  const direction = flow.direction || '—'
  const source = formatEndpoint(srcIP, srcPort)
  const destination = formatEndpoint(dstIP, dstPort)
  const infoText = info || (flags !== '—' ? flags : '') ||
    (status !== 'ACTIVE' && status !== 'UNKNOWN' ? status : `${protocol} datagram`)

  return (
    <div
      onClick={() => onClick && onClick(flow)}
      style={{
        display: 'grid', gridTemplateColumns: packetGridColumns, minWidth: 900,
        gap: 10, padding: '9px 12px', borderBottom: '1px solid #111',
        cursor: onClick ? (isSuspicious ? 'pointer' : 'default') : 'default',
        background: isSuspicious ? '#1a0a00' : 'transparent',
        fontSize: 11,
      }}
    >
      <div style={m(10, C.muted)}>{number}</div>
      <div title={source} style={{ ...m(10, C.blue), minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{source}</div>
      <div title={destination} style={{ ...m(10, C.green), minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>→ {destination}</div>
      <div style={{ ...m(10, C.muted), overflow: 'hidden', textOverflow: 'ellipsis' }}>{protocol}</div>
      <div style={m(10, C.muted)}>{length}</div>
      <div style={m(10, C.muted)}>{displayTime}</div>
      <div style={{ ...m(10, color), overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
        {`${infoText}${direction !== '—' ? ` · ${direction}` : ''}`}
      </div>
    </div>
  )
}

const mapNetworkConnection = (connection) => ({
  ...connection,
  src_ip: connection.src_ip || connection.remote_ip || stripEndpointPort(connection.remote, connection.remote_port),
  src_port: connection.src_port || connection.remote_port,
  dst_ip: connection.dst_ip || stripEndpointPort(connection.local, connection.local_port),
  dst_port: connection.dst_port || connection.local_port,
  protocol: connection.protocol || 'TCP',
  timestamp: connection.timestamp || new Date().toISOString(),
  status: connection.status || 'ACTIVE',
  direction: connection.direction || '—',
})

// ── Alert Row ─────────────────────────────────────────────
const AlertRow = ({ alert, onClick }) => {
  const severity = alert.severity || 'MEDIUM'
  const color = SEV[severity] || C.orange
  return (
    <div
      onClick={() => onClick && onClick(alert)}
      style={{
        display: 'grid', gridTemplateColumns: '100px 140px 140px 120px 80px 80px 100px',
        gap: 10, padding: '10px 14px', borderBottom: '1px solid #111',
        cursor: onClick ? 'pointer' : 'default',
        background: severity === 'CRITICAL' ? '#1a0000' : 'transparent',
      }}
    >
      <div style={{ padding: '2px 8px', background: color + '22', border: `1px solid ${color}`, borderRadius: 4, ...m(9, color), fontWeight: 'bold', textAlign: 'center' }}>{severity}</div>
      <div style={m(10, C.blue)}>{alert.attack_type || alert.type || 'Unknown'}</div>
      <div style={m(10, C.text)}>{alert.attacker_ip || alert.src_ip || 'Unknown'}</div>
      <div style={m(10, C.green)}>{alert.target_ip || alert.dst_ip || 'Unknown'}</div>
      <div style={m(10, C.muted)}>{alert.target_port || alert.port || '-'}</div>
      <div style={{ ...m(10, color), fontWeight: 'bold' }}>{alert.confidence || 0}%</div>
      <div style={m(9, '#666')}>{new Date(alert.timestamp).toLocaleTimeString()}</div>
    </div>
  )
}

// ── Attacker Profile ───────────────────────────────────────
const AttackerProfile = ({ ip, intel, loading, error, onClose, onRetry }) => {
  if (!ip) return null
  const geo = intel?.geo || {}
  const abuse = intel?.abuse || {}
  const shodan = intel?.shodan || {}

  return (
    <div style={{
      position: 'fixed', top: 0, right: 0, bottom: 0, width: 420,
      background: C.card, borderLeft: `2px solid ${C.blue}`,
      zIndex: 1000, overflow: 'auto', padding: 20,
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
        <h3 style={{ ...m(16, C.blue), margin: 0 }}>ATTACKER PROFILE</h3>
        <button onClick={onClose} style={{ background: 'transparent', border: 'none', color: C.muted, fontSize: 20, cursor: 'pointer' }}>✕</button>
      </div>

      <div style={cardStyle({ marginBottom: 16 })}>
        <div style={sLabel}>IDENTITY</div>
        <div style={{ marginBottom: 8 }}>
          <span style={m(9, C.muted)}>IP ADDRESS</span>
          <div style={{ ...m(14, C.blue), fontWeight: 'bold' }}>{ip}</div>
        </div>
        {geo.hostname && (
          <div style={{ marginBottom: 8 }}>
            <span style={m(9, C.muted)}>HOSTNAME</span>
            <div style={m(11, C.text)}>{geo.hostname}</div>
          </div>
        )}
      </div>

      <div style={cardStyle({ marginBottom: 16 })}>
        <div style={sLabel}>GEOLOCATION</div>
        {loading ? (
          <div style={m(11, C.blue)}>Looking up IP location…</div>
        ) : geo.type === 'private' ? (
          <div style={m(12, C.blue)}>LOCAL NETWORK — public geolocation is not applicable</div>
        ) : geo.type === 'unknown' || !geo.type ? (
          <div style={{ ...m(11, C.orange), lineHeight: 1.6 }}>
            <div>{error || geo.note || 'Geolocation lookup unavailable.'}</div>
            <button onClick={onRetry} style={{ marginTop: 10, padding: '6px 10px', background: 'transparent', border: `1px solid ${C.orange}`, borderRadius: 4, ...m(10, C.orange), cursor: 'pointer' }}>
              RETRY LOOKUP
            </button>
          </div>
        ) : (
          <>
            <div style={{ marginBottom: 8 }}>
              <span style={m(9, C.muted)}>COUNTRY</span>
              <div style={m(11, C.text)}>{geo.country_name || geo.country || 'Unknown'}</div>
            </div>
            <div style={{ marginBottom: 8 }}>
              <span style={m(9, C.muted)}>CITY</span>
              <div style={m(11, C.text)}>{geo.city || 'Unknown'}</div>
            </div>
            <div style={{ marginBottom: 8 }}>
              <span style={m(9, C.muted)}>REGION</span>
              <div style={m(11, C.text)}>{geo.region || 'Unknown'}</div>
            </div>
            <div style={{ marginBottom: 8 }}>
              <span style={m(9, C.muted)}>COORDINATES</span>
              <div style={m(11, C.text)}>{geo.lat != null && geo.lon != null ? `${geo.lat}, ${geo.lon}` : 'Not provided'}</div>
            </div>
            <div style={{ marginBottom: 8 }}>
              <span style={m(9, C.muted)}>TIMEZONE</span>
              <div style={m(11, C.text)}>{geo.timezone || 'Unknown'}</div>
            </div>
            {geo.note && <div style={{ ...m(9, C.muted), lineHeight: 1.5 }}>{geo.note}</div>}
          </>
        )}
      </div>

      <div style={cardStyle({ marginBottom: 16 })}>
        <div style={sLabel}>NETWORK INFO</div>
        <div style={{ marginBottom: 8 }}>
          <span style={m(9, C.muted)}>ISP</span>
          <div style={m(11, C.text)}>{geo.isp || abuse.isp || 'Unknown'}</div>
        </div>
        <div style={{ marginBottom: 8 }}>
          <span style={m(9, C.muted)}>ASN</span>
          <div style={m(11, C.text)}>{geo.asn || abuse.asn || 'Unknown'}</div>
        </div>
        <div style={{ marginBottom: 8 }}>
          <span style={m(9, C.muted)}>ORGANIZATION</span>
          <div style={m(11, C.text)}>{geo.org || abuse.org || 'Unknown'}</div>
        </div>
      </div>

      {abuse.confidence_score !== undefined && (
        <div style={cardStyle({ marginBottom: 16 })}>
          <div style={sLabel}>REPUTATION</div>
          <div style={{ marginBottom: 8 }}>
            <span style={m(9, C.muted)}>ABUSE CONFIDENCE</span>
            <div style={{ ...m(14, abuse.confidence_score > 50 ? C.red : C.green), fontWeight: 'bold' }}>{abuse.confidence_score}%</div>
          </div>
          <div style={{ marginBottom: 8 }}>
            <span style={m(9, C.muted)}>REPORTS</span>
            <div style={m(11, C.text)}>{abuse.total_reports || 0}</div>
          </div>
          <div style={{ marginBottom: 8 }}>
            <span style={m(9, C.muted)}>LAST REPORTED</span>
            <div style={m(11, C.text)}>{abuse.last_reported || 'Never'}</div>
          </div>
        </div>
      )}

      {shodan.open_ports && shodan.open_ports.length > 0 && (
        <div style={cardStyle({ marginBottom: 16 })}>
          <div style={sLabel}>OPEN PORTS</div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
            {shodan.open_ports.map(p => (
              <span key={p} style={{ padding: '3px 8px', background: '#0a0a1a', border: '1px solid #1a1a2e', borderRadius: 4, ...m(10, C.muted) }}>{p}</span>
            ))}
          </div>
        </div>
      )}

      {shodan.vulns && shodan.vulns.length > 0 && (
        <div style={cardStyle({ marginBottom: 16 })}>
          <div style={sLabel}>VULNERABILITIES</div>
          {shodan.vulns.slice(0, 5).map(v => (
            <div key={v} style={{ padding: '6px 10px', background: '#1a0000', border: '1px solid #330000', borderRadius: 4, marginBottom: 6, ...m(10, C.red) }}>{v}</div>
          ))}
        </div>
      )}
    </div>
  )
}

// ── MAIN DASHBOARD - SINGLE PAGE SOC INTERFACE ─────────────
export default function Dashboard() {
  const [stats, setStats] = useState(null)
  const [threats, setThreats] = useState([])
  const [incidents, setIncidents] = useState([])
  const [hpStatus, setHpStatus] = useState(null)
  const [labStatus, setLabStatus] = useState(null)
  const [secEvents, setSecEvents] = useState([])
  const [liveIncident, setLiveIncident] = useState(null)
  const [liveAlerts, setLiveAlerts] = useState([])
  const [loading, setLoading] = useState(true)
  const [networkStats, setNetworkStats] = useState(null)
  const [networkAlerts, setNetworkAlerts] = useState([])
  const [hpTriggers, setHpTriggers] = useState([])
  const [hpHitsToday, setHpHitsToday] = useState(0)
  const [hpFiles, setHpFiles] = useState([])
  const [connections, setConnections] = useState([])
  const [packets, setPackets] = useState([])
  const [selectedAttackerIP, setSelectedAttackerIP] = useState(null)
  const [attackerIntel, setAttackerIntel] = useState(null)
  const [attackerIntelLoading, setAttackerIntelLoading] = useState(false)
  const [attackerIntelError, setAttackerIntelError] = useState('')
  const [attackerIntelRetry, setAttackerIntelRetry] = useState(0)
  const [networkAuditLogs, setNetworkAuditLogs] = useState([])

  const navigate = useNavigate()
  const socketRef = useRef(null)
  const dataLoadRef = useRef(false)
  const networkLoadRef = useRef(false)
  const captureModeRef = useRef(null)

  const role = localStorage.getItem('role')
  const username = localStorage.getItem('user')
  const isAdmin = role === 'admin'
  const logout = () => { localStorage.clear(); navigate('/login', { replace: true }) }

  // ── Load Data ─────────────────────────────────────────────
  const loadData = async () => {
    if (dataLoadRef.current) return
    dataLoadRef.current = true
    console.log('[Dashboard] Starting data load...')
    try {
      const request = (promise, fallback, label) => promise.catch(error => {
        if (error?.response?.status === 401) throw error
        console.error(`${label} error:`, error)
        return { data: fallback }
      })
      const [
        statsRes, threatsRes, incidentsRes, hpRes, labRes, eventsRes,
        netStatsRes, captureRes, netAlertsRes, hpTriggersRes, hpFilesRes, auditRes,
      ] = await Promise.all([
        request(getStats(), {}, 'Stats'),
        request(getThreats(), [], 'Threats'),
        request(getIncidents(), { incidents: [] }, 'Incidents'),
        request(getHoneypotStatus(), {}, 'Honeypot status'),
        request(getLabStatus(), {}, 'Lab status'),
        request(getSecurityEvents(), { events: [] }, 'Events'),
        request(getNetworkStats(), {}, 'Network stats'),
        request(getCaptureStatus(), {}, 'Capture status'),
        request(getVerifiedNetworkAlerts(), { alerts: [] }, 'Verified network alerts'),
        request(getHoneypotTriggers(), { triggers: [] }, 'Honeypot triggers'),
        request(getHoneypotFiles(), { files: [] }, 'Honeypot files'),
        request(getNetworkAuditLogs(100), { logs: [] }, 'Network audit'),
      ])

      setStats(statsRes.data)
      // threats API returns array directly, not wrapped in { threats: [] }
      setThreats(Array.isArray(threatsRes.data) ? threatsRes.data : (threatsRes.data.threats || []))
      setIncidents(incidentsRes.data.incidents || [])
      setHpStatus(hpRes.data)
      setLabStatus(labRes.data)
      setSecEvents(eventsRes.data.events || [])
      const nextNetworkStats = {
        ...netStatsRes.data,
        capture_mode: captureRes.data.is_capturing ? 'tshark' : netStatsRes.data.capture_mode,
        packets_captured: captureRes.data.packets_captured ?? netStatsRes.data.packets_captured,
      }
      captureModeRef.current = nextNetworkStats.capture_mode
      setNetworkStats(nextNetworkStats)
      setNetworkAlerts((netAlertsRes.data.alerts || []).filter(alert =>
        alert.is_verified === true && alert.verification === 'trained_network_ids'
      ))
      setHpTriggers(hpTriggersRes.data.triggers || [])
      setHpHitsToday(Number(hpTriggersRes.data.verified_hits_today || 0))
      setHpFiles(hpFilesRes.data.files || [])
      setNetworkAuditLogs(auditRes.data.logs || [])
    } catch (e) {
      console.error('Failed to load dashboard data:', e)
      console.error('Error response:', e?.response?.data)
      console.error('Error message:', e?.message)
      // If unauthorized, clear storage and redirect to login
      if (e?.response?.status === 401) {
        localStorage.clear()
        navigate('/login', { replace: true })
        return
      }
      console.error('[Dashboard] Data refresh failed')
    } finally {
      setLoading(false)
      dataLoadRef.current = false
    }
  }

  // ── Load network data ─────────────────────────────────────
  const loadNetworkData = async () => {
    if (networkLoadRef.current) return
    if (captureModeRef.current === 'tshark') return
    networkLoadRef.current = true
    try {
      let hasPacketCapture = false
      // Load packets for Wireshark-like detailed view
      const packRes = await getNetworkPackets()
      const packData = packRes.data
      // Map packet data to connection format
      const mappedPackets = (packData.packets || []).map(pkt => ({
          src_ip: pkt.src_ip || '—',
          src_port: pkt.src_port || 0,
          dst_ip: pkt.dst_ip || '—',
          dst_port: pkt.dst_port || 0,
          protocol: pkt.protocol || pkt.proto || 'TCP',
          number: pkt.number || '',
          relative_time: pkt.relative_time,
          flags: pkt.flags || '—',
          length: pkt.length || 0,
          bytes: pkt.length || 0,
          ttl: pkt.ttl || '—',
          window: pkt.window || '—',
          seq: pkt.seq || '—',
          ack: pkt.ack || '—',
          status: pkt.flags ? pkt.flags.split('|')[0] : 'ACTIVE',
          timestamp: pkt.time || new Date().toISOString(),
          risk_score: 0,
          direction: pkt.direction || 'IN',
          info: pkt.info || '',
      }))
      if (mappedPackets.length > 0) {
        hasPacketCapture = true
        setConnections(mappedPackets)
        setPackets(packData.packets.slice(0, 500))
      }

      // Also load connections for stats
      const connRes = await getNetworkConnections()
      const connData = connRes.data
      const liveConnections = (connData.connections || []).map(mapNetworkConnection)
      // Packet capture requires elevated access; use the psutil connection
      // stream as the live view when packet capture is unavailable.
      if (!hasPacketCapture) setConnections(liveConnections)
    } catch (e) {
      console.error('Failed to load network data:', e)
      // Don't let network data errors block the dashboard
    } finally {
      networkLoadRef.current = false
    }
  }

  // ── WebSocket ─────────────────────────────────────────
  useEffect(() => {
    const socket = io('http://localhost:5000', {
      transports: ['polling'],
      upgrade: false,
      reconnection: true,
      reconnectionAttempts: Infinity,
      reconnectionDelay: 1000,
      reconnectionDelayMax: 5000,
      timeout: 10000,
    })
    socketRef.current = socket

    socket.on('live_incident', (data) => {
      const isSimulation = Boolean(data.scenario_id)
      if (!isSimulation && (data.is_verified !== true || data.verification !== 'trained_network_ids')) return
      setLiveIncident(data)
      const ts = new Date().toLocaleTimeString()
      const col = SEV[data.severity] || C.orange
      setLiveAlerts(prev => [{
        ts, msg: `${isSimulation ? 'SIMULATION · ' : ''}${data.attack_type?.replace(/_/g, ' ')} — Risk ${Math.round(data.risk_score || 0)}/100`,
        col, src: (data.attacker || {}).ip || '',
        geo: ((data.attacker || {}).geo || {}).city ? `${(data.attacker.geo).city}, ${(data.attacker.geo).country}` : '',
      }, ...prev.slice(0, 14)])
      loadData()
    })

    socket.on('network_alert', (data) => {
      const isVerified = data.is_verified === true && data.verification === 'trained_network_ids'
      if (!isVerified && !data.scenario_id) return
      if (!isVerified) {
        const ts = new Date().toLocaleTimeString()
        setLiveAlerts(prev => [{
          ts,
          msg: `SIMULATION · ${data.description || data.type || 'Network event'}`,
          col: SEV[data.severity] || C.orange,
          src: data.ip || '',
          geo: '',
        }, ...prev.slice(0, 14)])
        return
      }
      setNetworkAlerts(prev => {
        if (prev.some(alert => alert.id && alert.id === data.id)) return prev
        return [data, ...prev].slice(0, 1000)
      })
      const ts = new Date().toLocaleTimeString()
      const col = SEV[data.severity] || C.orange
      setLiveAlerts(prev => [{ ts, msg: data.description || data.type || 'Network alert', col, src: data.ip || '', geo: '' }, ...prev.slice(0, 14)])
    })

    socket.on('network_update', (data) => {
      const legacyCaptureMode = data.stats?.capture_mode === 'raw_socket+psutil'
      if (data.stats) {
        const previousCaptureMode = captureModeRef.current
        const incomingCaptureMode = data.stats.capture_mode
        const nextCaptureMode = legacyCaptureMode && previousCaptureMode === 'tshark'
          ? 'tshark'
          : (incomingCaptureMode || previousCaptureMode)
        captureModeRef.current = nextCaptureMode
        setNetworkStats(prev => {
          const preserveTSharkCount = legacyCaptureMode && nextCaptureMode === 'tshark'
          return {
            ...prev,
            ...data.stats,
            capture_mode: nextCaptureMode,
            packets_captured: preserveTSharkCount
              ? prev?.packets_captured
              : data.stats.packets_captured ?? prev?.packets_captured,
          }
        })
      }
      // The legacy monitor emits the same rolling packet snapshot repeatedly.
      // While TShark is active, only accept its bounded batches.
      if (!legacyCaptureMode && Array.isArray(data.packets) && data.packets.length > 0) {
        setPackets(prev => {
          const seen = new Set()
          return [...data.packets, ...prev]
            .filter(packet => {
              const key = `${packet.number || ''}:${packet.time || ''}:${packet.src_ip || ''}:${packet.dst_ip || ''}`
              if (seen.has(key)) return false
              seen.add(key)
              return true
            })
            .slice(0, 2000)
        })
        setConnections(prev => [...data.packets.map(mapNetworkConnection), ...prev].slice(0, 100))
      } else if (captureModeRef.current !== 'tshark' && !legacyCaptureMode && Array.isArray(data.connections)) {
        setConnections(data.connections.map(mapNetworkConnection))
      }
    })

    socket.on('honeypot_triggered', (entry) => {
      const ts = new Date().toLocaleTimeString()
      setLiveAlerts(prev => [{ ts, msg: `🍯 HONEYPOT: ${entry.resource} — ${entry.process_name || '?'}`, col: C.red, src: entry.source_ip || '', geo: '' }, ...prev.slice(0, 14)])
      setLiveIncident(prev => prev ? { ...prev, honeypot: { triggered: true, resource: entry.resource }, status: { ...prev.status, honeypot: true } } : prev)
      loadData()
    })

    socket.on('security_event', (ev) => {
      if (ev.severity === 'CRITICAL' || ev.severity === 'HIGH') {
        const ts = new Date().toLocaleTimeString()
        setLiveAlerts(prev => [{ ts, msg: ev.description || ev.event_type || 'Event', col: SEV[ev.severity] || C.orange, src: (ev.source || {}).ip || '', geo: '' }, ...prev.slice(0, 14)])
      }
      setSecEvents(prev => [ev, ...prev.slice(0, 49)])
    })

    socket.on('incident_created', () => loadData())
    socket.on('incident_updated', () => loadData())
    socket.on('file_scanned', () => loadData())

    return () => socket.disconnect()
  }, [])

  // ── Load attacker intel ───────────────────────────────────
  useEffect(() => {
    if (!selectedAttackerIP) return undefined
    let cancelled = false
    setAttackerIntel(null)
    setAttackerIntelError('')
    setAttackerIntelLoading(true)
    Promise.allSettled([geolocateIP(selectedAttackerIP), enrichIP(selectedAttackerIP)])
      .then(([geoResult, intelResult]) => {
        if (cancelled) return
        const nextIntel = {}
        if (geoResult.status === 'fulfilled') {
          nextIntel.geo = geoResult.value.data.geo
        } else {
          console.error('Geolocation lookup failed:', geoResult.reason)
          setAttackerIntelError('Geolocation request failed. Check the backend connection and retry.')
        }
        if (intelResult.status === 'fulfilled') {
          nextIntel.abuse = intelResult.value.data.abuseipdb
          nextIntel.shodan = intelResult.value.data.shodan
        } else {
          console.error('Threat intelligence lookup failed:', intelResult.reason)
        }
        setAttackerIntel(nextIntel)
      })
      .finally(() => {
        if (!cancelled) setAttackerIntelLoading(false)
      })
    return () => { cancelled = true }
  }, [selectedAttackerIP, attackerIntelRetry])

  // ── Initial load ─────────────────────────────────────────
  useEffect(() => {
    loadData()
    loadNetworkData()
    const interval = setInterval(() => {
      loadData()
      loadNetworkData()
    }, 10000)
    return () => clearInterval(interval)
  }, [])

  // ── Analytics Data ───────────────────────────────────────
  const attackTypes = {}
  incidents.forEach(i => {
    const type = i.attack_type || 'Unknown'
    attackTypes[type] = (attackTypes[type] || 0) + 1
  })
  const attackData = Object.entries(attackTypes).map(([name, value]) => ({ name, value }))

  const protocolRows = connections.reduce((counts, connection) => {
    const protocol = String(connection.protocol || connection.proto || 'OTHER').toUpperCase()
    const key = ['TCP', 'UDP', 'ICMP'].includes(protocol) ? protocol : 'Other'
    counts[key] = (counts[key] || 0) + 1
    return counts
  }, {})
  const protocolData = ['TCP', 'UDP', 'ICMP', 'Other']
    .map(name => ({ name, value: protocolRows[name] || 0 }))
    .filter(item => item.value > 0)
  const portCounts = connections.reduce((counts, connection) => {
    const port = connection.dst_port || connection.local_port || connection.remote_port
    if (port !== undefined && port !== null && String(port) !== '') {
      const key = String(port)
      counts[key] = (counts[key] || 0) + 1
    }
    return counts
  }, {})
  const topPorts = Object.entries(portCounts)
    .map(([port, count]) => ({ port, count }))
    .sort((a, b) => b.count - a.count)
  const localIP = String(networkStats?.local_ip || '').split('%', 1)[0]
  const verifiedLiveAlerts = networkAlerts.filter(alert => {
    if (alert.is_verified !== true || alert.verification !== 'trained_network_ids') return false
    const sourceIP = String(alert.attacker_ip || alert.src_ip || alert.ip || '').split('%', 1)[0].trim()
    const normalizedIP = sourceIP.toLowerCase()
    const isLoopback = normalizedIP === '::1' || normalizedIP === 'localhost' ||
      normalizedIP.startsWith('127.') || normalizedIP.startsWith('::ffff:127.')
    return sourceIP && normalizedIP !== 'unknown' && !isLoopback &&
      normalizedIP !== localIP.toLowerCase() && !alert.scenario_id
  })
  const attackers = [...new Set(verifiedLiveAlerts.map(a => a.attacker_ip || a.src_ip || a.ip).filter(Boolean))]
  const today = new Date().toDateString()
  const attacksToday = verifiedLiveAlerts.filter(alert => {
    const timestamp = alert.timestamp || alert.created_at
    return timestamp && new Date(timestamp).toDateString() === today
  }).length

  return (
    <div style={{ minHeight: '100vh', background: C.bg, padding: 20, fontFamily: 'monospace' }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
        <div>
          <h1 style={{ ...m(24, C.blue), margin: 0, letterSpacing: 2 }}>CYBERDEFENSE SOC</h1>
          <div style={{ ...m(11, C.muted), marginTop: 4 }}>Security Operations Center Dashboard</div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <Dot ok={true} pulse />
            <span style={m(11, C.green)}>SYSTEM ONLINE</span>
          </div>
          <span style={m(11, C.muted)}>|</span>
          <span style={m(11, C.text)}>{username}</span>
          <button onClick={logout} style={{ padding: '6px 12px', background: C.red + '22', border: `1px solid ${C.red}`, borderRadius: 4, ...m(10, C.red), cursor: 'pointer' }}>
            LOGOUT
          </button>
        </div>
      </div>
      <WorkspaceSwitcher />
      <div style={{ display: 'flex', gap: 8, marginBottom: 18 }}>
        <Link
          to="/ransomware-history"
          style={{ padding: '7px 12px', border: `1px solid ${C.red}`, borderRadius: 4, ...m(10, C.red), textDecoration: 'none' }}
        >
          🧬 RANSOMWARE HISTORY
        </Link>
        <Link
          to="/ransomware"
          style={{ padding: '7px 12px', border: `1px solid ${C.blue}`, borderRadius: 4, ...m(10, C.blue), textDecoration: 'none' }}
        >
          OPEN RANSOMWARE CENTER
        </Link>
      </div>

      {loading ? (
        <div style={{ textAlign: 'center', padding: 60, ...m(14, C.muted) }}>Loading SOC data...</div>
      ) : (
        <>
          {/* Overview Metrics */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16, marginBottom: 24 }}>
            <MetricCard label="ACTIVE CONNECTIONS" value={networkStats?.total_connections || connections.length || 0} color={C.blue} icon="🌐" />
            <MetricCard label="ACTIVE THREATS" value={threats.filter(t => t.status === 'quarantined').length || 0} color={C.red} icon="🚨" />
            <MetricCard label="CRITICAL ALERTS" value={verifiedLiveAlerts.filter(a => a.severity === 'CRITICAL').length} color={C.orange} icon="⚠️" />
            <MetricCard label="UNIQUE ATTACKERS" value={new Set(verifiedLiveAlerts.map(a => a.attacker_ip || a.src_ip || a.ip)).size} color={C.purple} icon="👤" />
            <MetricCard label="VERIFIED HONEYPOT HITS TODAY" value={hpHitsToday} color={C.yellow} icon="🍯" />
            <MetricCard label="NETWORK ATTACKS TODAY" value={attacksToday} color={C.green} icon="📊" />
            <MetricCard label="RISK SCORE" value={stats?.avg_risk_score?.toFixed(0) || 0} color={stats?.avg_risk_score > 50 ? C.red : C.green} icon="📈" />
            <MetricCard label="PACKETS TODAY" value={networkStats?.packets_captured || 0} color={C.blue} icon="📦" />
          </div>

          {/* Live Alert Ticker */}
          {liveAlerts.length > 0 && (
            <div style={{
              background: '#0a0a1a', border: `1px solid ${C.border}`, borderRadius: 8,
              padding: '10px 16px', marginBottom: 24, overflow: 'hidden',
            }}>
              <div style={{ ...m(9, C.muted), marginBottom: 8, letterSpacing: 2 }}>LIVE ALERTS</div>
              <div style={{ maxHeight: 100, overflow: 'auto' }}>
                {liveAlerts.map((alert, i) => (
                  <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '4px 0', borderBottom: '1px solid #111' }}>
                    <span style={{ ...m(9, '#666'), minWidth: 60 }}>{alert.ts}</span>
                    <span style={{ ...m(10, alert.col), fontWeight: 'bold' }}>{alert.msg}</span>
                    {alert.src && <span style={m(9, C.blue)}>{alert.src}</span>}
                    {alert.geo && <span style={m(9, C.muted)}>{alert.geo}</span>}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Network Flows Section */}
          <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 16, marginBottom: 24 }}>
            <div style={cardStyle()}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
                <div style={sLabel}>📦 LIVE PACKET CAPTURE (WIREHARK-LIKE)</div>
                <div style={{ display: 'flex', gap: 8 }}>
                  <span style={m(10, C.green)}>{packets.length} Packets</span>
                  <span style={m(10, C.orange)}>{connections.filter(c => c.direction === 'IN').length} IN</span>
                  <span style={m(10, C.purple)}>{connections.filter(c => c.direction === 'OUT').length} OUT</span>
                </div>
              </div>
              {!['scapy', 'tshark'].includes(networkStats?.capture_mode) && (
                <div style={{ ...m(9, C.yellow), marginBottom: 10 }}>
                  Packet capture unavailable; showing live OS connections ({networkStats?.capture_mode || 'starting'}).
                  Run the backend as Administrator with Npcap for packet-level capture.
                </div>
              )}
              <div style={{ maxHeight: 340, overflow: 'auto' }}>
                <div style={{
                  position: 'sticky',
                  top: 0,
                  zIndex: 1,
                  borderBottom: '1px solid #222',
                  padding: '8px 12px',
                  display: 'grid',
                  gridTemplateColumns: packetGridColumns,
                  minWidth: 900,
                  gap: 10,
                  background: C.card,
                }}>
                  <span style={m(9, C.muted)}>NO.</span>
                  <span style={m(9, C.muted)}>SOURCE</span>
                  <span style={m(9, C.muted)}>DESTINATION</span>
                  <span style={m(9, C.muted)}>PROTO</span>
                  <span style={m(9, C.muted)}>LEN</span>
                  <span style={m(9, C.muted)}>TIME</span>
                  <span style={m(9, C.muted)}>INFO</span>
                </div>
                {connections.slice(0, 30).map((flow, i) => (
                  <NetworkFlowRow key={flow.number || `${flow.src_ip}-${flow.src_port}-${i}`} flow={flow} onClick={(f) => {
                    if (f.risk_score > 50 || f.isSuspicious) {
                      setSelectedAttackerIP(f.src_ip || f.remote_ip)
                    }
                  }} />
                ))}
              </div>
            </div>

            <div style={cardStyle()}>
              <div style={sLabel}>PROTOCOL STATS</div>
              <div style={{ height: 200 }}>
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={protocolData.length ? protocolData : [{ name: 'No traffic', value: 1 }]}
                      cx="50%" cy="50%" outerRadius={60} fill="#888" label
                    >
                      <Cell fill={C.blue} />
                      <Cell fill={C.green} />
                      <Cell fill={C.orange} />
                      <Cell fill={C.muted} />
                    </Pie>
                    <Tooltip />
                  </PieChart>
                </ResponsiveContainer>
              </div>

              <div style={{ ...sLabel, marginTop: 24 }}>TOP PORTS</div>
              <div style={{ maxHeight: 150, overflow: 'auto' }}>
                {topPorts.slice(0, 10).map((p, i) => (
                  <div key={i} style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', borderBottom: '1px solid #111' }}>
                    <span style={m(10, C.blue)}>{p.port}</span>
                    <span style={m(10, C.muted)}>{p.count} conns</span>
                  </div>
                ))}
                {topPorts.length === 0 && <div style={m(10, C.muted)}>No port data yet</div>}
              </div>
            </div>
          </div>

          {/* Security Alerts Section */}
          <div style={cardStyle({ marginBottom: 24 })}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
              <div style={sLabel}>VERIFIED LIVE NETWORK ALERTS</div>
              <div style={{ display: 'flex', gap: 8 }}>
                <span style={m(10, C.red)}>{verifiedLiveAlerts.filter(a => a.severity === 'CRITICAL').length} Critical</span>
                <span style={m(10, C.orange)}>{verifiedLiveAlerts.filter(a => a.severity === 'HIGH').length} High</span>
                <span style={m(10, C.yellow)}>{verifiedLiveAlerts.filter(a => a.severity === 'MEDIUM').length} Medium</span>
              </div>
            </div>
            <div style={{ borderBottom: '1px solid #222', paddingBottom: 8, marginBottom: 8, display: 'grid', gridTemplateColumns: '100px 140px 140px 120px 80px 80px 100px', gap: 10 }}>
              <span style={m(9, C.muted)}>SEVERITY</span>
              <span style={m(9, C.muted)}>ATTACK TYPE</span>
              <span style={m(9, C.muted)}>ATTACKER IP</span>
              <span style={m(9, C.muted)}>TARGET IP</span>
              <span style={m(9, C.muted)}>PORT</span>
              <span style={m(9, C.muted)}>CONFIDENCE</span>
              <span style={m(9, C.muted)}>TIME</span>
            </div>
            <div style={{ maxHeight: 300, overflow: 'auto' }}>
              {verifiedLiveAlerts.length === 0 ? (
                <div style={{ ...m(10, C.muted), padding: 24, textAlign: 'center' }}>
                  No verified live network alerts. Historical incidents remain available in Incident Management.
                </div>
              ) : verifiedLiveAlerts.slice(0, 30).map((alert, i) => {
                // Map backend alert format to frontend format
                const mappedAlert = {
                  severity: alert.severity || 'MEDIUM',
                  attack_type: alert.attack_type || alert.type || 'Unknown',
                  attacker_ip: alert.attacker_ip || alert.ip || alert.src_ip || 'Unknown',
                  target_ip: alert.target_ip || alert.dst_ip || alert.extra?.target_ip || 'Unknown',
                  target_port: alert.target_port || alert.port || alert.extra?.target_port || '-',
                  confidence: alert.confidence || 0,
                  timestamp: alert.timestamp || alert.created_at || new Date().toISOString(),
                }
                return <AlertRow key={i} alert={mappedAlert} onClick={(a) => setSelectedAttackerIP(a.attacker_ip)} />
              })}
            </div>
          </div>

          {/* Attacker Intelligence & Honeypot Section */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 24 }}>
            <div style={cardStyle()}>
              <div style={sLabel}>DETECTED ATTACKERS</div>
              <div style={{ maxHeight: 300, overflow: 'auto' }}>
                {attackers.map((ip, i) => (
                  <div
                    key={i}
                    onClick={() => setSelectedAttackerIP(ip)}
                    style={{
                      padding: '12px 16px', borderBottom: '1px solid #111',
                      cursor: 'pointer', display: 'flex', justifyContent: 'space-between',
                      alignItems: 'center',
                    }}
                  >
                    <div>
                      <div style={{ ...m(12, C.blue), fontWeight: 'bold' }}>{ip}</div>
                      <div style={m(9, C.muted)}>
                        {verifiedLiveAlerts.filter(a => (a.attacker_ip || a.src_ip || a.ip) === ip).length} verified alerts
                      </div>
                    </div>
                    <button style={{ padding: '6px 12px', background: C.blue + '22', border: `1px solid ${C.blue}`, borderRadius: 4, ...m(10, C.blue), cursor: 'pointer' }}>
                      VIEW PROFILE
                    </button>
                  </div>
                ))}
              </div>
            </div>

            <div style={cardStyle()}>
              <div style={sLabel}>HONEYPOT STATUS</div>
              {hpStatus ? (
                <div style={{ marginBottom: 16 }}>
                  <div style={{ marginBottom: 12 }}>
                    <span style={m(9, C.muted)}>STATUS</span>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 4 }}>
                      <Dot ok={hpStatus.active} pulse />
                      <span style={{ ...m(11, hpStatus.active ? C.green : C.red), fontWeight: 'bold' }}>
                        {hpStatus.active ? 'ACTIVE' : 'INACTIVE'}
                      </span>
                    </div>
                  </div>
                  <div style={{ marginBottom: 12 }}>
                    <span style={m(9, C.muted)}>DECOY FILES</span>
                    <div style={m(11, C.text)}>{hpStatus.file_count || 0}</div>
                  </div>
                  <div style={{ marginBottom: 12 }}>
                    <span style={m(9, C.muted)}>VERIFIED HITS TODAY</span>
                    <div style={m(11, C.orange)}>{hpHitsToday}</div>
                  </div>
                </div>
              ) : (
                <div style={m(10, C.muted)}>No honeypot status</div>
              )}

              <div style={{ ...sLabel, marginTop: 24 }}>HONEYPOT TRIGGERS</div>
              <div style={{ ...m(9, C.muted), marginBottom: 8 }}>
                Only attributed OPEN, READ, or DELETE interactions are counted. Writes, unknown processes, and simulations are excluded.
              </div>
              <div style={{ maxHeight: 200, overflow: 'auto' }}>
                {hpTriggers.length === 0 ? (
                  <div style={{ ...m(10, C.muted), padding: 12 }}>No verified honeypot interactions recorded.</div>
                ) : hpTriggers.slice(0, 10).map((t, i) => (
                    <div key={t.event_id || i} style={{ padding: '12px 16px', borderBottom: '1px solid #111', background: '#1a000022' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8 }}>
                        <span style={{ ...m(11, C.red), fontWeight: 'bold' }}>{t.resource || 'Unknown'}</span>
                        <span style={m(9, '#666')}>{new Date(t.timestamp).toLocaleString()}</span>
                      </div>
                      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
                        <div>
                          <span style={m(9, C.muted)}>SOURCE IP</span>
                          <div style={m(10, C.blue)}>{t.source_ip || 'Local file access'}</div>
                        </div>
                        <div>
                          <span style={m(9, C.muted)}>PROCESS</span>
                          <div style={m(10, C.text)}>{t.process_name}</div>
                        </div>
                      </div>
                    </div>
                ))}
              </div>
            </div>
          </div>

          {/* Analytics Section */}
          <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 16, marginBottom: 24 }}>
            <div style={cardStyle()}>
              <div style={sLabel}>ATTACK TYPES DISTRIBUTION</div>
              <div style={{ height: 250 }}>
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={attackData}>
                    <XAxis dataKey="name" style={{ fontSize: 10, fill: C.muted }} />
                    <YAxis style={{ fontSize: 10, fill: C.muted }} />
                    <Tooltip />
                    <Bar dataKey="value" fill={C.blue} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>

            <div style={cardStyle()}>
              <div style={sLabel}>ATTACK TIMELINE</div>
              <div style={{ height: 250 }}>
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={incidents.slice(0, 20).map(i => ({
                    time: new Date(i.created_at).toLocaleTimeString(),
                    risk: i.risk_score || 0,
                  }))}>
                    <XAxis dataKey="time" style={{ fontSize: 10, fill: C.muted }} />
                    <YAxis style={{ fontSize: 10, fill: C.muted }} />
                    <Tooltip />
                    <Area type="monotone" dataKey="risk" stroke={C.red} fill={C.red + '33'} />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </div>

            <div style={cardStyle()}>
              <div style={sLabel}>TOP ATTACKERS</div>
              <div style={{ maxHeight: 200, overflow: 'auto' }}>
                {Object.entries(
                  incidents.reduce((acc, i) => {
                    const ip = i.attacker?.ip
                    if (ip) acc[ip] = (acc[ip] || 0) + 1
                    return acc
                  }, {})
                )
                  .sort((a, b) => b[1] - a[1])
                  .slice(0, 10)
                  .map(([ip, count], i) => (
                    <div key={i} style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 12px', borderBottom: '1px solid #111' }}>
                      <span style={m(10, C.blue)}>{ip}</span>
                      <span style={m(10, C.muted)}>{count} attacks</span>
                    </div>
                  ))}
              </div>
            </div>

            <div style={cardStyle()}>
              <div style={sLabel}>TARGETED PORTS</div>
              <div style={{ maxHeight: 200, overflow: 'auto' }}>
                {Object.entries(
                  incidents.reduce((acc, i) => {
                    const port = i.network?.target_port
                    if (port) acc[port] = (acc[port] || 0) + 1
                    return acc
                  }, {})
                )
                  .sort((a, b) => b[1] - a[1])
                  .slice(0, 10)
                  .map(([port, count], i) => (
                    <div key={i} style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 12px', borderBottom: '1px solid #111' }}>
                      <span style={m(10, C.green)}>{port}</span>
                      <span style={m(10, C.muted)}>{count} times</span>
                    </div>
                  ))}
              </div>
            </div>
          </div>
        </>
      )}

      {/* Attacker Profile Panel */}
      {selectedAttackerIP && (
        <AttackerProfile
          ip={selectedAttackerIP}
          intel={attackerIntel}
          loading={attackerIntelLoading}
          error={attackerIntelError}
          onRetry={() => setAttackerIntelRetry(value => value + 1)}
          onClose={() => { setSelectedAttackerIP(null); setAttackerIntel(null) }}
        />
      )}

      {/* Live Incident Card */}
      {liveIncident && (
        <div style={{
          position: 'fixed', bottom: 20, right: 20, width: 400,
          background: 'rgba(0,0,10,0.98)', border: `2px solid ${SEV[liveIncident.severity] || C.orange}`,
          borderRadius: 12, padding: 16, zIndex: 999,
          boxShadow: `0 0 40px ${SEV[liveIncident.severity] || C.orange}44`,
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
            <span style={{ ...m(12, SEV[liveIncident.severity] || C.orange), fontWeight: 'bold' }}>
              {liveIncident.scenario_id ? '🧪 LAB SIMULATION' : '🚨 MODEL-VERIFIED INCIDENT'}
            </span>
            <button onClick={() => setLiveIncident(null)} style={{ background: 'transparent', border: 'none', color: C.muted, cursor: 'pointer' }}>✕</button>
          </div>
          <div style={{ marginBottom: 8 }}>
            <span style={m(9, C.muted)}>ATTACK TYPE</span>
            <div style={m(11, C.text)}>{liveIncident.attack_type?.replace(/_/g, ' ') || 'Unknown'}</div>
          </div>
          <div style={{ marginBottom: 8 }}>
            <span style={m(9, C.muted)}>ATTACKER IP</span>
            <div style={m(11, C.blue)}>{liveIncident.attacker?.ip || 'Unknown'}</div>
          </div>
          <div style={{ marginBottom: 8 }}>
            <span style={m(9, C.muted)}>RISK SCORE</span>
            <div style={{ ...m(14, liveIncident.risk_score > 50 ? C.red : C.green), fontWeight: 'bold' }}>
              {liveIncident.risk_score?.toFixed(0) || 0}/100
            </div>
          </div>
          <button
            onClick={() => navigate(`/incidents/${liveIncident.incident_id}`)}
            style={{ width: '100%', padding: '8px', background: C.blue + '22', border: `1px solid ${C.blue}`, borderRadius: 4, ...m(10, C.blue), cursor: 'pointer', marginTop: 8 }}
          >
            VIEW DETAILS
          </button>
        </div>
      )}

      <style>{`
        @keyframes pulse {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.4; }
        }
      `}</style>
    </div>
  )
}
