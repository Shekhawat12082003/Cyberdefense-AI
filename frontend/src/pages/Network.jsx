import { useEffect, useRef, useState, useCallback, useMemo } from 'react'
import { useNavigate } from 'react-router-dom'
import { io } from 'socket.io-client'
import axios from 'axios'
import { getNetworkAuditLogs } from '../api'

const API = 'http://localhost:5000'

const TYPE_COLOR = {
  PORT_SCAN:   '#ff003c',
  BRUTE_FORCE: '#ff6b00',
  C2_BEACON:   '#c084fc',
  DATA_EXFIL:  '#ffcc00',
}
const TYPE_ICON = { PORT_SCAN: '🔍', BRUTE_FORCE: '🔨', C2_BEACON: '📡', DATA_EXFIL: '📤' }
const STATUS_COLOR = {
  ESTABLISHED: '#00ff88', LISTEN: '#00d4ff', TIME_WAIT: '#666',
  CLOSE_WAIT: '#ff6b00', SYN_SENT: '#ffcc00', SYN_RECV: '#ffcc00',
  FIN_WAIT1: '#999', FIN_WAIT2: '#999', CLOSING: '#999',
}

function fmt(iso) {
  if (!iso) return '—'
  const d = new Date(iso + (iso.endsWith('Z') ? '' : 'Z'))
  return d.toLocaleTimeString()
}

function isPrivate(ip) {
  if (!ip) return true
  return ['10.','172.16.','172.17.','172.18.','172.19.','172.20.','172.21.',
    '172.22.','172.23.','172.24.','172.25.','172.26.','172.27.','172.28.',
    '172.29.','172.30.','172.31.','192.168.','127.','::1','fe80']
    .some(p => ip.startsWith(p))
}

const PROTO_COLOR = {
  HTTPS: '#00d4ff', HTTP: '#00ff88', DNS: '#a78bfa', SSH: '#ff6b00',
  TCP: '#4488ff', UDP: '#c084fc', FTP: '#ffcc00', RDP: '#ff003c', OTHER: '#555',
}

function fmtPkt(iso) {
  if (!iso) return ''
  const d = new Date(iso + (iso.endsWith('Z') ? '' : 'Z'))
  return d.toLocaleTimeString('en', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' }) +
    '.' + String(d.getMilliseconds()).padStart(3, '0')
}

export default function Network() {
  const navigate  = useNavigate()
  const token     = localStorage.getItem('token')
  const socketRef = useRef(null)

  const [stats,        setStats]        = useState({ total_connections: 0, suspicious_ips: 0, alerts_today: 0, bytes_sent_mb: 0 })
  const [conns,        setConns]        = useState([])
  const [alerts,       setAlerts]       = useState([])
  const [liveAlerts,   setLiveAlerts]   = useState([])
  const [loading,      setLoading]      = useState(true)
  const [tab,          setTab]          = useState('connections')
  const [lastScan,     setLastScan]     = useState(null)
  const [scanCount,    setScanCount]    = useState(0)
  const [search,       setSearch]       = useState('')
  const [filterExt,    setFilterExt]    = useState(false)
  const [filterStatus, setFilterStatus] = useState('ALL')
  const [sortBy,       setSortBy]       = useState('process')
  const [sortDir,      setSortDir]      = useState('asc')
  const [packets,      setPackets]      = useState([])
  const [pktPaused,    setPktPaused]    = useState(false)
  const [pktFilter,    setPktFilter]    = useState('')
  const pktEndRef = useRef(null)

  const [netAuditLogs,    setNetAuditLogs]    = useState([])
  const [auditLoading,    setAuditLoading]    = useState(false)
  const [auditFilterType, setAuditFilterType] = useState('')
  const [auditFilterSev,  setAuditFilterSev]  = useState('')
  const [auditSearch,     setAuditSearch]     = useState('')

  const headers = { Authorization: `Bearer ${token}` }

  const fetchAll = useCallback(async () => {
    try {
      const [sRes, aRes, cRes, pRes] = await Promise.all([
        axios.get(`${API}/api/network/stats`,       { headers }),
        axios.get(`${API}/api/network/alerts`,      { headers }),
        axios.get(`${API}/api/network/connections`, { headers }),
        axios.get(`${API}/api/network/packets`,     { headers }),
      ])
      setStats(sRes.data)
      setAlerts(aRes.data.alerts || [])
      setConns(cRes.data.connections || [])
      if (!pktPaused) setPackets(pRes.data.packets || [])
      setLoading(false)
    } catch (err) {
      if (err.response?.status === 401) { localStorage.removeItem('token'); navigate('/') }
    }
  }, []) // eslint-disable-line

  const [liveIncident, setLiveIncident] = useState(null)

  useEffect(() => {
    if (!token) { navigate('/'); return }
    fetchAll()
    const interval = setInterval(fetchAll, 5000)   // poll every 5s for REST fallback
    const socket = io(API, { transports: ['websocket'], reconnection: true })
    socketRef.current = socket
    socket.on('network_update', (data) => {
      setConns(data.connections || [])
      setStats(data.stats)
      setLastScan(new Date())
      setScanCount(p => p + 1)
      setLoading(false)
      if (data.packets?.length && !pktPaused) {
        setPackets(p => {
          const merged = [...p, ...data.packets]
          return merged.slice(-500)
        })
      }
    })
    socket.on('network_alert', (data) => setLiveAlerts(p => [data, ...p].slice(0, 50)))
    socket.on('network_audit_event', (data) => setNetAuditLogs(p => [data, ...p].slice(0, 500)))
    // Live incident from real attack or simulation
    socket.on('live_incident', (data) => {
      setLiveIncident(data)
      setLiveAlerts(p => [{
        timestamp: data.timestamp,
        type:      data.attack_type,
        ip:        (data.attacker || {}).ip || '',
        severity:  data.severity,
        description: data.description,
      }, ...p].slice(0, 50))
    })
    return () => { clearInterval(interval); socket.disconnect() }
  }, []) // eslint-disable-line

  // fetch network audit log on mount and when tab switches to it
  useEffect(() => {
    if (tab !== 'auditlog') return
    setAuditLoading(true)
    getNetworkAuditLogs(500)
      .then(r => setNetAuditLogs(r.data))
      .catch(() => {})
      .finally(() => setAuditLoading(false))
  }, [tab]) // eslint-disable-line

  // auto-scroll packets to bottom unless paused
  useEffect(() => {
    if (!pktPaused && tab === 'packets' && pktEndRef.current) {
      pktEndRef.current.scrollIntoView({ behavior: 'smooth' })
    }
  }, [packets, tab, pktPaused])

  const allAlerts = useMemo(() => {
    const seen = new Set()
    return [...liveAlerts, ...alerts].filter(a => {
      const k = `${a.timestamp}-${a.type}-${a.ip}`
      if (seen.has(k)) return false
      seen.add(k); return true
    }).slice(0, 50)
  }, [liveAlerts, alerts])

  const filteredConns = useMemo(() => {
    let list = [...conns]
    if (filterExt) list = list.filter(c => !isPrivate(c.remote_ip))
    if (filterStatus !== 'ALL') list = list.filter(c => c.status === filterStatus)
    if (search.trim()) {
      const q = search.toLowerCase()
      list = list.filter(c =>
        c.remote?.toLowerCase().includes(q) || c.local?.toLowerCase().includes(q) ||
        c.process?.toLowerCase().includes(q) || String(c.pid).includes(q)
      )
    }
    list.sort((a, b) => {
      let va = a[sortBy] ?? '', vb = b[sortBy] ?? ''
      if (typeof va === 'string') va = va.toLowerCase()
      if (typeof vb === 'string') vb = vb.toLowerCase()
      if (va < vb) return sortDir === 'asc' ? -1 : 1
      if (va > vb) return sortDir === 'asc' ? 1 : -1
      return 0
    })
    return list
  }, [conns, search, filterExt, filterStatus, sortBy, sortDir])

  const processSummary = useMemo(() => {
    const map = {}
    conns.forEach(c => {
      const p = c.process || 'unknown'
      if (!map[p]) map[p] = { name: p, count: 0, external: 0 }
      map[p].count++
      if (!isPrivate(c.remote_ip)) map[p].external++
    })
    return Object.values(map).sort((a, b) => b.count - a.count).slice(0, 8)
  }, [conns])

  const statusBreakdown = useMemo(() => {
    const map = {}
    conns.forEach(c => { map[c.status] = (map[c.status] || 0) + 1 })
    return Object.entries(map).sort((a, b) => b[1] - a[1])
  }, [conns])

  const externalIPs = useMemo(() => {
    const map = {}
    conns.filter(c => !isPrivate(c.remote_ip)).forEach(c => {
      const ip = c.remote_ip
      if (!map[ip]) map[ip] = { ip, count: 0, processes: new Set() }
      map[ip].count++
      map[ip].processes.add(c.process)
    })
    return Object.values(map)
      .map(e => ({ ...e, processes: [...e.processes].filter(Boolean).join(', ') }))
      .sort((a, b) => b.count - a.count).slice(0, 20)
  }, [conns])

  const uniqueStatuses = useMemo(() => ['ALL', ...new Set(conns.map(c => c.status))], [conns])

  const filteredPackets = useMemo(() => {
    if (!pktFilter.trim()) return packets
    const q = pktFilter.toLowerCase()
    return packets.filter(p =>
      p.src?.toLowerCase().includes(q) ||
      p.dst?.toLowerCase().includes(q) ||
      p.proto?.toLowerCase().includes(q) ||
      p.info?.toLowerCase().includes(q) ||
      p.flags?.toLowerCase().includes(q)
    )
  }, [packets, pktFilter])

  function toggleSort(col) {
    if (sortBy === col) setSortDir(d => d === 'asc' ? 'desc' : 'asc')
    else { setSortBy(col); setSortDir('asc') }
  }

  const card = (accent = '#00d4ff') => ({
    background: 'rgba(0,0,0,0.55)', border: `1px solid ${accent}33`,
    borderRadius: 12, padding: '16px 20px',
  })
  const tabBtn = (active, color = '#00d4ff') => ({
    padding: '7px 18px', border: `1px solid ${active ? color : '#333'}`,
    borderRadius: 8, background: active ? `${color}22` : 'transparent',
    color: active ? color : '#555', cursor: 'pointer', fontFamily: 'monospace',
    fontSize: 12, fontWeight: active ? 700 : 400, transition: 'all 0.15s',
  })
  const thStyle = (col) => ({
    padding: '9px 12px', fontSize: 10, letterSpacing: 1.5,
    color: sortBy === col ? '#00d4ff' : '#555',
    cursor: 'pointer', userSelect: 'none', whiteSpace: 'nowrap', textAlign: 'left',
    background: sortBy === col ? '#00d4ff0a' : 'transparent',
  })
  const inputStyle = {
    background: '#111', border: '1px solid #333', borderRadius: 7,
    color: '#fff', padding: '7px 12px', fontFamily: 'monospace', fontSize: 12, outline: 'none',
  }

  return (
    <div style={{ minHeight: '100vh', background: '#050a0e', color: '#fff',
      fontFamily: "'Courier New', monospace", paddingBottom: 60 }}>

      {/* Header */}
      <div style={{ background: 'rgba(0,0,0,0.85)', borderBottom: '1px solid #00d4ff22',
        padding: '14px 28px', display: 'flex', alignItems: 'center', gap: 14,
        position: 'sticky', top: 0, zIndex: 100, backdropFilter: 'blur(10px)' }}>
        <button onClick={() => navigate('/dashboard')}
          style={{ background: 'none', border: 'none', color: '#555', cursor: 'pointer', fontSize: 18 }}>←</button>
        <span style={{ color: '#00d4ff', fontSize: 18, fontWeight: 700, letterSpacing: 2 }}>
          🌐 NETWORK TRAFFIC ANALYSER
        </span>
        <div style={{ marginLeft: 'auto', display: 'flex', gap: 16, alignItems: 'center', fontSize: 11 }}>
          {lastScan && <span style={{ color: '#333' }}>SCAN #{scanCount} · {lastScan.toLocaleTimeString()}</span>}
          <span style={{ display: 'flex', gap: 6, alignItems: 'center', color: '#00ff88' }}>
            <span style={{ width: 7, height: 7, borderRadius: '50%', background: '#00ff88',
              display: 'inline-block', animation: 'pulse 2s infinite' }} />
            LIVE · 2s
          </span>
        </div>
      </div>

      <div style={{ padding: '20px 28px', maxWidth: 1500, margin: '0 auto' }}>

        {/* ── Capture mode + local IP banner ────────── */}
        <div style={{
          background: stats.capture_mode === 'scapy' ? '#001a00' : '#1a0a00',
          border: `1px solid ${stats.capture_mode === 'scapy' ? '#00ff8844' : '#ff8c0044'}`,
          borderRadius: 8, padding: '8px 16px', marginBottom: 14,
          display: 'flex', justifyContent: 'space-between', alignItems: 'center',
          flexWrap: 'wrap', gap: 8,
        }}>
          <div style={{ display: 'flex', gap: 16, alignItems: 'center', flexWrap: 'wrap' }}>
            <span style={{
              fontFamily: 'monospace', fontSize: 10,
              color: stats.capture_mode === 'scapy' ? '#00ff88' : '#ff8c00',
              letterSpacing: 2,
            }}>
              {stats.capture_mode === 'scapy' ? '📦 FULL PACKET CAPTURE (Scapy)' : '🔗 CONNECTION MODE (psutil) — Run as Admin for full capture'}
            </span>
            {stats.local_ip && (
              <span style={{ fontFamily: 'monospace', fontSize: 10, color: '#00d4ff', letterSpacing: 1 }}>
                Monitoring: <strong>{stats.local_ip}</strong>
              </span>
            )}
            {stats.scans_detected > 0 && (
              <span style={{ fontFamily: 'monospace', fontSize: 10, color: '#ff003c', letterSpacing: 1 }}>
                🔍 {stats.scans_detected} scans detected
              </span>
            )}
            {stats.brute_force_detected > 0 && (
              <span style={{ fontFamily: 'monospace', fontSize: 10, color: '#ff8c00', letterSpacing: 1 }}>
                🔑 {stats.brute_force_detected} brute forces
              </span>
            )}
          </div>
          <span style={{ fontFamily: 'monospace', fontSize: 9, color: '#333' }}>
            {stats.packets_captured > 0 ? `${stats.packets_captured.toLocaleString()} packets` : ''}
          </span>
        </div>

        {/* ── LIVE INCIDENT CARD ──────────────────────── */}
        {liveIncident && (
          <div style={{
            background: 'rgba(0,0,8,0.98)',
            border: `2px solid ${{ CRITICAL: '#ff003c', HIGH: '#ff8c00', MEDIUM: '#ffe600' }[liveIncident.severity] || '#ff003c'}`,
            borderRadius: 12, marginBottom: 16, overflow: 'hidden',
            boxShadow: `0 0 40px ${{ CRITICAL: '#ff003c', HIGH: '#ff8c00' }[liveIncident.severity] || '#ff003c'}33`,
            animation: 'incidentIn 0.3s ease-out',
          }}>
            {/* Header */}
            <div style={{
              background: `${{ CRITICAL: '#ff003c', HIGH: '#ff8c00' }[liveIncident.severity] || '#ff003c'}22`,
              borderBottom: `1px solid ${{ CRITICAL: '#ff003c', HIGH: '#ff8c00' }[liveIncident.severity] || '#ff003c'}44`,
              padding: '10px 20px', display: 'flex', justifyContent: 'space-between', alignItems: 'center',
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <span style={{ width: 10, height: 10, borderRadius: '50%', background: '#ff003c',
                  display: 'inline-block', boxShadow: '0 0 10px #ff003c', animation: 'pulse 0.8s infinite' }} />
                <span style={{ fontFamily: 'monospace', fontSize: 13, color: '#fff', fontWeight: 700, letterSpacing: 3 }}>
                  🚨 LIVE ATTACK — {(liveIncident.attack_type || '').replace(/_/g, ' ')}
                </span>
                <span style={{
                  padding: '2px 10px', borderRadius: 3, fontFamily: 'monospace', fontSize: 10, fontWeight: 700, letterSpacing: 2,
                  background: `${{ CRITICAL: '#ff003c', HIGH: '#ff8c00' }[liveIncident.severity] || '#ff003c'}33`,
                  color: `${{ CRITICAL: '#ff003c', HIGH: '#ff8c00', MEDIUM: '#ffe600' }[liveIncident.severity] || '#ff003c'}`,
                  border: `1px solid ${{ CRITICAL: '#ff003c', HIGH: '#ff8c00' }[liveIncident.severity] || '#ff003c'}`,
                }}>{liveIncident.severity}</span>
              </div>
              <button onClick={() => setLiveIncident(null)} style={{
                background: 'transparent', border: '1px solid #333', borderRadius: 4,
                color: '#555', cursor: 'pointer', padding: '3px 8px', fontFamily: 'monospace', fontSize: 10,
              }}>✕</button>
            </div>

            {/* Content */}
            <div style={{ padding: 20, display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 200px', gap: 20, fontFamily: 'monospace' }}>

              {/* Attacker */}
              <div>
                <div style={{ fontSize: 9, color: '#444', letterSpacing: 3, marginBottom: 10 }}>ATTACKER</div>
                {[
                  ['Source IP',    (liveIncident.attacker || {}).ip || 'Unknown'],
                  ['MAC',          (liveIncident.attacker || {}).mac || 'Unknown'],
                  ['Protocol',     (liveIncident.attacker || {}).protocol || 'TCP'],
                  ['Target IP',    (liveIncident.target || {}).ip || 'Unknown'],
                  ['Target Port',  (liveIncident.target || {}).port || (liveIncident.network || {}).target_port || '—'],
                ].map(([k, v]) => (
                  <div key={k} style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 5, borderBottom: '1px solid #0d0d0d', paddingBottom: 3 }}>
                    <span style={{ fontSize: 10, color: '#555' }}>{k}</span>
                    <span style={{ fontSize: 10, color: k === 'Source IP' ? '#ff003c' : '#ccc', fontWeight: k === 'Source IP' ? 700 : 400 }}>{v}</span>
                  </div>
                ))}
                {/* Geo */}
                {(() => {
                  const geo = (liveIncident.attacker || {}).geo || {}
                  return (
                    <div style={{ marginTop: 8, padding: '6px 8px', background: '#080818', border: '1px solid #111', borderRadius: 4 }}>
                      <div style={{ fontSize: 9, color: '#333', letterSpacing: 2, marginBottom: 3 }}>📍 LOCATION</div>
                      {geo.type === 'private' ? (
                        <div style={{ fontSize: 11, color: '#00d4ff' }}>LOCAL NETWORK</div>
                      ) : geo.type === 'approximate' ? (
                        <>
                          <div style={{ fontSize: 12, color: '#00d4ff', fontWeight: 700 }}>{geo.city}, {geo.country}</div>
                          <div style={{ fontSize: 9, color: '#555', marginTop: 2 }}>{geo.isp}</div>
                          <div style={{ fontSize: 9, color: '#555' }}>{geo.asn}</div>
                          <div style={{ fontSize: 8, color: '#222', marginTop: 3 }}>⚠ APPROXIMATE</div>
                        </>
                      ) : (
                        <div style={{ fontSize: 10, color: '#444' }}>Unknown</div>
                      )}
                    </div>
                  )
                })()}
              </div>

              {/* Attack details */}
              <div>
                <div style={{ fontSize: 9, color: '#444', letterSpacing: 3, marginBottom: 10 }}>ATTACK DETAILS</div>
                {(() => {
                  const net = liveIncident.network || {}
                  const mitre = liveIncident.mitre || {}
                  return [
                    ['Type',       (liveIncident.attack_type || '').replace(/_/g, ' ')],
                    ['MITRE',      mitre.id ? `${mitre.id}` : '—'],
                    ['Technique',  mitre.name || '—'],
                    ['Ports Hit',  net.port_count || net.ports_hit?.length || '—'],
                    ['Service',    net.service || '—'],
                    ['Conns',      net.connection_count || '—'],
                    ['Capture',    net.capture_mode || 'psutil'],
                  ].map(([k, v]) => (
                    <div key={k} style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 5, borderBottom: '1px solid #0d0d0d', paddingBottom: 3 }}>
                      <span style={{ fontSize: 10, color: '#555' }}>{k}</span>
                      <span style={{ fontSize: 10, color: '#ccc' }}>{v}</span>
                    </div>
                  ))
                })()}
                {/* Ports scanned list */}
                {(liveIncident.network || {}).ports_hit?.length > 0 && (
                  <div style={{ marginTop: 6 }}>
                    <div style={{ fontSize: 9, color: '#333', letterSpacing: 2, marginBottom: 4 }}>PORTS SCANNED</div>
                    <div style={{ maxHeight: 50, overflowY: 'auto' }}>
                      {(liveIncident.network.ports_hit || []).slice(0, 40).map(p => (
                        <span key={p} style={{ display: 'inline-block', margin: '2px 2px', padding: '1px 5px',
                          background: '#0a0a1a', border: '1px solid #1a1a2e', borderRadius: 2, fontSize: 8, color: '#555' }}>
                          {p}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              {/* Risk */}
              <div>
                <div style={{ fontSize: 9, color: '#444', letterSpacing: 3, marginBottom: 10 }}>RISK ASSESSMENT</div>
                <div style={{ textAlign: 'center', marginBottom: 12 }}>
                  <div style={{
                    fontSize: 52, fontWeight: 700, lineHeight: 1,
                    color: liveIncident.risk_score >= 76 ? '#ff003c' : liveIncident.risk_score >= 51 ? '#ff8c00' : '#ffe600',
                    textShadow: `0 0 20px ${liveIncident.risk_score >= 76 ? '#ff003c' : '#ff8c00'}66`,
                  }}>{Math.round(liveIncident.risk_score || 0)}</div>
                  <div style={{ fontSize: 9, color: '#444', letterSpacing: 3, marginTop: 3 }}>/ 100</div>
                  <div style={{
                    display: 'inline-block', marginTop: 6, padding: '3px 12px', borderRadius: 4,
                    background: `${liveIncident.risk_score >= 76 ? '#ff003c' : '#ff8c00'}22`,
                    border: `1px solid ${liveIncident.risk_score >= 76 ? '#ff003c' : '#ff8c00'}`,
                    fontSize: 10, color: liveIncident.risk_score >= 76 ? '#ff003c' : '#ff8c00',
                    fontWeight: 700, letterSpacing: 2,
                  }}>{liveIncident.risk_level || 'HIGH'}</div>
                </div>
                {(liveIncident.risk_factors || []).slice(0, 4).map((f, i) => (
                  <div key={i} style={{ marginBottom: 5 }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 2 }}>
                      <span style={{ fontSize: 9, color: '#444' }}>{f.name}</span>
                      <span style={{ fontSize: 9, color: '#00d4ff', fontWeight: 700 }}>+{(f.contribution || 0).toFixed(1)}</span>
                    </div>
                    <div style={{ height: 3, background: '#111', borderRadius: 2 }}>
                      <div style={{ width: `${Math.min(((f.contribution||0)/(f.weight||25))*100, 100)}%`, height: '100%', background: '#00d4ff', borderRadius: 2 }} />
                    </div>
                  </div>
                ))}
              </div>

              {/* Actions */}
              <div>
                <div style={{ fontSize: 9, color: '#444', letterSpacing: 3, marginBottom: 10 }}>RESPONSE</div>
                {/* Status badges */}
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 4, marginBottom: 12 }}>
                  {[
                    ['DETECTED',   true,  '#00ff88'],
                    ['HONEYPOT',   (liveIncident.status || {}).honeypot, '#ff003c'],
                    ['ML ENGINE',  (liveIncident.status || {}).ml,       '#00d4ff'],
                    ['QUARANTINE', (liveIncident.status || {}).quarantine,'#ff8c00'],
                    ['EVIDENCE',   (liveIncident.status || {}).evidence,  '#a78bfa'],
                    ['BLOCKCHAIN', (liveIncident.status || {}).blockchain,'#00d4ff'],
                  ].map(([label, active, col]) => (
                    <div key={label} style={{
                      padding: '4px 6px', borderRadius: 3, textAlign: 'center',
                      background: active ? `${col}22` : '#0a0a0a',
                      border: `1px solid ${active ? col + '66' : '#111'}`,
                    }}>
                      <div style={{ fontSize: 8, color: active ? col : '#222', letterSpacing: 1 }}>{label}</div>
                    </div>
                  ))}
                </div>
                {/* Buttons */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
                  {liveIncident.incident_id && (
                    <button onClick={() => navigate(`/incidents/${liveIncident.incident_id}`)} style={{
                      padding: '6px', fontSize: 8, letterSpacing: 2, fontFamily: 'monospace',
                      background: '#ff003c11', border: '1px solid #ff003c', borderRadius: 3, color: '#ff003c', cursor: 'pointer',
                    }}>📋 VIEW INCIDENT</button>
                  )}
                  <button onClick={() => navigate('/incidents')} style={{
                    padding: '6px', fontSize: 8, letterSpacing: 2, fontFamily: 'monospace',
                    background: '#ff8c0011', border: '1px solid #ff8c00', borderRadius: 3, color: '#ff8c00', cursor: 'pointer',
                  }}>🚨 ALL INCIDENTS</button>
                  <button onClick={() => navigate('/')} style={{
                    padding: '6px', fontSize: 8, letterSpacing: 2, fontFamily: 'monospace',
                    background: '#00d4ff11', border: '1px solid #00d4ff', borderRadius: 3, color: '#00d4ff', cursor: 'pointer',
                  }}>🏠 DASHBOARD</button>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Stat cards */}
        <div style={{ display: 'flex', gap: 12, marginBottom: 20, flexWrap: 'wrap' }}>
          {[
            { label: 'ACTIVE CONNECTIONS', val: stats.total_connections, color: '#00d4ff' },
            { label: 'EXTERNAL IPs',       val: externalIPs.length,      color: '#a78bfa' },
            { label: 'SUSPICIOUS IPs',     val: stats.suspicious_ips,    color: '#ff003c' },
            { label: 'ALERTS',             val: (stats.alerts_today || 0) + liveAlerts.length, color: '#ff6b00' },
            { label: 'MB SENT',            val: stats.bytes_sent_mb,     color: '#00ff88' },
          ].map(({ label, val, color }) => (
            <div key={label} style={{ ...card(color), flex: 1, minWidth: 120 }}>
              <div style={{ fontSize: 9, color, letterSpacing: 2, marginBottom: 6 }}>{label}</div>
              <div style={{ fontSize: 28, fontWeight: 700, color: (val > 0 && !['ACTIVE CONNECTIONS','MB SENT'].includes(label)) ? color : '#fff' }}>
                {loading ? '…' : val}
              </div>
            </div>
          ))}
        </div>

        {/* Summary row */}
        {!loading && (
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 12, marginBottom: 20 }}>

            {/* Top processes */}
            <div style={{ ...card('#a78bfa') }}>
              <div style={{ fontSize: 10, color: '#a78bfa', letterSpacing: 2, marginBottom: 10 }}>TOP PROCESSES</div>
              {processSummary.length === 0
                ? <div style={{ color: '#333', fontSize: 11 }}>No data yet</div>
                : processSummary.map((p, i) => (
                  <div key={i} style={{ marginBottom: 7 }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 3 }}>
                      <span style={{ fontSize: 11, color: '#ccc', maxWidth: 130, overflow: 'hidden',
                        textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{p.name}</span>
                      <div style={{ display: 'flex', gap: 6 }}>
                        {p.external > 0 && (
                          <span style={{ fontSize: 9, color: '#ff6b00', background: '#ff6b0011',
                            border: '1px solid #ff6b0033', borderRadius: 4, padding: '1px 5px' }}>
                            {p.external} ext
                          </span>
                        )}
                        <span style={{ fontSize: 10, color: '#a78bfa' }}>{p.count}</span>
                      </div>
                    </div>
                    <div style={{ height: 3, background: '#111', borderRadius: 2 }}>
                      <div style={{ height: 3, background: '#a78bfa', borderRadius: 2, transition: 'width 0.4s',
                        width: `${Math.min(100, (p.count / (processSummary[0]?.count || 1)) * 100)}%` }} />
                    </div>
                  </div>
                ))
              }
            </div>

            {/* Status breakdown */}
            <div style={{ ...card('#00ff88') }}>
              <div style={{ fontSize: 10, color: '#00ff88', letterSpacing: 2, marginBottom: 10 }}>CONNECTION STATUS</div>
              {statusBreakdown.length === 0
                ? <div style={{ color: '#333', fontSize: 11 }}>No data yet</div>
                : statusBreakdown.map(([status, count], i) => (
                  <div key={i} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                    <span style={{ fontSize: 11, color: STATUS_COLOR[status] || '#888', minWidth: 100 }}>{status}</span>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, flex: 1 }}>
                      <div style={{ flex: 1, height: 3, background: '#111', borderRadius: 2 }}>
                        <div style={{ height: 3, background: STATUS_COLOR[status] || '#888', borderRadius: 2,
                          width: `${Math.min(100, (count / (conns.length || 1)) * 100)}%`, transition: 'width 0.4s' }} />
                      </div>
                      <span style={{ fontSize: 11, color: '#555', width: 28, textAlign: 'right' }}>{count}</span>
                    </div>
                  </div>
                ))
              }
            </div>

            {/* External IPs */}
            <div style={{ ...card('#ff6b00') }}>
              <div style={{ fontSize: 10, color: '#ff6b00', letterSpacing: 2, marginBottom: 10 }}>
                EXTERNAL IPs ({externalIPs.length})
              </div>
              {externalIPs.length === 0
                ? <div style={{ color: '#333', fontSize: 11 }}>No external connections</div>
                : <div style={{ maxHeight: 170, overflowY: 'auto', paddingRight: 2, scrollbarWidth: 'none', msOverflowStyle: 'none' }} className="hide-scroll">
                    {externalIPs.map((e, i) => (
                      <div key={i} style={{ display: 'flex', justifyContent: 'space-between',
                        alignItems: 'center', padding: '5px 0', borderBottom: '1px solid #ffffff08', gap: 8 }}>
                        <span style={{ fontSize: 11, color: '#ff6b00', fontFamily: 'monospace',
                          minWidth: 0, flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{e.ip}</span>
                        <div style={{ display: 'flex', gap: 6, alignItems: 'center', flexShrink: 0 }}>
                          <span style={{ fontSize: 9, color: '#444', maxWidth: 70,
                            overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{e.processes}</span>
                          <span style={{ fontSize: 10, background: '#ff6b0011', border: '1px solid #ff6b0033',
                            color: '#ff6b00', borderRadius: 4, padding: '1px 6px', flexShrink: 0 }}>{e.count}x</span>
                        </div>
                      </div>
                    ))}
                  </div>
              }
            </div>
          </div>
        )}

        {/* Tab bar */}
        <div style={{ display: 'flex', gap: 8, marginBottom: 14, flexWrap: 'wrap', alignItems: 'center' }}>
          <button style={tabBtn(tab === 'connections')} onClick={() => setTab('connections')}>
            🔗 CONNECTIONS ({filteredConns.length}/{conns.length})
          </button>
          <button style={tabBtn(tab === 'alerts', '#ff003c')} onClick={() => setTab('alerts')}>
            🚨 ALERTS ({allAlerts.length})
            {liveAlerts.length > 0 && (
              <span style={{ marginLeft: 6, background: '#ff003c', color: '#fff',
                borderRadius: 10, padding: '1px 6px', fontSize: 10 }}>
                {liveAlerts.length} NEW
              </span>
            )}
          </button>
          <button style={tabBtn(tab === 'packets', '#a78bfa')} onClick={() => setTab('packets')}>
            📦 PACKETS ({packets.length})
          </button>
          <button style={tabBtn(tab === 'auditlog', '#00ff88')} onClick={() => setTab('auditlog')}>
            📋 AUDIT LOG ({netAuditLogs.length})
          </button>

          {tab === 'connections' && (
            <div style={{ marginLeft: 'auto', display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
              <input value={search} onChange={e => setSearch(e.target.value)}
                placeholder="Search IP / process / port…" style={{ ...inputStyle, width: 220 }} />
              <select value={filterStatus} onChange={e => setFilterStatus(e.target.value)}
                style={{ ...inputStyle, width: 140, cursor: 'pointer' }}>
                {uniqueStatuses.map(s => <option key={s} value={s}>{s}</option>)}
              </select>
              <button onClick={() => setFilterExt(p => !p)} style={tabBtn(filterExt, '#ff6b00')}>
                🌍 EXTERNAL ONLY
              </button>
            </div>
          )}
        </div>

        {tab === 'connections' && (
          <div style={{ background: 'rgba(0,0,0,0.5)', border: '1px solid #00d4ff22', borderRadius: 12, overflow: 'hidden' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11, fontFamily: 'monospace' }}>
              <thead>
                <tr style={{ borderBottom: '1px solid #00d4ff22' }}>
                  {[
                    { col: 'local',       label: 'LOCAL' },
                    { col: 'remote',      label: 'REMOTE' },
                    { col: 'status',      label: 'STATUS' },
                    { col: 'process',     label: 'PROCESS' },
                    { col: 'pid',         label: 'PID' },
                    { col: 'remote_port', label: 'PORT' },
                  ].map(({ col, label }) => (
                    <th key={col} onClick={() => toggleSort(col)} style={thStyle(col)}>
                      {label} {sortBy === col ? (sortDir === 'asc' ? '▲' : '▼') : ''}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {loading ? (
                  <tr><td colSpan={6} style={{ padding: 50, textAlign: 'center', color: '#333' }}>
                    Scanning network…
                  </td></tr>
                ) : filteredConns.length === 0 ? (
                  <tr><td colSpan={6} style={{ padding: 50, textAlign: 'center', color: '#333' }}>
                    {conns.length === 0 ? 'No connections captured yet — waiting for socket data…' : 'No results match current filter'}
                  </td></tr>
                ) : (
                  filteredConns.slice(0, 200).map((c, i) => {
                    const ext = !isPrivate(c.remote_ip)
                    return (
                      <tr key={i} style={{
                        borderBottom: '1px solid #ffffff06',
                        background: ext ? 'rgba(255,107,0,0.04)' : (i % 2 === 0 ? 'transparent' : 'rgba(255,255,255,0.015)'),
                      }}>
                        <td style={{ padding: '7px 12px', color: '#555' }}>{c.local}</td>
                        <td style={{ padding: '7px 12px', color: ext ? '#ff6b00' : '#999', fontWeight: ext ? 700 : 400 }}>
                          {c.remote}{ext && <span style={{ marginLeft: 5, fontSize: 8, color: '#ff6b0066' }}>●</span>}
                        </td>
                        <td style={{ padding: '7px 12px' }}>
                          <span style={{ color: STATUS_COLOR[c.status] || '#888', fontSize: 10, fontWeight: 700 }}>
                            {c.status}
                          </span>
                        </td>
                        <td style={{ padding: '7px 12px', color: '#a78bfa', maxWidth: 140,
                          overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {c.process}
                        </td>
                        <td style={{ padding: '7px 12px', color: '#444' }}>{c.pid || '—'}</td>
                        <td style={{ padding: '7px 12px', color: '#555' }}>{c.remote_port}</td>
                      </tr>
                    )
                  })
                )}
              </tbody>
            </table>
            {filteredConns.length > 200 && (
              <div style={{ padding: '8px 16px', color: '#444', fontSize: 11, textAlign: 'center' }}>
                Showing 200 of {filteredConns.length} connections
              </div>
            )}
          </div>
        )}

        {/* Packets tab — Wireshark-style */}
        {tab === 'packets' && (
          <div style={{ background: 'rgba(0,0,0,0.5)', border: '1px solid #a78bfa22', borderRadius: 12, overflow: 'hidden' }}>
            {/* Packet toolbar */}
            <div style={{ display: 'flex', gap: 10, alignItems: 'center', padding: '10px 14px',
              borderBottom: '1px solid #a78bfa22', background: '#0a0712' }}>
              <span style={{ fontSize: 10, color: '#a78bfa', letterSpacing: 2 }}>LIVE CAPTURE</span>
              <span style={{ fontSize: 10, color: '#333' }}>·</span>
              <span style={{ fontSize: 10, color: '#555' }}>{packets.length} pkts captured</span>
              <div style={{ flex: 1 }}>
                <input value={pktFilter} onChange={e => setPktFilter(e.target.value)}
                  placeholder="Filter: IP / protocol / flags…"
                  style={{ ...inputStyle, width: '100%', maxWidth: 300 }} />
              </div>
              <button onClick={() => setPktPaused(p => !p)}
                style={{ ...tabBtn(pktPaused, '#ffcc00'), fontSize: 11 }}>
                {pktPaused ? '▶ RESUME' : '⏸ PAUSE'}
              </button>
              <button onClick={() => setPackets([])}
                style={{ padding: '5px 12px', border: '1px solid #333', borderRadius: 6,
                  background: 'transparent', color: '#555', cursor: 'pointer', fontSize: 11 }}>
                🗑 CLEAR
              </button>
            </div>
            {/* Packet legend */}
            <div style={{ display: 'flex', gap: 12, padding: '6px 14px', borderBottom: '1px solid #ffffff08',
              background: '#050709', flexWrap: 'wrap' }}>
              {Object.entries(PROTO_COLOR).filter(([k]) => k !== 'OTHER').map(([proto, color]) => (
                <span key={proto} style={{ fontSize: 9, color, display: 'flex', gap: 4, alignItems: 'center' }}>
                  <span style={{ width: 6, height: 6, borderRadius: 1, background: color, display: 'inline-block' }} />
                  {proto}
                </span>
              ))}
            </div>
            {/* Packet table */}
            <div style={{ maxHeight: 500, overflowY: 'auto', fontSize: 11, fontFamily: 'monospace' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                <thead style={{ position: 'sticky', top: 0, background: '#050709', zIndex: 1 }}>
                  <tr style={{ borderBottom: '1px solid #a78bfa22' }}>
                    <th style={{ padding: '7px 10px', fontSize: 9, color: '#555', textAlign: 'left', width: 85 }}>TIME</th>
                    <th style={{ padding: '7px 10px', fontSize: 9, color: '#555', textAlign: 'left', width: 50 }}>PROTO</th>
                    <th style={{ padding: '7px 10px', fontSize: 9, color: '#555', textAlign: 'left' }}>SOURCE</th>
                    <th style={{ padding: '7px 10px', fontSize: 9, color: '#555', textAlign: 'left' }}>DESTINATION</th>
                    <th style={{ padding: '7px 10px', fontSize: 9, color: '#555', textAlign: 'right', width: 55 }}>LEN</th>
                    <th style={{ padding: '7px 10px', fontSize: 9, color: '#555', textAlign: 'left' }}>FLAGS / INFO</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredPackets.length === 0 ? (
                    <tr><td colSpan={6} style={{ padding: 50, textAlign: 'center', color: '#333' }}>
                      {packets.length === 0
                        ? 'Waiting for packets… (requires admin/elevated privileges)'
                        : 'No packets match filter'}
                    </td></tr>
                  ) : (
                    filteredPackets.map((p, i) => {
                      const color = PROTO_COLOR[p.proto] || PROTO_COLOR.OTHER
                      const extSrc = !isPrivate(p.src_ip || '')
                      return (
                        <tr key={i} style={{
                          borderBottom: '1px solid #ffffff05',
                          background: extSrc ? 'rgba(255,107,0,0.03)' : (i % 2 === 0 ? 'transparent' : 'rgba(255,255,255,0.012)'),
                        }}>
                          <td style={{ padding: '4px 10px', color: '#444', whiteSpace: 'nowrap' }}>{fmtPkt(p.time)}</td>
                          <td style={{ padding: '4px 10px' }}>
                            <span style={{ color, background: `${color}18`, border: `1px solid ${color}33`,
                              borderRadius: 3, padding: '1px 5px', fontSize: 9, fontWeight: 700 }}>
                              {p.proto}
                            </span>
                          </td>
                          <td style={{ padding: '4px 10px', color: extSrc ? '#ff6b00' : '#aaa' }}>{p.src}</td>
                          <td style={{ padding: '4px 10px', color: '#888' }}>{p.dst}</td>
                          <td style={{ padding: '4px 10px', color: '#555', textAlign: 'right' }}>{p.length}</td>
                          <td style={{ padding: '4px 10px', color: color === PROTO_COLOR.OTHER ? '#444' : color, opacity: 0.8 }}>{p.info || p.flags}</td>
                        </tr>
                      )
                    })
                  )}
                </tbody>
              </table>
              <div ref={pktEndRef} />
            </div>
          </div>
        )}

        {/* Alerts table */}
        {tab === 'alerts' && (
          <div style={{ background: 'rgba(0,0,0,0.5)', border: '1px solid #ff003c22', borderRadius: 12, overflow: 'hidden' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11, fontFamily: 'monospace' }}>
              <thead>
                <tr style={{ borderBottom: '1px solid #ff003c22', background: '#ff003c08' }}>
                  <th style={thStyle('timestamp')}>TIME</th>
                  <th style={thStyle('type')}>TYPE</th>
                  <th style={thStyle('severity')}>SEVERITY</th>
                  <th style={thStyle('ip')}>IP</th>
                  <th style={{ padding: '9px 12px', fontSize: 10, letterSpacing: 1.5, color: '#555', textAlign: 'left' }}>DESCRIPTION</th>
                </tr>
              </thead>
              <tbody>
                {allAlerts.length === 0 ? (
                  <tr><td colSpan={5} style={{ padding: 60, textAlign: 'center', color: '#333', fontSize: 13 }}>
                    ✅ No threats detected — network is clean
                  </td></tr>
                ) : allAlerts.map((a, i) => (
                  <tr key={i} style={{
                    borderBottom: '1px solid #ffffff06',
                    background: i % 2 === 0 ? 'transparent' : 'rgba(255,255,255,0.015)',
                  }}>
                    <td style={{ padding: '9px 12px', color: '#555', whiteSpace: 'nowrap' }}>{fmt(a.timestamp)}</td>
                    <td style={{ padding: '9px 12px' }}>
                      <span style={{ color: TYPE_COLOR[a.type] || '#fff', fontWeight: 700, fontSize: 10 }}>
                        {TYPE_ICON[a.type]} {a.type?.replace(/_/g, ' ')}
                      </span>
                    </td>
                    <td style={{ padding: '9px 12px' }}>
                      <span style={{
                        color: a.severity === 'CRITICAL' ? '#ff003c' : '#ff6b00',
                        background: a.severity === 'CRITICAL' ? '#ff003c11' : '#ff6b0011',
                        border: `1px solid ${a.severity === 'CRITICAL' ? '#ff003c33' : '#ff6b0033'}`,
                        borderRadius: 5, padding: '2px 8px', fontSize: 9, fontWeight: 700,
                      }}>
                        {a.severity}
                      </span>
                    </td>
                    <td style={{ padding: '9px 12px', color: '#00d4ff', fontFamily: 'monospace' }}>{a.ip}</td>
                    <td style={{ padding: '9px 12px', color: '#888', fontSize: 11 }}>{a.description}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

        {/* Network Audit Log tab */}
        {tab === 'auditlog' && (() => {
          const SEV_COLOR = { CRITICAL: '#ff003c', HIGH: '#ff6b00', MEDIUM: '#ffcc00', LOW: '#00ff88', INFO: '#00d4ff' }
          const TYPE_ICON_MAP = { PORT_SCAN: '🔍', BRUTE_FORCE: '🔨', C2_BEACON: '📡', DATA_EXFIL: '📤' }
          const filtered = netAuditLogs.filter(l => {
            const matchType = !auditFilterType || l.event_type === auditFilterType
            const matchSev  = !auditFilterSev  || l.severity === auditFilterSev
            const matchIP   = !auditSearch.trim() ||
              l.ip?.toLowerCase().includes(auditSearch.toLowerCase()) ||
              l.description?.toLowerCase().includes(auditSearch.toLowerCase())
            return matchType && matchSev && matchIP
          })
          const uniqueTypes = [...new Set(netAuditLogs.map(l => l.event_type).filter(Boolean))]
          const uniqueSevs  = [...new Set(netAuditLogs.map(l => l.severity).filter(Boolean))]
          const critCount   = netAuditLogs.filter(l => l.severity === 'CRITICAL').length
          const highCount   = netAuditLogs.filter(l => l.severity === 'HIGH').length
          const uniqueIPs   = new Set(netAuditLogs.map(l => l.ip).filter(Boolean)).size
          return (
            <div>
              {/* Summary cards */}
              <div style={{ display: 'flex', gap: 10, marginBottom: 14, flexWrap: 'wrap' }}>
                {[
                  { label: 'TOTAL EVENTS', val: netAuditLogs.length, color: '#00d4ff' },
                  { label: 'CRITICAL',     val: critCount,            color: '#ff003c' },
                  { label: 'HIGH',         val: highCount,            color: '#ff6b00' },
                  { label: 'UNIQUE IPs',   val: uniqueIPs,            color: '#a78bfa' },
                ].map(({ label, val, color }) => (
                  <div key={label} style={{ ...card(color), minWidth: 110, flex: 1 }}>
                    <div style={{ fontSize: 9, color, letterSpacing: 2, marginBottom: 4 }}>{label}</div>
                    <div style={{ fontSize: 26, fontWeight: 700, color: val > 0 ? color : '#fff' }}>{val}</div>
                  </div>
                ))}
              </div>
              {/* Filters */}
              <div style={{ display: 'flex', gap: 8, marginBottom: 12, flexWrap: 'wrap', alignItems: 'center' }}>
                <select value={auditFilterType} onChange={e => setAuditFilterType(e.target.value)}
                  style={{ ...inputStyle, minWidth: 160, cursor: 'pointer' }}>
                  <option value=''>ALL EVENT TYPES</option>
                  {uniqueTypes.map(t => <option key={t} value={t}>{t}</option>)}
                </select>
                <select value={auditFilterSev} onChange={e => setAuditFilterSev(e.target.value)}
                  style={{ ...inputStyle, minWidth: 130, cursor: 'pointer' }}>
                  <option value=''>ALL SEVERITIES</option>
                  {uniqueSevs.map(s => <option key={s} value={s}>{s}</option>)}
                </select>
                <input value={auditSearch} onChange={e => setAuditSearch(e.target.value)}
                  placeholder='Search IP / description…'
                  style={{ ...inputStyle, width: 220 }} />
                {(auditFilterType || auditFilterSev || auditSearch) && (
                  <button onClick={() => { setAuditFilterType(''); setAuditFilterSev(''); setAuditSearch('') }}
                    style={{ padding: '7px 12px', border: '1px solid #333', borderRadius: 7,
                      background: 'transparent', color: '#555', cursor: 'pointer', fontSize: 11 }}>
                    ✕ CLEAR
                  </button>
                )}
                <span style={{ marginLeft: 'auto', fontSize: 11, color: '#444' }}>
                  Showing <span style={{ color: '#00ff88' }}>{filtered.length}</span> of {netAuditLogs.length}
                </span>
              </div>
              {/* Table */}
              <div style={{ background: 'rgba(0,0,0,0.5)', border: '1px solid #00ff8822',
                borderRadius: 12, overflow: 'hidden' }}>
                <div style={{ maxHeight: 540, overflowY: 'auto' }}>
                  <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11, fontFamily: 'monospace' }}>
                    <thead style={{ position: 'sticky', top: 0, background: '#050d09', zIndex: 1 }}>
                      <tr style={{ borderBottom: '1px solid #00ff8822' }}>
                        {['#', 'TIMESTAMP', 'SEV', 'EVENT TYPE', 'IP', 'PROTO', 'PORT', 'DESCRIPTION'].map(h => (
                          <th key={h} style={{ padding: '9px 12px', fontSize: 10, letterSpacing: 1.5,
                            color: '#555', textAlign: 'left', fontWeight: 'normal', whiteSpace: 'nowrap' }}>{h}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {auditLoading ? (
                        <tr><td colSpan={8} style={{ padding: 50, textAlign: 'center', color: '#00ff88', letterSpacing: 3 }}>LOADING…</td></tr>
                      ) : filtered.length === 0 ? (
                        <tr><td colSpan={8} style={{ padding: 60, textAlign: 'center', color: '#333', fontSize: 12 }}>
                          {netAuditLogs.length === 0
                            ? 'No network events logged yet — alerts will appear here when threats are detected'
                            : 'No events match current filter'}
                        </td></tr>
                      ) : (
                        filtered.map((l, i) => {
                          const sevColor  = SEV_COLOR[l.severity] || '#666'
                          const typeColor = TYPE_COLOR[l.event_type] || '#00d4ff'
                          return (
                            <tr key={l.id ?? i}
                              style={{ borderBottom: '1px solid #ffffff05',
                                background: i % 2 === 0 ? 'transparent' : 'rgba(255,255,255,0.012)' }}
                              onMouseEnter={e => e.currentTarget.style.background = 'rgba(0,255,136,0.03)'}
                              onMouseLeave={e => e.currentTarget.style.background = i % 2 === 0 ? 'transparent' : 'rgba(255,255,255,0.012)'}>
                              <td style={{ padding: '7px 12px', color: '#333' }}>{l.id ?? i + 1}</td>
                              <td style={{ padding: '7px 12px', color: '#444', whiteSpace: 'nowrap' }}>
                                {l.timestamp?.slice(0, 19).replace('T', ' ')}
                              </td>
                              <td style={{ padding: '7px 12px' }}>
                                <span style={{ color: sevColor, background: `${sevColor}11`,
                                  border: `1px solid ${sevColor}33`, borderRadius: 4,
                                  padding: '2px 7px', fontSize: 9, fontWeight: 700 }}>
                                  {l.severity}
                                </span>
                              </td>
                              <td style={{ padding: '7px 12px' }}>
                                <span style={{ color: typeColor, fontWeight: 700, fontSize: 10 }}>
                                  {TYPE_ICON_MAP[l.event_type] || '⚠️'} {l.event_type?.replace(/_/g, ' ')}
                                </span>
                              </td>
                              <td style={{ padding: '7px 12px', color: '#00d4ff', fontFamily: 'monospace' }}>{l.ip}</td>
                              <td style={{ padding: '7px 12px' }}>
                                {l.protocol ? (
                                  <span style={{ color: PROTO_COLOR[l.protocol] || '#aaa',
                                    background: `${PROTO_COLOR[l.protocol] || '#aaa'}18`,
                                    border: `1px solid ${PROTO_COLOR[l.protocol] || '#aaa'}33`,
                                    borderRadius: 3, padding: '1px 5px', fontSize: 9, fontWeight: 700 }}>
                                    {l.protocol}
                                  </span>
                                ) : <span style={{ color: '#333' }}>—</span>}
                              </td>
                              <td style={{ padding: '7px 12px', color: '#666' }}>{l.port ?? '—'}</td>
                              <td style={{ padding: '7px 12px', color: '#888', maxWidth: 280,
                                overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                                {l.description}
                              </td>
                            </tr>
                          )
                        })
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )
        })()}

      <style>{`
        @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.3} }
        @keyframes incidentIn { from{opacity:0;transform:translateY(-10px)} to{opacity:1;transform:translateY(0)} }
        ::-webkit-scrollbar{width:5px;height:5px}
        ::-webkit-scrollbar-track{background:transparent}
        ::-webkit-scrollbar-thumb{background:#222;border-radius:3px}
        select option{background:#111;color:#fff}
        .hide-scroll::-webkit-scrollbar{display:none}
      `}</style>
    </div>
  )
}