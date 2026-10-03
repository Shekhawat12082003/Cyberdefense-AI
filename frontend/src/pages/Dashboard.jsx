import { useState, useEffect, useRef } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { io } from 'socket.io-client'
import {
  getStats, getThreats, getIncidents, getHoneypotStatus,
  getLabStatus, getSecurityEvents
} from '../api'
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts'
import ThreatIntelPanel from '../components/ThreatIntelPanel'

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
const navBtn  = (color = C.blue) => ({
  padding: '7px 14px', fontSize: 10, fontFamily: 'monospace', fontWeight: 'bold',
  letterSpacing: 2, background: 'transparent', border: `1px solid ${color}`,
  borderRadius: 6, color, cursor: 'pointer', textDecoration: 'none',
  display: 'inline-block', whiteSpace: 'nowrap',
})

// ── Status dot ─────────────────────────────────────────────
const Dot = ({ ok, pulse }) => (
  <span style={{
    display: 'inline-block', width: 8, height: 8, borderRadius: '50%', flexShrink: 0,
    background: ok ? C.green : C.red, boxShadow: `0 0 6px ${ok ? C.green : C.red}`,
    animation: pulse ? 'pulse 1.4s infinite' : 'none',
  }} />
)

// ── Score bar ──────────────────────────────────────────────
const ScoreBar = ({ score }) => {
  const pct = Math.min(score, 100)
  const col = score > 70 ? C.red : score > 30 ? C.orange : C.green
  return (
    <div style={{ height: 4, background: '#111', borderRadius: 2 }}>
      <div style={{ width: `${pct}%`, height: '100%', background: col, borderRadius: 2, boxShadow: `0 0 6px ${col}` }} />
    </div>
  )
}

// ── Status badge row ───────────────────────────────────────
const StatusBadge = ({ label, active, activeColor = C.green }) => (
  <div style={{
    padding: '5px 10px', borderRadius: 4, textAlign: 'center',
    background: active ? activeColor + '22' : '#0a0a1a',
    border: `1px solid ${active ? activeColor + '66' : '#111'}`,
    transition: 'all 0.4s',
  }}>
    <div style={{ ...m(8, active ? activeColor : C.muted), letterSpacing: 1, marginBottom: 2 }}>
      {active ? '●' : '○'}
    </div>
    <div style={{ ...m(8, active ? activeColor : C.muted), letterSpacing: 1 }}>{label}</div>
  </div>
)

// ══════════════════════════════════════════════════════════
// LIVE INCIDENT CARD — appears when attack detected
// ══════════════════════════════════════════════════════════
function LiveIncidentCard({ incident, onDismiss, navigate }) {
  const [elapsed, setElapsed]   = useState(0)
  const [statuses, setStatuses] = useState({
    detected: true, honeypot: false, ml: false,
    quarantine: false, evidence: false, blockchain: false,
  })
  const startRef = useRef(Date.now())

  // Timer
  useEffect(() => {
    const id = setInterval(() => setElapsed(((Date.now() - startRef.current) / 1000).toFixed(2)), 100)
    return () => clearInterval(id)
  }, [])

  // Progressive status updates from incident data
  useEffect(() => {
    if (!incident) return
    const s = incident.status || {}
    setStatuses({
      detected:   true,
      honeypot:   s.honeypot   || incident.honeypot?.triggered || false,
      ml:         s.ml         || !!incident.ml?.prediction || false,
      quarantine: s.quarantine || false,
      evidence:   s.evidence   || false,
      blockchain: s.blockchain || false,
    })
  }, [incident])

  if (!incident) return null

  const sev      = incident.severity || 'HIGH'
  const sevColor = SEV[sev] || C.orange
  const score    = incident.risk_score || 0
  const riskColor = score >= 76 ? C.red : score >= 51 ? C.orange : score >= 26 ? C.yellow : C.green
  const attacker  = incident.attacker || {}
  const geo       = attacker.geo || {}
  const network   = incident.network || {}
  const process   = incident.process || {}
  const mitre     = incident.mitre || {}

  const geoLine = geo.type === 'private'
    ? 'LOCAL NETWORK'
    : geo.type === 'approximate'
      ? `${geo.city || '?'}, ${geo.country || '?'}`
      : 'Unknown'

  return (
    <div style={{
      position: 'relative',
      background: 'rgba(0,0,10,0.97)',
      border: `2px solid ${sevColor}`,
      borderRadius: 12,
      padding: 0,
      marginBottom: 20,
      boxShadow: `0 0 40px ${sevColor}44, inset 0 0 60px ${sevColor}08`,
      overflow: 'hidden',
      animation: 'incidentIn 0.4s ease-out',
    }}>

      {/* ── Scan line animation ─────────────────────── */}
      <div style={{
        position: 'absolute', top: 0, left: 0, right: 0, height: 2,
        background: `linear-gradient(90deg, transparent, ${sevColor}, transparent)`,
        animation: 'scanLine 2s linear infinite',
      }} />

      {/* ── Header bar ─────────────────────────────── */}
      <div style={{
        background: `linear-gradient(90deg, ${sevColor}22, transparent)`,
        borderBottom: `1px solid ${sevColor}33`,
        padding: '12px 20px',
        display: 'flex', justifyContent: 'space-between', alignItems: 'center',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <div style={{
            width: 10, height: 10, borderRadius: '50%',
            background: sevColor, boxShadow: `0 0 12px ${sevColor}`,
            animation: 'pulse 0.8s infinite',
          }} />
          <span style={{ ...m(13, '#fff'), fontWeight: 'bold', letterSpacing: 3 }}>
            🚨 LIVE INCIDENT — {incident.attack_type?.replace(/_/g, ' ') || 'THREAT DETECTED'}
          </span>
          <span style={{
            padding: '2px 10px', borderRadius: 3,
            background: sevColor + '33', border: `1px solid ${sevColor}`,
            ...m(10, sevColor), fontWeight: 'bold', letterSpacing: 2,
          }}>{sev}</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <span style={{ ...m(10, C.muted), letterSpacing: 1 }}>
            Detection: <span style={{ color: C.green }}>{elapsed}s</span>
          </span>
          <button onClick={onDismiss} style={{
            background: 'transparent', border: `1px solid ${C.muted}`,
            borderRadius: 4, color: C.muted, cursor: 'pointer',
            padding: '3px 8px', fontFamily: 'monospace', fontSize: 10,
          }}>✕ DISMISS</button>
        </div>
      </div>

      {/* ── Main content ────────────────────────────── */}
      <div style={{ padding: 20, display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 220px', gap: 16 }}>

        {/* Col 1: Attacker Info */}
        <div>
          <div style={sLabel}>ATTACKER INFORMATION</div>
          {[
            ['Source IP',    attacker.ip       || 'Unknown'],
            ['Source Port',  attacker.port     || 'Unknown'],
            ['Protocol',     attacker.protocol || 'TCP'],
            ['MAC Address',  attacker.mac      || 'Unknown'],
            ['Destination',  `${incident.target?.ip || '?'}:${incident.target?.port || '?'}`],
          ].map(([k, v]) => (
            <div key={k} style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6, borderBottom: '1px solid #0d0d1a', paddingBottom: 4 }}>
              <span style={m(10, C.muted)}>{k}</span>
              <span style={{ ...m(10, attacker.ip && k === 'Source IP' ? sevColor : '#ccc'), fontWeight: k === 'Source IP' ? 'bold' : 'normal' }}>{v}</span>
            </div>
          ))}

          {/* Geo */}
          <div style={{ marginTop: 12, padding: '8px 10px', background: '#080818', border: '1px solid #111', borderRadius: 4 }}>
            <div style={{ ...m(9, C.muted), letterSpacing: 2, marginBottom: 4 }}>📍 LOCATION</div>
            {geo.type === 'private' ? (
              <div style={m(11, C.blue)}>LOCAL NETWORK</div>
            ) : geo.type === 'approximate' ? (
              <>
                <div style={{ ...m(12, C.blue), fontWeight: 'bold' }}>{geoLine}</div>
                <div style={{ ...m(9, C.muted), marginTop: 2 }}>ISP: {geo.isp || 'Unknown'}</div>
                <div style={{ ...m(9, C.muted) }}>ASN: {geo.asn || 'Unknown'}</div>
                <div style={{ ...m(8, '#333'), marginTop: 4 }}>⚠ APPROXIMATE IP GEOLOCATION</div>
              </>
            ) : (
              <div style={m(10, C.muted)}>Location: Unknown</div>
            )}
          </div>
        </div>

        {/* Col 2: Attack Details */}
        <div>
          <div style={sLabel}>ATTACK DETAILS</div>
          {[
            ['Attack Type',  incident.attack_type?.replace(/_/g, ' ') || '?'],
            ['MITRE',        mitre.id ? `${mitre.id} — ${mitre.name}` : 'N/A'],
            ['Ports Hit',    network.ports_hit?.length ? `${network.ports_hit.length} ports` : network.connection_count ? `${network.connection_count} conns` : '—'],
            ['Target Port',  network.target_port || '—'],
            ['Process',      process.name || '—'],
            ['PID',          process.pid || '—'],
          ].map(([k, v]) => (
            <div key={k} style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6, borderBottom: '1px solid #0d0d1a', paddingBottom: 4 }}>
              <span style={m(10, C.muted)}>{k}</span>
              <span style={m(10, '#ccc')}>{v}</span>
            </div>
          ))}

          {/* Honeypot indicator */}
          {(statuses.honeypot || incident.honeypot?.triggered) && (
            <div style={{
              marginTop: 10, padding: '8px 10px',
              background: '#1a0000', border: `1px solid ${C.red}55`,
              borderRadius: 4,
            }}>
              <div style={{ ...m(10, C.red), fontWeight: 'bold' }}>🍯 HONEYPOT TRIGGERED</div>
              <div style={{ ...m(9, C.muted), marginTop: 3 }}>
                {incident.honeypot?.resource || 'Decoy resource accessed'}
              </div>
            </div>
          )}
        </div>

        {/* Col 3: Risk Score */}
        <div>
          <div style={sLabel}>RISK ASSESSMENT</div>

          {/* Big score */}
          <div style={{ textAlign: 'center', marginBottom: 16 }}>
            <div style={{
              ...m(56, riskColor), fontWeight: 'bold', lineHeight: 1,
              textShadow: `0 0 30px ${riskColor}88`,
            }}>{score.toFixed(0)}</div>
            <div style={{ ...m(10, C.muted), letterSpacing: 2, marginTop: 4 }}>RISK SCORE / 100</div>
            <div style={{
              display: 'inline-block', marginTop: 8, padding: '4px 14px',
              background: riskColor + '22', border: `1px solid ${riskColor}`,
              borderRadius: 4, ...m(11, riskColor), fontWeight: 'bold', letterSpacing: 3,
            }}>{incident.risk_level || 'HIGH'}</div>
          </div>

          {/* Factor bars */}
          <div style={{ marginBottom: 8 }}>
            {(incident.risk_factors || []).slice(0, 4).map((f, i) => (
              <div key={i} style={{ marginBottom: 6 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 2 }}>
                  <span style={m(9, C.muted)}>{f.name}</span>
                  <span style={{ ...m(9, C.blue), fontWeight: 'bold' }}>+{(f.contribution || 0).toFixed(1)}</span>
                </div>
                <div style={{ height: 3, background: '#111', borderRadius: 2 }}>
                  <div style={{
                    width: `${Math.min(((f.contribution || 0) / (f.weight || 25)) * 100, 100)}%`,
                    height: '100%', background: C.blue, borderRadius: 2,
                  }} />
                </div>
              </div>
            ))}
            {(!incident.risk_factors || incident.risk_factors.length === 0) && (
              <div style={m(9, C.muted)}>Risk factors loading...</div>
            )}
          </div>
        </div>

        {/* Col 4: Response Status + Actions */}
        <div>
          <div style={sLabel}>RESPONSE STATUS</div>

          {/* Status badges */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 6, marginBottom: 16 }}>
            <StatusBadge label="DETECTED"   active={statuses.detected}   activeColor={C.green} />
            <StatusBadge label="HONEYPOT"   active={statuses.honeypot}   activeColor={C.red} />
            <StatusBadge label="ML ENGINE"  active={statuses.ml}         activeColor={C.blue} />
            <StatusBadge label="QUARANTINE" active={statuses.quarantine} activeColor={C.orange} />
            <StatusBadge label="EVIDENCE"   active={statuses.evidence}   activeColor={C.purple} />
            <StatusBadge label="BLOCKCHAIN" active={statuses.blockchain} activeColor={C.blue} />
          </div>

          {/* Action buttons */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            {incident.incident_id && (
              <button onClick={() => navigate(`/incidents/${incident.incident_id}`)} style={{
                padding: '8px', fontSize: 9, letterSpacing: 2, fontFamily: 'monospace',
                background: sevColor + '22', border: `1px solid ${sevColor}`,
                borderRadius: 4, color: sevColor, cursor: 'pointer',
              }}>📋 VIEW INCIDENT</button>
            )}
            <button onClick={() => navigate('/incidents')} style={{
              padding: '8px', fontSize: 9, letterSpacing: 2, fontFamily: 'monospace',
              background: '#ff8c0011', border: `1px solid ${C.orange}`,
              borderRadius: 4, color: C.orange, cursor: 'pointer',
            }}>🚨 ALL INCIDENTS</button>
            <button onClick={() => navigate('/lab')} style={{
              padding: '8px', fontSize: 9, letterSpacing: 2, fontFamily: 'monospace',
              background: '#00d4ff11', border: `1px solid ${C.blue}`,
              borderRadius: 4, color: C.blue, cursor: 'pointer',
            }}>🔬 CYBER LAB</button>
            <button onClick={() => navigate('/network')} style={{
              padding: '8px', fontSize: 9, letterSpacing: 2, fontFamily: 'monospace',
              background: '#00ff8811', border: `1px solid ${C.green}`,
              borderRadius: 4, color: C.green, cursor: 'pointer',
            }}>🌐 NETWORK</button>
          </div>
        </div>
      </div>

      {/* ── Bottom: ports list if port scan ─────────── */}
      {network.ports_hit?.length > 0 && (
        <div style={{ borderTop: '1px solid #111', padding: '10px 20px', background: '#030308' }}>
          <span style={{ ...m(9, C.muted), letterSpacing: 2, marginRight: 12 }}>PORTS SCANNED:</span>
          {network.ports_hit.slice(0, 30).map(p => (
            <span key={p} style={{
              display: 'inline-block', margin: '2px 3px', padding: '1px 6px',
              background: '#0a0a1a', border: '1px solid #1a1a2e', borderRadius: 3,
              ...m(9, C.muted),
            }}>{p}</span>
          ))}
          {network.ports_hit.length > 30 && (
            <span style={m(9, C.muted)}> +{network.ports_hit.length - 30} more</span>
          )}
        </div>
      )}

      {/* ── Threat Intelligence ─────────────────────── */}
      {attacker.ip && (
        <div style={{ borderTop: '1px solid #111', padding: '14px 20px', background: '#030308' }}>
          <ThreatIntelPanel
            ip={attacker.ip}
            inlineData={incident.threat_intel}
          />
        </div>
      )}
    </div>
  )
}

// ══════════════════════════════════════════════════════════
// MAIN DASHBOARD
// ══════════════════════════════════════════════════════════
export default function Dashboard() {
  const [stats,       setStats]       = useState(null)
  const [threats,     setThreats]     = useState([])
  const [incidents,   setIncidents]   = useState([])
  const [hpStatus,    setHpStatus]    = useState(null)
  const [labStatus,   setLabStatus]   = useState(null)
  const [secEvents,   setSecEvents]   = useState([])
  const [liveIncident, setLiveIncident] = useState(null)   // the big card
  const [liveAlerts,  setLiveAlerts]  = useState([])
  const [loading,     setLoading]     = useState(true)
  const navigate  = useNavigate()
  const socketRef = useRef(null)

  const role     = localStorage.getItem('role')
  const username = localStorage.getItem('user')
  const isAdmin  = role === 'admin'
  const logout   = () => { localStorage.clear(); navigate('/login', { replace: true }) }

  // ── WebSocket ─────────────────────────────────────────
  useEffect(() => {
    const socket = io('http://localhost:5000', { transports: ['websocket'] })
    socketRef.current = socket

    // THE main event — any real or simulated attack → show incident card
    socket.on('live_incident', (data) => {
      setLiveIncident(data)
      // Also add to alert feed
      const ts  = new Date().toLocaleTimeString()
      const col = SEV[data.severity] || C.orange
      setLiveAlerts(prev => [{
        ts,
        msg:  `${data.attack_type?.replace(/_/g, ' ')} — Risk ${Math.round(data.risk_score || 0)}/100`,
        col,
        src:  (data.attacker || {}).ip || '',
        geo:  ((data.attacker || {}).geo || {}).city
              ? `${(data.attacker.geo).city}, ${(data.attacker.geo).country}`
              : '',
      }, ...prev.slice(0, 14)])
      loadData()
    })

    // Network alert without full incident yet
    socket.on('network_alert', (data) => {
      const ts  = new Date().toLocaleTimeString()
      const col = SEV[data.severity] || C.orange
      setLiveAlerts(prev => [{
        ts,
        msg:  data.description || data.type || 'Network alert',
        col,
        src:  data.ip || '',
        geo:  '',
      }, ...prev.slice(0, 14)])
    })

    socket.on('honeypot_triggered', (entry) => {
      const ts = new Date().toLocaleTimeString()
      setLiveAlerts(prev => [{
        ts,
        msg: `🍯 HONEYPOT: ${entry.resource} — ${entry.process_name || '?'}`,
        col: C.red, src: entry.source_ip || '', geo: '',
      }, ...prev.slice(0, 14)])
      // Update live incident card if one is showing
      setLiveIncident(prev => prev ? {
        ...prev,
        honeypot:   { triggered: true, resource: entry.resource },
        status:     { ...prev.status, honeypot: true },
      } : prev)
      loadData()
    })

    socket.on('security_event', (ev) => {
      if (ev.severity === 'CRITICAL' || ev.severity === 'HIGH') {
        const ts  = new Date().toLocaleTimeString()
        setLiveAlerts(prev => [{
          ts, msg: ev.description || ev.event_type || 'Event',
          col: SEV[ev.severity] || C.orange,
          src: (ev.source || {}).ip || '', geo: '',
        }, ...prev.slice(0, 14)])
      }
      setSecEvents(prev => [ev, ...prev.slice(0, 49)])
    })

    socket.on('incident_created', () => loadData())
    socket.on('incident_updated', () => loadData())
    socket.on('file_scanned',     () => loadData())

    return () => socket.disconnect()
  }, [])

  // ── Data fetch ────────────────────────────────────────
  const loadData = async () => {
    try {
      const [s, t, inc, hp, lab] = await Promise.all([
        getStats(),
        getThreats(),
        getIncidents({ limit: 5 }).catch(() => ({ data: { incidents: [] } })),
        getHoneypotStatus().catch(() => ({ data: {} })),
        getLabStatus().catch(() => ({ data: {} })),
      ])
      setStats(s.data)
      setThreats(t.data.slice(0, 10))
      setIncidents(inc.data.incidents || [])
      setHpStatus(hp.data)
      setLabStatus(lab.data)
    } catch (err) {
      if (err?.response?.status === 401) {
        localStorage.clear()
        navigate('/login', { replace: true })
      }
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadData()
    const id = setInterval(loadData, 10000)
    return () => clearInterval(id)
  }, [])

  // ── Derived ───────────────────────────────────────────
  const activeInc  = incidents.filter(i => i.status === 'ACTIVE').length
  const hpTriggers = hpStatus?.trigger_count || 0
  const labRunning = labStatus?.active_scenario
  const bcMode     = labStatus?.blockchain_mode || 'local'

  const topCards = stats ? [
    { label: 'FILES SCANNED',    value: stats.total_scanned,       color: C.blue,   icon: '📁' },
    { label: 'RANSOMWARE',       value: stats.active_threats,      color: C.red,    icon: '🦠' },
    { label: 'HIGH RISK',        value: stats.high_risk_alerts,    color: C.orange, icon: '⚠️' },
    { label: 'SUSPICIOUS',       value: stats.medium_threats,      color: C.yellow, icon: '🟡' },
    { label: 'ACTIVE INCIDENTS', value: activeInc,                 color: C.red,    icon: '🚨' },
    { label: 'HONEYPOT HITS',    value: hpTriggers,                color: C.red,    icon: '🍯' },
    { label: 'SYSTEM HEALTH',    value: `${stats.system_health}%`, color: C.green,  icon: '💚' },
    { label: 'BLOCKCHAIN',       value: bcMode.toUpperCase(),      color: C.blue,   icon: '⛓' },
  ] : []

  const services = [
    { name: 'ML Engine',    ok: true,                                 val: 'RF + DNN ONLINE' },
    { name: 'Blockchain',   ok: true,                                 val: bcMode.toUpperCase() },
    { name: 'File Monitor', ok: true,                                 val: 'watched/ ACTIVE' },
    { name: 'Honeypot',     ok: labStatus?.honeypot_active !== false, val: `${hpTriggers} triggers` },
    { name: 'Cyber Lab',    ok: true,                                 val: labRunning ? '🔴 SIM ACTIVE' : '🟢 READY' },
    { name: 'WebSocket',    ok: !!socketRef.current?.connected,       val: socketRef.current?.connected ? 'LIVE' : 'OFFLINE' },
  ]

  // Heatmap
  const dayMap = {}
  threats.forEach(t => { const d = (t.timestamp || '').slice(0, 10); if (d) dayMap[d] = (dayMap[d] || 0) + 1 })
  const today = new Date()
  const allDays = Array.from({ length: 112 }, (_, i) => {
    const d = new Date(today); d.setDate(today.getDate() - (111 - i))
    return d.toISOString().slice(0, 10)
  })
  const weeks = []; for (let w = 0; w < 16; w++) weeks.push(allDays.slice(w * 7, w * 7 + 7))
  const maxCount = Math.max(1, ...Object.values(dayMap))
  const cellColor = (date) => {
    const c = dayMap[date] || 0
    if (!c) return '#0a0a1a'
    const pct = c / maxCount
    return pct > 0.7 ? C.red : pct > 0.35 ? C.orange : '#00ff8855'
  }

  return (
    <div style={{ minHeight: '100vh', background: C.bg, padding: 24, fontFamily: 'monospace' }}>

      {/* ── Header ────────────────────────────────────── */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 20, flexWrap: 'wrap', gap: 12 }}>
        <div>
          <h1 style={{ ...m(20, '#fff'), fontWeight: 'bold', letterSpacing: 4, margin: '0 0 4px' }}>
            🛡️ CYBERDEFENSE AI — SOC PLATFORM
          </h1>
          <p style={{ ...m(10, C.muted), letterSpacing: 2, margin: 0 }}>
            Welcome, <span style={{ color: C.blue }}>{username}</span>
            {' '}— <span style={{ color: isAdmin ? C.red : C.blue }}>{role?.toUpperCase()}</span>
            {labRunning && <span style={{ marginLeft: 16, color: C.red }}> 🔴 SIM ACTIVE</span>}
            {liveIncident && <span style={{ marginLeft: 12, color: C.orange }}> 🚨 INCIDENT IN PROGRESS</span>}
          </p>
        </div>
        <div style={{ display: 'flex', gap: 5, flexWrap: 'wrap' }}>
          {[
            { to: '/threats',    label: '⚡ THREATS',   color: C.blue },
            { to: '/soc',        label: '🖥 SOC',       color: C.green },
            { to: '/lab',        label: '🔬 CYBER LAB', color: C.red },
            { to: '/incidents',  label: '🚨 INCIDENTS', color: C.orange },
            { to: '/network',    label: '🌐 NETWORK',   color: C.green },
            { to: '/analytics',  label: '📊 ANALYTICS', color: C.blue },
            { to: '/blockchain', label: '⛓ CHAIN',      color: C.blue },
            { to: '/chat',       label: '🤖 AI',        color: C.purple },
            { to: '/audit',      label: '📋 AUDIT',     color: C.purple },
            ...(isAdmin ? [{ to: '/admin', label: '⚙️ ADMIN', color: C.red }] : []),
          ].map(({ to, label, color }) => (
            <Link key={to} to={to} style={navBtn(color)}
              onMouseEnter={e => { e.target.style.background = color; e.target.style.color = '#000' }}
              onMouseLeave={e => { e.target.style.background = 'transparent'; e.target.style.color = color }}>
              {label}
            </Link>
          ))}
          <button onClick={logout} style={navBtn(C.red)}
            onMouseEnter={e => { e.target.style.background = C.red; e.target.style.color = '#000' }}
            onMouseLeave={e => { e.target.style.background = 'transparent'; e.target.style.color = C.red }}>
            🚪 LOGOUT
          </button>
        </div>
      </div>

      {loading ? (
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: 300, flexDirection: 'column', gap: 16 }}>
          <div style={{ fontSize: 40 }}>⚡</div>
          <p style={{ ...m(12, C.blue), letterSpacing: 4 }}>LOADING SOC DATA...</p>
        </div>
      ) : (
        <>
          {/* ════════════════════════════════════════════ */}
          {/* LIVE INCIDENT CARD — shown on attack detect  */}
          {/* ════════════════════════════════════════════ */}
          {liveIncident && (
            <LiveIncidentCard
              incident={liveIncident}
              onDismiss={() => setLiveIncident(null)}
              navigate={navigate}
            />
          )}

          {/* ════════════════════════════════════════════ */}
          {/* TOP METRIC CARDS                            */}
          {/* ════════════════════════════════════════════ */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(8,1fr)', gap: 10, marginBottom: 16 }}>
            {topCards.map((c, i) => (
              <div key={i} style={{ ...cardStyle({ padding: 14 }), borderColor: c.color + '33', textAlign: 'center' }}>
                <div style={{ fontSize: 18, marginBottom: 4 }}>{c.icon}</div>
                <div style={{ ...m(20, c.color), fontWeight: 'bold', lineHeight: 1, textShadow: `0 0 10px ${c.color}66` }}>
                  {c.value ?? '—'}
                </div>
                <div style={{ ...m(8, C.muted), letterSpacing: 2, marginTop: 4 }}>{c.label}</div>
              </div>
            ))}
          </div>

          {/* ════════════════════════════════════════════ */}
          {/* ROW 2: System | Live Alerts | Incidents     */}
          {/* ════════════════════════════════════════════ */}
          <div style={{ display: 'grid', gridTemplateColumns: '250px 1fr 300px', gap: 14, marginBottom: 14 }}>

            {/* System Status */}
            <div style={cardStyle()}>
              <div style={sLabel}>SYSTEM STATUS</div>
              {services.map((s, i) => (
                <div key={i} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 9 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
                    <Dot ok={s.ok} pulse={s.name === 'WebSocket' && s.ok} />
                    <span style={m(10, '#aaa')}>{s.name}</span>
                  </div>
                  <span style={{ ...m(9, s.ok ? C.green : C.red), maxWidth: 110, textAlign: 'right' }}>{s.val}</span>
                </div>
              ))}
              <div style={{ marginTop: 12, borderTop: `1px solid ${C.dim}`, paddingTop: 10, display: 'flex', flexDirection: 'column', gap: 6 }}>
                <button onClick={() => navigate('/lab')} style={{
                  padding: '7px', fontSize: 9, letterSpacing: 2, fontFamily: 'monospace',
                  background: '#ff003c11', border: `1px solid ${C.red}`, borderRadius: 4, color: C.red, cursor: 'pointer',
                }}>🔬 CYBER LAB</button>
                <button onClick={() => navigate('/soc')} style={{
                  padding: '7px', fontSize: 9, letterSpacing: 2, fontFamily: 'monospace',
                  background: '#00ff8811', border: `1px solid ${C.green}`, borderRadius: 4, color: C.green, cursor: 'pointer',
                }}>🖥 SOC WAR ROOM</button>
              </div>
            </div>

            {/* Live Alerts Feed */}
            <div style={{ ...cardStyle(), display: 'flex', flexDirection: 'column' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 10 }}>
                <div style={sLabel}>⚡ LIVE SECURITY ALERTS</div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                  <Dot ok pulse />
                  <span style={{ ...m(9, C.green), letterSpacing: 2 }}>LIVE</span>
                </div>
              </div>
              {liveAlerts.length === 0 ? (
                <div style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 8 }}>
                  <div style={{ fontSize: 28 }}>🟢</div>
                  <div style={m(11, C.muted)}>System nominal — no active alerts</div>
                  <div style={{ ...m(9, '#1a1a2e') }}>Run a simulation or trigger a real attack to see live detection</div>
                </div>
              ) : liveAlerts.map((a, i) => (
                <div key={i} style={{
                  display: 'flex', gap: 8, alignItems: 'flex-start', marginBottom: 6,
                  padding: '6px 8px', borderRadius: 4,
                  background: i === 0 ? a.col + '11' : 'transparent',
                  border: `1px solid ${i === 0 ? a.col + '44' : 'transparent'}`,
                  transition: 'all 0.3s',
                }}>
                  <span style={{ ...m(9, C.muted), whiteSpace: 'nowrap', flexShrink: 0 }}>{a.ts}</span>
                  <div style={{ flex: 1 }}>
                    <div style={m(10, a.col)}>{a.msg}</div>
                    {a.src && <div style={{ ...m(9, C.muted), marginTop: 1 }}>{a.src}{a.geo ? ` — ${a.geo}` : ''}</div>}
                  </div>
                </div>
              ))}
            </div>

            {/* Recent Incidents */}
            <div style={{ ...cardStyle(), display: 'flex', flexDirection: 'column' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 10 }}>
                <div style={sLabel}>🚨 INCIDENTS</div>
                <Link to="/incidents" style={{ ...m(9, C.blue), textDecoration: 'none' }}>VIEW ALL →</Link>
              </div>
              {incidents.length === 0 ? (
                <div style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 8 }}>
                  <div style={{ fontSize: 24 }}>✅</div>
                  <div style={m(11, C.muted)}>No incidents</div>
                  <button onClick={() => navigate('/lab')} style={{
                    padding: '5px 12px', fontSize: 9, fontFamily: 'monospace', letterSpacing: 2,
                    background: '#ff003c11', border: `1px solid ${C.red}`, borderRadius: 4, color: C.red, cursor: 'pointer',
                  }}>RUN SIMULATION →</button>
                </div>
              ) : incidents.map((inc, i) => {
                const col = SEV[inc.severity] || C.muted
                return (
                  <div key={i} onClick={() => navigate(`/incidents/${inc.id}`)} style={{
                    display: 'flex', gap: 8, alignItems: 'center', marginBottom: 8,
                    padding: '7px 10px', borderRadius: 6, cursor: 'pointer',
                    background: '#080818', border: `1px solid ${col}22`,
                  }}>
                    <div style={{ width: 8, height: 8, borderRadius: '50%', flexShrink: 0, background: col, boxShadow: `0 0 5px ${col}` }} />
                    <div style={{ flex: 1, overflow: 'hidden' }}>
                      <div style={{ ...m(10, '#ccc'), whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                        {inc.title || inc.attack_type}
                      </div>
                      <div style={{ ...m(9, C.muted), marginTop: 2 }}>
                        {inc.source_ip || ''}{inc.source_ip ? ' • ' : ''}{(inc.created_at || '').slice(11, 19)}
                        {inc.honeypot_hit ? ' 🍯' : ''}
                      </div>
                    </div>
                    <div style={{ ...m(16, col), fontWeight: 'bold' }}>{Math.round(inc.risk_score || 0)}</div>
                  </div>
                )
              })}
            </div>
          </div>

          {/* ════════════════════════════════════════════ */}
          {/* ROW 3: Timeline + Honeypot + Lab           */}
          {/* ════════════════════════════════════════════ */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 250px', gap: 14, marginBottom: 14 }}>
            <div style={cardStyle()}>
              <div style={sLabel}>📈 THREAT SCORE TIMELINE</div>
              {stats?.timeline?.length > 0 ? (
                <ResponsiveContainer width="100%" height={150}>
                  <AreaChart data={[...stats.timeline].reverse()}>
                    <defs>
                      <linearGradient id="sg" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%"  stopColor={C.red} stopOpacity={0.35} />
                        <stop offset="95%" stopColor={C.red} stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <XAxis dataKey="time" hide />
                    <YAxis domain={[0, 100]} tick={{ fill: C.muted, fontSize: 9, fontFamily: 'monospace' }} />
                    <Tooltip
                      contentStyle={{ background: C.card, border: `1px solid ${C.border}`, fontFamily: 'monospace', fontSize: 11, color: '#fff' }}
                      formatter={(v) => [v.toFixed(1), 'Score']}
                      labelFormatter={() => ''}
                    />
                    <Area type="monotone" dataKey="score" stroke={C.red} strokeWidth={2}
                      fill="url(#sg)" dot={false} activeDot={{ r: 4, fill: C.red }} />
                  </AreaChart>
                </ResponsiveContainer>
              ) : (
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: 120, ...m(11, C.muted) }}>
                  No data yet — scan files or run a simulation
                </div>
              )}
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              <div style={{ ...cardStyle({ padding: 14 }), borderColor: '#ff003c33', flex: 1 }}>
                <div style={sLabel}>🍯 HONEYPOT</div>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
                  <span style={m(10, '#aaa')}>Decoy Files</span>
                  <span style={{ ...m(14, C.blue), fontWeight: 'bold' }}>{hpStatus?.file_count || 7}</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={m(10, '#aaa')}>Triggers</span>
                  <span style={{ ...m(14, hpTriggers > 0 ? C.red : C.green), fontWeight: 'bold' }}>
                    {hpTriggers > 0 ? `🔴 ${hpTriggers}` : '🟢 0'}
                  </span>
                </div>
              </div>
              <div style={{ ...cardStyle({ padding: 14 }), borderColor: labRunning ? '#ff003c33' : C.border, flex: 1 }}>
                <div style={sLabel}>🔬 CYBER LAB</div>
                <div style={{ ...m(10, labRunning ? C.red : C.green), marginBottom: 8 }}>
                  {labRunning ? '🔴 SIMULATION RUNNING' : '🟢 READY'}
                </div>
                <button onClick={() => navigate('/lab')} style={{
                  display: 'block', width: '100%', padding: '6px', fontSize: 9, letterSpacing: 2,
                  fontFamily: 'monospace', background: '#ff003c11',
                  border: `1px solid ${C.red}`, borderRadius: 4, color: C.red, cursor: 'pointer',
                }}>OPEN LAB →</button>
              </div>
            </div>
          </div>

          {/* ════════════════════════════════════════════ */}
          {/* ROW 4: Heatmap                             */}
          {/* ════════════════════════════════════════════ */}
          {threats.length > 0 && (
            <div style={{ ...cardStyle(), marginBottom: 14 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 12 }}>
                <div style={sLabel}>📅 DETECTION HEATMAP — LAST 16 WEEKS</div>
                <div style={{ display: 'flex', gap: 6, alignItems: 'center', ...m(9, C.muted) }}>
                  LOW
                  {['#00ff8855', C.orange, C.red].map(c => (
                    <span key={c} style={{ width: 10, height: 10, background: c, borderRadius: 2, display: 'inline-block' }} />
                  ))}
                  HIGH
                </div>
              </div>
              <div style={{ display: 'flex', gap: 3 }}>
                {weeks.map((week, wi) => (
                  <div key={wi} style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
                    {week.map(date => (
                      <div key={date} title={`${date}: ${dayMap[date] || 0} detections`} style={{
                        width: 13, height: 13, borderRadius: 2,
                        background: cellColor(date),
                        border: date === today.toISOString().slice(0, 10) ? `1px solid ${C.blue}` : '1px solid transparent',
                        cursor: 'default', transition: 'transform 0.1s',
                      }}
                        onMouseEnter={e => e.target.style.transform = 'scale(1.3)'}
                        onMouseLeave={e => e.target.style.transform = 'scale(1)'}
                      />
                    ))}
                  </div>
                ))}
              </div>
              <div style={{ marginTop: 8, ...m(9, '#333') }}>
                {Object.values(dayMap).reduce((a, b) => a + b, 0)} total detections across {Object.keys(dayMap).length} active days
              </div>
            </div>
          )}

          {/* ════════════════════════════════════════════ */}
          {/* ROW 5: Security Events + File Scans        */}
          {/* ════════════════════════════════════════════ */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14, marginBottom: 14 }}>
            <div style={cardStyle()}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 10 }}>
                <div style={sLabel}>🔴 SECURITY EVENTS</div>
                <span style={{ ...m(9, C.muted) }}>{secEvents.length}</span>
              </div>
              {secEvents.length === 0 ? (
                <div style={{ ...m(10, C.muted), textAlign: 'center', padding: '16px 0' }}>
                  No events. <button onClick={() => navigate('/lab')} style={{ background: 'none', border: 'none', color: C.red, cursor: 'pointer', fontFamily: 'monospace', fontSize: 10 }}>Run a simulation →</button>
                </div>
              ) : secEvents.slice(0, 8).map((ev, i) => {
                const col = SEV[ev.severity] || C.muted
                return (
                  <div key={i} style={{ display: 'flex', gap: 8, marginBottom: 5, alignItems: 'baseline' }}>
                    <span style={{ ...m(9, C.muted), whiteSpace: 'nowrap' }}>{(ev.timestamp || '').slice(11, 19)}</span>
                    <span style={{ ...m(8, col), padding: '1px 5px', background: col + '22', borderRadius: 2, whiteSpace: 'nowrap' }}>{ev.severity}</span>
                    <span style={{ ...m(9, '#777'), whiteSpace: 'nowrap', maxWidth: 120, overflow: 'hidden', textOverflow: 'ellipsis' }}>{ev.event_type}</span>
                    <span style={{ ...m(9, '#aaa'), overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{ev.description}</span>
                  </div>
                )
              })}
            </div>

            <div style={cardStyle()}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 10 }}>
                <div style={sLabel}>🔍 FILE SCANNER</div>
                <Link to="/threats" style={{ ...m(9, C.blue), textDecoration: 'none' }}>VIEW ALL →</Link>
              </div>
              {threats.length === 0 ? (
                <div style={{ ...m(10, C.muted), textAlign: 'center', padding: '16px 0' }}>
                  No scans. <Link to="/threats" style={{ color: C.blue }}>Scan a file</Link> or run a simulation.
                </div>
              ) : threats.slice(0, 7).map((t, i) => {
                const col = t.prediction === 'Ransomware' ? C.red : t.prediction === 'Suspicious' ? C.orange : C.green
                return (
                  <div key={i} style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 7 }}>
                    <div style={{ width: 6, height: 6, borderRadius: '50%', background: col, flexShrink: 0 }} />
                    <div style={{ flex: 1, overflow: 'hidden' }}>
                      <div style={{ ...m(10, '#ccc'), whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{t.file_name}</div>
                      <ScoreBar score={t.threat_score || 0} />
                    </div>
                    <div style={{ textAlign: 'right', flexShrink: 0 }}>
                      <div style={{ ...m(11, col), fontWeight: 'bold' }}>{(t.threat_score || 0).toFixed(1)}</div>
                      <div style={{ ...m(8, col) }}>{t.prediction}</div>
                    </div>
                  </div>
                )
              })}
            </div>
          </div>

          {/* ════════════════════════════════════════════ */}
          {/* ROW 6: Full Detection Log                  */}
          {/* ════════════════════════════════════════════ */}
          <div style={cardStyle()}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 14 }}>
              <div style={sLabel}>📋 DETECTION LOG</div>
              <Link to="/threats" style={{ ...m(9, C.blue), textDecoration: 'none' }}>FULL PAGE →</Link>
            </div>
            <div style={{ overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', ...m(11) }}>
                <thead>
                  <tr style={{ borderBottom: `1px solid ${C.dim}` }}>
                    {['FILE', 'PREDICTION', 'SCORE', 'RISK', 'MITRE', 'AI SUMMARY', 'TIMESTAMP'].map(h => (
                      <th key={h} style={{ ...m(9, C.muted), textAlign: 'left', padding: '7px 12px', letterSpacing: 2, fontWeight: 'normal' }}>
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {threats.length === 0 ? (
                    <tr>
                      <td colSpan={7} style={{ textAlign: 'center', padding: 32, ...m(11, C.muted) }}>
                        No detections — <Link to="/threats" style={{ color: C.blue }}>scan a file</Link>
                        {' '}or <button onClick={() => navigate('/lab')} style={{ background: 'none', border: 'none', color: C.red, cursor: 'pointer', fontFamily: 'monospace', fontSize: 11 }}>start a simulation</button>
                      </td>
                    </tr>
                  ) : threats.map((t, i) => {
                    const sc = t.threat_score > 70 ? C.red : t.threat_score > 30 ? C.orange : C.green
                    const pc = t.prediction === 'Ransomware' ? C.red : t.prediction === 'Suspicious' ? C.orange : C.green
                    const rc = { HIGH: C.red, MEDIUM: C.orange, LOW: C.green }[t.risk_level] || C.muted
                    let mt = []
                    try { mt = JSON.parse(t.mitre_tactics || '[]') } catch {}
                    return (
                      <tr key={i} style={{ borderBottom: `1px solid ${C.dim}` }}
                        onMouseEnter={e => e.currentTarget.style.background = '#0d0d1a'}
                        onMouseLeave={e => e.currentTarget.style.background = 'transparent'}>
                        <td style={{ padding: '8px 12px', color: '#ccc', maxWidth: 140, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{t.file_name}</td>
                        <td style={{ padding: '8px 12px', color: pc, fontWeight: 'bold' }}>{t.prediction}</td>
                        <td style={{ padding: '8px 12px', color: sc, fontWeight: 'bold', textShadow: `0 0 6px ${sc}44` }}>{(t.threat_score || 0).toFixed(1)}</td>
                        <td style={{ padding: '8px 12px' }}>
                          <span style={{ padding: '2px 7px', borderRadius: 3, background: rc + '22', border: `1px solid ${rc}44`, ...m(9, rc), letterSpacing: 1 }}>
                            {t.risk_level || '—'}
                          </span>
                        </td>
                        <td style={{ padding: '8px 12px' }}>
                          {mt.slice(0, 2).map(mm => (
                            <a key={mm.id} href={mm.url} target="_blank" rel="noreferrer"
                              style={{ display: 'block', color: C.purple, fontSize: 9, textDecoration: 'none' }} title={mm.name}>
                              {mm.id}
                            </a>
                          ))}
                          {mt.length === 0 && <span style={{ color: C.muted }}>—</span>}
                        </td>
                        <td style={{ padding: '8px 12px', maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {t.ai_summary ? <span style={m(9, '#888')}>{t.ai_summary.slice(0, 65)}{t.ai_summary.length > 65 ? '…' : ''}</span> : <span style={{ color: C.muted }}>—</span>}
                        </td>
                        <td style={{ padding: '8px 12px', ...m(9, C.muted), whiteSpace: 'nowrap' }}>
                          {(t.timestamp || '').slice(0, 19).replace('T', ' ')}
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}

      <style>{`
        @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.3} }
        @keyframes scanLine { 0%{transform:translateX(-100%)} 100%{transform:translateX(100%)} }
        @keyframes incidentIn { from{opacity:0;transform:translateY(-12px)} to{opacity:1;transform:translateY(0)} }
      `}</style>
    </div>
  )
}
