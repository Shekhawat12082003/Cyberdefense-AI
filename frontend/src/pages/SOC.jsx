import { useState, useEffect, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import { io } from 'socket.io-client'
import axios from 'axios'
import { getStats, getThreats, getHoneypotStatus, getLabStatus, getIncidents } from '../api'
import {
  PieChart, Pie, Cell, Tooltip, ResponsiveContainer,
  BarChart, Bar, XAxis, YAxis
} from 'recharts'

const COLORS = ['#ff003c', '#ff8c00', '#00ff88']
const SEV_COLOR = { CRITICAL: '#ff003c', HIGH: '#ff8c00', MEDIUM: '#ffe600', LOW: '#00ff88', MODERATE: '#ffe600' }

// ══════════════════════════════════════════════════════════
// MATRIX RAIN
// ══════════════════════════════════════════════════════════
function MatrixRain() {
  const canvasRef = useRef(null)

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    const ctx = canvas.getContext('2d')

    const resize = () => {
      canvas.width  = window.innerWidth
      canvas.height = window.innerHeight
    }
    resize()
    window.addEventListener('resize', resize)

    const chars   = '01アイウエオカキクケコサシスセソタチツテトナニヌネノ'
    const fontSize = 13
    const cols    = Math.floor(canvas.width / fontSize)
    const drops   = Array(cols).fill(1)

    const draw = () => {
      ctx.fillStyle = 'rgba(0,0,16,0.05)'
      ctx.fillRect(0, 0, canvas.width, canvas.height)
      ctx.fillStyle = '#003322'
      ctx.font      = `${fontSize}px monospace`
      drops.forEach((y, i) => {
        const char = chars[Math.floor(Math.random() * chars.length)]
        ctx.fillStyle = Math.random() > 0.97 ? '#00ff88' : '#003322'
        ctx.fillText(char, i * fontSize, y * fontSize)
        if (y * fontSize > canvas.height && Math.random() > 0.975) drops[i] = 0
        drops[i]++
      })
    }

    const id = setInterval(draw, 60)
    return () => {
      clearInterval(id)
      window.removeEventListener('resize', resize)
    }
  }, [])

  return (
    <canvas ref={canvasRef} style={{
      position: 'fixed', top: 0, left: 0,
      width: '100%', height: '100%',
      zIndex: 0, opacity: 0.18
    }} />
  )
}

// ══════════════════════════════════════════════════════════
// LIVE CLOCK
// ══════════════════════════════════════════════════════════
function LiveClock() {
  const [time, setTime] = useState(new Date())
  useEffect(() => {
    const id = setInterval(() => setTime(new Date()), 1000)
    return () => clearInterval(id)
  }, [])
  return (
    <div style={{ textAlign: 'right', fontFamily: 'monospace' }}>
      <div style={{ color: '#00d4ff', fontSize: 28, fontWeight: 'bold', letterSpacing: 4 }}>
        {time.toLocaleTimeString()}
      </div>
      <div style={{ color: '#444', fontSize: 11, letterSpacing: 3 }}>
        {time.toLocaleDateString('en-US', { weekday: 'short', year: 'numeric', month: 'short', day: 'numeric' })}
      </div>
    </div>
  )
}

// ══════════════════════════════════════════════════════════
// MAIN SOC PAGE
// ══════════════════════════════════════════════════════════
const ACTION_COLOR = {
  LOGIN_FAILED:       '#ff003c',
  LOGIN_SUCCESS:      '#00ff88',
  SCAN:               '#00d4ff',
  UPLOAD_SCAN:        '#00d4ff',
  THREATS_CLEARED:    '#ff8c00',
  QUARANTINE_CLEARED: '#ff8c00',
  USER_CREATED:       '#ffe600',
  USER_DELETED:       '#ff003c',
  PASSWORD_CHANGED:   '#ffe600',
  SETTINGS_CHANGED:   '#ff8c00',
  REPORT_DOWNLOAD:    '#aaa',
  CSV_EXPORT:         '#aaa',
}

function toFeedEntry(e) {
  const action = (e.action || e.action_type || '').trim()
  return {
    time:    new Date(e.timestamp).toLocaleTimeString(),
    action,
    user:    e.username || e.user || '—',
    details: e.details  || '',
    color:   ACTION_COLOR[action] || '#aaa'
  }
}

export default function SOC() {
  const [stats,       setStats]       = useState(null)
  const [threats,     setThreats]     = useState([])
  const [liveEvents,  setLiveEvents]  = useState([])   // real-time socket events
  const [history,     setHistory]     = useState([])   // DB audit log snapshot
  const [alertBanner, setAlertBanner] = useState(null)
  const [lastScore,   setLastScore]   = useState(null)
  const [hpStatus,    setHpStatus]    = useState(null)
  const [labStatus,   setLabStatus]   = useState(null)
  const [incidents,   setIncidents]   = useState([])
  const [secEvents,   setSecEvents]   = useState([])   // unified security events
  const [lastAttacker, setLastAttacker] = useState(null)
  const navigate = useNavigate()
  const socketRef = useRef(null)

  // Combined feed: live events on top, historical below (deduplicated by time+action)
  const activity = [...liveEvents, ...history.filter(h =>
    !liveEvents.some(l => l.time === h.time && l.action === h.action && l.user === h.user)
  )]

  // ── WebSocket ──────────────────────────────────────────
  useEffect(() => {
    const socket = io('http://localhost:5000', { transports: ['websocket'] })
    socketRef.current = socket

    socket.on('high_threat_alert', (data) => {
      setAlertBanner(data)
      setLastScore(Math.min(data.threat_score ?? 0, 100))
      if (data.source_ip) {
        setLastAttacker(data)
      }
      setTimeout(() => setAlertBanner(null), 8000)
    })

    socket.on('audit_event', (data) => {
      if (!data.action) return
      setLiveEvents(prev => [toFeedEntry(data), ...prev.slice(0, 499)])
    })

    // New: unified security events
    socket.on('security_event', (ev) => {
      const sev = ev.severity || 'LOW'
      setSecEvents(prev => [{
        ts:    (ev.timestamp || '').slice(11, 19),
        type:  ev.event_type || '?',
        sev,
        desc:  ev.description || ev.event_type || '',
        src:   (ev.source || {}).ip || '',
        color: SEV_COLOR[sev] || '#aaa',
      }, ...prev.slice(0, 199)])

      // Track latest attacker
      if ((ev.source || {}).ip) {
        setLastAttacker(ev)
      }
    })

    socket.on('honeypot_triggered', () => {
      fetchData()
    })

    socket.on('incident_created', () => {
      fetchData()
    })

    return () => socket.disconnect()
  }, [])

  // ── Data fetch ─────────────────────────────────────────
  const fetchData = async () => {
    try {
      const token = localStorage.getItem('token')
      const headers = token ? { Authorization: `Bearer ${token}` } : {}
      const [s, t, a, hp, lab, inc] = await Promise.all([
        getStats(),
        getThreats(),
        axios.get('http://localhost:5000/api/audit-log?limit=500', { headers }),
        getHoneypotStatus().catch(() => ({ data: {} })),
        getLabStatus().catch(() => ({ data: {} })),
        getIncidents({ limit: 20 }).catch(() => ({ data: { incidents: [] } })),
      ])
      setStats(s.data)
      const list = t.data.slice(0, 20)
      setThreats(list)
      if (list.length > 0) setLastScore(Math.min(list[0].threat_score ?? 0, 100))
      const entries = (a.data || []).filter(e => e.action).map(toFeedEntry)
      setHistory(entries)
      setHpStatus(hp.data)
      setLabStatus(lab.data)
      setIncidents(inc.data.incidents || [])
    } catch {}
  }

  useEffect(() => {
    fetchData()
    const id = setInterval(fetchData, 10000)
    return () => clearInterval(id)
  }, [])

  // ── Derived values ─────────────────────────────────────
  const threatLevel = !lastScore ? 'LOW'
    : lastScore > 70 ? 'CRITICAL'
    : lastScore > 50 ? 'HIGH'
    : lastScore > 30 ? 'MEDIUM'
    : 'LOW'

  const levelColor = {
    CRITICAL: '#ff003c', HIGH: '#ff8c00', MEDIUM: '#ffe600', LOW: '#00ff88'
  }[threatLevel]

  const pieData = stats ? [
    { name: 'Ransomware', value: stats.active_threats      || 0 },
    { name: 'Suspicious', value: stats.medium_threats      || 0 },
    { name: 'Benign',     value: (stats.total_scanned || 0) - (stats.active_threats || 0) - (stats.medium_threats || 0) }
  ].filter(d => d.value > 0) : []

  const barData = threats.slice(0, 8).map(t => ({
    name:  t.file_name?.substring(0, 10) || 'file',
    score: Math.min(t.threat_score ?? 0, 100)
  })).reverse()

  const activeIncidents  = incidents.filter(i => i.status === 'ACTIVE').length
  const criticalIncidents = incidents.filter(i => i.severity === 'CRITICAL').length
  const hpTriggers = hpStatus?.trigger_count || 0
  const labRunning = labStatus?.active_scenario

  const services = [
    { name: 'ML Engine',    ok: true },
    { name: 'Blockchain',   ok: true, val: (labStatus?.blockchain_mode || 'local').toUpperCase() },
    { name: 'File Monitor', ok: true },
    { name: 'Honeypot',     ok: labStatus?.honeypot_active !== false, val: `${labStatus?.honeypot_active !== false ? 'ACTIVE' : 'OFFLINE'} (${hpTriggers} hits)` },
    { name: 'Cyber Lab',    ok: true, val: labRunning ? '🔴 SIM RUNNING' : '🟢 READY' },
    { name: 'WebSocket',    ok: !!socketRef.current?.connected },
  ]

  // Attacker info from latest event
  const attSrcIp   = lastAttacker ? ((lastAttacker.source || {}).ip || lastAttacker.source_ip || null) : null
  const attProcName = lastAttacker ? ((lastAttacker.process || {}).name || lastAttacker.process_name || null) : null
  const attType    = lastAttacker ? ((lastAttacker.attack || {}).type || lastAttacker.event_type || lastAttacker.prediction || null) : null

  // ── Styles ─────────────────────────────────────────────
  const cardStyle = (border = '#00d4ff22') => ({
    background: 'rgba(0,10,30,0.85)',
    border: `1px solid ${border}`,
    borderRadius: 8,
    padding: 16,
    backdropFilter: 'blur(4px)'
  })

  const labelStyle = { color: '#444', fontFamily: 'monospace', fontSize: 10, letterSpacing: 3, marginBottom: 6 }
  const mono  = (sz = 13, color = '#fff') => ({ fontFamily: 'monospace', fontSize: sz, color })

  return (
    <div style={{ minHeight: '100vh', background: '#000010', position: 'relative' }}>

      <MatrixRain />

      {/* ── Alert Banner ───────────────────────────────── */}
      {alertBanner && (
        <div style={{
          position: 'fixed', top: 0, left: 0, right: 0, zIndex: 9999,
          background: 'linear-gradient(90deg, #ff003c, #ff8c00, #ff003c)',
          backgroundSize: '200% 100%',
          animation: 'alertSlide 1s ease-in-out infinite',
          padding: '12px 24px',
          textAlign: 'center',
          fontFamily: 'monospace',
          fontWeight: 'bold',
          fontSize: 14,
          letterSpacing: 3,
          color: '#fff',
          cursor: 'pointer',
        }} onClick={() => navigate('/incidents')}>
          🚨 {alertBanner.event_type || alertBanner.prediction?.toUpperCase() || 'HIGH THREAT'} DETECTED
          {attSrcIp ? ` — FROM ${attSrcIp}` : ''}
          {` — SCORE: ${Math.min(alertBanner.threat_score ?? 85, 100).toFixed(0)}`}
          {` — RISK: ${alertBanner.risk_level || 'HIGH'}`}
          &nbsp;&nbsp;[ VIEW INCIDENT → ]
        </div>
      )}

      <div style={{ position: 'relative', zIndex: 1, padding: '24px 28px', paddingTop: alertBanner ? 64 : 24 }}>

        {/* ── Header ──────────────────────────────────── */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 20 }}>
          <div>
            <h1 style={{ ...mono(22, '#fff'), fontWeight: 'bold', letterSpacing: 6, margin: '0 0 4px' }}>
              🛡️ CYBERDEFENSE SOC
            </h1>
            <p style={{ ...mono(10, '#444'), letterSpacing: 4, margin: 0 }}>SECURITY OPERATIONS CENTER — LIVE</p>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
            <LiveClock />
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              <button onClick={() => navigate('/lab')} style={{
                padding: '6px 14px', fontSize: 10, fontFamily: 'monospace', letterSpacing: 2,
                background: '#ff003c11', border: '1px solid #ff003c', borderRadius: 5,
                color: '#ff003c', cursor: 'pointer'
              }}>🔬 CYBER LAB</button>
              <button onClick={() => navigate('/incidents')} style={{
                padding: '6px 14px', fontSize: 10, fontFamily: 'monospace', letterSpacing: 2,
                background: '#ff8c0011', border: '1px solid #ff8c00', borderRadius: 5,
                color: '#ff8c00', cursor: 'pointer'
              }}>🚨 INCIDENTS</button>
              <button onClick={() => navigate('/')} style={{
                padding: '6px 14px', fontSize: 10, fontFamily: 'monospace', letterSpacing: 2,
                background: 'transparent', border: '1px solid #00d4ff', borderRadius: 5,
                color: '#00d4ff', cursor: 'pointer'
              }}>← DASHBOARD</button>
              <button onClick={() => document.documentElement.requestFullscreen?.()} style={{
                padding: '6px 14px', fontSize: 10, fontFamily: 'monospace', letterSpacing: 2,
                background: 'transparent', border: '1px solid #00ff88', borderRadius: 5,
                color: '#00ff88', cursor: 'pointer'
              }}>⛶ FULLSCREEN</button>
            </div>
          </div>
        </div>

        {/* ── Threat Level Banner ──────────────────────── */}
        <div style={{
          ...cardStyle(),
          borderColor: levelColor,
          marginBottom: 16,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: '12px 20px',
          boxShadow: `0 0 20px ${levelColor}44`
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
            <div style={{
              width: 12, height: 12, borderRadius: '50%',
              background: levelColor, boxShadow: `0 0 10px ${levelColor}`,
              animation: 'pulse 1s infinite'
            }} />
            <span style={{ ...mono(11, '#666'), letterSpacing: 3 }}>THREAT LEVEL</span>
            <span style={{ ...mono(18, levelColor), fontWeight: 'bold', letterSpacing: 6 }}>
              {threatLevel}
            </span>
            {labRunning && (
              <span style={{
                marginLeft: 16, padding: '3px 10px',
                background: '#ff003c22', border: '1px solid #ff003c',
                borderRadius: 4, ...mono(9, '#ff003c'), letterSpacing: 2,
                animation: 'pulse 1s infinite'
              }}>🔬 SIM ACTIVE: {labRunning}</span>
            )}
          </div>
          <div style={{ display: 'flex', gap: 24, alignItems: 'center' }}>
            {lastScore && (
              <div style={{ textAlign: 'right' }}>
                <div style={{ ...mono(32, levelColor), fontWeight: 'bold', lineHeight: 1 }}>
                  {Math.min(lastScore ?? 0, 100).toFixed(1)}
                </div>
                <div style={{ ...mono(9, '#444'), letterSpacing: 3 }}>LATEST SCORE</div>
              </div>
            )}
            <div style={{ textAlign: 'right' }}>
              <div style={{ ...mono(20, criticalIncidents > 0 ? '#ff003c' : '#444'), fontWeight: 'bold', lineHeight: 1 }}>
                {activeIncidents}
              </div>
              <div style={{ ...mono(9, '#444'), letterSpacing: 3 }}>ACTIVE INC.</div>
            </div>
          </div>
        </div>

        {/* ── TOP Stats Row ─────────────────────────────── */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(6, 1fr)', gap: 10, marginBottom: 16 }}>
          {[
            { label: 'TOTAL SCANNED',   value: stats?.total_scanned    ?? '—', icon: '📁', color: '#00d4ff' },
            { label: 'ACTIVE THREATS',  value: stats?.active_threats   ?? '—', icon: '🚨', color: '#ff003c' },
            { label: 'HIGH RISK',       value: stats?.high_risk_alerts ?? '—', icon: '⚠️',  color: '#ff8c00' },
            { label: 'SYSTEM HEALTH',   value: stats ? `${stats.system_health}%` : '—', icon: '💚', color: '#00ff88' },
            { label: 'HONEYPOT HITS',   value: hpTriggers,               icon: '🍯', color: '#ff003c' },
            { label: 'INCIDENTS',       value: activeIncidents,          icon: '📋', color: '#ffe600' },
          ].map(s => (
            <div key={s.label} style={{ ...cardStyle(), borderColor: s.color + '44', textAlign: 'center', padding: 12 }}>
              <div style={{ fontSize: 18, marginBottom: 4 }}>{s.icon}</div>
              <div style={{ ...mono(22, s.color), fontWeight: 'bold', lineHeight: 1 }}>{s.value}</div>
              <div style={{ ...mono(8, '#444'), letterSpacing: 2, marginTop: 3 }}>{s.label}</div>
            </div>
          ))}
        </div>

        {/* ── Attacker Panel (shows when attack detected) ── */}
        {lastAttacker && (
          <div style={{
            ...cardStyle('#ff003c44'),
            borderColor: '#ff003c',
            marginBottom: 16,
            boxShadow: '0 0 20px #ff003c22',
          }}>
            <div style={{ ...labelStyle, color: '#ff003c' }}>🎯 LIVE ATTACKER INTELLIGENCE</div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16 }}>
              <div>
                <div style={{ ...mono(9, '#444'), letterSpacing: 2, marginBottom: 4 }}>SOURCE IP</div>
                <div style={{ ...mono(16, '#ff003c'), fontWeight: 'bold' }}>{attSrcIp || 'Unknown'}</div>
                <div style={{ ...mono(9, '#555'), marginTop: 2 }}>
                  {attSrcIp && (attSrcIp.startsWith('192.168.') || attSrcIp.startsWith('10.') || attSrcIp.startsWith('172.'))
                    ? 'LOCAL NETWORK'
                    : attSrcIp ? 'EXTERNAL IP' : ''}
                </div>
              </div>
              <div>
                <div style={{ ...mono(9, '#444'), letterSpacing: 2, marginBottom: 4 }}>ATTACK TYPE</div>
                <div style={{ ...mono(13, '#ff8c00'), fontWeight: 'bold' }}>
                  {attType || 'UNKNOWN'}
                </div>
              </div>
              <div>
                <div style={{ ...mono(9, '#444'), letterSpacing: 2, marginBottom: 4 }}>PROCESS</div>
                <div style={{ ...mono(12, '#00d4ff') }}>
                  {attProcName || 'Unknown'}
                </div>
                {lastAttacker?.process_pid || (lastAttacker?.process || {}).pid ? (
                  <div style={{ ...mono(9, '#555') }}>
                    PID: {(lastAttacker?.process || {}).pid || lastAttacker?.process_pid}
                  </div>
                ) : null}
              </div>
              <div>
                <div style={{ ...mono(9, '#444'), letterSpacing: 2, marginBottom: 4 }}>LAST SEEN</div>
                <div style={{ ...mono(11, '#aaa') }}>
                  {(lastAttacker?.timestamp || '').slice(11, 19)}
                </div>
                <div style={{ ...mono(9, '#555'), marginTop: 2 }}>
                  {lastAttacker?.scenario_id ? `Scenario: ${lastAttacker.scenario_id.slice(0, 16)}` : ''}
                </div>
              </div>
            </div>
            <div style={{ marginTop: 10, display: 'flex', gap: 8 }}>
              <button onClick={() => navigate('/incidents')} style={{
                padding: '5px 12px', fontSize: 9, fontFamily: 'monospace', letterSpacing: 2,
                background: '#ff003c22', border: '1px solid #ff003c', borderRadius: 4,
                color: '#ff003c', cursor: 'pointer',
              }}>VIEW INCIDENT →</button>
              <button onClick={() => navigate('/lab')} style={{
                padding: '5px 12px', fontSize: 9, fontFamily: 'monospace', letterSpacing: 2,
                background: 'transparent', border: '1px solid #444', borderRadius: 4,
                color: '#555', cursor: 'pointer',
              }}>CYBER LAB</button>
            </div>
          </div>
        )}

        {/* ── Middle Row ──────────────────────────────── */}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 300px', gap: 14, marginBottom: 14 }}>

          {/* Recent Detections */}
          <div style={cardStyle()}>
            <div style={labelStyle}>RECENT DETECTIONS</div>
            {threats.slice(0, 6).map((t, i) => {
              const c = t.prediction === 'Ransomware' ? '#ff003c' : t.prediction === 'Suspicious' ? '#ff8c00' : '#00ff88'
              return (
                <div key={i} style={{ marginBottom: 10 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 3 }}>
                    <span style={{ ...mono(10, '#aaa'), overflow: 'hidden', whiteSpace: 'nowrap', maxWidth: 160, textOverflow: 'ellipsis' }}>
                      {t.file_name}
                    </span>
                    <span style={{ ...mono(10, c), fontWeight: 'bold' }}>{Math.min(t.threat_score ?? 0, 100).toFixed(1)}</span>
                  </div>
                  <div style={{ height: 4, background: '#0d0d1a', borderRadius: 2 }}>
                    <div style={{ width: `${Math.min(t.threat_score ?? 0, 100)}%`, height: '100%', background: c, borderRadius: 2, boxShadow: `0 0 6px ${c}` }} />
                  </div>
                </div>
              )
            })}
            {threats.length === 0 && (
              <div style={{ ...mono(10, '#333'), paddingTop: 10 }}>No detections yet. Drop a file into watched/ or run a simulation.</div>
            )}
          </div>

          {/* Score Bar Chart */}
          <div style={cardStyle()}>
            <div style={labelStyle}>THREAT SCORE HISTORY</div>
            {barData.length > 0 ? (
              <ResponsiveContainer width="100%" height={170}>
                <BarChart data={barData} margin={{ top: 0, bottom: 0, left: -20, right: 0 }}>
                  <XAxis dataKey="name" tick={{ fill: '#444', fontSize: 8 }} />
                  <YAxis domain={[0, 100]} tick={{ fill: '#444', fontSize: 8 }} />
                  <Tooltip
                    contentStyle={{ background: '#000a1e', border: '1px solid #00d4ff33', color: '#fff', fontFamily: 'monospace', fontSize: 11 }}
                    labelStyle={{ color: '#00d4ff', fontFamily: 'monospace', fontSize: 11 }}
                    itemStyle={{ color: '#fff', fontFamily: 'monospace', fontSize: 11 }}
                  />
                  <Bar dataKey="score" radius={[3, 3, 0, 0]}>
                    {barData.map((d, i) => (
                      <Cell key={i} fill={d.score > 70 ? '#ff003c' : d.score > 30 ? '#ff8c00' : '#00ff88'} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div style={{ ...mono(11, '#333'), textAlign: 'center', paddingTop: 40 }}>No data yet</div>
            )}
          </div>

          {/* System Services */}
          <div style={cardStyle()}>
            <div style={labelStyle}>SYSTEM STATUS</div>
            {services.map((s, i) => (
              <div key={i} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
                <span style={mono(11, '#aaa')}>{s.name}</span>
                <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                  <div style={{ width: 7, height: 7, borderRadius: '50%', background: s.ok ? '#00ff88' : '#ff003c', boxShadow: `0 0 6px ${s.ok ? '#00ff88' : '#ff003c'}` }} />
                  <span style={{ ...mono(9, s.ok ? '#00ff88' : '#ff003c'), letterSpacing: 1 }}>{s.val || (s.ok ? 'ONLINE' : 'OFFLINE')}</span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* ── Live Security Events + Feed Row ──────────── */}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14, marginBottom: 14 }}>

          {/* Live Security Events (new unified events) */}
          <div style={{ ...cardStyle('#ff003c22'), display: 'flex', flexDirection: 'column', maxHeight: 240 }}>
            <div style={{ ...labelStyle, display: 'flex', justifyContent: 'space-between' }}>
              <span>LIVE SECURITY EVENTS</span>
              <span style={{ color: '#333', fontSize: 9 }}>{secEvents.length} events</span>
            </div>
            <div style={{ overflowY: 'auto', flex: 1 }}>
              {secEvents.length === 0 ? (
                <div style={{ ...mono(10, '#333') }}>Waiting for events... Run a simulation to see live events.</div>
              ) : secEvents.slice(0, 30).map((e, i) => (
                <div key={i} style={{ display: 'flex', gap: 8, marginBottom: 3, alignItems: 'baseline' }}>
                  <span style={{ ...mono(9, '#333'), whiteSpace: 'nowrap', flexShrink: 0 }}>{e.ts}</span>
                  <span style={{
                    ...mono(8, e.color), whiteSpace: 'nowrap', flexShrink: 0,
                    padding: '1px 4px', background: e.color + '22', borderRadius: 2,
                    minWidth: 60, textAlign: 'center', letterSpacing: 1,
                  }}>{e.sev}</span>
                  <span style={{ ...mono(9, '#666'), whiteSpace: 'nowrap', flexShrink: 0, maxWidth: 130, overflow: 'hidden', textOverflow: 'ellipsis' }}>{e.type}</span>
                  <span style={{ ...mono(9, '#aaa'), overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{e.desc}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Audit Log Feed */}
          <div style={{ ...cardStyle(), display: 'flex', flexDirection: 'column', maxHeight: 240 }}>
            <div style={{ ...labelStyle, display: 'flex', justifyContent: 'space-between' }}>
              <span>PLATFORM ACTIVITY</span>
              <span style={{ color: '#333', fontSize: 9 }}>{activity.length} events</span>
            </div>
            <div style={{ overflowY: 'auto', flex: 1 }}>
              {activity.length === 0 ? (
                <div style={{ ...mono(11, '#333') }}>Waiting for events...</div>
              ) : activity.slice(0, 30).map((a, i) => (
                <div key={i} style={{ display: 'flex', gap: 8, marginBottom: 3, alignItems: 'baseline' }}>
                  <span style={{ ...mono(9, '#555'), whiteSpace: 'nowrap', flexShrink: 0 }}>{a.time}</span>
                  <span style={{ ...mono(9, a.color), whiteSpace: 'nowrap', flexShrink: 0, fontWeight: 'bold', minWidth: 110 }}>{a.action}</span>
                  <span style={{ ...mono(9, '#888'), whiteSpace: 'nowrap', flexShrink: 0, minWidth: 55 }}>{a.user}</span>
                  <span style={{ ...mono(9, '#555') }}>{a.details}</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* ── Bottom Row ──────────────────────────────── */}
        <div style={{ display: 'grid', gridTemplateColumns: '200px 1fr 240px', gap: 14 }}>

          {/* Pie Chart */}
          <div style={cardStyle()}>
            <div style={labelStyle}>DISTRIBUTION</div>
            {pieData.length > 0 ? (
              <>
                <ResponsiveContainer width="100%" height={120}>
                  <PieChart>
                    <Pie data={pieData} cx="50%" cy="50%" innerRadius={30} outerRadius={55} dataKey="value">
                      {pieData.map((_, i) => <Cell key={i} fill={COLORS[i % COLORS.length]} />)}
                    </Pie>
                    <Tooltip
                      contentStyle={{ background: '#000a1e', border: '1px solid #00d4ff33', color: '#fff', fontFamily: 'monospace', fontSize: 11 }}
                      labelStyle={{ color: '#00d4ff', fontFamily: 'monospace', fontSize: 11 }}
                      itemStyle={{ color: '#fff', fontFamily: 'monospace', fontSize: 11 }}
                    />
                  </PieChart>
                </ResponsiveContainer>
                {pieData.map((d, i) => (
                  <div key={i} style={{ display: 'flex', justifyContent: 'space-between', marginTop: 4 }}>
                    <span style={{ ...mono(9, COLORS[i]), letterSpacing: 1 }}>▪ {d.name}</span>
                    <span style={mono(9, '#888')}>{d.value}</span>
                  </div>
                ))}
              </>
            ) : (
              <div style={{ ...mono(11, '#333'), textAlign: 'center', paddingTop: 30 }}>No data</div>
            )}
          </div>

          {/* Recent Incidents */}
          <div style={{ ...cardStyle('#ff8c0022'), display: 'flex', flexDirection: 'column' }}>
            <div style={{ ...labelStyle, display: 'flex', justifyContent: 'space-between' }}>
              <span>RECENT INCIDENTS</span>
              <button onClick={() => navigate('/incidents')} style={{
                padding: '2px 8px', fontSize: 8, letterSpacing: 2, fontFamily: 'monospace',
                background: 'transparent', border: '1px solid #444', borderRadius: 3,
                color: '#555', cursor: 'pointer',
              }}>VIEW ALL →</button>
            </div>
            {incidents.length === 0 ? (
              <div style={{ ...mono(10, '#333') }}>No incidents. Run a simulation to generate incidents.</div>
            ) : incidents.slice(0, 5).map((inc, i) => {
              const col = SEV_COLOR[inc.severity] || '#aaa'
              return (
                <div
                  key={i}
                  onClick={() => navigate(`/incidents/${inc.id}`)}
                  style={{
                    display: 'flex', gap: 10, alignItems: 'center', marginBottom: 8,
                    cursor: 'pointer', padding: '5px 8px', borderRadius: 4,
                    background: '#05050f', border: `1px solid ${col}22`,
                  }}
                >
                  <div style={{ width: 8, height: 8, borderRadius: '50%', flexShrink: 0, background: col, boxShadow: `0 0 6px ${col}` }} />
                  <div style={{ flex: 1, overflow: 'hidden' }}>
                    <div style={{ ...mono(10, '#ccc'), overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {inc.title || inc.attack_type}
                    </div>
                    <div style={{ ...mono(9, '#444') }}>
                      {inc.source_ip ? `${inc.source_ip} • ` : ''}{(inc.created_at || '').slice(11, 19)}
                    </div>
                  </div>
                  <div style={{ ...mono(14, col), fontWeight: 'bold', flexShrink: 0 }}>
                    {Math.round(inc.risk_score || 0)}
                  </div>
                </div>
              )
            })}
          </div>

          {/* Quick Actions */}
          <div style={cardStyle()}>
            <div style={labelStyle}>QUICK ACTIONS</div>
            {[
              { label: '🔬 CYBER LAB',    path: '/lab',       color: '#ff003c' },
              { label: '🚨 INCIDENTS',    path: '/incidents', color: '#ff8c00' },
              { label: '🌐 NETWORK',      path: '/network',   color: '#00d4ff' },
              { label: '⛓ BLOCKCHAIN',   path: '/blockchain',color: '#00d4ff' },
              { label: '🤖 AI ANALYST',   path: '/chat',      color: '#9b59b6' },
              { label: '📋 AUDIT LOG',    path: '/audit',     color: '#aaa' },
            ].map((a, i) => (
              <button key={i} onClick={() => navigate(a.path)} style={{
                display: 'block', width: '100%', marginBottom: 6,
                padding: '7px 12px', fontSize: 9, fontFamily: 'monospace', letterSpacing: 2,
                background: a.color + '11', border: `1px solid ${a.color}44`,
                borderRadius: 4, color: a.color, cursor: 'pointer', textAlign: 'left',
              }}>{a.label}</button>
            ))}
          </div>
        </div>

      </div>

      <style>{`
        @keyframes pulse {
          0%, 100% { opacity: 1; }
          50%       { opacity: 0.3; }
        }
        @keyframes alertSlide {
          0%   { background-position: 0% 50%; }
          100% { background-position: 200% 50%; }
        }
      `}</style>
    </div>
  )
}
