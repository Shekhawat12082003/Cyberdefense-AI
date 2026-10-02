/**
 * LiveIncidentCard
 * Renders when a real or simulated attack is detected.
 * Shows: attacker intel, geolocation, risk score, status pipeline,
 * action buttons (graph, timeline, forensics, replay).
 */
import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'

const C = {
  bg:     '#000010',
  card:   '#05051a',
  red:    '#ff003c',
  orange: '#ff8c00',
  green:  '#00ff88',
  blue:   '#00d4ff',
  yellow: '#ffe600',
  purple: '#a78bfa',
  muted:  '#444',
  dim:    '#1a1a2e',
  text:   '#ccc',
}

const SEV_COLOR = {
  CRITICAL: C.red,
  HIGH:     C.orange,
  MODERATE: C.yellow,
  MEDIUM:   C.orange,
  LOW:      C.green,
}

const m = (sz = 11, color = C.text) => ({ fontFamily: 'monospace', fontSize: sz, color })

function StatusBadge({ label, done, active = false }) {
  const col = done ? C.green : active ? C.orange : C.muted
  return (
    <div style={{
      display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 4,
    }}>
      <div style={{
        width: 32, height: 32, borderRadius: '50%',
        border: `2px solid ${col}`,
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        background: done ? col + '22' : 'transparent',
        boxShadow: done ? `0 0 12px ${col}66` : 'none',
        transition: 'all 0.4s',
      }}>
        <span style={{ fontSize: 14 }}>
          {done ? '✓' : active ? '⋯' : '○'}
        </span>
      </div>
      <span style={{ ...m(8, col), letterSpacing: 1, textAlign: 'center', maxWidth: 60 }}>
        {label}
      </span>
    </div>
  )
}

function StatusPipeline({ status = {} }) {
  const steps = [
    { key: 'detected',   label: 'DETECTED' },
    { key: 'honeypot',   label: 'HONEYPOT' },
    { key: 'ml',         label: 'ML ENGINE' },
    { key: 'quarantine', label: 'QUARANTINE' },
    { key: 'evidence',   label: 'EVIDENCE' },
    { key: 'blockchain', label: 'BLOCKCHAIN' },
  ]

  return (
    <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 4 }}>
      {steps.map((s, i) => (
        <div key={s.key} style={{ display: 'flex', alignItems: 'center', flex: 1 }}>
          <div style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
            <StatusBadge label={s.label} done={status[s.key] === true} active={false} />
          </div>
          {i < steps.length - 1 && (
            <div style={{
              height: 2, flex: 0.5, marginBottom: 18,
              background: status[s.key] ? C.green : C.dim,
              transition: 'background 0.4s',
            }} />
          )}
        </div>
      ))}
    </div>
  )
}

function GeoPanel({ geo }) {
  if (!geo) return (
    <div style={{ ...m(10, C.muted), textAlign: 'center', padding: '8px 0' }}>Loading location...</div>
  )

  const t = geo.type || 'unknown'

  if (t === 'private') return (
    <div style={{ textAlign: 'center' }}>
      <div style={{ ...m(16, C.blue), fontWeight: 'bold', marginBottom: 4 }}>LOCAL NETWORK</div>
      <div style={{ ...m(9, C.muted) }}>Private / Internal IP</div>
      <div style={{ ...m(9, '#333'), marginTop: 2 }}>Not routable on internet</div>
    </div>
  )

  if (t === 'approximate') return (
    <div>
      <div style={{ ...m(13, C.orange), fontWeight: 'bold', marginBottom: 8 }}>
        📍 {geo.city}{geo.city && geo.country ? ', ' : ''}{geo.country}
      </div>
      {[
        ['Country',  geo.country],
        ['Region',   geo.region],
        ['City',     geo.city],
        ['ISP',      geo.isp],
        ['ASN',      geo.asn],
        ['Timezone', geo.timezone],
        ['Coords',   geo.lat ? `${Number(geo.lat).toFixed(2)}, ${Number(geo.lon).toFixed(2)}` : null],
      ].filter(([, v]) => v).map(([k, v]) => (
        <div key={k} style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
          <span style={m(9, C.muted)}>{k}</span>
          <span style={{ ...m(9, C.text), maxWidth: 140, textAlign: 'right', wordBreak: 'break-all' }}>{v}</span>
        </div>
      ))}
      <div style={{
        marginTop: 8, padding: '4px 6px', borderRadius: 3,
        background: '#00ff8811', border: `1px solid ${C.green}22`,
        ...m(8, '#00ff8877'),
      }}>⚠ APPROXIMATE — not exact location</div>
    </div>
  )

  return <div style={{ ...m(10, C.muted) }}>Location: Unknown</div>
}

function RiskMeter({ score = 0, level = 'LOW' }) {
  const col = SEV_COLOR[level] || C.green
  const pct = Math.min(score, 100)

  return (
    <div style={{ textAlign: 'center' }}>
      {/* Circular ring */}
      <div style={{
        width: 100, height: 100, margin: '0 auto 8px',
        borderRadius: '50%',
        background: `conic-gradient(${col} ${pct * 3.6}deg, ${C.dim} 0deg)`,
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        boxShadow: `0 0 24px ${col}44`,
        position: 'relative',
      }}>
        <div style={{
          width: 76, height: 76, borderRadius: '50%',
          background: C.card,
          display: 'flex', flexDirection: 'column',
          alignItems: 'center', justifyContent: 'center',
        }}>
          <div style={{ ...m(28, col), fontWeight: 'bold', lineHeight: 1 }}>{Math.round(score)}</div>
          <div style={{ ...m(8, C.muted), letterSpacing: 1 }}>/ 100</div>
        </div>
      </div>
      <div style={{
        display: 'inline-block', padding: '3px 12px', borderRadius: 4,
        background: col + '22', border: `1px solid ${col}`,
        ...m(11, col), fontWeight: 'bold', letterSpacing: 3,
      }}>{level}</div>
    </div>
  )
}

export default function LiveIncidentCard({ incident, onDismiss }) {
  const navigate = useNavigate()
  const [elapsed, setElapsed] = useState(0)
  const [status, setStatus] = useState(incident?.status || {})
  const [detectionTime] = useState(Date.now())

  // Elapsed timer
  useEffect(() => {
    const id = setInterval(() => setElapsed(((Date.now() - detectionTime) / 1000).toFixed(2)), 100)
    return () => clearInterval(id)
  }, [detectionTime])

  // Auto-progress status steps for simulation realism
  useEffect(() => {
    if (!incident) return
    const timers = []

    // Honeypot check (0.8s)
    timers.push(setTimeout(() => setStatus(s => ({ ...s, honeypot: incident?.honeypot?.triggered || false })), 800))
    // ML (1.5s)
    timers.push(setTimeout(() => setStatus(s => ({ ...s, ml: true })), 1500))
    // Quarantine (2.5s)
    timers.push(setTimeout(() => setStatus(s => ({ ...s, quarantine: true })), 2500))
    // Evidence (3.5s)
    timers.push(setTimeout(() => setStatus(s => ({ ...s, evidence: true })), 3500))
    // Blockchain (5s)
    timers.push(setTimeout(() => setStatus(s => ({ ...s, blockchain: true })), 5000))

    return () => timers.forEach(clearTimeout)
  }, [incident?.incident_id])

  if (!incident) return null

  const sev      = incident.severity || 'HIGH'
  const sevCol   = SEV_COLOR[sev] || C.orange
  const attacker = incident.attacker || {}
  const geo      = attacker.geo || {}
  const network  = incident.network || {}
  const proc     = incident.process || {}
  const hp       = incident.honeypot || {}
  const mitre    = incident.mitre || {}
  const factors  = incident.risk_factors || []
  const incId    = incident.incident_id

  const ATTACK_LABELS = {
    PORT_SCAN:          '🔍 PORT SCAN',
    BRUTE_FORCE:        '🔑 BRUTE FORCE',
    C2_BEACON:          '📡 C2 BEACON',
    DATA_EXFIL:         '📤 DATA EXFIL',
    DATA_EXFILTRATION:  '📤 DATA EXFIL',
    RANSOMWARE:         '🦠 RANSOMWARE',
    SUSPICIOUS_PROCESS: '⚙️ SUSP PROCESS',
    HONEYPOT_TRIGGERED: '🍯 HONEYPOT',
    PHISHING:           '🎣 PHISHING',
    FILE_RANSOMWARE_PAYLOAD: '🦠 RANSOMWARE FILE',
    FILE_RANSOMWARE_DROPPER: '🦠 DROPPER',
    HONEYPOT_ACCESS:    '🍯 HONEYPOT',
  }
  const attackLabel = ATTACK_LABELS[incident.attack_type] || incident.attack_type || 'UNKNOWN'

  return (
    <div style={{
      background: C.card,
      border: `1px solid ${sevCol}`,
      borderRadius: 12,
      boxShadow: `0 0 40px ${sevCol}33, 0 0 80px ${sevCol}11`,
      overflow: 'hidden',
      animation: 'incidentPulse 2s ease-in-out 1',
    }}>

      {/* ── Header bar ────────────────────────────────── */}
      <div style={{
        background: `linear-gradient(90deg, ${sevCol}33, transparent)`,
        borderBottom: `1px solid ${sevCol}44`,
        padding: '12px 20px',
        display: 'flex', justifyContent: 'space-between', alignItems: 'center',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <div style={{
            width: 10, height: 10, borderRadius: '50%',
            background: sevCol, boxShadow: `0 0 10px ${sevCol}`,
            animation: 'pulse 1s infinite',
          }} />
          <span style={{ ...m(15, '#fff'), fontWeight: 'bold', letterSpacing: 3 }}>
            {attackLabel}
          </span>
          <span style={{
            padding: '2px 8px', borderRadius: 3,
            background: sevCol + '22', border: `1px solid ${sevCol}`,
            ...m(9, sevCol), letterSpacing: 2, fontWeight: 'bold',
          }}>{sev}</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
          <div style={{ textAlign: 'right' }}>
            <div style={{ ...m(9, C.muted), letterSpacing: 2 }}>DETECTION TIME</div>
            <div style={{ ...m(13, C.green), fontWeight: 'bold' }}>{elapsed}s</div>
          </div>
          {onDismiss && (
            <button onClick={onDismiss} style={{
              background: 'transparent', border: `1px solid ${C.muted}`,
              borderRadius: 4, color: C.muted, cursor: 'pointer',
              fontFamily: 'monospace', fontSize: 10, padding: '3px 8px',
            }}>✕</button>
          )}
        </div>
      </div>

      <div style={{ padding: 20 }}>

        {/* ── Status Pipeline ──────────────────────────── */}
        <div style={{
          marginBottom: 20, padding: '12px 16px',
          background: '#000', borderRadius: 8, border: `1px solid ${C.dim}`,
        }}>
          <StatusPipeline status={{ detected: true, ...status }} />
        </div>

        {/* ── Main grid ────────────────────────────────── */}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 200px', gap: 16, marginBottom: 16 }}>

          {/* Left: Attacker Info */}
          <div style={{
            background: '#000', borderRadius: 8, padding: 14,
            border: `1px solid ${C.dim}`,
          }}>
            <div style={{ ...m(9, C.muted), letterSpacing: 3, marginBottom: 10 }}>ATTACKER INFORMATION</div>
            {[
              ['Source IP',   attacker.ip   || 'Unknown'],
              ['Source Port', attacker.port || 'Unknown'],
              ['Protocol',    attacker.protocol || 'TCP'],
              ['MAC Address', attacker.mac  || 'Unknown'],
              ['Dest IP',     (incident.target || {}).ip || 'Unknown'],
              ['Dest Port',   (incident.target || {}).port || 'Unknown'],
              ...(proc.name ? [
                ['Process',     proc.name],
                ['PID',         proc.pid || 'Unknown'],
              ] : []),
              ...(hp.triggered ? [
                ['Honeypot', <span style={{ color: C.red, fontWeight: 'bold' }}>🍯 TRIGGERED — {hp.resource || '?'}</span>],
              ] : []),
              ...(network.ports_hit?.length ? [
                ['Ports Scanned', network.ports_hit.slice(0, 5).join(', ') + (network.ports_hit.length > 5 ? '…' : '')],
              ] : []),
              ...(network.connection_count ? [
                ['Auth Attempts', network.connection_count],
              ] : []),
            ].map(([k, v], i) => (
              <div key={i} style={{
                display: 'flex', justifyContent: 'space-between',
                padding: '5px 0', borderBottom: `1px solid ${C.dim}`,
              }}>
                <span style={m(9, C.muted)}>{k}</span>
                <span style={{ ...m(9, C.text), maxWidth: 160, textAlign: 'right', wordBreak: 'break-all' }}>{v}</span>
              </div>
            ))}
            {mitre.id && (
              <div style={{ marginTop: 10 }}>
                <a href={mitre.url} target="_blank" rel="noreferrer" style={{
                  display: 'inline-block', padding: '3px 8px',
                  background: C.purple + '22', border: `1px solid ${C.purple}44`,
                  borderRadius: 3, ...m(9, C.purple), textDecoration: 'none',
                }}>
                  MITRE {mitre.id} — {mitre.name}
                </a>
              </div>
            )}
          </div>

          {/* Center: Geolocation */}
          <div style={{
            background: '#000', borderRadius: 8, padding: 14,
            border: `1px solid ${C.dim}`,
          }}>
            <div style={{ ...m(9, C.muted), letterSpacing: 3, marginBottom: 10 }}>
              APPROXIMATE LOCATION
            </div>
            <GeoPanel geo={geo} />
          </div>

          {/* Right: Risk Meter */}
          <div style={{
            background: '#000', borderRadius: 8, padding: 14,
            border: `1px solid ${C.dim}`,
            display: 'flex', flexDirection: 'column', alignItems: 'center',
          }}>
            <div style={{ ...m(9, C.muted), letterSpacing: 3, marginBottom: 12 }}>RISK SCORE</div>
            <RiskMeter score={incident.risk_score || 0} level={incident.risk_level || 'LOW'} />

            {factors.length > 0 && (
              <div style={{ width: '100%', marginTop: 14 }}>
                {factors.slice(0, 3).map((f, i) => (
                  <div key={i} style={{ marginBottom: 6 }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 2 }}>
                      <span style={m(8, C.muted)}>{f.name}</span>
                      <span style={{ ...m(9, C.blue), fontWeight: 'bold' }}>+{(f.contribution || 0).toFixed(1)}</span>
                    </div>
                    <div style={{ height: 3, background: C.dim, borderRadius: 2 }}>
                      <div style={{
                        width: `${Math.min(((f.contribution || 0) / (f.weight || 1)) * 100, 100)}%`,
                        height: '100%', background: C.blue, borderRadius: 2,
                      }} />
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* ── Live status badges ────────────────────────── */}
        <div style={{
          display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 16,
        }}>
          {[
            { key: 'detected',   icon: '🎯', label: 'DETECTED',   col: C.green },
            { key: 'honeypot',   icon: '🍯', label: 'HONEYPOT',   col: C.red   },
            { key: 'ml',         icon: '🤖', label: 'ML SCAN',    col: C.blue  },
            { key: 'quarantine', icon: '🔒', label: 'QUARANTINE', col: C.orange },
            { key: 'evidence',   icon: '📦', label: 'EVIDENCE',   col: C.blue  },
            { key: 'blockchain', icon: '⛓',  label: 'BLOCKCHAIN', col: C.purple },
          ].map(b => {
            const done = b.key === 'detected' ? true : (status[b.key] === true)
            return (
              <div key={b.key} style={{
                padding: '5px 10px', borderRadius: 5, display: 'flex', alignItems: 'center', gap: 5,
                background: done ? b.col + '22' : '#0a0a0a',
                border: `1px solid ${done ? b.col : C.dim}`,
                transition: 'all 0.4s',
              }}>
                <span style={{ fontSize: 12 }}>{b.icon}</span>
                <span style={{ ...m(9, done ? b.col : C.muted), letterSpacing: 1, fontWeight: done ? 'bold' : 'normal' }}>
                  {b.label}
                </span>
                {done && <span style={{ ...m(9, b.col) }}>✓</span>}
              </div>
            )
          })}
        </div>

        {/* ── Action buttons ────────────────────────────── */}
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          {incId && (
            <>
              <button onClick={() => navigate(`/incidents/${incId}`)} style={{
                padding: '8px 16px', fontSize: 10, fontFamily: 'monospace', letterSpacing: 2,
                background: sevCol + '22', border: `1px solid ${sevCol}`,
                borderRadius: 5, color: sevCol, cursor: 'pointer', fontWeight: 'bold',
              }}>📋 VIEW INCIDENT</button>

              <button onClick={() => navigate(`/incidents/${incId}?tab=graph`)} style={{
                padding: '8px 16px', fontSize: 10, fontFamily: 'monospace', letterSpacing: 2,
                background: C.blue + '11', border: `1px solid ${C.blue}`,
                borderRadius: 5, color: C.blue, cursor: 'pointer',
              }}>🕸 ATTACK GRAPH</button>

              <button onClick={() => navigate(`/incidents/${incId}?tab=timeline`)} style={{
                padding: '8px 16px', fontSize: 10, fontFamily: 'monospace', letterSpacing: 2,
                background: C.purple + '11', border: `1px solid ${C.purple}`,
                borderRadius: 5, color: C.purple, cursor: 'pointer',
              }}>📅 TIMELINE</button>

              <button onClick={() => navigate(`/incidents/${incId}?tab=evidence`)} style={{
                padding: '8px 16px', fontSize: 10, fontFamily: 'monospace', letterSpacing: 2,
                background: C.orange + '11', border: `1px solid ${C.orange}`,
                borderRadius: 5, color: C.orange, cursor: 'pointer',
              }}>🔬 FORENSICS</button>

              <button onClick={() => navigate(`/incidents/${incId}?tab=replay`)} style={{
                padding: '8px 16px', fontSize: 10, fontFamily: 'monospace', letterSpacing: 2,
                background: C.green + '11', border: `1px solid ${C.green}`,
                borderRadius: 5, color: C.green, cursor: 'pointer',
              }}>▶ REPLAY</button>
            </>
          )}

          <button onClick={() => navigate('/lab')} style={{
            padding: '8px 16px', fontSize: 10, fontFamily: 'monospace', letterSpacing: 2,
            background: 'transparent', border: `1px solid ${C.dim}`,
            borderRadius: 5, color: C.muted, cursor: 'pointer', marginLeft: 'auto',
          }}>🔬 CYBER LAB</button>
        </div>

      </div>

      <style>{`
        @keyframes incidentPulse {
          0%   { box-shadow: 0 0 40px ${sevCol}33, 0 0 80px ${sevCol}11; }
          50%  { box-shadow: 0 0 60px ${sevCol}55, 0 0 120px ${sevCol}22; }
          100% { box-shadow: 0 0 40px ${sevCol}33, 0 0 80px ${sevCol}11; }
        }
        @keyframes pulse {
          0%, 100% { opacity: 1; }
          50%       { opacity: 0.3; }
        }
      `}</style>
    </div>
  )
}
