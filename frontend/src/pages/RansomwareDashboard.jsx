import { useEffect, useMemo, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { Area, AreaChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { getStats, getThreats } from '../api'
import WorkspaceSwitcher from '../components/WorkspaceSwitcher'

const colors = {
  blue: '#00d4ff',
  red: '#ff003c',
  orange: '#ff8c00',
  green: '#00ff88',
  purple: '#a78bfa',
  bg: '#000010',
  card: '#05051a',
}

const buttonStyle = (color) => ({
  padding: '8px 14px',
  border: `1px solid ${color}`,
  borderRadius: 6,
  color,
  background: 'transparent',
  fontFamily: 'monospace',
  fontSize: 10,
  fontWeight: 'bold',
  letterSpacing: 1,
  textDecoration: 'none',
  whiteSpace: 'nowrap',
})

const panelStyle = {
  background: colors.card,
  border: '1px solid #00d4ff22',
  borderRadius: 10,
  padding: 24,
  marginBottom: 24,
}

function scoreColor(score) {
  return score > 70 ? colors.red : score > 30 ? colors.orange : colors.green
}

function DetectionTable({ threats }) {
  return (
    <div style={panelStyle}>
      <h2 style={{ color: colors.blue, fontFamily: 'monospace', fontSize: 12, letterSpacing: 3, margin: '0 0 20px' }}>
        🔍 RECENT DETECTIONS
      </h2>
      <div style={{ overflowX: 'auto' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontFamily: 'monospace', fontSize: 11 }}>
          <thead>
            <tr style={{ borderBottom: '1px solid #111' }}>
              {['FILE', 'PREDICTION', 'SCORE', 'MITRE', 'AI SUMMARY', 'TIMESTAMP'].map(label => (
                <th key={label} style={{ color: '#444', textAlign: 'left', padding: '8px 12px', letterSpacing: 2, fontWeight: 'normal' }}>
                  {label}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {threats.length === 0 ? (
              <tr>
                <td colSpan={6} style={{ textAlign: 'center', padding: 32, color: '#444' }}>
                  No detections yet — <Link to="/threats" style={{ color: colors.blue }}>run a scan</Link>
                </td>
              </tr>
            ) : threats.map((threat, index) => {
              const score = Number(threat.threat_score || 0)
              const predictionColor = threat.prediction === 'Ransomware'
                ? colors.red
                : threat.prediction === 'Suspicious' ? colors.orange : colors.green
              let tactics = []
              try {
                tactics = typeof threat.mitre_tactics === 'string'
                  ? JSON.parse(threat.mitre_tactics || '[]')
                  : threat.mitre_tactics || []
              } catch {
                tactics = []
              }
              return (
                <tr key={threat.id || index} style={{ borderBottom: '1px solid #0a0a1a' }}>
                  <td style={{ padding: '10px 12px', color: '#ccc', maxWidth: 140 }}>{threat.file_name || 'unknown'}</td>
                  <td style={{ padding: '10px 12px', color: predictionColor, fontWeight: 'bold' }}>{threat.prediction || 'Unknown'}</td>
                  <td style={{ padding: '10px 12px', color: scoreColor(score), fontWeight: 'bold' }}>{score.toFixed(1)}</td>
                  <td style={{ padding: '10px 12px' }}>
                    {tactics.slice(0, 2).map(tactic => (
                      <a key={tactic.id} href={tactic.url} target="_blank" rel="noreferrer" style={{ display: 'block', color: colors.purple, fontSize: 10 }}>
                        {tactic.id}
                      </a>
                    ))}
                  </td>
                  <td style={{ padding: '10px 12px', color: '#888', maxWidth: 220 }}>{threat.ai_summary || '—'}</td>
                  <td style={{ padding: '10px 12px', color: '#555', whiteSpace: 'nowrap' }}>{threat.timestamp?.slice(0, 19).replace('T', ' ') || '—'}</td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </div>
  )
}

export default function RansomwareDashboard() {
  const [stats, setStats] = useState(null)
  const [threats, setThreats] = useState([])
  const [loading, setLoading] = useState(true)
  const navigate = useNavigate()
  const role = localStorage.getItem('role')
  const username = localStorage.getItem('user')

  const load = async () => {
    try {
      const [statsResponse, threatsResponse] = await Promise.all([getStats(), getThreats()])
      setStats(statsResponse.data)
      const data = Array.isArray(threatsResponse.data) ? threatsResponse.data : threatsResponse.data.threats || []
      setThreats(data.slice(0, 10))
    } catch (error) {
      if (error?.response?.status === 401) {
        localStorage.clear()
        navigate('/login', { replace: true })
      }
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    load()
    const interval = setInterval(load, 10000)
    return () => clearInterval(interval)
  }, [])

  const heatmap = useMemo(() => {
    const counts = {}
    threats.forEach(threat => {
      const date = (threat.timestamp || '').slice(0, 10)
      if (date) counts[date] = (counts[date] || 0) + 1
    })
    const today = new Date()
    return Array.from({ length: 112 }, (_, index) => {
      const date = new Date(today)
      date.setDate(today.getDate() - (111 - index))
      const key = date.toISOString().slice(0, 10)
      return { date: key, count: counts[key] || 0 }
    })
  }, [threats])

  const logout = () => {
    localStorage.clear()
    navigate('/login', { replace: true })
  }

  const cards = [
    ['📁', 'TOTAL SCANNED', stats?.total_scanned, colors.blue],
    ['🚨', 'ACTIVE THREATS', stats?.active_threats, colors.red],
    ['⚠️', 'HIGH RISK ALERTS', stats?.high_risk_alerts, colors.orange],
    ['💚', 'SYSTEM HEALTH', stats ? `${stats.system_health}%` : '—', colors.green],
  ]

  return (
    <main style={{ minHeight: '100vh', background: colors.bg, padding: 24, color: '#ccc' }}>
      <WorkspaceSwitcher />
      <header style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 16, flexWrap: 'wrap', marginBottom: 28 }}>
        <div>
          <h1 style={{ color: '#fff', fontFamily: 'monospace', fontSize: 20, letterSpacing: 4, margin: '0 0 6px' }}>
            🛡️ RANSOMWARE DEFENSE CENTER
          </h1>
          <p style={{ color: '#555', fontFamily: 'monospace', fontSize: 11, margin: 0, letterSpacing: 2 }}>
            Welcome, <span style={{ color: colors.blue }}>{username}</span> — <span style={{ color: role === 'admin' ? colors.red : colors.blue }}>{role?.toUpperCase()}</span>
          </p>
        </div>
        <nav style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          <Link to="/threats" style={buttonStyle(colors.blue)}>⚡ THREATS</Link>
          <Link to="/analytics" style={buttonStyle(colors.blue)}>📊 ANALYTICS</Link>
          <Link to="/blockchain" style={buttonStyle(colors.blue)}>⛓️ BLOCKCHAIN</Link>
          <Link to="/soc" style={buttonStyle(colors.green)}>🖥 SOC</Link>
          <Link to="/chat" style={buttonStyle(colors.orange)}>🤖 AI CHAT</Link>
          <Link to="/audit" style={buttonStyle(colors.purple)}>📋 AUDIT LOG</Link>
          <Link to="/network" style={buttonStyle(colors.green)}>🌐 NETWORK</Link>
          {role === 'admin' && <Link to="/admin" style={buttonStyle(colors.red)}>⚙️ ADMIN</Link>}
          <button onClick={logout} style={{ ...buttonStyle(colors.red), cursor: 'pointer' }}>🚪 LOGOUT</button>
        </nav>
      </header>

      {loading ? (
        <div style={{ height: 300, display: 'grid', placeItems: 'center', color: colors.blue, fontFamily: 'monospace', letterSpacing: 3 }}>
          ⚡ LOADING RANSOMWARE DATA...
        </div>
      ) : (
        <>
          <section style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(190px, 1fr))', gap: 16, marginBottom: 24 }}>
            {cards.map(([icon, label, value, color]) => (
              <div key={label} style={{ ...panelStyle, marginBottom: 0, borderColor: `${color}33` }}>
                <div style={{ fontSize: 28 }}>{icon}</div>
                <div style={{ color, fontSize: 32, fontFamily: 'monospace', fontWeight: 'bold' }}>{value ?? '—'}</div>
                <div style={{ color: '#555', fontSize: 10, fontFamily: 'monospace', letterSpacing: 2, marginTop: 6 }}>{label}</div>
              </div>
            ))}
          </section>

          {stats?.total_scanned > 0 && (
            <section style={panelStyle}>
              <h2 style={{ color: colors.blue, fontFamily: 'monospace', fontSize: 12, letterSpacing: 3, margin: '0 0 20px' }}>📈 THREAT SCORE TIMELINE</h2>
              <ResponsiveContainer width="100%" height={220}>
                <AreaChart data={[...(stats.timeline || [])].reverse()}>
                  <XAxis dataKey="time" hide />
                  <YAxis domain={[0, 100]} stroke="#333" />
                  <Tooltip contentStyle={{ background: colors.card, border: '1px solid #00d4ff33', color: '#fff' }} />
                  <Area type="monotone" dataKey="score" stroke={colors.red} fill={`${colors.red}22`} />
                </AreaChart>
              </ResponsiveContainer>
            </section>
          )}

          <section style={panelStyle}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
              <h2 style={{ color: colors.blue, fontFamily: 'monospace', fontSize: 12, letterSpacing: 3, margin: 0 }}>📅 DETECTION HEATMAP — LAST 16 WEEKS</h2>
              <span style={{ color: '#555', fontFamily: 'monospace', fontSize: 10 }}>LOW ░ ▒ ▓ HIGH</span>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(16, 1fr)', gridAutoFlow: 'column', gridTemplateRows: 'repeat(7, 13px)', gap: 3 }}>
              {heatmap.map(cell => (
                <span key={cell.date} title={`${cell.date}: ${cell.count} detections`} style={{ background: cell.count > 2 ? colors.red : cell.count > 0 ? colors.orange : '#0a0a1a', borderRadius: 2 }} />
              ))}
            </div>
            <div style={{ color: '#444', fontFamily: 'monospace', fontSize: 10, marginTop: 10 }}>{threats.length} recent detections shown across the active history window</div>
          </section>

          <DetectionTable threats={threats} />
        </>
      )}
    </main>
  )
}
