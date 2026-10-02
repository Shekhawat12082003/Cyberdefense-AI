import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { io } from 'socket.io-client'
import { getIncidents } from '../api'

const mono = (sz = 13, c = '#fff') => ({ fontFamily: 'monospace', fontSize: sz, color: c })
const card = (border = '#00d4ff22') => ({
  background: 'rgba(0,10,30,0.95)', border: `1px solid ${border}`,
  borderRadius: 8, padding: 16,
})
const SEV_COLOR = { CRITICAL: '#ff003c', HIGH: '#ff8c00', MODERATE: '#ffe600', LOW: '#00ff88' }

export default function Incidents() {
  const navigate  = useNavigate()
  const [incidents, setIncidents] = useState([])
  const [filter,    setFilter]    = useState('ALL')
  const [loading,   setLoading]   = useState(true)

  const fetchIncidents = async () => {
    try {
      const r = await getIncidents({ limit: 100 })
      setIncidents(r.data.incidents || [])
    } catch {}
    setLoading(false)
  }

  useEffect(() => {
    fetchIncidents()
    const id = setInterval(fetchIncidents, 5000)
    return () => clearInterval(id)
  }, [])

  // Live updates
  useEffect(() => {
    const socket = io('http://localhost:5000', { transports: ['websocket'] })
    socket.on('incident_created', () => fetchIncidents())
    socket.on('incident_updated', () => fetchIncidents())
    return () => socket.disconnect()
  }, [])

  const filtered = filter === 'ALL' ? incidents
    : incidents.filter(i => i.status === filter || i.severity === filter)

  const counts = {
    CRITICAL: incidents.filter(i => i.severity === 'CRITICAL').length,
    HIGH:     incidents.filter(i => i.severity === 'HIGH').length,
    ACTIVE:   incidents.filter(i => i.status === 'ACTIVE').length,
    CLOSED:   incidents.filter(i => i.status === 'CLOSED').length,
  }

  return (
    <div style={{ minHeight: '100vh', background: '#000010', padding: '24px 28px', fontFamily: 'monospace' }}>

      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 20 }}>
        <div>
          <h1 style={{ ...mono(20, '#fff'), fontWeight: 'bold', letterSpacing: 5, margin: '0 0 4px' }}>
            🚨 INCIDENTS
          </h1>
          <p style={{ ...mono(10, '#444'), letterSpacing: 3, margin: 0 }}>CORRELATED SECURITY INCIDENTS</p>
        </div>
        <div style={{ display: 'flex', gap: 10 }}>
          <button onClick={() => navigate('/lab')} style={{
            padding: '8px 16px', fontSize: 10, letterSpacing: 2, fontFamily: 'monospace',
            background: 'transparent', border: '1px solid #ff003c', borderRadius: 5,
            color: '#ff003c', cursor: 'pointer',
          }}>🔬 CYBER LAB</button>
          <button onClick={() => navigate('/')} style={{
            padding: '8px 16px', fontSize: 10, letterSpacing: 2, fontFamily: 'monospace',
            background: 'transparent', border: '1px solid #444', borderRadius: 5,
            color: '#888', cursor: 'pointer',
          }}>← DASHBOARD</button>
        </div>
      </div>

      {/* Stats */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12, marginBottom: 20 }}>
        {[
          { label: 'CRITICAL', value: counts.CRITICAL, color: '#ff003c' },
          { label: 'HIGH',     value: counts.HIGH,     color: '#ff8c00' },
          { label: 'ACTIVE',   value: counts.ACTIVE,   color: '#ffe600' },
          { label: 'CLOSED',   value: counts.CLOSED,   color: '#00ff88' },
        ].map(s => (
          <div key={s.label} style={{ ...card(), borderColor: s.color + '44', textAlign: 'center' }}>
            <div style={{ ...mono(28, s.color), fontWeight: 'bold', lineHeight: 1 }}>{s.value}</div>
            <div style={{ ...mono(9, '#444'), letterSpacing: 3, marginTop: 4 }}>{s.label}</div>
          </div>
        ))}
      </div>

      {/* Filters */}
      <div style={{ display: 'flex', gap: 8, marginBottom: 16 }}>
        {['ALL', 'ACTIVE', 'CLOSED', 'CRITICAL', 'HIGH'].map(f => (
          <button key={f} onClick={() => setFilter(f)} style={{
            padding: '5px 12px', fontSize: 9, letterSpacing: 2, fontFamily: 'monospace',
            background: filter === f ? '#00d4ff22' : 'transparent',
            border: `1px solid ${filter === f ? '#00d4ff' : '#222'}`,
            borderRadius: 4, color: filter === f ? '#00d4ff' : '#444', cursor: 'pointer',
          }}>{f}</button>
        ))}
        <span style={{ ...mono(10, '#333'), marginLeft: 'auto', alignSelf: 'center' }}>
          {filtered.length} incidents
        </span>
      </div>

      {/* Incidents Table */}
      {loading ? (
        <div style={{ ...mono(12, '#333'), textAlign: 'center', padding: 40 }}>Loading incidents...</div>
      ) : filtered.length === 0 ? (
        <div style={{ ...card(), textAlign: 'center', padding: 40 }}>
          <div style={mono(14, '#333')}>No incidents yet</div>
          <div style={{ ...mono(10, '#222'), marginTop: 8 }}>
            Run a simulation from the Cyber Lab to generate incidents
          </div>
          <button onClick={() => navigate('/lab')} style={{
            marginTop: 16, padding: '8px 20px', fontSize: 10, letterSpacing: 2,
            fontFamily: 'monospace', background: '#ff003c22',
            border: '1px solid #ff003c', borderRadius: 5, color: '#ff003c', cursor: 'pointer',
          }}>OPEN CYBER LAB</button>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {filtered.map(inc => {
            const sev   = inc.severity || 'LOW'
            const col   = SEV_COLOR[sev] || '#aaa'
            const score = inc.risk_score || 0

            return (
              <div
                key={inc.id}
                onClick={() => navigate(`/incidents/${inc.id}`)}
                style={{
                  ...card(), cursor: 'pointer',
                  borderColor: col + '33',
                  display: 'flex', gap: 16, alignItems: 'center',
                  transition: 'all 0.2s',
                  ':hover': { borderColor: col },
                }}
              >
                {/* Severity dot */}
                <div style={{
                  width: 12, height: 12, borderRadius: '50%', flexShrink: 0,
                  background: col, boxShadow: `0 0 8px ${col}`,
                }} />

                {/* Main content */}
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ ...mono(12, '#fff'), fontWeight: 'bold', marginBottom: 3 }}>
                    {inc.title || inc.attack_type}
                  </div>
                  <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap' }}>
                    <span style={mono(9, '#555')}>ID: {inc.id}</span>
                    <span style={mono(9, '#555')}>Type: {inc.attack_type}</span>
                    {inc.source_ip && <span style={mono(9, '#555')}>From: {inc.source_ip}</span>}
                    {inc.process_name && <span style={mono(9, '#555')}>Process: {inc.process_name}</span>}
                    {inc.honeypot_hit && <span style={{ ...mono(9, '#ff003c'), fontWeight: 'bold' }}>🍯 HONEYPOT</span>}
                  </div>
                </div>

                {/* Score */}
                <div style={{ textAlign: 'right', flexShrink: 0 }}>
                  <div style={{ ...mono(22, col), fontWeight: 'bold', lineHeight: 1 }}>{score.toFixed(0)}</div>
                  <div style={{ ...mono(9, '#444'), letterSpacing: 1 }}>/100</div>
                </div>

                {/* Status */}
                <div style={{ flexShrink: 0 }}>
                  <div style={{
                    padding: '3px 8px', borderRadius: 3,
                    background: col + '22', border: `1px solid ${col + '44'}`,
                    ...mono(9, col), letterSpacing: 2, marginBottom: 4,
                  }}>{sev}</div>
                  <div style={{
                    padding: '3px 8px', borderRadius: 3,
                    background: inc.status === 'ACTIVE' ? '#ffe60022' : '#00ff8822',
                    border: `1px solid ${inc.status === 'ACTIVE' ? '#ffe60044' : '#00ff8844'}`,
                    ...mono(9, inc.status === 'ACTIVE' ? '#ffe600' : '#00ff88'), letterSpacing: 2,
                  }}>{inc.status}</div>
                </div>

                {/* Timestamp */}
                <div style={{ ...mono(9, '#333'), flexShrink: 0, whiteSpace: 'nowrap' }}>
                  {(inc.created_at || '').slice(0, 19).replace('T', '\n')}
                </div>

                <div style={{ ...mono(11, '#444'), flexShrink: 0 }}>→</div>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}
