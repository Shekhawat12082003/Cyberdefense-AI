import { useState, useEffect, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import { io } from 'socket.io-client'
import { getLabStatus, startSimulation, stopSimulation, resetLab,
         getHoneypotStatus, getHoneypotTriggers, getHoneypotFiles } from '../api'

const mono = (sz = 13, color = '#fff') => ({ fontFamily: 'monospace', fontSize: sz, color })
const card = (border = '#00d4ff22') => ({
  background: 'rgba(0,10,30,0.92)',
  border: `1px solid ${border}`,
  borderRadius: 8,
  padding: 16,
})

const SIMULATIONS = [
  { id: 'ransomware',         label: '🦠 Ransomware',          desc: 'File encryption simulation', severity: 'CRITICAL' },
  { id: 'portscan',           label: '🔍 Port Scan',            desc: 'Recon reconnaissance sim',   severity: 'HIGH' },
  { id: 'brute-force',        label: '🔑 Brute Force',          desc: 'Auth attack simulation',     severity: 'HIGH' },
  { id: 'phishing',           label: '🎣 Phishing',             desc: 'Email attack chain sim',     severity: 'HIGH' },
  { id: 'suspicious-process', label: '⚙️  Suspicious Process',  desc: 'Malicious process sim',      severity: 'HIGH' },
  { id: 'data-exfiltration',  label: '📤 Data Exfiltration',    desc: 'Data theft simulation',      severity: 'CRITICAL' },
  { id: 'honeypot',           label: '🍯 Honeypot Access',      desc: 'Decoy file access sim',      severity: 'CRITICAL' },
  { id: 'full-attack',        label: '🚀 Full Attack',          desc: '7-stage complete simulation', severity: 'CRITICAL' },
]

const SEV_COLOR = {
  CRITICAL: '#ff003c', HIGH: '#ff8c00', MEDIUM: '#ffe600', LOW: '#00ff88', INFO: '#00d4ff'
}

export default function CyberLab() {
  const navigate = useNavigate()
  const [labStatus,   setLabStatus]   = useState(null)
  const [hpStatus,    setHpStatus]    = useState(null)
  const [hpTriggers,  setHpTriggers]  = useState([])
  const [hpFiles,     setHpFiles]     = useState([])
  const [simLogs,     setSimLogs]     = useState([])
  const [activeScen,  setActiveScen]  = useState(null)
  const [running,     setRunning]     = useState(false)
  const [terminal,    setTerminal]    = useState([])
  const [labMode,     setLabMode]     = useState(true)
  const logsRef = useRef(null)
  const socketRef = useRef(null)

  const addLog = (msg, color = '#00d4ff', icon = '') => {
    const ts = new Date().toLocaleTimeString()
    setTerminal(prev => [...prev.slice(-500), { ts, msg, color, icon }])
  }

  // ── WebSocket ──────────────────────────────────────────
  useEffect(() => {
    const socket = io('http://localhost:5000', { transports: ['websocket'] })
    socketRef.current = socket

    socket.on('sim_log', (entry) => {
      const msg = entry.message || ''
      const isStep = msg.includes('STAGE') || msg.includes('Phase') || msg.includes('✅') || msg.includes('🚀')
      addLog(msg, isStep ? '#00ff88' : '#aaa')
    })

    socket.on('security_event', (ev) => {
      const sev  = ev.severity || 'LOW'
      const desc = ev.description || ev.event_type || ''
      addLog(`[EVENT] ${desc}`, SEV_COLOR[sev] || '#aaa', sev === 'CRITICAL' ? '🔴' : '🟠')
    })

    socket.on('honeypot_triggered', (entry) => {
      const msg = `🍯 HONEYPOT: ${entry.resource} accessed by ${entry.process_name || '?'}`
      addLog(msg, '#ff003c', '🍯')
      setHpTriggers(prev => [entry, ...prev.slice(0, 49)])
    })

    socket.on('soc_update', (data) => {
      if (data.type === 'security_event') {
        const sev = data.severity || 'LOW'
        addLog(`[SOC] ${data.description || data.event_type}`, SEV_COLOR[sev] || '#aaa')
      }
    })

    return () => socket.disconnect()
  }, [])

  // ── Auto-scroll terminal ───────────────────────────────
  useEffect(() => {
    if (logsRef.current) {
      logsRef.current.scrollTop = logsRef.current.scrollHeight
    }
  }, [terminal])

  // ── Fetch status ───────────────────────────────────────
  const fetchStatus = async () => {
    try {
      const [ls, hs, ht, hf] = await Promise.all([
        getLabStatus(), getHoneypotStatus(), getHoneypotTriggers(), getHoneypotFiles()
      ])
      setLabStatus(ls.data)
      setHpStatus(hs.data)
      setHpTriggers(ht.data.triggers || [])
      setHpFiles(hf.data.files || [])
      setActiveScen(ls.data.active_scenario)
      setRunning(!!ls.data.active_scenario)
    } catch {}
  }

  useEffect(() => {
    fetchStatus()
    const id = setInterval(fetchStatus, 3000)
    return () => clearInterval(id)
  }, [])

  // ── Run simulation ─────────────────────────────────────
  const runSim = async (simId) => {
    if (running) {
      addLog('⚠️  Simulation already running. Stop it first.', '#ff8c00')
      return
    }
    setRunning(true)
    addLog(`\n══ Starting: ${simId.toUpperCase()} ══`, '#00d4ff', '🚀')
    addLog('Connecting to simulation engine...', '#555')
    try {
      const r = await startSimulation(simId)
      const sid = r.data.scenario_id
      setActiveScen(sid)
      addLog(`Scenario: ${sid}`, '#00ff88')
      addLog('Simulation running... (watch SOC dashboard for live alerts)', '#aaa')
    } catch (e) {
      const err = e.response?.data?.error || e.message || 'Unknown error'
      addLog(`❌ Error: ${err}`, '#ff003c')
      setRunning(false)
    }
  }

  const stopSim = async () => {
    try {
      const r = await stopSimulation()
      addLog(`✅ ${r.data.message || 'Stopped'}`, '#00ff88')
    } catch {}
    setRunning(false)
    setActiveScen(null)
    await fetchStatus()
  }

  const resetLabEnv = async () => {
    if (!confirm('Reset lab environment? This clears simulation data.')) return
    try {
      const r = await resetLab()
      addLog(`✅ ${r.data.message}`, '#00ff88')
      setSimLogs([])
      setTerminal([])
      await fetchStatus()
    } catch (e) {
      addLog(`❌ Reset failed: ${e.message}`, '#ff003c')
    }
  }

  const clearTerminal = () => setTerminal([])

  const statusDot = (ok) => (
    <span style={{
      display: 'inline-block', width: 8, height: 8, borderRadius: '50%',
      background: ok ? '#00ff88' : '#ff003c',
      boxShadow: `0 0 6px ${ok ? '#00ff88' : '#ff003c'}`,
      marginRight: 6,
    }} />
  )

  return (
    <div style={{ minHeight: '100vh', background: '#000010', padding: '24px 28px', fontFamily: 'monospace' }}>

      {/* ── Header ──────────────────────────────────────── */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 20 }}>
        <div>
          <h1 style={{ ...mono(22, '#fff'), fontWeight: 'bold', letterSpacing: 5, margin: '0 0 4px' }}>
            🔬 CYBER RANGE
          </h1>
          <p style={{ ...mono(10, '#444'), letterSpacing: 3, margin: 0 }}>CONTROLLED ATTACK SIMULATION LAB</p>
        </div>
        <div style={{ display: 'flex', gap: 10 }}>
          <button onClick={() => navigate('/soc')} style={{
            padding: '8px 16px', fontSize: 10, letterSpacing: 2, fontFamily: 'monospace',
            background: 'transparent', border: '1px solid #00d4ff', borderRadius: 5,
            color: '#00d4ff', cursor: 'pointer',
          }}>SOC DASHBOARD</button>
          <button onClick={() => navigate('/')} style={{
            padding: '8px 16px', fontSize: 10, letterSpacing: 2, fontFamily: 'monospace',
            background: 'transparent', border: '1px solid #444', borderRadius: 5,
            color: '#888', cursor: 'pointer',
          }}>← DASHBOARD</button>
        </div>
      </div>

      {/* ── Safety Banner ───────────────────────────────── */}
      <div style={{
        ...card('#ff8c0033'), borderColor: '#ff8c00', marginBottom: 20,
        padding: '10px 16px', display: 'flex', alignItems: 'center', gap: 12,
      }}>
        <span style={{ fontSize: 20 }}>⚠️</span>
        <div>
          <div style={{ ...mono(11, '#ff8c00'), fontWeight: 'bold', letterSpacing: 2 }}>SAFE ACADEMIC SIMULATION ENVIRONMENT</div>
          <div style={{ ...mono(10, '#666'), marginTop: 2 }}>
            All simulations are controlled and contained. No real malware • No real encryption • No unauthorized network access
          </div>
        </div>
        <div style={{ marginLeft: 'auto', display: 'flex', gap: 8 }}>
          <div style={{
            padding: '4px 10px', borderRadius: 4,
            background: labStatus?.active_scenario ? '#ff003c22' : '#00ff8822',
            border: `1px solid ${labStatus?.active_scenario ? '#ff003c' : '#00ff88'}`,
            ...mono(9, labStatus?.active_scenario ? '#ff003c' : '#00ff88'),
            letterSpacing: 2,
          }}>
            {labStatus?.active_scenario ? '🔴 SIM RUNNING' : '🟢 READY'}
          </div>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '300px 1fr', gap: 16 }}>

        {/* ── Left: Status + Honeypot ──────────────────── */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>

          {/* System Status */}
          <div style={card()}>
            <div style={{ ...mono(9, '#444'), letterSpacing: 3, marginBottom: 12 }}>SYSTEM STATUS</div>
            {[
              { label: 'ML Engine',   ok: labStatus?.ml_online !== false },
              { label: 'Blockchain',  ok: true, val: labStatus?.blockchain_mode || '?' },
              { label: 'Honeypot',    ok: labStatus?.honeypot_active !== false },
              { label: 'File Monitor', ok: true },
              { label: 'WebSocket',   ok: !!socketRef.current?.connected },
            ].map((s, i) => (
              <div key={i} style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8 }}>
                <span style={mono(11, '#aaa')}>{s.label}</span>
                <span style={{ ...mono(10, s.ok ? '#00ff88' : '#ff003c'), letterSpacing: 2 }}>
                  {statusDot(s.ok)}{s.val || (s.ok ? 'ONLINE' : 'OFFLINE')}
                </span>
              </div>
            ))}
            <div style={{ marginTop: 12, borderTop: '1px solid #111', paddingTop: 10 }}>
              <div style={{ ...mono(9, '#444'), letterSpacing: 2, marginBottom: 6 }}>ACTIVE SCENARIO</div>
              <div style={{ ...mono(10, activeScen ? '#ff8c00' : '#333'), letterSpacing: 1 }}>
                {activeScen || 'None'}
              </div>
            </div>
          </div>

          {/* Honeypot Status */}
          <div style={card('#ff003c22')}>
            <div style={{ ...mono(9, '#444'), letterSpacing: 3, marginBottom: 10 }}>🍯 HONEYPOT STATUS</div>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8 }}>
              <span style={mono(11, '#aaa')}>Decoy Files</span>
              <span style={{ ...mono(14, '#00d4ff'), fontWeight: 'bold' }}>{hpFiles.length}</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 12 }}>
              <span style={mono(11, '#aaa')}>Total Triggers</span>
              <span style={{ ...mono(14, hpTriggers.length > 0 ? '#ff003c' : '#00ff88'), fontWeight: 'bold' }}>
                {hpStatus?.trigger_count || hpTriggers.length}
              </span>
            </div>
            <div style={{ ...mono(9, '#444'), letterSpacing: 2, marginBottom: 6 }}>RECENT TRIGGERS</div>
            {hpTriggers.length === 0 ? (
              <div style={{ ...mono(10, '#333') }}>No triggers yet</div>
            ) : hpTriggers.slice(0, 4).map((t, i) => (
              <div key={i} style={{
                background: '#1a0000', border: '1px solid #ff003c22',
                borderRadius: 4, padding: '6px 8px', marginBottom: 4,
              }}>
                <div style={{ ...mono(9, '#ff003c'), fontWeight: 'bold' }}>{t.resource}</div>
                <div style={{ ...mono(9, '#666') }}>{t.process_name} | {(t.timestamp || '').slice(11, 19)}</div>
              </div>
            ))}
          </div>

          {/* Honeypot Files */}
          <div style={card()}>
            <div style={{ ...mono(9, '#444'), letterSpacing: 3, marginBottom: 10 }}>🗂️  DECOY FILES</div>
            {hpFiles.map((f, i) => (
              <div key={i} style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
                <span style={{ ...mono(9, '#aaa'), maxWidth: 170, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {f.name}
                </span>
                <span style={{ ...mono(9, '#ff003c'), letterSpacing: 1 }}>DECOY</span>
              </div>
            ))}
          </div>

          {/* Controls */}
          <div style={card()}>
            <div style={{ ...mono(9, '#444'), letterSpacing: 3, marginBottom: 10 }}>LAB CONTROLS</div>
            <button
              onClick={stopSim}
              disabled={!running}
              style={{
                width: '100%', padding: '8px', marginBottom: 8, fontSize: 10, fontFamily: 'monospace',
                letterSpacing: 2, cursor: running ? 'pointer' : 'not-allowed',
                background: running ? '#ff003c22' : 'transparent',
                border: `1px solid ${running ? '#ff003c' : '#333'}`,
                borderRadius: 4, color: running ? '#ff003c' : '#444',
              }}>
              ⏹ STOP SIMULATION
            </button>
            <button onClick={resetLabEnv} style={{
              width: '100%', padding: '8px', marginBottom: 8, fontSize: 10, fontFamily: 'monospace',
              letterSpacing: 2, cursor: 'pointer', background: 'transparent',
              border: '1px solid #ff8c0066', borderRadius: 4, color: '#ff8c00',
            }}>
              🔄 RESET LAB
            </button>
            <button onClick={clearTerminal} style={{
              width: '100%', padding: '8px', fontSize: 10, fontFamily: 'monospace',
              letterSpacing: 2, cursor: 'pointer', background: 'transparent',
              border: '1px solid #33333366', borderRadius: 4, color: '#555',
            }}>
              🗑️  CLEAR TERMINAL
            </button>
          </div>
        </div>

        {/* ── Right: Simulation Panel + Terminal ──────── */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>

          {/* Simulation Cards */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 10 }}>
            {SIMULATIONS.map(sim => {
              const isActive = activeScen && activeScen.startsWith(sim.id.replace('-', '_'))
              const col      = SEV_COLOR[sim.severity] || '#00d4ff'
              return (
                <button
                  key={sim.id}
                  onClick={() => runSim(sim.id)}
                  disabled={running}
                  style={{
                    padding: '14px 10px', cursor: running ? 'not-allowed' : 'pointer',
                    background: isActive ? `${col}22` : 'rgba(0,10,30,0.8)',
                    border: `1px solid ${isActive ? col : col + '44'}`,
                    borderRadius: 8, textAlign: 'left',
                    transition: 'all 0.2s',
                    opacity: running && !isActive ? 0.5 : 1,
                  }}
                >
                  <div style={{ ...mono(16, col), marginBottom: 4 }}>{sim.label}</div>
                  <div style={{ ...mono(9, '#555'), lineHeight: 1.4 }}>{sim.desc}</div>
                  <div style={{
                    marginTop: 8, display: 'inline-block', padding: '2px 6px',
                    background: col + '22', borderRadius: 3,
                    ...mono(8, col), letterSpacing: 1,
                  }}>{sim.severity}</div>
                </button>
              )
            })}
          </div>

          {/* Terminal Output */}
          <div style={{ ...card('#00d4ff22'), flex: 1, display: 'flex', flexDirection: 'column' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
              <div style={{ ...mono(9, '#444'), letterSpacing: 3 }}>SIMULATION TERMINAL</div>
              <div style={{ display: 'flex', gap: 8 }}>
                {running && (
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    <div style={{
                      width: 8, height: 8, borderRadius: '50%', background: '#ff003c',
                      animation: 'pulse 1s infinite',
                    }} />
                    <span style={{ ...mono(9, '#ff003c'), letterSpacing: 2 }}>RUNNING</span>
                  </div>
                )}
                <button onClick={() => navigate('/soc')} style={{
                  padding: '3px 8px', fontSize: 9, letterSpacing: 1, fontFamily: 'monospace',
                  background: 'transparent', border: '1px solid #00d4ff44', borderRadius: 3,
                  color: '#00d4ff', cursor: 'pointer',
                }}>OPEN SOC →</button>
              </div>
            </div>

            <div
              ref={logsRef}
              style={{
                flex: 1, overflowY: 'auto', minHeight: 300, maxHeight: 420,
                background: '#000', border: '1px solid #111', borderRadius: 4,
                padding: 12, fontFamily: 'monospace',
              }}
            >
              {terminal.length === 0 ? (
                <div style={{ color: '#333', fontSize: 12 }}>
                  {'> '}Select a simulation above to begin...{'\n'}
                  {'> '}All simulations run through the live ML detection pipeline.
                </div>
              ) : terminal.map((line, i) => (
                <div key={i} style={{ fontSize: 11, color: line.color || '#aaa', marginBottom: 2, lineHeight: 1.4 }}>
                  <span style={{ color: '#333' }}>[{line.ts}] </span>
                  {line.icon && <span style={{ marginRight: 4 }}>{line.icon}</span>}
                  {line.msg}
                </div>
              ))}
            </div>

            {/* Quick commands */}
            <div style={{ marginTop: 10, ...mono(9, '#333') }}>
              CLI: <span style={{ color: '#00d4ff' }}>python cyberdefense_cli.py simulate full-attack</span>
              &nbsp;|&nbsp;
              <span style={{ color: '#00d4ff' }}>python cyberdefense_cli.py help</span>
            </div>
          </div>
        </div>
      </div>

      <style>{`
        @keyframes pulse {
          0%, 100% { opacity: 1; }
          50%       { opacity: 0.3; }
        }
      `}</style>
    </div>
  )
}
