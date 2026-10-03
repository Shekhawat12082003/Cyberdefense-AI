import { useState, useEffect } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import {
  getIncident, investigateIncident, getIncidentEvidence,
  replayIncident, getAttackGraph, geolocateIP
} from '../api'
import ThreatIntelPanel from '../components/ThreatIntelPanel'

const mono = (sz = 13, c = '#fff') => ({ fontFamily: 'monospace', fontSize: sz, color: c })
const card = (border = '#00d4ff22') => ({
  background: 'rgba(0,10,30,0.95)',
  border: `1px solid ${border}`,
  borderRadius: 8, padding: 16,
})
const SEV_COLOR = { CRITICAL: '#ff003c', HIGH: '#ff8c00', MODERATE: '#ffe600', LOW: '#00ff88', MEDIUM: '#ff8c00' }
const label9 = { fontFamily: 'monospace', fontSize: 9, letterSpacing: 3, color: '#444', marginBottom: 8 }

export default function IncidentView() {
  const { id } = useParams()
  const navigate = useNavigate()

  const [incident,     setIncident]     = useState(null)
  const [investigation, setInvestigation] = useState(null)
  const [evidence,     setEvidence]     = useState(null)
  const [replayEvents, setReplayEvents] = useState([])
  const [attackGraph,  setAttackGraph]  = useState(null)
  const [geo,          setGeo]          = useState(null)
  const [loading,      setLoading]      = useState(true)
  const [tab,          setTab]          = useState('overview')
  const [replaying,    setReplaying]    = useState(false)
  const [replayIndex,  setReplayIndex]  = useState(0)

  useEffect(() => {
    if (!id) return
    fetchAll()
  }, [id])

  const fetchAll = async () => {
    setLoading(true)
    try {
      const [incR, graphR] = await Promise.all([
        getIncident(id),
        getAttackGraph(id).catch(() => ({ data: { nodes: [], edges: [] } })),
      ])
      setIncident(incR.data)
      setAttackGraph(graphR.data)

      // Geolocate source IP
      const srcIp = incR.data?.source_ip
      if (srcIp && !['Unknown', null, undefined].includes(srcIp)) {
        geolocateIP(srcIp).then(r => setGeo(r.data)).catch(() => {})
      }
    } catch (e) {
      console.error(e)
    }
    setLoading(false)
  }

  const loadInvestigation = async () => {
    try {
      const r = await investigateIncident(id)
      setInvestigation(r.data.investigation)
    } catch {}
  }

  const loadEvidence = async () => {
    try {
      const r = await getIncidentEvidence(id)
      setEvidence(r.data.bundle)
    } catch {}
  }

  const loadReplay = async () => {
    try {
      const r = await replayIncident(id)
      setReplayEvents(r.data.events || [])
    } catch {}
  }

  useEffect(() => {
    if (tab === 'investigate' && !investigation) loadInvestigation()
    if (tab === 'evidence'   && !evidence)      loadEvidence()
    if (tab === 'replay'     && !replayEvents.length) loadReplay()
  }, [tab])

  // Replay animation
  const startReplay = () => {
    setReplayIndex(0)
    setReplaying(true)
    let idx = 0
    const interval = setInterval(() => {
      idx++
      setReplayIndex(idx)
      if (idx >= replayEvents.length) {
        clearInterval(interval)
        setReplaying(false)
      }
    }, 600)
  }

  if (loading) return (
    <div style={{ minHeight: '100vh', background: '#000010', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      <span style={{ ...mono(14, '#00d4ff'), letterSpacing: 4 }}>LOADING INCIDENT...</span>
    </div>
  )

  if (!incident) return (
    <div style={{ minHeight: '100vh', background: '#000010', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      <span style={{ ...mono(14, '#ff003c'), letterSpacing: 4 }}>INCIDENT NOT FOUND</span>
    </div>
  )

  const sev       = incident.severity || 'LOW'
  const sevColor  = SEV_COLOR[sev] || '#00ff88'
  const riskScore = incident.risk_score || 0
  const riskLevel = incident.risk_level || 'LOW'
  const riskColor = SEV_COLOR[riskLevel] || '#00ff88'
  const geoDisplay = geo?.display || {}
  const timeline  = Array.isArray(incident.timeline) ? incident.timeline : []
  const riskFactors = (incident.risk_factors?.factors) || []

  const TABS = [
    { id: 'overview',    label: 'OVERVIEW' },
    { id: 'attacker',    label: 'ATTACKER' },
    { id: 'investigate', label: 'AI INVESTIGATE' },
    { id: 'timeline',    label: 'TIMELINE' },
    { id: 'graph',       label: 'ATTACK GRAPH' },
    { id: 'evidence',    label: 'EVIDENCE' },
    { id: 'replay',      label: 'REPLAY' },
  ]

  return (
    <div style={{ minHeight: '100vh', background: '#000010', padding: '24px 28px', fontFamily: 'monospace' }}>

      {/* ── Header ──────────────────────────────────────── */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 16 }}>
        <div>
          <div style={{ ...mono(10, '#444'), letterSpacing: 3, marginBottom: 4 }}>INCIDENT DETAILS</div>
          <h1 style={{ ...mono(20, '#fff'), fontWeight: 'bold', letterSpacing: 3, margin: 0 }}>
            {incident.title || incident.attack_type}
          </h1>
          <div style={{ ...mono(10, '#555'), marginTop: 4 }}>ID: {incident.id}</div>
        </div>
        <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
          <div style={{
            padding: '6px 14px', borderRadius: 4,
            background: sevColor + '22', border: `1px solid ${sevColor}`,
            ...mono(12, sevColor), fontWeight: 'bold', letterSpacing: 2,
          }}>{sev}</div>
          <button onClick={() => navigate('/incidents')} style={{
            padding: '8px 16px', fontSize: 10, letterSpacing: 2, fontFamily: 'monospace',
            background: 'transparent', border: '1px solid #444', borderRadius: 5,
            color: '#888', cursor: 'pointer',
          }}>← INCIDENTS</button>
        </div>
      </div>

      {/* ── Tabs ────────────────────────────────────────── */}
      <div style={{ display: 'flex', gap: 4, marginBottom: 16, flexWrap: 'wrap' }}>
        {TABS.map(t => (
          <button key={t.id} onClick={() => setTab(t.id)} style={{
            padding: '6px 14px', fontSize: 9, letterSpacing: 2, fontFamily: 'monospace',
            background: tab === t.id ? '#00d4ff22' : 'transparent',
            border: `1px solid ${tab === t.id ? '#00d4ff' : '#222'}`,
            borderRadius: 4, color: tab === t.id ? '#00d4ff' : '#555', cursor: 'pointer',
          }}>{t.label}</button>
        ))}
      </div>

      {/* ════════════════════════════════════════════════ */}
      {/* OVERVIEW TAB                                     */}
      {/* ════════════════════════════════════════════════ */}
      {tab === 'overview' && (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 280px', gap: 14 }}>

          {/* Attack Details */}
          <div style={card()}>
            <div style={label9}>ATTACK DETAILS</div>
            {[
              ['Attack',       incident.attack_type],
              ['Severity',     <span style={{ color: sevColor, fontWeight: 'bold' }}>{sev}</span>],
              ['Risk Score',   <span style={{ color: riskColor, fontWeight: 'bold' }}>{riskScore}/100</span>],
              ['Source IP',    incident.source_ip || 'Unknown'],
              ['Source Port',  incident.source_port || 'Unknown'],
              ['Destination',  `${incident.dest_ip || '?'}:${incident.dest_port || '?'}`],
              ['Protocol',     incident.protocol || 'Unknown'],
              ['Process',      incident.process_name || 'Unknown'],
              ['PID',          incident.process_pid || 'Unknown'],
              ['Honeypot',     incident.honeypot_hit ? <span style={{ color: '#ff003c', fontWeight: 'bold' }}>TRIGGERED</span> : 'No'],
              ['Files',        incident.files_affected || 0],
              ['ML Class',     incident.ml_prediction || 'N/A'],
              ['Response',     <span style={{ color: '#00ff88', fontWeight: 'bold' }}>{incident.response || 'MONITORING'}</span>],
              ['Status',       incident.status],
              ['Detected',     (incident.created_at || '').slice(0, 19).replace('T', ' ')],
            ].map(([k, v]) => (
              <div key={k} style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6, borderBottom: '1px solid #0d0d0d', paddingBottom: 4 }}>
                <span style={mono(10, '#555')}>{k}</span>
                <span style={mono(10, '#ccc')}>{v}</span>
              </div>
            ))}
          </div>

          {/* Risk Score Breakdown */}
          <div style={card()}>
            <div style={label9}>RISK SCORE BREAKDOWN</div>
            <div style={{ textAlign: 'center', marginBottom: 16 }}>
              <div style={{ ...mono(52, riskColor), fontWeight: 'bold', lineHeight: 1 }}>{riskScore}</div>
              <div style={{ ...mono(10, '#444'), letterSpacing: 3, marginTop: 4 }}>OUT OF 100</div>
              <div style={{
                display: 'inline-block', marginTop: 8, padding: '4px 12px',
                background: riskColor + '22', border: `1px solid ${riskColor}`,
                borderRadius: 4, ...mono(10, riskColor), fontWeight: 'bold', letterSpacing: 2,
              }}>{riskLevel}</div>
            </div>

            {riskFactors.length > 0 ? riskFactors.map((f, i) => (
              <div key={i} style={{ marginBottom: 10 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 3 }}>
                  <span style={mono(10, '#aaa')}>{f.name}</span>
                  <span style={{ ...mono(10, '#00d4ff'), fontWeight: 'bold' }}>+{f.contribution?.toFixed(1)}</span>
                </div>
                <div style={{ height: 4, background: '#0d0d1a', borderRadius: 2 }}>
                  <div style={{
                    width: `${Math.min((f.contribution / f.weight) * 100, 100)}%`,
                    height: '100%', background: '#00d4ff', borderRadius: 2,
                    boxShadow: '0 0 6px #00d4ff',
                  }} />
                </div>
                <div style={{ ...mono(9, '#444'), marginTop: 2 }}>{f.reason}</div>
              </div>
            )) : (
              <div style={{ ...mono(10, '#333'), textAlign: 'center', paddingTop: 20 }}>No factor data</div>
            )}
          </div>

          {/* Process Intelligence */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            <div style={card()}>
              <div style={label9}>PROCESS INTELLIGENCE</div>
              {[
                ['Process',     incident.process_name || 'Unknown'],
                ['PID',         incident.process_pid || 'Unknown'],
                ['Path',        incident.process_path || 'Unknown'],
              ].map(([k, v]) => (
                <div key={k} style={{ marginBottom: 8 }}>
                  <div style={mono(9, '#444')}>{k}</div>
                  <div style={{ ...mono(10, '#ccc'), wordBreak: 'break-all' }}>{v}</div>
                </div>
              ))}
            </div>

            <div style={card()}>
              <div style={label9}>FILE INFORMATION</div>
              {[
                ['File Name',  incident.file_name || 'Unknown'],
                ['SHA-256',    incident.file_sha256 ? incident.file_sha256.slice(0, 16) + '...' : 'Unknown'],
                ['Files Affected', incident.files_affected || 0],
              ].map(([k, v]) => (
                <div key={k} style={{ marginBottom: 8 }}>
                  <div style={mono(9, '#444')}>{k}</div>
                  <div style={{ ...mono(10, '#ccc'), wordBreak: 'break-all' }}>{v}</div>
                </div>
              ))}
            </div>

            {incident.honeypot_hit && (
              <div style={{ ...card('#ff003c33'), borderColor: '#ff003c' }}>
                <div style={label9}>🍯 HONEYPOT TRIGGERED</div>
                <div style={{ ...mono(11, '#ff003c'), fontWeight: 'bold' }}>DECOY FILE ACCESSED</div>
                <div style={{ ...mono(10, '#888'), marginTop: 4 }}>{incident.honeypot_resource || 'Unknown resource'}</div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ════════════════════════════════════════════════ */}
      {/* ATTACKER TAB                                     */}
      {/* ════════════════════════════════════════════════ */}
      {tab === 'attacker' && (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14 }}>

          {/* Attacker Info */}
          <div style={card()}>
            <div style={label9}>ATTACKER INFORMATION</div>
            {[
              ['Source IP',     incident.source_ip || 'Unknown'],
              ['IP Version',    incident.source_ip?.includes(':') ? 'IPv6' : 'IPv4'],
              ['Source Port',   incident.source_port || 'Unknown'],
              ['Destination IP', incident.dest_ip || 'Unknown'],
              ['Destination Port', incident.dest_port || 'Unknown'],
              ['Protocol',      incident.protocol || 'Unknown'],
              ['MAC Address',   incident.source_mac || (
                incident.source_ip && !incident.source_ip.startsWith('192.168') && !incident.source_ip.startsWith('10.')
                  ? 'Not observable remotely'
                  : 'Unknown'
              )],
            ].map(([k, v]) => (
              <div key={k} style={{
                display: 'flex', justifyContent: 'space-between', padding: '8px 0',
                borderBottom: '1px solid #0d0d0d',
              }}>
                <span style={mono(10, '#555')}>{k}</span>
                <span style={{ ...mono(10, '#ccc'), maxWidth: 220, textAlign: 'right', wordBreak: 'break-all' }}>{v}</span>
              </div>
            ))}
          </div>

          {/* Geolocation */}
          <div style={card()}>
            <div style={label9}>APPROXIMATE IP GEOLOCATION</div>
            {!geo ? (
              <div style={{ ...mono(11, '#333'), paddingTop: 20 }}>Loading geolocation...</div>
            ) : geo.display?.type === 'private' ? (
              <div>
                <div style={{ ...mono(14, '#00d4ff'), fontWeight: 'bold', marginBottom: 8 }}>LOCAL NETWORK</div>
                <div style={{ ...mono(10, '#666') }}>Private/Local IP Address</div>
                <div style={{ ...mono(10, '#444'), marginTop: 4 }}>Not routable on internet</div>
              </div>
            ) : geo.display?.type === 'approximate' ? (
              <div>
                <div style={{ ...mono(14, '#00d4ff'), fontWeight: 'bold', marginBottom: 12 }}>
                  {geo.display?.city}, {geo.display?.country}
                </div>
                {[
                  ['Country',   geo.display?.country],
                  ['Region',    geo.display?.region],
                  ['City',      geo.display?.city],
                  ['ISP',       geo.display?.isp],
                  ['ASN',       geo.display?.asn],
                  ['Organization', geo.display?.org],
                  ['Timezone',  geo.display?.timezone],
                  ['Coordinates', geo.display?.lat ? `${geo.display.lat?.toFixed(2)}, ${geo.display.lon?.toFixed(2)}` : 'N/A'],
                ].map(([k, v]) => (
                  <div key={k} style={{
                    display: 'flex', justifyContent: 'space-between', padding: '5px 0',
                    borderBottom: '1px solid #0d0d0d',
                  }}>
                    <span style={mono(10, '#555')}>{k}</span>
                    <span style={{ ...mono(10, '#ccc'), maxWidth: 200, textAlign: 'right' }}>{v || 'Unknown'}</span>
                  </div>
                ))}
                <div style={{
                  marginTop: 12, padding: '6px 10px', background: '#0a1a0a',
                  border: '1px solid #00ff8833', borderRadius: 4,
                  ...mono(9, '#00ff8888'),
                }}>
                  ⚠️ {geo.display?.note}
                </div>
              </div>
            ) : (
              <div style={{ ...mono(11, '#555'), paddingTop: 20 }}>
                Location: Unknown — Geolocation unavailable for this IP
              </div>
            )}
          </div>

          {/* Threat Intelligence — AbuseIPDB + Shodan */}
          <ThreatIntelPanel
            ip={incident.source_ip}
            fileHash={incident.file_sha256}
          />
        </div>
      )}

      {/* ════════════════════════════════════════════════ */}
      {/* AI INVESTIGATE TAB                              */}
      {/* ════════════════════════════════════════════════ */}
      {tab === 'investigate' && (
        <div style={card()}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
            <div style={label9}>AI INCIDENT INVESTIGATION</div>
            <button onClick={loadInvestigation} style={{
              padding: '6px 14px', fontSize: 9, letterSpacing: 2, fontFamily: 'monospace',
              background: '#00d4ff22', border: '1px solid #00d4ff', borderRadius: 4,
              color: '#00d4ff', cursor: 'pointer',
            }}>🔄 REFRESH</button>
          </div>
          {!investigation ? (
            <div style={{ ...mono(11, '#333'), textAlign: 'center', padding: 40 }}>
              Loading AI investigation... This uses actual incident data.
            </div>
          ) : (
            <div style={{
              background: '#000a1e', border: '1px solid #00d4ff22', borderRadius: 6,
              padding: 20, ...mono(12, '#ccc'), lineHeight: 1.8, whiteSpace: 'pre-wrap',
            }}>
              {investigation}
            </div>
          )}
          <div style={{ ...mono(9, '#333'), marginTop: 12 }}>
            Investigation uses real incident telemetry. AI cannot fabricate evidence. 
            If information is unavailable, it will say "Not available from collected telemetry."
          </div>
        </div>
      )}

      {/* ════════════════════════════════════════════════ */}
      {/* TIMELINE TAB                                     */}
      {/* ════════════════════════════════════════════════ */}
      {tab === 'timeline' && (
        <div style={card()}>
          <div style={label9}>ATTACK TIMELINE</div>
          {timeline.length === 0 ? (
            <div style={{ ...mono(11, '#333'), textAlign: 'center', padding: 40 }}>No timeline data</div>
          ) : (
            <div style={{ position: 'relative', paddingLeft: 20 }}>
              <div style={{
                position: 'absolute', left: 7, top: 0, bottom: 0,
                width: 2, background: 'linear-gradient(#00d4ff, #ff003c)',
                borderRadius: 2,
              }} />
              {timeline.map((entry, i) => {
                const sevC = SEV_COLOR[entry.severity] || '#00d4ff'
                return (
                  <div key={i} style={{ marginBottom: 16, position: 'relative' }}>
                    <div style={{
                      position: 'absolute', left: -22, top: 3, width: 10, height: 10,
                      borderRadius: '50%', background: sevC,
                      boxShadow: `0 0 8px ${sevC}`,
                    }} />
                    <div style={{ display: 'flex', gap: 12, alignItems: 'baseline' }}>
                      <span style={{ ...mono(9, '#444'), whiteSpace: 'nowrap' }}>
                        {(entry.time || '').slice(11, 19)}
                      </span>
                      <span style={{ ...mono(11, '#fff'), fontWeight: 'bold' }}>
                        {entry.event}
                      </span>
                    </div>
                    {entry.description && entry.description !== entry.event && (
                      <div style={{ ...mono(10, '#666'), marginTop: 3, marginLeft: 60 }}>
                        {entry.description}
                      </div>
                    )}
                  </div>
                )
              })}
            </div>
          )}
        </div>
      )}

      {/* ════════════════════════════════════════════════ */}
      {/* ATTACK GRAPH TAB                                */}
      {/* ════════════════════════════════════════════════ */}
      {tab === 'graph' && (
        <div style={card()}>
          <div style={label9}>ATTACK GRAPH</div>
          {!attackGraph || !attackGraph.nodes?.length ? (
            <div style={{ ...mono(11, '#333'), textAlign: 'center', padding: 40 }}>No graph data available</div>
          ) : (
            <AttackGraph nodes={attackGraph.nodes} edges={attackGraph.edges} />
          )}
        </div>
      )}

      {/* ════════════════════════════════════════════════ */}
      {/* EVIDENCE TAB                                    */}
      {/* ════════════════════════════════════════════════ */}
      {tab === 'evidence' && (
        <div style={card()}>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 16 }}>
            <div style={label9}>FORENSIC EVIDENCE BUNDLE</div>
            <button onClick={loadEvidence} style={{
              padding: '6px 14px', fontSize: 9, letterSpacing: 2, fontFamily: 'monospace',
              background: '#00d4ff22', border: '1px solid #00d4ff', borderRadius: 4,
              color: '#00d4ff', cursor: 'pointer',
            }}>🔄 GENERATE</button>
          </div>
          {!evidence ? (
            <div style={{ ...mono(11, '#333'), textAlign: 'center', padding: 40 }}>
              Click GENERATE to create forensic evidence bundle
            </div>
          ) : (
            <div>
              <div style={{
                background: '#000a1e', border: '1px solid #00ff8833', borderRadius: 6,
                padding: 12, marginBottom: 12,
              }}>
                <div style={{ ...mono(10, '#00ff88'), fontWeight: 'bold', marginBottom: 4 }}>EVIDENCE HASH (SHA-256)</div>
                <div style={{ ...mono(11, '#00d4ff'), wordBreak: 'break-all' }}>
                  {evidence.meta?.evidence_hash || 'N/A'}
                </div>
                <div style={{ ...mono(9, '#333'), marginTop: 6 }}>
                  This hash is recorded on blockchain for tamper detection
                </div>
              </div>

              {[
                ['Incident', evidence.incident_summary],
                ['Attacker', evidence.attacker_info],
                ['Process',  evidence.process_info],
                ['File',     evidence.file_info],
                ['ML',       evidence.ml_analysis],
                ['Response', evidence.response_actions],
                ['Blockchain', evidence.blockchain],
              ].map(([title, obj]) => obj && Object.keys(obj).some(k => obj[k]) ? (
                <div key={title} style={{ marginBottom: 12 }}>
                  <div style={{ ...mono(9, '#444'), letterSpacing: 3, marginBottom: 6 }}>{title.toUpperCase()}</div>
                  <div style={{
                    background: '#050510', border: '1px solid #111', borderRadius: 4, padding: 10,
                  }}>
                    {Object.entries(obj).filter(([, v]) => v != null && v !== 0 && v !== '').map(([k, v]) => (
                      <div key={k} style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                        <span style={mono(9, '#444')}>{k}</span>
                        <span style={{ ...mono(9, '#aaa'), maxWidth: 300, textAlign: 'right', wordBreak: 'break-all' }}>
                          {typeof v === 'object' ? JSON.stringify(v).slice(0, 60) : String(v).slice(0, 80)}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              ) : null)}
            </div>
          )}
        </div>
      )}

      {/* ════════════════════════════════════════════════ */}
      {/* REPLAY TAB                                      */}
      {/* ════════════════════════════════════════════════ */}
      {tab === 'replay' && (
        <div style={card()}>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 16 }}>
            <div style={label9}>INCIDENT REPLAY — ACTUAL RECORDED EVENTS</div>
            <div style={{ display: 'flex', gap: 8 }}>
              <button onClick={loadReplay} style={{
                padding: '6px 14px', fontSize: 9, letterSpacing: 2, fontFamily: 'monospace',
                background: 'transparent', border: '1px solid #444', borderRadius: 4,
                color: '#888', cursor: 'pointer',
              }}>🔄 LOAD</button>
              <button onClick={startReplay} disabled={replaying || !replayEvents.length} style={{
                padding: '6px 14px', fontSize: 9, letterSpacing: 2, fontFamily: 'monospace',
                background: replaying ? '#00ff8822' : '#00d4ff22',
                border: `1px solid ${replaying ? '#00ff88' : '#00d4ff'}`,
                borderRadius: 4, color: replaying ? '#00ff88' : '#00d4ff', cursor: 'pointer',
              }}>{replaying ? '▶ REPLAYING...' : '▶ PLAY REPLAY'}</button>
            </div>
          </div>
          {!replayEvents.length ? (
            <div style={{ ...mono(11, '#333'), textAlign: 'center', padding: 40 }}>
              No recorded events. Click LOAD to fetch events.
            </div>
          ) : (
            <div style={{ maxHeight: 500, overflowY: 'auto' }}>
              {replayEvents.slice(0, replayIndex || replayEvents.length).map((ev, i) => {
                const sev  = ev.severity || 'LOW'
                const col  = SEV_COLOR[sev] || '#aaa'
                const isCurrent = replaying && i === replayIndex - 1
                return (
                  <div key={i} style={{
                    display: 'flex', gap: 10, padding: '6px 8px', marginBottom: 3,
                    background: isCurrent ? '#001a00' : 'transparent',
                    border: `1px solid ${isCurrent ? '#00ff88' : 'transparent'}`,
                    borderRadius: 4, transition: 'all 0.3s',
                  }}>
                    <span style={{ ...mono(9, '#333'), whiteSpace: 'nowrap' }}>
                      {(ev.timestamp || '').slice(11, 19)}
                    </span>
                    <span style={{ ...mono(9, col), minWidth: 80, fontWeight: 'bold' }}>{sev}</span>
                    <span style={{ ...mono(9, '#777'), minWidth: 150, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                      {ev.event_type}
                    </span>
                    <span style={mono(9, '#aaa')}>{ev.description}</span>
                  </div>
                )
              })}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

// ── Simple Attack Graph Visualizer ────────────────────────
function AttackGraph({ nodes, edges }) {
  const TYPE_COLOR = {
    ip:          '#ff8c00',
    process:     '#00d4ff',
    file:        '#ffe600',
    honeypot:    '#ff003c',
    destination: '#aaa',
    ml:          '#9b59b6',
    incident:    '#ff003c',
    response:    '#00ff88',
  }

  return (
    <div style={{ padding: 16 }}>
      {/* Nodes */}
      <div style={{ marginBottom: 20 }}>
        <div style={{ fontFamily: 'monospace', fontSize: 9, color: '#444', letterSpacing: 3, marginBottom: 12 }}>NODES</div>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
          {nodes.map(n => {
            const col = TYPE_COLOR[n.type] || '#aaa'
            return (
              <div key={n.id} style={{
                padding: '6px 12px',
                background: col + '11',
                border: `1px solid ${col}44`,
                borderRadius: 6,
                fontFamily: 'monospace',
              }}>
                <div style={{ fontSize: 8, color: col + '88', letterSpacing: 2, marginBottom: 2 }}>{n.type?.toUpperCase()}</div>
                <div style={{ fontSize: 11, color: col, fontWeight: 'bold' }}>{n.label}</div>
              </div>
            )
          })}
        </div>
      </div>

      {/* Edges */}
      <div>
        <div style={{ fontFamily: 'monospace', fontSize: 9, color: '#444', letterSpacing: 3, marginBottom: 12 }}>CONNECTIONS</div>
        {edges.map((e, i) => {
          const srcNode = nodes.find(n => n.id === e.source)
          const dstNode = nodes.find(n => n.id === e.target)
          if (!srcNode || !dstNode) return null
          return (
            <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
              <span style={{
                padding: '3px 8px', background: '#0d0d1a', border: '1px solid #111', borderRadius: 4,
                fontFamily: 'monospace', fontSize: 10, color: TYPE_COLOR[srcNode.type] || '#aaa',
              }}>{srcNode.label}</span>
              <span style={{ fontFamily: 'monospace', fontSize: 9, color: '#444' }}>
                ──{e.label || '→'}──▶
              </span>
              <span style={{
                padding: '3px 8px', background: '#0d0d1a', border: '1px solid #111', borderRadius: 4,
                fontFamily: 'monospace', fontSize: 10, color: TYPE_COLOR[dstNode.type] || '#aaa',
              }}>{dstNode.label}</span>
            </div>
          )
        })}
      </div>
    </div>
  )
}
