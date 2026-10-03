/**
 * ThreatIntelPanel — shows AbuseIPDB + Shodan + VirusTotal results
 * Used in: IncidentView (attacker tab), Dashboard (live incident card), Network page
 *
 * Props:
 *   ip        — attacker IP to enrich
 *   fileHash  — (optional) SHA-256 hash for VirusTotal
 *   compact   — bool, use smaller layout
 *   inlineData— pre-fetched threat_intel from live_incident event (skips API call)
 */
import { useState, useEffect } from 'react'
import { enrichIP, checkVirusTotal, getIntelStatus } from '../api'

const m = (sz = 11, c = '#ccc') => ({ fontFamily: 'monospace', fontSize: sz, color: c })
const sLabel = { fontFamily: 'monospace', fontSize: 9, color: '#444', letterSpacing: 3, marginBottom: 8, textTransform: 'uppercase' }

const RISK_COLOR = {
  CRITICAL: '#ff003c', HIGH: '#ff8c00', MEDIUM: '#ffe600',
  LOW: '#00ff88', CLEAN: '#00ff88', UNKNOWN: '#555',
}

function RiskBadge({ level }) {
  const col = RISK_COLOR[level] || '#555'
  return (
    <span style={{
      padding: '2px 8px', borderRadius: 3, fontSize: 9, fontFamily: 'monospace',
      fontWeight: 700, letterSpacing: 1,
      background: col + '22', border: `1px solid ${col + '66'}`, color: col,
    }}>{level || 'UNKNOWN'}</span>
  )
}

// ── AbuseIPDB Section ─────────────────────────────────────
function AbuseSection({ data, loading }) {
  if (loading) return <div style={m(10, '#333')}>Checking AbuseIPDB...</div>
  if (!data) return <div style={m(10, '#222')}>AbuseIPDB not configured — add ABUSEIPDB_API_KEY to .env</div>
  if (!data.available) return (
    <div style={m(10, '#444')}>
      {data.note?.includes('API key') ? '⚙️ ' : '⚠️ '}{data.note}
    </div>
  )

  const score = data.abuse_score || 0
  const scoreColor = score >= 75 ? '#ff003c' : score >= 25 ? '#ff8c00' : '#00ff88'

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
        <div style={{ ...m(22, scoreColor), fontWeight: 'bold', lineHeight: 1 }}>{score}%</div>
        <div style={{ textAlign: 'right' }}>
          <RiskBadge level={data.risk_level} />
          <div style={{ ...m(9, '#555'), marginTop: 3 }}>{data.total_reports} reports</div>
        </div>
      </div>
      <div style={{ height: 4, background: '#111', borderRadius: 2, marginBottom: 10 }}>
        <div style={{ width: `${score}%`, height: '100%', background: scoreColor, borderRadius: 2, boxShadow: `0 0 6px ${scoreColor}` }} />
      </div>
      {[
        ['ISP',          data.isp || 'Unknown'],
        ['Country',      data.country_code || 'Unknown'],
        ['Usage Type',   data.usage_type || 'Unknown'],
        ['Last Reported', data.last_reported ? data.last_reported.slice(0, 10) : 'Never'],
        ['Tor Exit Node', data.is_tor ? '🔴 YES' : '✅ No'],
      ].map(([k, v]) => (
        <div key={k} style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4, borderBottom: '1px solid #0d0d0d', paddingBottom: 3 }}>
          <span style={m(9, '#444')}>{k}</span>
          <span style={{ ...m(9, '#ccc') }}>{v}</span>
        </div>
      ))}
      <a href={data.url} target="_blank" rel="noreferrer"
        style={{ ...m(9, '#00d4ff'), textDecoration: 'none', display: 'block', marginTop: 8 }}>
        🔗 View on AbuseIPDB →
      </a>
    </div>
  )
}

// ── Shodan Section ────────────────────────────────────────
function ShodanSection({ data, loading }) {
  if (loading) return <div style={m(10, '#333')}>Checking Shodan...</div>
  if (!data) return <div style={m(10, '#222')}>Shodan not configured — add SHODAN_API_KEY to .env</div>
  if (!data.available) return (
    <div style={m(10, '#444')}>{data.note}</div>
  )
  if (data.note === 'No Shodan data for this IP') return (
    <div style={m(10, '#444')}>No Shodan data for this IP (new/private host)</div>
  )

  return (
    <div>
      {/* Key stats */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, marginBottom: 10 }}>
        {[
          { label: 'OPEN PORTS', value: data.port_count || 0, color: data.port_count > 5 ? '#ff8c00' : '#00ff88' },
          { label: 'CVEs',       value: data.cve_count  || 0, color: data.cve_count  > 0 ? '#ff003c' : '#00ff88' },
        ].map(s => (
          <div key={s.label} style={{ background: '#080818', border: '1px solid #111', borderRadius: 4, padding: '8px', textAlign: 'center' }}>
            <div style={{ ...m(20, s.color), fontWeight: 'bold', lineHeight: 1 }}>{s.value}</div>
            <div style={{ ...m(8, '#444'), letterSpacing: 2, marginTop: 3 }}>{s.label}</div>
          </div>
        ))}
      </div>

      {/* Organization */}
      {[
        ['Org',   data.org  || 'Unknown'],
        ['OS',    data.os   || 'Unknown'],
        ['City',  data.city || 'Unknown'],
      ].map(([k, v]) => (
        <div key={k} style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4, borderBottom: '1px solid #0d0d0d', paddingBottom: 3 }}>
          <span style={m(9, '#444')}>{k}</span>
          <span style={m(9, '#ccc')}>{v}</span>
        </div>
      ))}

      {/* Open ports */}
      {data.open_ports?.length > 0 && (
        <div style={{ marginTop: 8 }}>
          <div style={{ ...m(9, '#444'), letterSpacing: 2, marginBottom: 5 }}>OPEN PORTS</div>
          <div>
            {data.open_ports.slice(0, 15).map(p => {
              const dangerous = [22, 23, 3389, 5900, 445, 21, 3306, 27017, 6379].includes(p)
              return (
                <span key={p} style={{
                  display: 'inline-block', margin: '2px 3px', padding: '2px 6px',
                  background: dangerous ? '#1a0000' : '#0a0a1a',
                  border: `1px solid ${dangerous ? '#ff003c44' : '#1a1a2e'}`,
                  borderRadius: 3, ...m(9, dangerous ? '#ff8c00' : '#555'),
                }}>{p}</span>
              )
            })}
          </div>
        </div>
      )}

      {/* CVEs */}
      {data.cves?.length > 0 && (
        <div style={{ marginTop: 8, padding: '6px 8px', background: '#1a0000', border: '1px solid #ff003c22', borderRadius: 4 }}>
          <div style={{ ...m(9, '#ff003c'), fontWeight: 'bold', marginBottom: 4 }}>⚠ KNOWN CVEs</div>
          {data.cves.slice(0, 5).map(cve => (
            <a key={cve} href={`https://nvd.nist.gov/vuln/detail/${cve}`} target="_blank" rel="noreferrer"
              style={{ display: 'block', ...m(9, '#ff8c00'), textDecoration: 'none', marginBottom: 2 }}>
              {cve}
            </a>
          ))}
        </div>
      )}

      {/* Risk note */}
      {data.risk_note && data.risk_note !== 'No known threats' && (
        <div style={{ marginTop: 8, ...m(9, '#ff8c00') }}>⚠ {data.risk_note}</div>
      )}

      <a href={data.url} target="_blank" rel="noreferrer"
        style={{ ...m(9, '#00d4ff'), textDecoration: 'none', display: 'block', marginTop: 8 }}>
        🔗 View on Shodan →
      </a>
    </div>
  )
}

// ── VirusTotal Section ────────────────────────────────────
function VirusTotalSection({ data, loading }) {
  if (loading) return <div style={m(10, '#333')}>Checking VirusTotal...</div>
  if (!data) return <div style={m(10, '#222')}>VirusTotal not configured — add VIRUSTOTAL_API_KEY to .env</div>
  if (!data.available) return (
    <div style={m(10, '#444')}>{data.note}</div>
  )
  if (data.note?.includes('not found')) return (
    <div style={m(10, '#444')}>File not in VirusTotal database (new/unknown file)</div>
  )

  const mal   = data.malicious || 0
  const total = data.total_engines || 0
  const pct   = total > 0 ? Math.round((mal / total) * 100) : 0
  const col   = mal >= total * 0.5 ? '#ff003c' : mal > 0 ? '#ff8c00' : '#00ff88'

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
        <div>
          <div style={{ ...m(20, col), fontWeight: 'bold', lineHeight: 1 }}>
            {mal}<span style={{ ...m(13, '#444') }}>/{total}</span>
          </div>
          <div style={{ ...m(9, '#444'), letterSpacing: 2, marginTop: 2 }}>ENGINES DETECTED</div>
        </div>
        <RiskBadge level={data.verdict} />
      </div>

      <div style={{ height: 4, background: '#111', borderRadius: 2, marginBottom: 10 }}>
        <div style={{ width: `${pct}%`, height: '100%', background: col, borderRadius: 2 }} />
      </div>

      {data.popular_name && (
        <div style={{ padding: '6px 10px', background: '#1a0000', border: '1px solid #ff003c22', borderRadius: 4, marginBottom: 8 }}>
          <div style={{ ...m(9, '#444'), marginBottom: 3 }}>MALWARE FAMILY</div>
          <div style={{ ...m(12, '#ff8c00'), fontWeight: 'bold' }}>{data.popular_name}</div>
        </div>
      )}

      {[
        ['File Type',   data.file_type || 'Unknown'],
        ['File Size',   data.file_size ? `${(data.file_size/1024).toFixed(1)} KB` : 'Unknown'],
        ['First Seen',  data.first_seen ? new Date(data.first_seen * 1000).toLocaleDateString() : 'Unknown'],
      ].map(([k, v]) => (
        <div key={k} style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4, borderBottom: '1px solid #0d0d0d', paddingBottom: 3 }}>
          <span style={m(9, '#444')}>{k}</span>
          <span style={m(9, '#ccc')}>{v}</span>
        </div>
      ))}

      {/* Top detections */}
      {data.detected_by?.length > 0 && (
        <div style={{ marginTop: 8 }}>
          <div style={{ ...m(9, '#444'), letterSpacing: 2, marginBottom: 5 }}>DETECTED BY</div>
          {data.detected_by.slice(0, 5).map((d, i) => (
            <div key={i} style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 3 }}>
              <span style={m(9, '#777')}>{d.engine}</span>
              <span style={{ ...m(9, '#ff8c00') }}>{d.result?.slice(0, 30)}</span>
            </div>
          ))}
        </div>
      )}

      <a href={data.url} target="_blank" rel="noreferrer"
        style={{ ...m(9, '#00d4ff'), textDecoration: 'none', display: 'block', marginTop: 8 }}>
        🔗 View on VirusTotal →
      </a>
    </div>
  )
}

// ══════════════════════════════════════════════════════════
// MAIN COMPONENT
// ══════════════════════════════════════════════════════════
export default function ThreatIntelPanel({ ip, fileHash, compact = false, inlineData = null }) {
  const [abuseData,  setAbuseData]  = useState(null)
  const [shodanData, setShodanData] = useState(null)
  const [vtData,     setVtData]     = useState(null)
  const [loading,    setLoading]    = useState(false)
  const [configured, setConfigured] = useState(null)

  // Use inline data from live_incident if available
  useEffect(() => {
    if (inlineData) {
      setAbuseData(inlineData.abuseipdb || null)
      setShodanData(inlineData.shodan   || null)
      return
    }
  }, [inlineData])

  // Fetch status and data
  useEffect(() => {
    getIntelStatus()
      .then(r => setConfigured(r.data))
      .catch(() => setConfigured({ any_active: false }))
  }, [])

  const runEnrichment = async () => {
    setLoading(true)
    try {
      if (ip) {
        const r = await enrichIP(ip)
        setAbuseData(r.data.abuseipdb || null)
        setShodanData(r.data.shodan   || null)
      }
      if (fileHash) {
        const r = await checkVirusTotal(fileHash)
        setVtData(r.data)
      }
    } catch (e) {
      console.error('Intel fetch failed:', e)
    } finally {
      setLoading(false)
    }
  }

  const cardStyle = (color = '#00d4ff22') => ({
    background: '#05051a', border: `1px solid ${color}`,
    borderRadius: 8, padding: 14,
  })

  if (!ip && !fileHash) return null

  const isPrivate = ip && (
    ip.startsWith('192.168.') || ip.startsWith('10.') ||
    ip.startsWith('172.') || ip === '127.0.0.1' || ip.startsWith('::1')
  )

  return (
    <div style={{ gridColumn: '1 / -1' }}>
      {/* Header */}
      <div style={{
        display: 'flex', justifyContent: 'space-between', alignItems: 'center',
        marginBottom: 12, padding: '10px 14px',
        background: '#080818', border: '1px solid #00d4ff22', borderRadius: 8,
      }}>
        <div>
          <div style={{ ...m(11, '#00d4ff'), fontWeight: 'bold', letterSpacing: 2 }}>
            🔍 THREAT INTELLIGENCE
          </div>
          <div style={{ ...m(9, '#444'), marginTop: 2 }}>
            AbuseIPDB · Shodan · VirusTotal
            {configured && !configured.any_active && (
              <span style={{ color: '#ff8c00', marginLeft: 8 }}>
                ⚠ No API keys configured — add to .env
              </span>
            )}
          </div>
        </div>
        {!inlineData && !isPrivate && (
          <button onClick={runEnrichment} disabled={loading} style={{
            padding: '6px 14px', fontSize: 9, letterSpacing: 2, fontFamily: 'monospace',
            background: loading ? '#111' : '#00d4ff22',
            border: '1px solid #00d4ff', borderRadius: 4,
            color: loading ? '#444' : '#00d4ff', cursor: loading ? 'not-allowed' : 'pointer',
          }}>
            {loading ? '⏳ CHECKING...' : '🔍 ENRICH IP'}
          </button>
        )}
        {isPrivate && (
          <span style={{ ...m(9, '#444') }}>Private IP — external lookup not applicable</span>
        )}
      </div>

      {/* Panels */}
      {!isPrivate && (
        <div style={{ display: 'grid', gridTemplateColumns: fileHash ? '1fr 1fr 1fr' : '1fr 1fr', gap: 12 }}>

          {/* AbuseIPDB */}
          <div style={cardStyle('#ff003c22')}>
            <div style={{ ...sLabel, color: '#ff003c' }}>🛡 ABUSEIPDB</div>
            <AbuseSection data={abuseData} loading={loading && !abuseData} />
          </div>

          {/* Shodan */}
          <div style={cardStyle('#ff8c0022')}>
            <div style={{ ...sLabel, color: '#ff8c00' }}>🌐 SHODAN</div>
            <ShodanSection data={shodanData} loading={loading && !shodanData} />
          </div>

          {/* VirusTotal — only when fileHash provided */}
          {fileHash && (
            <div style={cardStyle('#a78bfa22')}>
              <div style={{ ...sLabel, color: '#a78bfa' }}>🦠 VIRUSTOTAL</div>
              <VirusTotalSection data={vtData} loading={loading && !vtData} />
            </div>
          )}
        </div>
      )}
    </div>
  )
}
