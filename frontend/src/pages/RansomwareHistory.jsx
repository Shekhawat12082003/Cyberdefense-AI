import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { getThreats } from '../api'

const formatDate = (value) => value
  ? new Date(value).toLocaleString()
  : '—'

export default function RansomwareHistory() {
  const [records, setRecords] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => {
    getThreats()
      .then(({ data }) => {
        const threats = Array.isArray(data) ? data : data.threats || []
        setRecords(threats.filter(item => item.prediction === 'Ransomware'))
      })
      .catch(() => setError('Unable to load ransomware history. Check that the backend is running.'))
      .finally(() => setLoading(false))
  }, [])

  return (
    <main style={{
      minHeight: '100vh',
      background: '#000010',
      color: '#ccc',
      padding: 24,
      fontFamily: 'monospace',
    }}>
      <div style={{ maxWidth: 1200, margin: '0 auto' }}>
        <div style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          marginBottom: 28,
        }}>
          <div>
            <h1 style={{ color: '#00d4ff', fontSize: 24, letterSpacing: 2, margin: 0 }}>
              RANSOMWARE HISTORY
            </h1>
            <p style={{ color: '#666', fontSize: 11, letterSpacing: 2 }}>
              PREVIOUS RANSOMWARE DETECTIONS
            </p>
          </div>
          <Link
            to="/ransomware"
            style={{
              color: '#00d4ff',
              border: '1px solid #00d4ff',
              borderRadius: 4,
              padding: '8px 14px',
              fontSize: 11,
              textDecoration: 'none',
            }}
          >
            ← RANSOMWARE CENTER
          </Link>
        </div>

        {error && (
          <div style={{
            border: '1px solid #ff003c66',
            color: '#ff6688',
            padding: 14,
            marginBottom: 16,
            borderRadius: 6,
          }}>
            {error}
          </div>
        )}

        <section style={{
          background: '#05051a',
          border: '1px solid #00d4ff22',
          borderRadius: 8,
          padding: 20,
          overflowX: 'auto',
        }}>
          {loading ? (
            <div style={{ color: '#666', padding: 30, textAlign: 'center' }}>
              Loading ransomware history...
            </div>
          ) : records.length === 0 ? (
            <div style={{ color: '#666', padding: 30, textAlign: 'center' }}>
              No previous ransomware detections found.
            </div>
          ) : (
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
              <thead>
                <tr style={{ color: '#666', textAlign: 'left', borderBottom: '1px solid #222' }}>
                  <th style={{ padding: 10 }}>FILE</th>
                  <th style={{ padding: 10 }}>THREAT SCORE</th>
                  <th style={{ padding: 10 }}>RISK</th>
                  <th style={{ padding: 10 }}>AI SUMMARY</th>
                  <th style={{ padding: 10 }}>BLOCKCHAIN HASH</th>
                  <th style={{ padding: 10 }}>DETECTED</th>
                </tr>
              </thead>
              <tbody>
                {records.map((record) => (
                  <tr key={record.id} style={{ borderBottom: '1px solid #151525' }}>
                    <td style={{ padding: 10, color: '#fff' }}>{record.file_name || 'unknown'}</td>
                    <td style={{ padding: 10, color: '#ff003c', fontWeight: 'bold' }}>
                      {Number(record.threat_score || 0).toFixed(1)}
                    </td>
                    <td style={{ padding: 10, color: '#ff8c00' }}>RANSOMWARE</td>
                    <td style={{ padding: 10, color: '#999', maxWidth: 300 }}>
                      {record.ai_summary || '—'}
                    </td>
                    <td style={{ padding: 10, color: '#a78bfa', maxWidth: 180, wordBreak: 'break-all' }}>
                      {record.blockchain_hash || '—'}
                    </td>
                    <td style={{ padding: 10, color: '#777', whiteSpace: 'nowrap' }}>
                      {formatDate(record.timestamp)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </section>
      </div>
    </main>
  )
}
