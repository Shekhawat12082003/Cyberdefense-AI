import { useState, useEffect } from 'react'
import { Link, useNavigate } from 'react-router-dom'

export default function Admin() {
  const navigate  = useNavigate()
  const [tab,     setTab]     = useState('users')
  const [users,   setUsers]   = useState([])
  const [qFiles,  setQFiles]  = useState([])
  const [sysInfo, setSysInfo] = useState(null)
  const [stats,   setStats]   = useState(null)
  const [loading, setLoading] = useState(false)
  const [msg,     setMsg]     = useState(null)
  const [newUser, setNewUser] = useState({ username: '', password: '', role: 'analyst' })
  const [threshold, setThreshold] = useState(70)

  const role = localStorage.getItem('role')

  useEffect(() => {
    if (role !== 'admin') navigate('/')
  }, [])

  const headers = {
    'Content-Type': 'application/json',
    Authorization:  `Bearer ${localStorage.getItem('token')}`
  }

  const showMsg = (text, type = 'success') => {
    setMsg({ text, type })
    setTimeout(() => setMsg(null), 3000)
  }

  // Fetch current threshold from backend on mount
  useEffect(() => {
    fetch('http://localhost:5000/api/admin/settings', { headers })
      .then(r => r.ok ? r.json() : null)
      .then(d => { if (d?.threat_threshold !== undefined) setThreshold(d.threat_threshold) })
      .catch(() => {})
  }, [])

  const loadAll = async () => {
    try {
      const [u, q, s, st] = await Promise.all([
        fetch('http://localhost:5000/api/admin/users',      { headers }).then(r => r.json()),
        fetch('http://localhost:5000/api/admin/quarantine', { headers }).then(r => r.json()),
        fetch('http://localhost:5000/api/admin/system',     { headers }).then(r => r.json()),
        fetch('http://localhost:5000/api/stats',            { headers }).then(r => r.json()),
      ])
      setUsers(Array.isArray(u) ? u : [])
      setQFiles(Array.isArray(q) ? q : [])
      setSysInfo(s)
      setStats(st)
    } catch {
      showMsg('Failed to load data', 'error')
    }
  }

  useEffect(() => { loadAll() }, [])

  const addUser = async () => {
    if (!newUser.username || !newUser.password) {
      showMsg('Username and password required', 'error')
      return
    }
    setLoading(true)
    try {
      const res  = await fetch('http://localhost:5000/api/admin/users', {
        method: 'POST', headers,
        body:   JSON.stringify(newUser)
      })
      const data = await res.json()
      if (res.ok) {
        showMsg(`✅ User ${newUser.username} created`)
        setNewUser({ username: '', password: '', role: 'analyst' })
        loadAll()
      } else {
        showMsg(data.error, 'error')
      }
    } finally {
      setLoading(false)
    }
  }

  const deleteUser = async (username) => {
    if (!confirm(`Delete user "${username}"?`)) return
    const res = await fetch(`http://localhost:5000/api/admin/users/${username}`, {
      method: 'DELETE', headers
    })
    if (res.ok) {
      showMsg(`🗑️ User ${username} deleted`)
      loadAll()
    }
  }

  const clearQuarantine = async () => {
    if (!confirm('Clear all quarantined files permanently?')) return
    const res  = await fetch('http://localhost:5000/api/admin/quarantine/clear', {
      method: 'DELETE', headers
    })
    const data = await res.json()
    showMsg(data.status)
    loadAll()
  }

  const clearThreats = async () => {
    if (!confirm('Clear entire threat database? Cannot be undone!')) return
    const res  = await fetch('http://localhost:5000/api/admin/threats/clear', {
      method: 'DELETE', headers
    })
    const data = await res.json()
    showMsg(data.status)
    loadAll()
  }

  const testEmail = async () => {
    const res  = await fetch('http://localhost:5000/api/email/test', {
      method: 'POST', headers
    })
    const data = await res.json()
    showMsg(data.status || data.error)
  }

  const testAlert = async () => {
    await fetch('http://localhost:5000/api/test-alert', {
      method: 'POST', headers
    })
    showMsg('🚨 Test alert sent to dashboard!')
  }

  const updateThreshold = async () => {
    const res  = await fetch('http://localhost:5000/api/admin/settings', {
      method: 'POST', headers,
      body:   JSON.stringify({ threat_threshold: threshold })
    })
    const data = await res.json()
    showMsg(data.status)
  }

  const TABS = [
    { id: 'users',      label: '👤 USERS'      },
    { id: 'quarantine', label: '🔒 QUARANTINE'  },
    { id: 'system',     label: '⚙️ SYSTEM'      },
    { id: 'settings',   label: '🛠️ SETTINGS'   },
  ]

  return (
    <div className="min-h-screen bg-black cyber-grid p-6">

      {/* Header */}
      <div className="flex justify-between items-center mb-6">
        <div>
          <h1 className="text-2xl font-bold neon-text-blue tracking-widest cursor">
            ADMIN PANEL
          </h1>
          <p className="text-xs text-gray-500 mt-1">
            System administration — admin access only
          </p>
        </div>
        <div className="flex gap-3">
          <button onClick={loadAll}
            className="px-4 py-2 text-xs border border-green-400 text-green-400 rounded hover:bg-green-400 hover:text-black transition">
            🔄 REFRESH
          </button>
          <Link to="/" className="px-4 py-2 text-xs border border-cyan-400 text-cyan-400 rounded hover:bg-cyan-400 hover:text-black transition">
            ← DASHBOARD
          </Link>
        </div>
      </div>

      {/* Message Toast */}
      {msg && (
        <div className={`mb-4 p-3 rounded text-sm fade-in font-bold ${msg.type === 'error' ? 'glow-red bg-red-950 text-red-400' : 'glow-green bg-green-950 text-green-400'}`}>
          {msg.text}
        </div>
      )}

      {/* Stats Bar */}
      {sysInfo && (
        <div className="grid grid-cols-5 gap-3 mb-6">
          {[
            { label: 'USERS',       value: sysInfo.users_count,      color: 'text-cyan-400'   },
            { label: 'TOTAL SCANS', value: stats?.total_scanned || 0,   color: 'text-white'    },
            { label: 'THREATS',     value: stats?.active_threats || 0, color: 'text-red-500'  },
            { label: 'QUARANTINED', value: sysInfo.quarantine_files, color: 'text-yellow-400' },
            { label: 'BLOCKCHAIN',  value: sysInfo.blockchain_logs,  color: 'text-green-400'  },
          ].map((s, i) => (
            <div key={i} className="glow-blue bg-gray-950 rounded p-4 text-center cyber-card">
              <div className={`text-3xl font-bold ${s.color}`}
                style={{ textShadow: `0 0 15px currentColor` }}>
                {s.value}
              </div>
              <div className="text-xs text-gray-500 tracking-widest mt-1">{s.label}</div>
            </div>
          ))}
        </div>
      )}

      {/* Tabs */}
      <div className="flex gap-2 mb-6 border-b border-gray-800 pb-2">
        {TABS.map(t => (
          <button key={t.id} onClick={() => setTab(t.id)}
            className={`px-5 py-2 text-xs tracking-widest rounded-t transition ${
              tab === t.id
                ? 'bg-cyan-400 text-black font-bold'
                : 'border border-gray-700 text-gray-400 hover:border-cyan-400 hover:text-cyan-400'
            }`}>
            {t.label}
          </button>
        ))}
      </div>

      {/* ── USERS TAB ── */}
      {tab === 'users' && (
        <div className="space-y-6 fade-in">

          {/* Add User */}
          <div className="glow-blue bg-gray-950 rounded-lg p-6 cyber-card">
            <h2 className="neon-text-blue text-sm tracking-widest mb-4">➕ ADD NEW USER</h2>
            <div className="grid grid-cols-3 gap-4 mb-4">
              <div>
                <label className="text-xs text-gray-400 tracking-widest">USERNAME</label>
                <input
                  className="w-full mt-1 px-3 py-2 bg-black border border-gray-700 rounded text-white text-sm focus:outline-none focus:border-cyan-400 transition"
                  value={newUser.username}
                  onChange={e => setNewUser(p => ({ ...p, username: e.target.value }))}
                  placeholder="e.g. john_doe"
                />
              </div>
              <div>
                <label className="text-xs text-gray-400 tracking-widest">PASSWORD</label>
                <input
                  type="password"
                  className="w-full mt-1 px-3 py-2 bg-black border border-gray-700 rounded text-white text-sm focus:outline-none focus:border-cyan-400 transition"
                  value={newUser.password}
                  onChange={e => setNewUser(p => ({ ...p, password: e.target.value }))}
                  placeholder="strong password"
                />
              </div>
              <div>
                <label className="text-xs text-gray-400 tracking-widest">ROLE</label>
                <select
                  className="w-full mt-1 px-3 py-2 bg-black border border-gray-700 rounded text-white text-sm focus:outline-none focus:border-cyan-400 transition"
                  value={newUser.role}
                  onChange={e => setNewUser(p => ({ ...p, role: e.target.value }))}>
                  <option value="analyst">Analyst</option>
                  <option value="admin">Admin</option>
                </select>
              </div>
            </div>
            <button onClick={addUser} disabled={loading}
              className="px-8 py-2 bg-cyan-400 text-black font-bold text-xs tracking-widest rounded hover:opacity-80 transition disabled:opacity-50">
              {loading ? '⏳ CREATING...' : '➕ CREATE USER'}
            </button>
          </div>

          {/* User List */}
          <div className="glow-blue bg-gray-950 rounded-lg p-6 cyber-card">
            <h2 className="neon-text-blue text-sm tracking-widest mb-4">
              👥 USER LIST
              <span className="ml-2 text-gray-600 text-xs font-normal">({users.length} users)</span>
            </h2>
            <table className="w-full text-xs">
              <thead>
                <tr className="text-gray-500 border-b border-gray-800">
                  <th className="text-left py-2 pr-6">#</th>
                  <th className="text-left py-2 pr-6">USERNAME</th>
                  <th className="text-left py-2 pr-6">ROLE</th>
                  <th className="text-left py-2">ACTIONS</th>
                </tr>
              </thead>
              <tbody>
                {users.map((u, i) => (
                  <tr key={i} className="border-b border-gray-900 hover:bg-gray-900 transition">
                    <td className="py-3 pr-6 text-gray-600">{i + 1}</td>
                    <td className="py-3 pr-6 text-white font-bold">{u.username}</td>
                    <td className="py-3 pr-6">
                      <span className={`px-3 py-1 rounded text-xs font-bold ${u.role === 'admin' ? 'bg-red-950 text-red-400' : 'bg-blue-950 text-blue-400'}`}>
                        {u.role.toUpperCase()}
                      </span>
                    </td>
                    <td className="py-3">
                      {u.username !== 'admin' ? (
                        <button onClick={() => deleteUser(u.username)}
                          className="text-xs border border-red-500 text-red-500 px-3 py-1 rounded hover:bg-red-500 hover:text-black transition">
                          🗑️ DELETE
                        </button>
                      ) : (
                        <span className="text-xs text-gray-600 italic">Protected</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ── QUARANTINE TAB ── */}
      {tab === 'quarantine' && (
        <div className="glow-blue bg-gray-950 rounded-lg p-6 cyber-card fade-in">
          <div className="flex justify-between items-center mb-4">
            <h2 className="neon-text-blue text-sm tracking-widest">
              🔒 QUARANTINED FILES
              <span className="ml-2 text-gray-600 text-xs font-normal">({qFiles.length} files)</span>
            </h2>
            <button onClick={clearQuarantine}
              className="px-4 py-2 text-xs border border-red-500 text-red-500 rounded hover:bg-red-500 hover:text-black transition">
              🗑️ CLEAR ALL
            </button>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="text-gray-500 border-b border-gray-800">
                  <th className="text-left py-2 pr-4">FILE NAME</th>
                  <th className="text-left py-2 pr-4">PREDICTION</th>
                  <th className="text-left py-2 pr-4">SCORE</th>
                  <th className="text-left py-2">QUARANTINED AT</th>
                </tr>
              </thead>
              <tbody>
                {qFiles.length === 0 && (
                  <tr>
                    <td colSpan={4} className="text-center text-gray-600 py-10">
                      ✅ No quarantined files
                    </td>
                  </tr>
                )}
                {[...qFiles].reverse().map((f, i) => (
                  <tr key={i} className="border-b border-gray-900 hover:bg-gray-900 transition">
                    <td className="py-2 pr-4 text-yellow-400 font-mono">
                      {f.original?.split('\\').pop()?.split('/').pop() || 'unknown'}
                    </td>
                    <td className="py-2 pr-4 text-red-400 font-bold">{f.prediction}</td>
                    <td className="py-2 pr-4 text-red-500 font-bold">{f.score}</td>
                    <td className="py-2 text-gray-400">{f.timestamp?.slice(0, 19)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ── SYSTEM TAB ── */}
      {tab === 'system' && sysInfo && (
        <div className="space-y-4 fade-in">
          <div className="glow-blue bg-gray-950 rounded-lg p-6 cyber-card">
            <h2 className="neon-text-blue text-sm tracking-widest mb-4">⚙️ SYSTEM INFORMATION</h2>
            <div className="grid grid-cols-2 gap-3 text-xs">
              {[
                { label: 'Platform',          value: sysInfo.platform                             },
                { label: 'Python Version',    value: sysInfo.python                               },
                { label: 'Blockchain Mode',   value: sysInfo.blockchain_mode                      },
                { label: 'Email Alerts',      value: sysInfo.email_enabled                        },
                { label: 'Contract Address',  value: sysInfo.contract?.slice(0, 22) + '...'       },
                { label: 'Server Time (UTC)', value: sysInfo.uptime?.slice(0, 19)                 },
                { label: 'Total Users',       value: sysInfo.users_count                          },
                { label: 'Blockchain Logs',   value: sysInfo.blockchain_logs                      },
                { label: 'Quarantine Files',  value: sysInfo.quarantine_files                     },
              ].map((row, i) => (
                <div key={i} className="flex justify-between items-center bg-black rounded p-3">
                  <span className="text-gray-500">{row.label}</span>
                  <span className="text-cyan-400 font-bold font-mono">{row.value}</span>
                </div>
              ))}
            </div>
          </div>

          <div className="glow-blue bg-gray-950 rounded-lg p-6 cyber-card">
            <h2 className="neon-text-blue text-sm tracking-widest mb-4">🧪 TEST SYSTEMS</h2>
            <div className="flex gap-3 flex-wrap">
              <button onClick={testEmail}
                className="px-5 py-2 text-xs border border-cyan-400 text-cyan-400 rounded hover:bg-cyan-400 hover:text-black transition">
                📧 SEND TEST EMAIL
              </button>
              <button onClick={testAlert}
                className="px-5 py-2 text-xs border border-red-500 text-red-500 rounded hover:bg-red-500 hover:text-black transition">
                🚨 SEND TEST ALERT
              </button>
              <button onClick={loadAll}
                className="px-5 py-2 text-xs border border-green-400 text-green-400 rounded hover:bg-green-400 hover:text-black transition">
                🔄 REFRESH ALL DATA
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── SETTINGS TAB ── */}
      {tab === 'settings' && (
        <div className="space-y-4 fade-in">

          {/* Threshold */}
          <div className="glow-blue bg-gray-950 rounded-lg p-6 cyber-card">
            <h2 className="neon-text-blue text-sm tracking-widest mb-4">⚡ THREAT THRESHOLD</h2>
            <p className="text-xs text-gray-500 mb-4">
              Files scoring above this value trigger HIGH THREAT alerts and emails.
              Current: <span className="text-cyan-400 font-bold">{threshold}</span>
            </p>
            <div className="flex gap-3 items-center">
              <input
                type="range" min="0" max="100"
                value={threshold}
                onChange={e => setThreshold(Number(e.target.value))}
                className="flex-1"
              />
              <span className="text-cyan-400 font-bold text-lg w-12 text-center">{threshold}</span>
              <button onClick={updateThreshold}
                className="px-4 py-2 text-xs bg-cyan-400 text-black font-bold rounded hover:opacity-80 transition">
                SAVE
              </button>
            </div>
          </div>

          {/* Danger Zone */}
          <div className="glow-red bg-gray-950 rounded-lg p-6 cyber-card">
            <h2 className="neon-text-red text-sm tracking-widest mb-4">⚠️ DANGER ZONE</h2>
            <div className="space-y-3">
              <div className="flex items-center justify-between bg-black rounded p-4 border border-gray-800">
                <div>
                  <div className="text-sm text-white font-bold">Clear Threat Database</div>
                  <div className="text-xs text-gray-500 mt-1">
                    Permanently delete all scan records from SQLite
                  </div>
                </div>
                <button onClick={clearThreats}
                  className="px-4 py-2 text-xs border border-red-500 text-red-500 rounded hover:bg-red-500 hover:text-black transition">
                  🗑️ CLEAR DB
                </button>
              </div>
              <div className="flex items-center justify-between bg-black rounded p-4 border border-gray-800">
                <div>
                  <div className="text-sm text-white font-bold">Clear Quarantine Folder</div>
                  <div className="text-xs text-gray-500 mt-1">
                    Permanently delete all quarantined files
                  </div>
                </div>
                <button onClick={clearQuarantine}
                  className="px-4 py-2 text-xs border border-red-500 text-red-500 rounded hover:bg-red-500 hover:text-black transition">
                  🗑️ CLEAR QUARANTINE
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

    </div>
  )
}