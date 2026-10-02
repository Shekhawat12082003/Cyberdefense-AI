import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { useState, useEffect } from 'react'
import axios from 'axios'
import Login      from './pages/Login'
import Dashboard  from './pages/Dashboard'
import Threats    from './pages/Threats'
import Analytics  from './pages/Analytics'
import Blockchain from './pages/Blockchain'
import Admin      from './pages/Admin'
import SOC        from './pages/SOC'
import Chatbot    from './pages/Chatbot'
import AuditLog   from './pages/AuditLog'
import Network    from './pages/Network'
import CyberLab   from './pages/CyberLab'
import Incidents  from './pages/Incidents'
import IncidentView from './pages/IncidentView'

// ══════════════════════════════════════════════════════════
// TOKEN CHECK HOOK
// Runs on every protected page load
// Calls backend to confirm token is still valid
// ══════════════════════════════════════════════════════════
function useTokenCheck() {
  const [status, setStatus] = useState('loading')

  useEffect(() => {
    const token = localStorage.getItem('token')
    const role  = localStorage.getItem('role')
    const user  = localStorage.getItem('user')

    // Nothing in storage → go to login immediately
    if (!token || !role || !user) {
      localStorage.clear()
      setStatus('invalid')
      return
    }

    // Safety timeout — if backend is slow/down, don't get stuck forever
    const timeout = setTimeout(() => {
      console.warn('Backend timeout — using cached token')
      setStatus('valid')
    }, 3000)

    // Verify token with backend
    axios.get('http://localhost:5000/api/verify-token', {
      headers: { Authorization: `Bearer ${token}` }
    })
    .then(() => {
      clearTimeout(timeout)
      setStatus('valid')
    })
    .catch((err) => {
      clearTimeout(timeout)
      if (err?.response?.status === 401) {
        // Token expired or invalid → force fresh login
        localStorage.clear()
        setStatus('invalid')
      } else {
        // Network error / CORS / backend down
        // Trust local storage rather than locking user out
        console.warn('Backend unreachable — trusting cached token')
        setStatus('valid')
      }
    })
  }, [])

  return status
}

// ══════════════════════════════════════════════════════════
// LOADING SCREEN
// Shows while token is being verified
// ══════════════════════════════════════════════════════════
function LoadingScreen({ message = 'VERIFYING SESSION...' }) {
  return (
    <div style={{
      minHeight: '100vh',
      background: '#000010',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      flexDirection: 'column',
      gap: 20
    }}>
      <div style={{ fontSize: 52 }}>🛡️</div>

      {/* Animated scan bar */}
      <div style={{
        width: 220,
        height: 2,
        background: '#0a0a1a',
        borderRadius: 2,
        overflow: 'hidden'
      }}>
        <div style={{
          height: '100%',
          width: '40%',
          background: '#00d4ff',
          borderRadius: 2,
          boxShadow: '0 0 12px #00d4ff',
          animation: 'scanAnim 1.2s ease-in-out infinite'
        }} />
      </div>

      <p style={{
        color: '#00d4ff',
        fontFamily: 'monospace',
        fontSize: 11,
        letterSpacing: 4,
        margin: 0
      }}>
        {message}
      </p>

      <style>{`
        @keyframes scanAnim {
          0%   { transform: translateX(-150%); }
          100% { transform: translateX(400%); }
        }
      `}</style>
    </div>
  )
}

// ══════════════════════════════════════════════════════════
// PRIVATE ROUTE
// Any logged in user (admin or analyst)
// ══════════════════════════════════════════════════════════
function PrivateRoute({ children }) {
  const status = useTokenCheck()

  if (status === 'loading') {
    return <LoadingScreen message="VERIFYING SESSION..." />
  }
  if (status === 'invalid') {
    return <Navigate to="/login" replace />
  }
  return children
}

// ══════════════════════════════════════════════════════════
// ADMIN ROUTE
// Only admin role — analyst gets sent home
// ══════════════════════════════════════════════════════════
function AdminRoute({ children }) {
  const status = useTokenCheck()
  const role   = localStorage.getItem('role')

  if (status === 'loading') {
    return <LoadingScreen message="VERIFYING ACCESS..." />
  }
  if (status === 'invalid') {
    return <Navigate to="/login" replace />
  }
  if (role !== 'admin') {
    return <Navigate to="/" replace />
  }
  return children
}

// ══════════════════════════════════════════════════════════
// MAIN APP
// ══════════════════════════════════════════════════════════
export default function App() {
  return (
    <BrowserRouter>
      <Routes>

        {/* Public — no auth needed */}
        <Route path="/login" element={<Login />} />

        {/* Protected — any logged in user */}
        <Route path="/" element={
          <PrivateRoute><Dashboard /></PrivateRoute>
        } />
        <Route path="/threats" element={
          <PrivateRoute><Threats /></PrivateRoute>
        } />
        <Route path="/analytics" element={
          <PrivateRoute><Analytics /></PrivateRoute>
        } />
        <Route path="/blockchain" element={
          <PrivateRoute><Blockchain /></PrivateRoute>
        } />

        {/* Admin only */}
        <Route path="/admin" element={
          <AdminRoute><Admin /></AdminRoute>
        } />

        {/* SOC war room — any logged in user */}
        <Route path="/soc" element={
          <PrivateRoute><SOC /></PrivateRoute>
        } />

        {/* AI Chatbot — any logged in user */}
        <Route path="/chat" element={
          <PrivateRoute><Chatbot /></PrivateRoute>
        } />

        {/* Audit Log — any logged in user */}
        <Route path="/audit" element={
          <PrivateRoute><AuditLog /></PrivateRoute>
        } />

        {/* Network Traffic Analyser */}
        <Route path="/network" element={
          <PrivateRoute><Network /></PrivateRoute>
        } />

        {/* Cyber Lab — attack simulation */}
        <Route path="/lab" element={
          <PrivateRoute><CyberLab /></PrivateRoute>
        } />

        {/* Incidents list */}
        <Route path="/incidents" element={
          <PrivateRoute><Incidents /></PrivateRoute>
        } />

        {/* Incident detail view */}
        <Route path="/incidents/:id" element={
          <PrivateRoute><IncidentView /></PrivateRoute>
        } />

        {/* Catch all unknown routes */}
        <Route path="*" element={<Navigate to="/" replace />} />

      </Routes>
    </BrowserRouter>
  )
}