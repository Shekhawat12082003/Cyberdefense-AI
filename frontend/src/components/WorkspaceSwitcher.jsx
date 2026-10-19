import { Link, useLocation } from 'react-router-dom'

const linkStyle = (active, color) => ({
  padding: '8px 14px',
  border: `1px solid ${active ? color : '#263044'}`,
  borderRadius: 4,
  color: active ? color : '#778099',
  background: active ? `${color}14` : 'transparent',
  fontFamily: 'monospace',
  fontSize: 10,
  letterSpacing: 1,
  textDecoration: 'none',
  transition: 'all 160ms ease',
})

export default function WorkspaceSwitcher() {
  const { pathname } = useLocation()
  const ransomwareActive = pathname.startsWith('/ransomware') || pathname === '/threats'

  return (
    <nav
      aria-label="Workspace"
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: 8,
        padding: 6,
        marginBottom: 18,
        background: '#05051a',
        border: '1px solid #1b2440',
        borderRadius: 6,
        width: 'fit-content',
      }}
    >
      <Link to="/" style={linkStyle(!ransomwareActive, '#00d4ff')}>
        ◈ SOC DASHBOARD
      </Link>
      <Link to="/ransomware" style={linkStyle(ransomwareActive, '#ff003c')}>
        ☠ RANSOMWARE CENTER
      </Link>
    </nav>
  )
}
