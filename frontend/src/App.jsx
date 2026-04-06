import { useState } from 'react'

const API_BASE = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000'

function LoginCard({ onLogin }) {
  const [username, setUsername] = useState('admin')
  const [password, setPassword] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const submit = async (event) => {
    event.preventDefault()
    setError('')
    setLoading(true)
    try {
      const response = await fetch(`${API_BASE}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
      })
      if (!response.ok) {
        throw new Error('Invalid username or password')
      }
      const data = await response.json()
      onLogin(data)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div style={styles.card}>
      <h1 style={styles.title}>Security Perspective</h1>
      <p style={styles.subtitle}>Sign in to access configuration and maturity insights</p>
      <form onSubmit={submit} style={styles.form}>
        <label style={styles.label}>Username</label>
        <input style={styles.input} value={username} onChange={(e) => setUsername(e.target.value)} />
        <label style={styles.label}>Password</label>
        <input
          type="password"
          style={styles.input}
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          placeholder="Enter password"
        />
        {error && <div style={styles.error}>{error}</div>}
        <button style={styles.button} disabled={loading}>
          {loading ? 'Signing in...' : 'Login'}
        </button>
      </form>
      <p style={styles.helper}>Default local admin: <b>admin</b></p>
    </div>
  )
}

function Dashboard({ onLogout }) {
  return (
    <main style={styles.dashboard}>
      <div style={styles.topbar}>
        <h2 style={{ margin: 0 }}>Welcome, Admin</h2>
        <button style={styles.logout} onClick={onLogout}>Logout</button>
      </div>
      <section style={styles.panel}>
        <h3>Phase 1 Status</h3>
        <ul>
          <li>FortiWeb data collection APIs are available.</li>
          <li>PostgreSQL + Redis + Celery services are wired.</li>
          <li>Next step: build full configuration and maturity dashboards.</li>
        </ul>
      </section>
    </main>
  )
}

export default function App() {
  const [session, setSession] = useState(() => {
    const raw = localStorage.getItem('sp_session')
    return raw ? JSON.parse(raw) : null
  })

  const handleLogin = (data) => {
    localStorage.setItem('sp_session', JSON.stringify(data))
    setSession(data)
  }

  const handleLogout = () => {
    localStorage.removeItem('sp_session')
    setSession(null)
  }

  return (
    <div style={styles.page}>
      {!session ? <LoginCard onLogin={handleLogin} /> : <Dashboard onLogout={handleLogout} />}
    </div>
  )
}

const styles = {
  page: {
    minHeight: '100vh',
    display: 'flex',
    justifyContent: 'center',
    alignItems: 'center',
    background: 'linear-gradient(135deg, #0f172a, #1d4ed8)',
    padding: '1rem'
  },
  card: {
    width: '100%',
    maxWidth: '420px',
    background: 'rgba(255,255,255,0.95)',
    borderRadius: '18px',
    boxShadow: '0 20px 35px rgba(0,0,0,0.25)',
    padding: '2rem'
  },
  title: { marginBottom: '0.5rem', color: '#0f172a' },
  subtitle: { marginTop: 0, color: '#334155' },
  form: { display: 'grid', gap: '0.65rem' },
  label: { fontSize: '0.9rem', color: '#334155' },
  input: {
    padding: '0.7rem',
    border: '1px solid #cbd5e1',
    borderRadius: '10px',
    outline: 'none'
  },
  button: {
    marginTop: '0.8rem',
    padding: '0.85rem',
    border: 0,
    borderRadius: '10px',
    color: 'white',
    background: '#2563eb',
    fontWeight: 600,
    cursor: 'pointer'
  },
  error: {
    marginTop: '0.5rem',
    padding: '0.5rem',
    background: '#fee2e2',
    color: '#991b1b',
    borderRadius: '8px'
  },
  helper: { marginTop: '1rem', color: '#64748b', fontSize: '0.9rem' },
  dashboard: {
    width: '100%',
    maxWidth: '850px',
    background: '#f8fafc',
    borderRadius: '16px',
    padding: '1.25rem'
  },
  topbar: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: '1rem'
  },
  logout: {
    border: '1px solid #cbd5e1',
    background: 'white',
    borderRadius: '8px',
    padding: '0.45rem 0.9rem',
    cursor: 'pointer'
  },
  panel: {
    border: '1px solid #e2e8f0',
    borderRadius: '10px',
    padding: '1rem',
    background: 'white'
  }
}
