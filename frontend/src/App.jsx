import { useEffect, useState } from 'react'

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
  const [policies, setPolicies] = useState([])
  const [loadingPolicies, setLoadingPolicies] = useState(true)
  const [policyError, setPolicyError] = useState('')
  const [rates, setRates] = useState([])
  const [loadingRates, setLoadingRates] = useState(true)
  const [rateError, setRateError] = useState('')
  const [collectingRates, setCollectingRates] = useState(false)

  useEffect(() => {
    const fetchPolicies = async () => {
      setLoadingPolicies(true)
      setPolicyError('')
      try {
        const response = await fetch(`${API_BASE}/server-policies`)
        if (!response.ok) {
          throw new Error('Unable to load server policy data')
        }
        const data = await response.json()
        setPolicies(data)
      } catch (err) {
        setPolicyError(err.message)
      } finally {
        setLoadingPolicies(false)
      }
    }
    fetchPolicies()
  }, [])

  useEffect(() => {
    const fetchRates = async () => {
      setLoadingRates(true)
      setRateError('')
      try {
        const response = await fetch(`${API_BASE}/exchange-rates/latest`)
        if (!response.ok) {
          throw new Error('Unable to load exchange rates')
        }
        const data = await response.json()
        setRates(data)
      } catch (err) {
        setRateError(err.message)
      } finally {
        setLoadingRates(false)
      }
    }
    fetchRates()
  }, [])

  const collectRates = async () => {
    setCollectingRates(true)
    setRateError('')
    try {
      const response = await fetch(`${API_BASE}/exchange-rates/collect`, {
        method: 'POST',
        headers: { 'X-Role': 'admin' }
      })
      if (!response.ok) {
        throw new Error('Failed to collect exchange rates')
      }
      const latest = await fetch(`${API_BASE}/exchange-rates/latest`)
      const rows = await latest.json()
      setRates(rows)
    } catch (err) {
      setRateError(err.message)
    } finally {
      setCollectingRates(false)
    }
  }

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
      <section style={{ ...styles.panel, marginTop: '1rem' }}>
        <h3>Server Policy (Test Data)</h3>
        {loadingPolicies && <p>Loading server policies...</p>}
        {policyError && <p style={styles.errorText}>{policyError}</p>}
        {!loadingPolicies && !policyError && (
          <table style={styles.table}>
            <thead>
              <tr>
                <th style={styles.th}>IP</th>
                <th style={styles.th}>Hostnames</th>
              </tr>
            </thead>
            <tbody>
              {policies.map((row) => (
                <tr key={row.id}>
                  <td style={styles.td}>{row.ip}</td>
                  <td style={styles.td}>{row.hostnames}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
      <section style={{ ...styles.panel, marginTop: '1rem' }}>
        <div style={styles.sectionHeader}>
          <h3 style={{ margin: 0 }}>USD Exchange Rates</h3>
          <button style={styles.collectBtn} onClick={collectRates} disabled={collectingRates}>
            {collectingRates ? 'Collecting...' : 'Collect Latest'}
          </button>
        </div>
        {loadingRates && <p>Loading exchange rates...</p>}
        {rateError && <p style={styles.errorText}>{rateError}</p>}
        {!loadingRates && !rateError && rates.length === 0 && (
          <p>No exchange-rate data yet. Click “Collect Latest”.</p>
        )}
        {!loadingRates && !rateError && rates.length > 0 && (
          <table style={styles.table}>
            <thead>
              <tr>
                <th style={styles.th}>Currency</th>
                <th style={styles.th}>Rate</th>
              </tr>
            </thead>
            <tbody>
              {rates.slice(0, 20).map((row) => (
                <tr key={row.currency}>
                  <td style={styles.td}>{row.currency}</td>
                  <td style={styles.td}>{row.rate}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
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
  },
  sectionHeader: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: '0.75rem'
  },
  collectBtn: {
    border: 0,
    background: '#0ea5e9',
    color: 'white',
    padding: '0.45rem 0.8rem',
    borderRadius: '8px',
    cursor: 'pointer'
  },
  table: {
    width: '100%',
    borderCollapse: 'collapse'
  },
  th: {
    textAlign: 'left',
    borderBottom: '1px solid #e2e8f0',
    padding: '0.5rem'
  },
  td: {
    borderBottom: '1px solid #f1f5f9',
    padding: '0.5rem'
  },
  errorText: {
    color: '#991b1b'
  }
}
