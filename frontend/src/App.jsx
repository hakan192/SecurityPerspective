import { useEffect, useState } from 'react'

const resolvedHost = window.location.hostname || 'localhost'
const configuredApiBase = import.meta.env.VITE_API_BASE_URL
const API_BASE =
  configuredApiBase && configuredApiBase.includes('localhost') && !['localhost', '127.0.0.1'].includes(resolvedHost)
    ? configuredApiBase.replace('localhost', resolvedHost)
    : configuredApiBase || `http://${resolvedHost}:8000`

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
    <div style={styles.loginPage}>
      <div style={styles.loginCard}>
        <h1 style={styles.loginTitle}>SecurityPerspective</h1>
        <p style={styles.loginSubtitle}>Sign in to continue</p>
        <form onSubmit={submit} style={styles.form}>
          <label style={styles.label}>Username</label>
          <input style={styles.input} value={username} onChange={(e) => setUsername(e.target.value)} />
          <label style={styles.label}>Password</label>
          <input type="password" style={styles.input} value={password} onChange={(e) => setPassword(e.target.value)} />
          {error && <div style={styles.error}>{error}</div>}
          <button style={styles.primaryBtn} disabled={loading}>{loading ? 'Signing in...' : 'Login'}</button>
        </form>
      </div>
    </div>
  )
}

function AppShell({ session, onLogout }) {
  const [sidebarOpen, setSidebarOpen] = useState(true)
  const [activeTab, setActiveTab] = useState('waf')
  const [wafResponse, setWafResponse] = useState(null)
  const [loadingWaf, setLoadingWaf] = useState(false)
  const [wafError, setWafError] = useState('')
  const [collectingWaf, setCollectingWaf] = useState(false)
  const [statusMessage, setStatusMessage] = useState('')

  const loadWafResponse = async () => {
    setLoadingWaf(true)
    setWafError('')
    try {
      const res = await fetch(`${API_BASE}/fortiweb/server-policy/latest`)
      if (!res.ok) {
        throw new Error('No WAF API response found. Collect data first.')
      }
      const data = await res.json()
      setWafResponse(data.payload)
      setStatusMessage('Loaded latest WAF API response.')
    } catch (err) {
      setWafError(err.message)
    } finally {
      setLoadingWaf(false)
    }
  }

  const collectWafResponse = async () => {
    setCollectingWaf(true)
    setWafError('')
    try {
      const response = await fetch(`${API_BASE}/fortiweb/server-policy/collect`, {
        method: 'POST',
        headers: { 'X-Role': 'admin' }
      })
      if (!response.ok) {
        throw new Error('Failed to collect WAF data from FortiWeb.')
      }
      const data = await response.json()
      setWafResponse(data.payload)
      setStatusMessage('Successfully collected WAF configuration from FortiWeb.')
    } catch (err) {
      setWafError(err.message)
    } finally {
      setCollectingWaf(false)
      setLoadingWaf(false)
    }
  }

  useEffect(() => {
    if (activeTab === 'waf') {
      loadWafResponse()
    }
  }, [activeTab])

  return (
    <div style={styles.appRoot}>
      <header style={styles.topHeader}>
        <div style={styles.leftHeader}>
          <button style={styles.iconBtn} onClick={() => setSidebarOpen((v) => !v)} title="Toggle sidebar">☰</button>
          <h2 style={styles.platformName}>SecurityPerspective</h2>
        </div>
        <div style={styles.profileBox}>
          <div style={{ fontWeight: 700 }}>Profile</div>
          <div>Logged in: <b>{session?.username || 'admin'}</b></div>
          <button style={styles.logoutBtn} onClick={onLogout}>Logout</button>
        </div>
      </header>

      {statusMessage && <div style={styles.statusBanner}>{statusMessage}</div>}

      <div style={styles.mainLayout}>
        {sidebarOpen && (
          <aside style={styles.sidebar}>
            <button
              style={activeTab === 'waf' ? styles.navBtnActive : styles.navBtn}
              onClick={() => setActiveTab('waf')}
            >
              WAF Configuration
            </button>
            <button
              style={activeTab === 'maturity' ? styles.navBtnActive : styles.navBtn}
              onClick={() => setActiveTab('maturity')}
            >
              Maturity Level
            </button>
            <button style={styles.settingsBtn}>⚙ Platform Settings</button>
          </aside>
        )}

        <main style={styles.contentArea}>
          {activeTab === 'waf' && (
            <section style={styles.panel}>
              <div style={styles.panelHeader}>
                <h3 style={{ margin: 0 }}>WAF Configuration API Response</h3>
                <div style={{ display: 'flex', gap: '0.5rem' }}>
                  <button style={styles.secondaryBtnSmall} onClick={collectWafResponse} disabled={collectingWaf}>
                    {collectingWaf ? 'Collecting...' : 'Collect from WAF'}
                  </button>
                  <button style={styles.primaryBtnSmall} onClick={loadWafResponse} disabled={loadingWaf}>
                    {loadingWaf ? 'Refreshing...' : 'Refresh'}
                  </button>
                </div>
              </div>
              {loadingWaf && <p>Loading WAF response...</p>}
              {wafError && <p style={styles.errorText}>{wafError}</p>}
              {!loadingWaf && !wafError && !wafResponse && (
                <div style={styles.emptyState}>
                  <p>No response data yet.</p>
                  <p>Click <b>Collect from WAF</b> to fetch data from FortiWeb.</p>
                </div>
              )}
              {!loadingWaf && !wafError && wafResponse && (
                <pre style={styles.responseBox}>{JSON.stringify(wafResponse, null, 2)}</pre>
              )}
            </section>
          )}

          {activeTab === 'maturity' && (
            <section style={styles.panel}>
              <h3 style={{ marginTop: 0 }}>Maturity Level</h3>
              <p>Maturity scoring panel placeholder. Next step: visualize per-control and category scores.</p>
            </section>
          )}
        </main>
      </div>
    </div>
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

  return session ? <AppShell session={session} onLogout={handleLogout} /> : <LoginCard onLogin={handleLogin} />
}

const styles = {
  loginPage: {
    minHeight: '100vh',
    background: 'linear-gradient(135deg, #0f172a, #1d4ed8)',
    display: 'grid',
    placeItems: 'center',
    padding: '1rem'
  },
  loginCard: {
    width: '100%',
    maxWidth: '420px',
    background: 'rgba(255,255,255,0.95)',
    borderRadius: '16px',
    padding: '1.5rem',
    boxShadow: '0 16px 28px rgba(0,0,0,0.22)'
  },
  loginTitle: { margin: 0 },
  loginSubtitle: { marginTop: '0.4rem', color: '#334155' },
  form: { display: 'grid', gap: '0.6rem' },
  label: { fontSize: '0.9rem' },
  input: { padding: '0.7rem', borderRadius: '10px', border: '1px solid #cbd5e1' },
  error: { background: '#fee2e2', color: '#991b1b', borderRadius: '8px', padding: '0.5rem' },
  primaryBtn: {
    marginTop: '0.6rem',
    padding: '0.75rem',
    border: 0,
    borderRadius: '10px',
    background: '#2563eb',
    color: 'white',
    fontWeight: 700,
    cursor: 'pointer'
  },
  appRoot: {
    minHeight: '100vh',
    background: 'linear-gradient(180deg, #eef2ff 0%, #f8fafc 100%)',
    padding: '0.75rem',
    display: 'grid',
    gridTemplateRows: 'auto 1fr',
    gap: '0.75rem'
  },
  topHeader: {
    background: '#ffffff',
    borderRadius: '12px',
    border: '1px solid #c7d2fe',
    padding: '0.75rem 1rem',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between'
  },
  leftHeader: { display: 'flex', alignItems: 'center', gap: '0.75rem' },
  iconBtn: {
    border: '1px solid #cbd5e1',
    background: 'white',
    borderRadius: '8px',
    width: '34px',
    height: '34px',
    cursor: 'pointer'
  },
  platformName: { margin: 0 },
  profileBox: {
    border: '1px solid #cbd5e1',
    borderRadius: '12px',
    padding: '0.5rem 0.75rem',
    display: 'grid',
    gap: '0.25rem',
    fontSize: '0.9rem'
  },
  logoutBtn: {
    border: 0,
    background: '#ef4444',
    color: 'white',
    borderRadius: '8px',
    padding: '0.35rem 0.6rem',
    cursor: 'pointer'
  },
  mainLayout: {
    display: 'grid',
    gridTemplateColumns: 'auto 1fr',
    gap: '0.75rem',
    minHeight: 0,
    flex: 1
  },
  sidebar: {
    width: '220px',
    background: 'white',
    border: '1px solid #c7d2fe',
    borderRadius: '12px',
    padding: '0.75rem',
    display: 'grid',
    alignContent: 'start',
    gap: '0.6rem'
  },
  navBtn: {
    border: '1px solid #bfdbfe',
    borderRadius: '10px',
    background: 'white',
    padding: '0.65rem',
    textAlign: 'left',
    cursor: 'pointer'
  },
  navBtnActive: {
    border: '1px solid #2563eb',
    borderRadius: '10px',
    background: '#dbeafe',
    padding: '0.65rem',
    textAlign: 'left',
    cursor: 'pointer',
    color: '#1e3a8a',
    fontWeight: 700
  },
  settingsBtn: {
    marginTop: 'auto',
    border: '1px solid #cbd5e1',
    borderRadius: '20px',
    background: 'white',
    padding: '0.45rem 0.6rem',
    cursor: 'pointer',
    textAlign: 'left'
  },
  contentArea: { minWidth: 0 },
  panel: {
    background: 'white',
    border: '1px solid #c7d2fe',
    borderRadius: '12px',
    padding: '1rem',
    minHeight: '72vh'
  },
  panelHeader: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' },
  primaryBtnSmall: {
    border: 0,
    background: '#2563eb',
    color: 'white',
    borderRadius: '8px',
    padding: '0.45rem 0.7rem',
    cursor: 'pointer'
  },
  secondaryBtnSmall: {
    border: '1px solid #0ea5e9',
    background: '#e0f2fe',
    color: '#0369a1',
    borderRadius: '8px',
    padding: '0.45rem 0.7rem',
    cursor: 'pointer'
  },
  emptyState: {
    border: '1px dashed #94a3b8',
    borderRadius: '10px',
    padding: '1rem',
    background: '#f8fafc',
    color: '#334155'
  },
  responseBox: {
    background: '#0f172a',
    color: '#e2e8f0',
    borderRadius: '10px',
    padding: '0.75rem',
    maxHeight: '63vh',
    overflow: 'auto',
    fontSize: '0.82rem'
  },
  errorText: { color: '#991b1b' },
  statusBanner: {
    background: '#dcfce7',
    border: '1px solid #86efac',
    color: '#166534',
    padding: '0.6rem 0.8rem',
    borderRadius: '10px'
  }
}
