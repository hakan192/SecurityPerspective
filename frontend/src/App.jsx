import { useEffect, useMemo, useState } from 'react'

const resolvedHost = window.location.hostname || 'localhost'
const configuredApiBase = import.meta.env.VITE_API_BASE_URL
const API_BASE =
  configuredApiBase && configuredApiBase.includes('localhost') && !['localhost', '127.0.0.1'].includes(resolvedHost)
    ? configuredApiBase.replace('localhost', resolvedHost)
    : configuredApiBase || `http://${resolvedHost}:8000`

function LogoMark() {
  return (
    <div style={styles.logoWrap}>
      <svg width="32" height="32" viewBox="0 0 64 64" fill="none" aria-hidden="true">
        <path d="M32 4L56 14V30C56 44 45 55 32 60C19 55 8 44 8 30V14L32 4Z" stroke="#4FC3F7" strokeWidth="4" />
        <path d="M12 30C18 21 25 17 32 17C39 17 46 21 52 30" stroke="#7DD3FC" strokeWidth="4" strokeLinecap="round" />
        <circle cx="32" cy="31" r="8" fill="#38BDF8" />
      </svg>
      <div style={styles.logoText}><span style={{ color: '#F8FAFC' }}>Security</span><span style={{ color: '#38BDF8' }}>Perspective</span></div>
    </div>
  )
}

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
      if (!response.ok) throw new Error('Invalid username or password')
      onLogin(await response.json())
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div style={styles.loginPage}>
      <div style={styles.loginCard}>
        <LogoMark />
        <p style={styles.loginSubtitle}>Secure dashboard access</p>
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

function OverviewCards() {
  const cards = [
    { title: 'Overall Maturity', value: '68 / 100', tone: '#38BDF8' },
    { title: 'Critical Findings', value: '5', tone: '#F97316' },
    { title: 'Compliant Controls', value: '27', tone: '#22C55E' },
    { title: 'Data Freshness', value: '2m ago', tone: '#A78BFA' }
  ]

  return (
    <div style={styles.cardGrid}>
      {cards.map((item) => (
        <div key={item.title} style={styles.metricCard}>
          <div style={styles.metricTitle}>{item.title}</div>
          <div style={{ ...styles.metricValue, color: item.tone }}>{item.value}</div>
        </div>
      ))}
    </div>
  )
}

function MaturityPanel() {
  return (
    <div style={styles.dashboardGrid}>
      <section style={styles.panelBlock}>
        <h3 style={styles.panelTitle}>Maturity Trend</h3>
        <div style={styles.trendArea}>
          <div style={styles.fakeChartLine} />
          <p style={styles.panelHint}>Trend visualization placeholder (weekly maturity progression).</p>
        </div>
      </section>
      <section style={styles.panelBlock}>
        <h3 style={styles.panelTitle}>Recent Findings</h3>
        <ul style={styles.findingsList}>
          <li>Missing strict TLS policy on external virtual server</li>
          <li>Logging disabled in one policy profile</li>
          <li>Admin authentication mode not set to MFA</li>
        </ul>
      </section>
      <section style={styles.panelBlockWide}>
        <h3 style={styles.panelTitle}>Configuration Source Status</h3>
        <div style={styles.sourceGrid}>
          <div style={styles.sourceOk}>FortiWeb API: Connected</div>
          <div style={styles.sourceOk}>PostgreSQL: Healthy</div>
          <div style={styles.sourceWarn}>Redis/Celery: Monitoring</div>
          <div style={styles.sourceOk}>Frontend Sync: Active</div>
        </div>
      </section>
    </div>
  )
}

function AppShell({ session, onLogout }) {
  const [sidebarOpen, setSidebarOpen] = useState(true)
  const [activeTab, setActiveTab] = useState('waf')
  const [wafResponse, setWafResponse] = useState(null)
  const [loadingWaf, setLoadingWaf] = useState(false)
  const [wafError, setWafError] = useState('')

  const profileName = useMemo(() => session?.username || 'admin', [session])

  const loadWafResponse = async () => {
    setLoadingWaf(true)
    setWafError('')
    try {
      const res = await fetch(`${API_BASE}/fortiweb/server-policy/latest`)
      if (!res.ok) throw new Error('No WAF API response found. Collect from WAF first.')
      const data = await res.json()
      setWafResponse(data.payload)
    } catch (err) {
      setWafError(err.message)
    } finally {
      setLoadingWaf(false)
    }
  }

  const collectWafResponse = async () => {
    setLoadingWaf(true)
    setWafError('')
    try {
      const response = await fetch(`${API_BASE}/fortiweb/server-policy/collect`, {
        method: 'POST',
        headers: { 'X-Role': 'admin' }
      })
      if (!response.ok) throw new Error('Failed to collect WAF data from FortiWeb')
      const data = await response.json()
      setWafResponse(data.payload)
    } catch (err) {
      setWafError(err.message)
    } finally {
      setLoadingWaf(false)
    }
  }

  useEffect(() => {
    if (activeTab === 'waf') loadWafResponse()
  }, [activeTab])

  return (
    <div style={styles.appRoot}>
      <header style={styles.topHeader}>
        <div style={styles.headerLeft}>
          <button style={styles.iconBtn} onClick={() => setSidebarOpen((v) => !v)} title="Toggle sidebar">☰</button>
          <LogoMark />
        </div>
        <div style={styles.profileCard}>
          <div style={styles.profileTitle}>Profile</div>
          <div style={styles.profileUser}>Logged in as {profileName}</div>
          <button style={styles.logoutBtn} onClick={onLogout}>Logout</button>
        </div>
      </header>

      <div style={styles.mainWrap}>
        {sidebarOpen && (
          <aside style={styles.sidebar}>
            <button onClick={() => setActiveTab('waf')} style={activeTab === 'waf' ? styles.navBtnActive : styles.navBtn}>WAF Configuration</button>
            <button onClick={() => setActiveTab('maturity')} style={activeTab === 'maturity' ? styles.navBtnActive : styles.navBtn}>Maturity Level</button>
            <button style={styles.settingsBtn}>⚙ Platform Settings</button>
          </aside>
        )}

        <main style={styles.contentArea}>
          {activeTab === 'waf' ? (
            <section style={styles.panel}>
              <div style={styles.panelTopRow}>
                <h3 style={styles.panelTitle}>API response</h3>
                <div style={styles.rowBtns}>
                  <button style={styles.secondaryBtn} onClick={collectWafResponse} disabled={loadingWaf}>Collect from WAF</button>
                  <button style={styles.primaryBtnSmall} onClick={loadWafResponse} disabled={loadingWaf}>Refresh</button>
                </div>
              </div>
              {loadingWaf && <p style={styles.panelHint}>Loading...</p>}
              {wafError && <p style={styles.errorText}>{wafError}</p>}
              {!loadingWaf && !wafError && wafResponse && (
                <pre style={styles.responseBox}>{JSON.stringify(wafResponse, null, 2)}</pre>
              )}
            </section>
          ) : (
            <>
              <OverviewCards />
              <MaturityPanel />
            </>
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
    background: 'radial-gradient(circle at 20% 20%, #0f172a, #020617)',
    display: 'grid',
    placeItems: 'center',
    padding: '1rem'
  },
  loginCard: {
    width: '100%', maxWidth: '430px', background: 'rgba(15, 23, 42, 0.92)', border: '1px solid #1e3a8a',
    borderRadius: '16px', padding: '1.5rem', boxShadow: '0 18px 30px rgba(2,6,23,0.5)', color: '#e2e8f0'
  },
  logoWrap: { display: 'flex', alignItems: 'center', gap: '0.6rem' },
  logoText: { fontSize: '1.4rem', fontWeight: 800, letterSpacing: '0.2px' },
  loginSubtitle: { color: '#94a3b8', marginBottom: '1rem' },
  form: { display: 'grid', gap: '0.55rem' },
  label: { color: '#cbd5e1', fontSize: '0.9rem' },
  input: { padding: '0.68rem', borderRadius: '10px', border: '1px solid #334155', background: '#0f172a', color: '#f8fafc' },
  error: { background: '#7f1d1d', color: '#fee2e2', borderRadius: '8px', padding: '0.5rem' },
  primaryBtn: { marginTop: '0.65rem', padding: '0.72rem', border: 0, borderRadius: '10px', background: '#0284c7', color: 'white', fontWeight: 700, cursor: 'pointer' },

  appRoot: {
    minHeight: '100vh', background: 'linear-gradient(140deg, #020617 0%, #0b1120 55%, #0f172a 100%)', color: '#e2e8f0',
    padding: '0.8rem', display: 'grid', gridTemplateRows: 'auto 1fr', gap: '0.8rem'
  },
  topHeader: { background: '#0b1224', border: '1px solid #1e3a8a', borderRadius: '14px', padding: '0.8rem 1rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center' },
  headerLeft: { display: 'flex', alignItems: 'center', gap: '0.7rem' },
  iconBtn: { border: '1px solid #334155', background: '#0f172a', color: '#e2e8f0', borderRadius: '8px', width: '34px', height: '34px', cursor: 'pointer' },
  profileCard: { border: '1px solid #334155', borderRadius: '12px', padding: '0.5rem 0.7rem', background: '#020617', minWidth: '190px' },
  profileTitle: { color: '#93c5fd', fontWeight: 700, marginBottom: '0.2rem' },
  profileUser: { fontSize: '0.9rem', marginBottom: '0.4rem' },
  logoutBtn: { border: 0, background: '#ef4444', color: 'white', borderRadius: '8px', padding: '0.35rem 0.6rem', cursor: 'pointer' },

  mainWrap: { display: 'grid', gridTemplateColumns: 'auto 1fr', gap: '0.8rem' },
  sidebar: { width: '230px', background: '#0b1224', border: '1px solid #1e3a8a', borderRadius: '14px', padding: '0.8rem', display: 'grid', gap: '0.6rem', alignContent: 'start' },
  navBtn: { border: '1px solid #334155', background: '#0f172a', color: '#cbd5e1', borderRadius: '10px', padding: '0.65rem', textAlign: 'left', cursor: 'pointer' },
  navBtnActive: { border: '1px solid #38bdf8', background: '#082f49', color: '#e0f2fe', borderRadius: '10px', padding: '0.65rem', textAlign: 'left', cursor: 'pointer', fontWeight: 700 },
  settingsBtn: { marginTop: 'auto', border: '1px solid #334155', background: '#020617', color: '#cbd5e1', borderRadius: '18px', padding: '0.45rem 0.6rem', textAlign: 'left', cursor: 'pointer' },

  contentArea: { minWidth: 0, display: 'grid', gap: '0.8rem' },
  panel: { background: '#0b1224', border: '1px solid #1e3a8a', borderRadius: '14px', padding: '1rem', minHeight: '72vh' },
  panelTopRow: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' },
  panelTitle: { margin: 0, color: '#93c5fd' },
  panelHint: { color: '#94a3b8' },
  rowBtns: { display: 'flex', gap: '0.5rem' },
  secondaryBtn: { border: '1px solid #0ea5e9', background: '#082f49', color: '#e0f2fe', borderRadius: '8px', padding: '0.45rem 0.7rem', cursor: 'pointer' },
  primaryBtnSmall: { border: 0, background: '#0284c7', color: 'white', borderRadius: '8px', padding: '0.45rem 0.7rem', cursor: 'pointer' },
  responseBox: { background: '#020617', border: '1px solid #1e293b', color: '#dbeafe', borderRadius: '10px', padding: '0.75rem', maxHeight: '63vh', overflow: 'auto', fontSize: '0.82rem' },
  errorText: { color: '#fca5a5' },

  cardGrid: { display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '0.8rem' },
  metricCard: { background: '#0b1224', border: '1px solid #1e3a8a', borderRadius: '12px', padding: '0.9rem' },
  metricTitle: { color: '#94a3b8', fontSize: '0.86rem' },
  metricValue: { fontSize: '1.35rem', fontWeight: 800, marginTop: '0.35rem' },

  dashboardGrid: { display: 'grid', gridTemplateColumns: '1.5fr 1fr', gap: '0.8rem' },
  panelBlock: { background: '#0b1224', border: '1px solid #1e3a8a', borderRadius: '12px', padding: '0.9rem' },
  panelBlockWide: { gridColumn: '1 / -1', background: '#0b1224', border: '1px solid #1e3a8a', borderRadius: '12px', padding: '0.9rem' },
  trendArea: { minHeight: '180px', display: 'grid', placeItems: 'center', border: '1px dashed #334155', borderRadius: '10px', background: '#020617' },
  fakeChartLine: { width: '80%', height: '2px', background: 'linear-gradient(90deg, #38bdf8, #22d3ee, #38bdf8)' },
  findingsList: { margin: 0, paddingLeft: '1rem', color: '#cbd5e1', lineHeight: 1.7 },
  sourceGrid: { display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '0.6rem' },
  sourceOk: { background: '#052e16', border: '1px solid #166534', color: '#86efac', borderRadius: '10px', padding: '0.55rem' },
  sourceWarn: { background: '#3f1d00', border: '1px solid #9a3412', color: '#fdba74', borderRadius: '10px', padding: '0.55rem' }
}
