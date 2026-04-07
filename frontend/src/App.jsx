import { useEffect, useMemo, useRef, useState } from 'react'

const resolvedHost = window.location.hostname || 'localhost'
const configuredApiBase = import.meta.env.VITE_API_BASE_URL
const API_BASE =
  configuredApiBase && configuredApiBase.includes('localhost') && !['localhost', '127.0.0.1'].includes(resolvedHost)
    ? configuredApiBase.replace('localhost', resolvedHost)
    : configuredApiBase || `http://${resolvedHost}:8000`

function Brand({ small = false }) {
  return (
    <div style={{ ...styles.brandWrap, ...(small ? styles.brandWrapSmall : {}) }}>
      <img src="/branding/securityperspective-logo.png" alt="SecurityPerspective logo" style={{ ...styles.brandImage, ...(small ? styles.brandImageSmall : {}) }} />
      {!small && (
        <div style={styles.logoText}>
          <span style={{ color: '#F8FAFC' }}>Security</span><span style={{ color: '#38BDF8' }}>Perspective</span>
        </div>
      )}
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
        <Brand />
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

function SearchPage({ username, wafText, onSearch }) {
  const [query, setQuery] = useState('')
  const [result, setResult] = useState('')
  const inputRef = useRef(null)

  useEffect(() => {
    inputRef.current?.focus()
  }, [])

  const submit = (e) => {
    e.preventDefault()
    if (!query.trim()) {
      setResult('Please enter a search term.')
      return
    }
    const normalized = wafText.toLowerCase()
    const term = query.toLowerCase()
    const count = normalized.split(term).length - 1
    if (count > 0) {
      setResult(`Found ${count} matches in the latest WAF response.`)
    } else {
      setResult('No matches found in the latest WAF response.')
    }
    onSearch?.(query)
  }

  return (
    <section style={styles.searchPanel}>
      <h2 style={styles.searchTitle}>How can I help, {username}?</h2>
      <form style={styles.searchForm} onSubmit={submit}>
        <span style={styles.searchPrefix}>＋</span>
        <input
          ref={inputRef}
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search WAF configuration..."
          style={styles.searchInput}
        />
        <button style={styles.searchBtn}>Search</button>
      </form>
      {result && <p style={styles.searchResult}>{result}</p>}
    </section>
  )
}

function MaturityPanel() {
  return (
    <div style={styles.dashboardGrid}>
      <section style={styles.panelBlock}><h3 style={styles.panelTitle}>Executive Overview</h3><p style={styles.panelHint}>Overall maturity 68/100 · 5 critical findings · 27 compliant controls.</p></section>
      <section style={styles.panelBlock}><h3 style={styles.panelTitle}>Maturity Trend</h3><div style={styles.trendArea}><div style={styles.fakeChartLine} /></div></section>
      <section style={styles.panelBlockWide}><h3 style={styles.panelTitle}>Recent Findings</h3><ul style={styles.findingsList}><li>TLS policy weak on external server</li><li>Missing logging in one profile</li><li>MFA not enabled for admin path</li></ul></section>
    </div>
  )
}

function AppShell({ session, onLogout }) {
  const [sidebarOpen, setSidebarOpen] = useState(true)
  const [activeTab, setActiveTab] = useState('search')
  const [wafResponse, setWafResponse] = useState(null)
  const [loadingWaf, setLoadingWaf] = useState(false)
  const [wafError, setWafError] = useState('')

  const username = useMemo(() => session?.username || 'admin', [session])
  const wafText = useMemo(() => JSON.stringify(wafResponse || {}), [wafResponse])

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
    if (activeTab === 'waf' || activeTab === 'search') loadWafResponse()
  }, [activeTab])

  const resetToSearch = () => {
    setActiveTab('search')
  }

  return (
    <div style={styles.appRoot}>
      <header style={styles.topHeader}>
        <div style={styles.headerLeft}>
          <button style={styles.iconBtn} onClick={() => setSidebarOpen((v) => !v)} title="Toggle sidebar">☰</button>
          <div style={styles.platformTitle}>SecurityPerspective</div>
        </div>
        <div style={styles.headerRight}>
          <div style={styles.profileUser}>Logged in as {username}</div>
          <button style={styles.logoutBtn} onClick={onLogout}>Logout</button>
          <button style={styles.logoCornerBtn} onClick={resetToSearch} title="Go to Search">
            <Brand small />
          </button>
        </div>
      </header>

      <div style={styles.mainWrap}>
        {sidebarOpen && (
          <aside style={styles.sidebar}>
            <button onClick={() => setActiveTab('search')} style={activeTab === 'search' ? styles.navBtnActive : styles.navBtn}>Search</button>
            <button onClick={() => setActiveTab('waf')} style={activeTab === 'waf' ? styles.navBtnActive : styles.navBtn}>WAF Configuration</button>
            <button onClick={() => setActiveTab('maturity')} style={activeTab === 'maturity' ? styles.navBtnActive : styles.navBtn}>Maturity Level</button>
            <button style={styles.settingsBtn}>⚙ Platform Settings</button>
          </aside>
        )}

        <main style={styles.contentArea}>
          {activeTab === 'search' && <SearchPage username={username} wafText={wafText} />}

          {activeTab === 'waf' && (
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
              {!loadingWaf && !wafError && wafResponse && <pre style={styles.responseBox}>{JSON.stringify(wafResponse, null, 2)}</pre>}
            </section>
          )}

          {activeTab === 'maturity' && <MaturityPanel />}
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
  loginPage: { minHeight: '100vh', background: 'radial-gradient(circle at 20% 20%, #0f172a, #020617)', display: 'grid', placeItems: 'center', padding: '1rem' },
  loginCard: { width: '100%', maxWidth: '430px', background: 'rgba(15, 23, 42, 0.92)', border: '1px solid #1e3a8a', borderRadius: '16px', padding: '1.5rem', boxShadow: '0 18px 30px rgba(2,6,23,0.5)', color: '#e2e8f0' },
  brandWrap: { display: 'flex', alignItems: 'center', gap: '0.6rem' },
  brandWrapSmall: { gap: 0 },
  brandImage: { width: '64px', height: '64px', objectFit: 'contain', borderRadius: '8px', boxShadow: '0 8px 18px rgba(2,132,199,0.3)' },
  brandImageSmall: { width: '42px', height: '42px', boxShadow: 'none' },
  logoText: { fontSize: '2rem', fontWeight: 900, letterSpacing: '0.25px' },
  loginSubtitle: { color: '#94a3b8', marginBottom: '1rem' },
  form: { display: 'grid', gap: '0.55rem' },
  label: { color: '#cbd5e1', fontSize: '0.9rem' },
  input: { padding: '0.68rem', borderRadius: '10px', border: '1px solid #334155', background: '#0f172a', color: '#f8fafc' },
  error: { background: '#7f1d1d', color: '#fee2e2', borderRadius: '8px', padding: '0.5rem' },
  primaryBtn: { marginTop: '0.65rem', padding: '0.72rem', border: 0, borderRadius: '10px', background: '#0284c7', color: 'white', fontWeight: 700, cursor: 'pointer' },

  appRoot: { minHeight: '100vh', background: 'linear-gradient(140deg, #020617 0%, #0b1120 55%, #0f172a 100%)', color: '#e2e8f0', padding: '0.8rem', display: 'grid', gridTemplateRows: 'auto 1fr', gap: '0.8rem' },
  topHeader: { background: '#0b1224', border: '1px solid #1e3a8a', borderRadius: '14px', padding: '1rem 1.1rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center' },
  headerLeft: { display: 'flex', alignItems: 'center', gap: '0.7rem' },
  headerRight: { display: 'flex', alignItems: 'center', gap: '0.6rem' },
  platformTitle: { fontWeight: 800, fontSize: '1.1rem', color: '#e2e8f0' },
  iconBtn: { border: '1px solid #334155', background: '#0f172a', color: '#e2e8f0', borderRadius: '8px', width: '34px', height: '34px', cursor: 'pointer' },
  profileUser: { fontSize: '0.9rem', color: '#cbd5e1' },
  logoutBtn: { border: 0, background: '#ef4444', color: 'white', borderRadius: '8px', padding: '0.35rem 0.6rem', cursor: 'pointer' },
  logoCornerBtn: { border: '1px solid #334155', borderRadius: '10px', background: '#020617', padding: '0.2rem', cursor: 'pointer' },

  mainWrap: { display: 'grid', gridTemplateColumns: 'auto 1fr', gap: '0.8rem' },
  sidebar: { width: '230px', background: '#0b1224', border: '1px solid #1e3a8a', borderRadius: '14px', padding: '0.8rem', display: 'grid', gap: '0.6rem', alignContent: 'start' },
  navBtn: { border: '1px solid #334155', background: '#0f172a', color: '#cbd5e1', borderRadius: '10px', padding: '0.65rem', textAlign: 'left', cursor: 'pointer' },
  navBtnActive: { border: '1px solid #38bdf8', background: '#082f49', color: '#e0f2fe', borderRadius: '10px', padding: '0.65rem', textAlign: 'left', cursor: 'pointer', fontWeight: 700 },
  settingsBtn: { marginTop: 'auto', border: '1px solid #334155', background: '#020617', color: '#cbd5e1', borderRadius: '18px', padding: '0.45rem 0.6rem', textAlign: 'left', cursor: 'pointer' },

  contentArea: { minWidth: 0, display: 'grid', gap: '0.8rem' },
  searchPanel: { background: '#0b1224', border: '1px solid #1e3a8a', borderRadius: '14px', minHeight: '72vh', display: 'grid', alignContent: 'center', justifyItems: 'center', gap: '1rem', padding: '1rem' },
  searchTitle: { margin: 0, color: '#e2e8f0', fontSize: '2rem' },
  searchForm: { width: '100%', maxWidth: '760px', background: '#020617', border: '1px solid #334155', borderRadius: '999px', padding: '0.35rem', display: 'grid', gridTemplateColumns: '40px 1fr auto', alignItems: 'center' },
  searchPrefix: { textAlign: 'center', color: '#94a3b8', fontSize: '1.2rem' },
  searchInput: { background: 'transparent', border: 0, outline: 'none', color: '#f8fafc', fontSize: '1rem', padding: '0.4rem 0.2rem' },
  searchBtn: { border: 0, background: '#0284c7', color: 'white', borderRadius: '999px', padding: '0.55rem 1rem', cursor: 'pointer', marginRight: '0.2rem' },
  searchResult: { color: '#93c5fd' },

  panel: { background: '#0b1224', border: '1px solid #1e3a8a', borderRadius: '14px', padding: '1rem', minHeight: '72vh' },
  panelTopRow: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' },
  panelTitle: { margin: 0, color: '#93c5fd' },
  panelHint: { color: '#94a3b8' },
  rowBtns: { display: 'flex', gap: '0.5rem' },
  secondaryBtn: { border: '1px solid #0ea5e9', background: '#082f49', color: '#e0f2fe', borderRadius: '8px', padding: '0.45rem 0.7rem', cursor: 'pointer' },
  primaryBtnSmall: { border: 0, background: '#0284c7', color: 'white', borderRadius: '8px', padding: '0.45rem 0.7rem', cursor: 'pointer' },
  responseBox: { background: '#020617', border: '1px solid #1e293b', color: '#dbeafe', borderRadius: '10px', padding: '0.75rem', maxHeight: '63vh', overflow: 'auto', fontSize: '0.82rem' },
  errorText: { color: '#fca5a5' },

  dashboardGrid: { display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.8rem' },
  panelBlock: { background: '#0b1224', border: '1px solid #1e3a8a', borderRadius: '12px', padding: '0.9rem' },
  panelBlockWide: { gridColumn: '1 / -1', background: '#0b1224', border: '1px solid #1e3a8a', borderRadius: '12px', padding: '0.9rem' },
  trendArea: { minHeight: '180px', display: 'grid', placeItems: 'center', border: '1px dashed #334155', borderRadius: '10px', background: '#020617' },
  fakeChartLine: { width: '80%', height: '2px', background: 'linear-gradient(90deg, #38bdf8, #22d3ee, #38bdf8)' },
  findingsList: { margin: 0, paddingLeft: '1rem', color: '#cbd5e1', lineHeight: 1.7 }
}
