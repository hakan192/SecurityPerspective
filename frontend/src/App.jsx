import { useEffect, useMemo, useRef, useState } from 'react'
import './App.css'

const resolvedHost = window.location.hostname || 'localhost'
const configuredApiBase = import.meta.env.VITE_API_BASE_URL
const API_BASE =
  configuredApiBase && configuredApiBase.includes('localhost') && !['localhost', '127.0.0.1'].includes(resolvedHost)
    ? configuredApiBase.replace('localhost', resolvedHost)
    : configuredApiBase || `http://${resolvedHost}:8000`

const navItems = [
  {
    id: 'waf',
    label: 'WAF Configuration',
    description: 'Policies, gaps, and remediation priorities'
  },
  {
    id: 'overview',
    label: 'Executive Overview',
    description: 'Leadership-ready security posture summaries'
  }
]

function LoginCard({ onLogin, darkMode, onToggleTheme }) {
  const logoSrc = '/branding/securityperspective-logo.png'
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
    <div className={`login-page ${darkMode ? 'dark' : 'light'}`}>
      <div className="login-card">
        <div className="login-head">
          <div className="brand-wrap">
            <div className="brand-logo-shell">
              <img src={logoSrc} alt="SecurityPerspective logo" className="brand-logo" />
            </div>
            <h1 className="brand-title">
              <span>Security</span> <span className="gradient-text">Perspective</span>
            </h1>
          </div>
          <button type="button" onClick={onToggleTheme} className="theme-btn">
            {darkMode ? 'Light' : 'Dark'}
          </button>
        </div>

        <form onSubmit={submit} className="login-form">
          <label htmlFor="username">Username</label>
          <input id="username" type="text" placeholder="Enter your username" value={username} onChange={(e) => setUsername(e.target.value)} />

          <label htmlFor="password">Password</label>
          <input id="password" type="password" placeholder="Enter your password" value={password} onChange={(e) => setPassword(e.target.value)} />

          {error && <div className="error-box">{error}</div>}

          <button className="signin-btn" disabled={loading}>
            {loading ? 'Signing in...' : 'Sign in'}
          </button>
        </form>
      </div>
    </div>
  )
}

function AppShell({ session, onLogout, darkMode, onToggleTheme }) {
  const logoSrc = '/branding/securityperspective-logo.png'
  const [activeNav, setActiveNav] = useState('home')
  const [menuOpen, setMenuOpen] = useState(false)
  const [prompt, setPrompt] = useState('')
  const [searchResult, setSearchResult] = useState('')
  const [wafResponse, setWafResponse] = useState(null)
  const [loadingWaf, setLoadingWaf] = useState(false)
  const [wafError, setWafError] = useState('')
  const menuRef = useRef(null)

  const username = useMemo(() => session?.username || 'admin', [session])
  const wafText = useMemo(() => JSON.stringify(wafResponse || {}), [wafResponse])

  useEffect(() => {
    const handleClickOutside = (event) => {
      if (menuRef.current && !menuRef.current.contains(event.target)) {
        setMenuOpen(false)
      }
    }

    document.addEventListener('mousedown', handleClickOutside)
    return () => document.removeEventListener('mousedown', handleClickOutside)
  }, [])

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
    if (activeNav === 'waf' || activeNav === 'home') loadWafResponse()
  }, [activeNav])

  const submitSearch = (event) => {
    event.preventDefault()
    if (!prompt.trim()) {
      setSearchResult('Please enter a search term.')
      return
    }

    const normalized = wafText.toLowerCase()
    const term = prompt.toLowerCase()
    const count = normalized.split(term).length - 1

    if (count > 0) {
      setSearchResult(`Found ${count} matches in the latest WAF response.`)
    } else {
      setSearchResult('No matches found in the latest WAF response.')
    }
  }

  return (
    <div className={`dashboard-page ${darkMode ? 'dark' : 'light'}`}>
      <div className="ambient-layer" />
      <div className="dashboard-shell">
        <aside className="sidebar">
          <div>
            <button onClick={() => setActiveNav('home')} className="home-link">
              <div className="brand-logo-shell">
                <img src={logoSrc} alt="SecurityPerspective logo" className="brand-logo" />
              </div>
              <div>
                <div className="kicker">Security Platform</div>
                <div className="brand-title sidebar-title">
                  <span>Security</span> <span className="gradient-text">Perspective</span>
                </div>
              </div>
            </button>
            <nav className="nav-list">
              {navItems.map((item) => {
                const active = activeNav === item.id
                return (
                  <button key={item.id} type="button" onClick={() => setActiveNav(item.id)} className={`nav-item ${active ? 'active' : ''}`}>
                    <div>
                      <div className="nav-title">{item.label}</div>
                      <div className="nav-desc">{item.description}</div>
                    </div>
                    <span className="status-dot" />
                  </button>
                )
              })}
            </nav>
          </div>

          <button type="button" className="settings-btn">
            ⚙ Platform Settings
          </button>
        </aside>

        <main className="main-panel">
          <header className="topbar">
            <div>
              <div className="kicker">Workspace</div>
              <h1 className="workspace-title">{activeNav === 'home' ? 'Search' : activeNav === 'waf' ? 'WAF Configuration' : 'Executive Overview'}</h1>
            </div>

            <div className="topbar-right">
              <button type="button" onClick={onToggleTheme} className="theme-btn">
                {darkMode ? 'Light' : 'Dark'}
              </button>

              <div className="profile-menu" ref={menuRef}>
                <button type="button" onClick={() => setMenuOpen((prev) => !prev)} className="avatar-btn">
                  {username.slice(0, 2).toUpperCase()}
                </button>

                {menuOpen && (
                  <div className="menu-popover">
                    <div className="user-card">
                      <div className="nav-title">{username}</div>
                      <div className="nav-desc">Cyber Security Lead</div>
                    </div>
                    <button type="button" className="menu-action">Help</button>
                    <button type="button" className="menu-action" onClick={onLogout}>Logout</button>
                  </div>
                )}
              </div>
            </div>
          </header>

          <section className="body-content">
            {activeNav === 'home' && (
              <form className="search-wrap" onSubmit={submitSearch}>
                <div className="hero-text">How can I help you? :)</div>
                <div className="search-bar">
                  <input type="text" value={prompt} onChange={(e) => setPrompt(e.target.value)} placeholder="Search..." />
                  <button type="submit">Search</button>
                </div>
                {searchResult && <p className="search-result">{searchResult}</p>}
              </form>
            )}

            {activeNav === 'waf' && (
              <section className="waf-panel">
                <div className="waf-header-row">
                  <div className="nav-title">Latest API response</div>
                  <div className="waf-buttons">
                    <button type="button" className="menu-action" onClick={collectWafResponse} disabled={loadingWaf}>Collect from WAF</button>
                    <button type="button" className="theme-btn" onClick={loadWafResponse} disabled={loadingWaf}>Refresh</button>
                  </div>
                </div>
                {loadingWaf && <p className="nav-desc">Loading...</p>}
                {wafError && <p className="error-box">{wafError}</p>}
                {!loadingWaf && !wafError && wafResponse && <pre className="waf-response">{JSON.stringify(wafResponse, null, 2)}</pre>}
              </section>
            )}

            {activeNav === 'overview' && <div className="hero-text muted">This page will be designed next.</div>}
          </section>
        </main>
      </div>
    </div>
  )
}

export default function App() {
  const [darkMode, setDarkMode] = useState(() => {
    const storedTheme = localStorage.getItem('sp_theme')
    if (storedTheme === 'dark') return true
    if (storedTheme === 'light') return false
    return window.matchMedia('(prefers-color-scheme: dark)').matches
  })

  const [session, setSession] = useState(() => {
    const raw = localStorage.getItem('sp_session')
    return raw ? JSON.parse(raw) : null
  })

  useEffect(() => {
    localStorage.setItem('sp_theme', darkMode ? 'dark' : 'light')
  }, [darkMode])

  const toggleTheme = () => {
    setDarkMode((prev) => !prev)
  }

  const handleLogin = (data) => {
    localStorage.setItem('sp_session', JSON.stringify(data))
    setSession(data)
  }

  const handleLogout = () => {
    localStorage.removeItem('sp_session')
    setSession(null)
  }

  return session
    ? <AppShell session={session} onLogout={handleLogout} darkMode={darkMode} onToggleTheme={toggleTheme} />
    : <LoginCard onLogin={handleLogin} darkMode={darkMode} onToggleTheme={toggleTheme} />
}
