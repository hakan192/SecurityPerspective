import { useEffect, useId, useMemo, useRef, useState } from 'react'
import './App.css'

const resolvedHost = window.location.hostname || 'localhost'
const configuredApiBase = import.meta.env.VITE_API_BASE_URL
const API_BASE =
  configuredApiBase && configuredApiBase.includes('localhost') && !['localhost', '127.0.0.1'].includes(resolvedHost)
    ? configuredApiBase.replace('localhost', resolvedHost)
    : configuredApiBase || `http://${resolvedHost}:8000`

const SERVER_POLICY_ENDPOINT = '/fortiweb/server-policy/latest'

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

const seededDevices = [
  { id: 'fw-prod-tr-01', name: 'FortiWeb-Prod-TR-01', ip: '10.10.1.15', model: 'FortiWeb VM · v7.4.2', environment: 'Production', region: 'Istanbul', lastSync: '5 min ago', status: 'Online' },
  { id: 'fw-dr-01', name: 'FortiWeb-DR-01', ip: '10.20.1.22', model: 'FortiWeb 4000E · v7.2.6', environment: 'Disaster Recovery', region: 'Ankara', lastSync: '42 min ago', status: 'Warning' },
  { id: 'fw-test-01', name: 'FortiWeb-Test-01', ip: '10.30.8.9', model: 'FortiWeb VM · v7.4.1', environment: 'Test', region: 'Izmir', lastSync: '3 hours ago', status: 'Offline' }
]

function extractServerPolicyNames(payload) {
  const seen = new Set()
  const names = []

  const addName = (value) => {
    if (typeof value !== 'string') return
    const trimmed = value.trim()
    if (!trimmed || seen.has(trimmed)) return
    seen.add(trimmed)
    names.push(trimmed)
  }

  const parseMaybeJson = (value) => {
    if (typeof value !== 'string') return null
    try {
      return JSON.parse(value)
    } catch {
      return null
    }
  }

  const walk = (node, rawJsonContext = false) => {
    if (!node) return

    if (Array.isArray(node)) {
      node.forEach((item) => walk(item, rawJsonContext))
      return
    }

    if (typeof node !== 'object') return

    if (typeof node.name === 'string' && (rawJsonContext || 'name' in node)) {
      addName(node.name)
    }

    Object.entries(node).forEach(([key, value]) => {
      if (key === 'raw_json') {
        const parsed = parseMaybeJson(value)
        if (parsed) walk(parsed, true)
      } else if (key === 'results' && Array.isArray(value)) {
        value.forEach((item) => walk(item, rawJsonContext))
      } else {
        walk(value, rawJsonContext)
      }
    })
  }

  walk(payload)
  return names
}

function SecurityPerspectiveLogo({ className = 'brand-logo' }) {
  const gradientId = useId()

  return (
    <svg className={className} viewBox="0 0 512 512" fill="none" xmlns="http://www.w3.org/2000/svg" aria-label="SecurityPerspective logo" role="img">
      <defs>
        <linearGradient id={gradientId} x1="112" y1="96" x2="400" y2="416" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#00A94F" />
          <stop offset="100%" stopColor="#004481" />
        </linearGradient>
      </defs>
      <rect width="512" height="512" rx="140" fill="#0F172A" />
      <path
        d="M256 110C310 110 355 125 390 150V240C390 315 340 380 256 402C172 380 122 315 122 240V150C157 125 202 110 256 110Z"
        stroke={`url(#${gradientId})`}
        strokeWidth="28"
        strokeLinejoin="round"
      />
      <ellipse cx="256" cy="250" rx="95" ry="60" stroke={`url(#${gradientId})`} strokeWidth="24" />
      <circle cx="256" cy="250" r="28" fill="#00A94F" />
    </svg>
  )
}

function LoginCard({ onLogin, darkMode, onToggleTheme }) {
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
              <SecurityPerspectiveLogo />
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
  const [sidebarOpen, setSidebarOpen] = useState(true)
  const [activeNav, setActiveNav] = useState('home')
  const [settingsExpanded, setSettingsExpanded] = useState(false)
  const [settingsGearSpinning, setSettingsGearSpinning] = useState(false)
  const [menuOpen, setMenuOpen] = useState(false)
  const [prompt, setPrompt] = useState('')
  const [searchResult, setSearchResult] = useState('')
  const [wafResponse, setWafResponse] = useState(null)
  const [selectedPolicyName, setSelectedPolicyName] = useState('')
  const [loadingWaf, setLoadingWaf] = useState(false)
  const [wafError, setWafError] = useState('')
  const [devices, setDevices] = useState(seededDevices)
  const [deviceSearch, setDeviceSearch] = useState('')
  const [deviceStatusFilter, setDeviceStatusFilter] = useState('All')
  const [addDeviceModalOpen, setAddDeviceModalOpen] = useState(false)
  const [newDevice, setNewDevice] = useState({
    name: 'FortiWeb-Prod-02',
    ip: '10.10.1.25',
    environment: 'Production',
    region: 'Istanbul',
    model: 'FortiWeb VM',
    firmware: '7.4.2'
  })
  const menuRef = useRef(null)

  const username = useMemo(() => session?.username || 'admin', [session])
  const wafText = useMemo(() => JSON.stringify(wafResponse || {}), [wafResponse])
  const serverPolicyNames = useMemo(() => extractServerPolicyNames(wafResponse), [wafResponse])
  const filteredDevices = useMemo(() => {
    const search = deviceSearch.trim().toLowerCase()
    return devices.filter((device) => {
      const statusMatch = deviceStatusFilter === 'All' || device.status === deviceStatusFilter
      if (!statusMatch) return false
      if (!search) return true
      return [device.name, device.ip, device.region, device.environment].join(' ').toLowerCase().includes(search)
    })
  }, [deviceSearch, deviceStatusFilter, devices])
  const deviceStats = useMemo(
    () => ({
      total: devices.length,
      online: devices.filter((d) => d.status === 'Online').length,
      warning: devices.filter((d) => d.status === 'Warning').length,
      offline: devices.filter((d) => d.status === 'Offline').length
    }),
    [devices]
  )

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
      const res = await fetch(`${API_BASE}${SERVER_POLICY_ENDPOINT}`)
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

  const openPlatformSettings = () => {
    const nextExpandedState = !settingsExpanded
    setSettingsExpanded(nextExpandedState)
    if (nextExpandedState) {
      setActiveNav('device-config')
    } else if (activeNav === 'device-config') {
      setActiveNav('home')
    }
    setSettingsGearSpinning(true)
    window.setTimeout(() => setSettingsGearSpinning(false), 650)
  }

  const updateNewDeviceField = (field, value) => {
    setNewDevice((prev) => ({ ...prev, [field]: value }))
  }

  const saveNewDevice = () => {
    setDevices((prev) => [
      {
        id: `${newDevice.name.toLowerCase().replace(/[^a-z0-9]+/g, '-')}-${Date.now()}`,
        name: newDevice.name,
        ip: newDevice.ip,
        model: `${newDevice.model} · v${newDevice.firmware}`,
        environment: newDevice.environment,
        region: newDevice.region,
        lastSync: 'Just now',
        status: 'Online'
      },
      ...prev
    ])
    setAddDeviceModalOpen(false)
  }

  return (
    <div className={`dashboard-page ${darkMode ? 'dark' : 'light'}`}>
      <div className="ambient-layer" />
      <div className={`dashboard-shell ${sidebarOpen ? 'sidebar-open' : 'sidebar-closed'}`}>
        <aside className={`sidebar ${sidebarOpen ? 'is-open' : 'is-closed'}`}>
          <div>
            <button onClick={() => setActiveNav('home')} className="home-link">
              <div className="brand-logo-shell">
                <SecurityPerspectiveLogo />
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
                  <button
                    key={item.id}
                    type="button"
                    onClick={() => {
                      setActiveNav(item.id)
                    }}
                    className={`nav-item ${active ? 'active' : ''}`}
                  >
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

          <div className={`settings-box ${settingsExpanded ? 'expanded' : ''}`}>
            <button type="button" className={`settings-btn ${settingsGearSpinning ? 'spinning' : ''}`} onClick={openPlatformSettings}>
              <span className="settings-gear" aria-hidden="true">⚙</span> Platform Settings
            </button>
            {settingsExpanded && (
              <button type="button" className={`settings-subitem ${activeNav === 'device-config' ? 'active' : ''}`} onClick={() => setActiveNav('device-config')}>
                Device Config
              </button>
            )}
          </div>
        </aside>

        <main className="main-panel">
          <header className="topbar">
            <div>
              <button type="button" onClick={() => setSidebarOpen((prev) => !prev)} className="sidebar-icon-btn" aria-label={sidebarOpen ? 'Close sidebar' : 'Open sidebar'}>
                <span className="sidebar-icon" aria-hidden="true">◧</span>
                <span className="sidebar-tooltip">{sidebarOpen ? 'Close sidebar' : 'Open sidebar'}</span>
              </button>
              <div className="kicker">Workspace</div>
              <h1 className="workspace-title">
                {activeNav === 'home'
                  ? 'Search'
                  : activeNav === 'waf'
                    ? 'WAF Configuration'
                    : activeNav === 'device-config'
                      ? 'Device Config'
                      : 'Executive Overview'}
              </h1>
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
              <section className="waf-panel modern-waf">
                <div className="waf-header-row">
                  <div>
                    <div className="nav-title">Server policy cards</div>
                    <div className="waf-endpoint">API endpoint: {SERVER_POLICY_ENDPOINT}</div>
                  </div>
                  <div className="waf-buttons">
                    <button type="button" className="menu-action" onClick={collectWafResponse} disabled={loadingWaf}>Collect from WAF</button>
                    <button type="button" className="theme-btn" onClick={loadWafResponse} disabled={loadingWaf}>Refresh</button>
                  </div>
                </div>
                {loadingWaf && <p className="nav-desc">Loading...</p>}
                {wafError && <p className="error-box">{wafError}</p>}
                {!loadingWaf && !wafError && (
                  <>
                    <div className="waf-card-grid">
                      {serverPolicyNames.length === 0 && <p className="nav-desc">No policy names found in raw_json.name fields.</p>}
                      {serverPolicyNames.map((policyName) => {
                        const selected = selectedPolicyName === policyName
                        return (
                          <button
                            key={policyName}
                            type="button"
                            className={`policy-card ${selected ? 'selected' : ''}`}
                            onClick={() => setSelectedPolicyName(selected ? '' : policyName)}
                          >
                            <p className="policy-label">Policy Name</p>
                            <p className="policy-name">{policyName}</p>
                            {selected && <p className="policy-meta">Expanded view enabled for this policy card.</p>}
                          </button>
                        )
                      })}
                    </div>
                    {wafResponse && <pre className="waf-response">{JSON.stringify(wafResponse, null, 2)}</pre>}
                  </>
                )}
              </section>
            )}

            {activeNav === 'overview' && <div className="hero-text muted">This page will be designed next.</div>}
            {activeNav === 'device-config' && (
              <section className="device-page">
                <div className="device-topbar">
                  <div>
                    <span className="device-kicker">● Device Management</span>
                    <h2 className="device-title">Manage FortiWeb Devices</h2>
                    <p className="device-subtitle">Add, review, filter, and remove devices connected to your WAF configuration platform.</p>
                  </div>
                  <button type="button" className="add-device-btn" onClick={() => setAddDeviceModalOpen(true)}>+ Add Device</button>
                </div>

                <div className="device-stats-grid">
                  <article className="device-stat-card"><p>Total Devices</p><h3>{deviceStats.total}</h3><span>Across all environments</span></article>
                  <article className="device-stat-card"><p>Online</p><h3>{deviceStats.online}</h3><span>Healthy and reachable</span></article>
                  <article className="device-stat-card"><p>Warning</p><h3>{deviceStats.warning}</h3><span>Needs attention</span></article>
                  <article className="device-stat-card"><p>Offline</p><h3>{deviceStats.offline}</h3><span>No recent sync</span></article>
                </div>

                <div className="device-filter-row">
                  <input type="text" placeholder="Search by device name, IP, or region" value={deviceSearch} onChange={(e) => setDeviceSearch(e.target.value)} />
                  <select value={deviceStatusFilter} onChange={(e) => setDeviceStatusFilter(e.target.value)}>
                    <option>All</option>
                    <option>Online</option>
                    <option>Warning</option>
                    <option>Offline</option>
                  </select>
                </div>

                <div className="device-list">
                  {filteredDevices.map((device) => (
                    <article className="device-card" key={device.id}>
                      <div>
                        <h3 className="device-card-name">{device.name} <span className={`status-pill ${device.status.toLowerCase()}`}>{device.status}</span></h3>
                        <div className="device-card-meta">{device.ip}</div>
                        <div className="device-card-meta">{device.model}</div>
                      </div>
                      <div><p className="device-label">Environment</p><strong>{device.environment}</strong></div>
                      <div><p className="device-label">Region</p><strong>{device.region}</strong></div>
                      <div><p className="device-label">Last Sync</p><strong>{device.lastSync}</strong></div>
                      <div className="device-actions"><button type="button">View</button><button type="button" className="danger">Delete</button></div>
                    </article>
                  ))}
                </div>

                {addDeviceModalOpen && (
                  <div className="device-modal-overlay" role="dialog" aria-modal="true">
                    <div className="device-modal">
                      <div className="device-modal-head">
                        <div>
                          <h3>Add Device</h3>
                          <p>Register a new FortiWeb device for API sync and configuration tracking.</p>
                        </div>
                        <button type="button" className="device-modal-close" onClick={() => setAddDeviceModalOpen(false)}>×</button>
                      </div>

                      <div className="device-modal-grid">
                        <label>Device Name<input value={newDevice.name} onChange={(e) => updateNewDeviceField('name', e.target.value)} /></label>
                        <label>Management IP<input value={newDevice.ip} onChange={(e) => updateNewDeviceField('ip', e.target.value)} /></label>
                        <label>Environment<select value={newDevice.environment} onChange={(e) => updateNewDeviceField('environment', e.target.value)}><option>Production</option><option>Disaster Recovery</option><option>Test</option></select></label>
                        <label>Region<input value={newDevice.region} onChange={(e) => updateNewDeviceField('region', e.target.value)} /></label>
                        <label>Model<select value={newDevice.model} onChange={(e) => updateNewDeviceField('model', e.target.value)}><option>FortiWeb VM</option><option>FortiWeb 4000E</option></select></label>
                        <label>Firmware Version<input value={newDevice.firmware} onChange={(e) => updateNewDeviceField('firmware', e.target.value)} /></label>
                      </div>
                      <div className="device-modal-actions">
                        <button type="button" onClick={() => setAddDeviceModalOpen(false)}>Cancel</button>
                        <button type="button" className="primary" onClick={saveNewDevice}>Save Device</button>
                      </div>
                    </div>
                  </div>
                )}
              </section>
            )}
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
