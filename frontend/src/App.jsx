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

const MAIN_WAF_TAB_ID = 'waf-main-tab'

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

function FullDetailsPage({ policy }) {
  if (!policy) return null

  const details = [
    ['Device', policy._deviceName || '-'],
    ['Location', policy._deviceLocation || '-'],
    ['Server Policy', policy.server_policy_name || '-'],
    ['IP', policy.ip || '-'],
    ['SNI', policy.sni || '-'],
    ['Hostname', policy.allow_hosts_entries?.[0]?.host || '-'],
    ['Traffic Mirror', policy['traffic-mirror'] ?? policy.traffic_mirror ?? '-'],
    ['TLS v1.3', String(policy.tls_v13 ?? '-')],
    ['TLS v1.2', String(policy.tls_v12 ?? '-')],
    ['TLS v1.1', String(policy.tls_v11 ?? '-')],
    ['TLS v1.0', String(policy.tls_v10 ?? '-')],
    ['HTTP/2', String(policy.http2 ?? '-')]
  ]

  return (
    <section className="full-details-page">
      <div className="full-details-head">
        <h3>{policy.server_policy_name || 'Policy Details'}</h3>
        <p>Detailed view of selected policy configuration.</p>
      </div>
      <table className="policy-table">
        <tbody>
          {details.map(([label, value]) => (
            <tr key={label}>
              <th>{label}</th>
              <td>{value || '-'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
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
  const [loadingWaf, setLoadingWaf] = useState(false)
  const [wafError, setWafError] = useState('')
  const [selectedLocation, setSelectedLocation] = useState('All')
  const [expandedPolicyCard, setExpandedPolicyCard] = useState('')
  const [wafSearch, setWafSearch] = useState('')
  const [wafTabs, setWafTabs] = useState([{ id: MAIN_WAF_TAB_ID, title: 'WAF Configuration', type: 'main' }])
  const [activeWafTabId, setActiveWafTabId] = useState(MAIN_WAF_TAB_ID)
  const [devices, setDevices] = useState([])
  const [deviceSearch, setDeviceSearch] = useState('')
  const [deviceStatusFilter, setDeviceStatusFilter] = useState('All')
  const [addDeviceModalOpen, setAddDeviceModalOpen] = useState(false)
  const [viewedDevice, setViewedDevice] = useState(null)
  const [deviceError, setDeviceError] = useState('')
  const [loadingDevices, setLoadingDevices] = useState(false)
  const [newDevice, setNewDevice] = useState({
    name: 'FortiWeb-Prod-02',
    ip: '10.10.1.25',
    environment: 'Production',
    region: 'Istanbul',
    model: 'FortiWeb VM',
    firmware: '7.4.2',
    apikey: ''
  })
  const menuRef = useRef(null)

  const username = useMemo(() => session?.username || 'admin', [session])
  const wafText = useMemo(() => JSON.stringify(wafResponse || {}), [wafResponse])
  const wafDevices = useMemo(() => {
    const devices = wafResponse?.devices
    return Array.isArray(devices) ? devices : []
  }, [wafResponse])
  const deviceRegionByName = useMemo(() => {
    const index = {}
    devices.forEach((device) => {
      index[device.name] = device.region || 'Unknown'
    })
    return index
  }, [devices])
  const locationOptions = useMemo(() => {
    const regionSet = new Set(['All'])
    wafDevices.forEach((device) => {
      regionSet.add(deviceRegionByName[device.device_name] || device.location || device.region || 'Unknown')
    })
    return Array.from(regionSet)
  }, [deviceRegionByName, wafDevices])
  const wafPolicies = useMemo(
    () =>
      wafDevices.flatMap((device) => {
        if (device.error) {
          return [{
            server_policy_name: `Error: ${device.error}`,
            _deviceName: device.device_name,
            _deviceLocation: deviceRegionByName[device.device_name] || device.location || device.region || 'Unknown'
          }]
        }
        const policies = Array.isArray(device.server_policies) ? device.server_policies : []
        return policies.map((policy) => ({
          ...policy,
          _deviceName: device.device_name,
          _deviceLocation: deviceRegionByName[device.device_name] || device.location || device.region || 'Unknown'
        }))
      }),
    [deviceRegionByName, wafDevices]
  )
  const filteredWafPolicies = useMemo(() => {
    const query = wafSearch.trim().toLowerCase()
    return wafPolicies.filter((policy) => {
      const policyLocation = (policy._deviceLocation || 'Unknown').toLowerCase()
      if (selectedLocation !== 'All' && selectedLocation.toLowerCase() !== policyLocation) return false
      if (!query) return true
      if (typeof policy === 'string') return policy.toLowerCase().includes(query)
      const policyName = (policy.server_policy_name || '').toLowerCase()
      const ip = (policy.ip || '').toLowerCase()
      const hostnames = (policy.allow_hosts_entries || [])
        .map((entry) => entry.host || '')
        .join(' ')
        .toLowerCase()
      return policyName.includes(query) || ip.includes(query) || hostnames.includes(query)
    })
  }, [wafPolicies, wafSearch, selectedLocation])
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

  useEffect(() => {
    setExpandedPolicyCard('')
  }, [selectedLocation])

  const loadDevices = async () => {
    setLoadingDevices(true)
    setDeviceError('')
    try {
      const res = await fetch(`${API_BASE}/devices`)
      if (!res.ok) throw new Error('Failed to load devices')
      const data = await res.json()
      setDevices(data)
    } catch (err) {
      setDeviceError(err.message)
    } finally {
      setLoadingDevices(false)
    }
  }

  useEffect(() => {
    if (activeNav === 'device-config') loadDevices()
  }, [activeNav])

  useEffect(() => {
    if (activeNav === 'waf' && devices.length === 0) loadDevices()
  }, [activeNav, devices.length])

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

  const saveNewDevice = async () => {
    setDeviceError('')
    try {
      if (!newDevice.apikey.trim()) {
        throw new Error('APIKEY cannot be Empty')
      }
      const res = await fetch(`${API_BASE}/devices`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Role': 'admin' },
        body: JSON.stringify({
          name: newDevice.name,
          ip: newDevice.ip,
          model: newDevice.model,
          environment: newDevice.environment,
          region: newDevice.region,
          firmware: newDevice.firmware,
          apikey: newDevice.apikey,
          status: 'Online',
          last_sync: 'Just now'
        })
      })
      if (!res.ok) throw new Error('Failed to save device')
      const created = await res.json()
      setDevices((prev) => [created, ...prev])
      setAddDeviceModalOpen(false)
    } catch (err) {
      setDeviceError(err.message)
    }
  }

  const viewDevice = async (deviceId) => {
    setDeviceError('')
    try {
      const res = await fetch(`${API_BASE}/devices/${deviceId}`)
      if (!res.ok) throw new Error('Failed to load device details')
      const device = await res.json()
      setViewedDevice(device)
    } catch (err) {
      setDeviceError(err.message)
    }
  }

  const deleteDevice = async (deviceId) => {
    setDeviceError('')
    try {
      const res = await fetch(`${API_BASE}/devices/${deviceId}`, {
        method: 'DELETE',
        headers: { 'X-Role': 'admin' }
      })
      if (!res.ok) throw new Error('Failed to delete device')
      setDevices((prev) => prev.filter((device) => device.id !== deviceId))
      if (viewedDevice?.id === deviceId) setViewedDevice(null)
    } catch (err) {
      setDeviceError(err.message)
    }
  }

  const getPolicyStatus = (policy) => {
    const ip = typeof policy === 'string' ? '' : (policy.ip || '').trim()
    if (!ip) return { label: 'Not Protected', className: 'not-protected' }
    const monitorMode = typeof policy === 'string' ? '' : String(policy['monitor-mode'] ?? policy.monitor_mode ?? '').toLowerCase()
    if (monitorMode === 'enable') return { label: 'Monitoring', className: 'monitoring' }
    return { label: 'Blocking', className: 'blocking' }
  }

  const openPolicyTab = (policy, index) => {
    const policyName = policy?.server_policy_name || `Policy ${index + 1}`
    const deviceName = policy?._deviceName || 'Unknown Device'
    const tabId = `${deviceName}-${policyName}-${index}`

    setWafTabs((prev) => {
      if (prev.some((tab) => tab.id === tabId)) return prev
      return [...prev, { id: tabId, title: policyName, type: 'policy', policy }]
    })
    setActiveWafTabId(tabId)
  }

  const closeWafTab = (tabId) => {
    if (tabId === MAIN_WAF_TAB_ID) return
    setWafTabs((prev) => {
      const next = prev.filter((tab) => tab.id !== tabId)
      if (activeWafTabId === tabId) {
        const closedIndex = prev.findIndex((tab) => tab.id === tabId)
        const fallback = next[Math.max(0, closedIndex - 1)] || next[0] || { id: MAIN_WAF_TAB_ID }
        setActiveWafTabId(fallback.id)
      }
      return next
    })
  }

  const activeWafTab = wafTabs.find((tab) => tab.id === activeWafTabId) || wafTabs[0]

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
              {activeNav === 'waf' && <p className="waf-updated">Last updated: {new Date().toLocaleString()}</p>}
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
                <div className="workspace-tab-bar" role="tablist" aria-label="WAF workspace tabs">
                  {wafTabs.map((tab) => (
                    <button
                      key={tab.id}
                      type="button"
                      role="tab"
                      aria-selected={activeWafTabId === tab.id}
                      className={`workspace-tab ${activeWafTabId === tab.id ? 'active' : ''}`}
                      onClick={() => setActiveWafTabId(tab.id)}
                    >
                      <span className="workspace-tab-label">{tab.title}</span>
                      {tab.id !== MAIN_WAF_TAB_ID && (
                        <span
                          className="workspace-tab-close"
                          role="button"
                          aria-label={`Close ${tab.title}`}
                          onClick={(event) => {
                            event.stopPropagation()
                            closeWafTab(tab.id)
                          }}
                        >
                          ×
                        </span>
                      )}
                    </button>
                  ))}
                </div>

                {activeWafTab?.type === 'main' ? (
                  <>
                    <div className="waf-search-shell">
                      <div className="waf-policy-search">
                        <input
                          type="text"
                          value={wafSearch}
                          onChange={(e) => setWafSearch(e.target.value)}
                          placeholder="Search by policy name, IP, or hostname"
                          aria-label="Search WAF policies"
                        />
                      </div>
                      <div className="waf-location-card">
                        <span className="waf-location-label">Location</span>
                        <select value={selectedLocation} onChange={(e) => setSelectedLocation(e.target.value)} aria-label="Filter by location">
                          {locationOptions.map((location) => (
                            <option key={location} value={location}>{location}</option>
                          ))}
                        </select>
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
                        {wafPolicies.length === 0 ? (
                          <div className="waf-empty-state">
                            <p className="nav-desc">No devices or server policies found.</p>
                          </div>
                        ) : filteredWafPolicies.length === 0 ? (
                          <div className="waf-empty-state">
                            <p className="nav-desc">No matches found for "{wafSearch}".</p>
                          </div>
                        ) : (
                          <div className="waf-card-grid">
                            {filteredWafPolicies.map((policy, index) => {
                              const { label: policyStatusLabel, className: policyStatusClass } = getPolicyStatus(policy)
                              const policyName = typeof policy === 'string' ? policy : policy.server_policy_name
                              const policyIp = typeof policy === 'string' ? '' : policy.ip
                              const tlsV10 = typeof policy === 'string' ? null : policy.tls_v10
                              const tlsV11 = typeof policy === 'string' ? null : policy.tls_v11
                              const tlsV12 = typeof policy === 'string' ? null : policy.tls_v12
                              const tlsV13 = typeof policy === 'string' ? null : policy.tls_v13
                              const http2 = typeof policy === 'string' ? null : policy.http2
                              const trafficMirror = typeof policy === 'string' ? '' : (policy['traffic-mirror'] ?? policy.traffic_mirror ?? '')
                              const sni = typeof policy === 'string' ? '' : policy.sni
                              const allowHostsEntries = typeof policy === 'string' ? [] : (policy.allow_hosts_entries || [])
                              const hostname = allowHostsEntries[0]?.host || ''
                              const clientCertificateDetails = typeof policy === 'string' ? {} : (policy.client_certificate_details || {})
                              const certificateCn = clientCertificateDetails.cn || clientCertificateDetails.subject || '-'
                              const certificateIssuer = clientCertificateDetails.issuer || '-'
                              const certificateExpireDate = clientCertificateDetails.expire_date || clientCertificateDetails.valid_to || '-'
                              const certificateDaysLeft = clientCertificateDetails.days_left ?? '-'
                              const tlsV10V11 = [tlsV10, tlsV11].map((value) => (value === null ? '-' : String(value))).join(' / ')
                              return (
                              <article
                                className={`policy-card ${expandedPolicyCard === `${policyName}-${index}` ? 'selected' : ''}`}
                                key={`${policy._deviceName}-${policyName}-${index}`}
                                onClick={() => setExpandedPolicyCard((prev) => (prev === `${policyName}-${index}` ? '' : `${policyName}-${index}`))}
                              >
                                <div className="policy-top-row">
                                  <div>
                                    <p className="policy-label">Server Policy</p>
                                    <p className="policy-name">{policyName}</p>
                                    <div className="policy-device-row">
                                      <span className="policy-device-icon" aria-hidden="true">
                                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                                          <rect width="20" height="8" x="2" y="2" rx="2" ry="2" />
                                          <rect width="20" height="8" x="2" y="14" rx="2" ry="2" />
                                          <line x1="6" x2="6.01" y1="6" y2="6" />
                                          <line x1="6" x2="6.01" y1="18" y2="18" />
                                        </svg>
                                      </span>
                                      <span className="policy-device-label">Device</span>
                                      <strong>{policy._deviceName || '-'}</strong>
                                    </div>
                                  </div>
                                  <div className="policy-status-wrap">
                                    <span className={`policy-status-pill ${policyStatusClass}`}>{policyStatusLabel}</span>
                                    <span className={`policy-expand-icon ${expandedPolicyCard === `${policyName}-${index}` ? 'expanded' : ''}`} aria-hidden="true">
                                      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
                                        <path d="m6 9 6 6 6-6" />
                                      </svg>
                                    </span>
                                  </div>
                                </div>
                                {expandedPolicyCard === `${policyName}-${index}` && (
                                  <section className="policy-summary" aria-label="Quick configuration summary">
                                    <div className="policy-summary-head">
                                      <div>
                                        <h4>Quick configuration summary</h4>
                                        <p className="policy-summary-subtitle">Review endpoint, certificate, and network posture before opening the full page.</p>
                                      </div>
                                      <button
                                        type="button"
                                        className="policy-full-details-btn"
                                        onClick={(event) => {
                                          event.stopPropagation()
                                          if (typeof policy === 'string') return
                                          openPolicyTab(policy, index)
                                        }}
                                      >
                                        <span>Full Details</span>
                                        <svg
                                          className="policy-full-details-icon"
                                          viewBox="0 0 24 24"
                                          fill="none"
                                          xmlns="http://www.w3.org/2000/svg"
                                          aria-hidden="true"
                                        >
                                          <path d="M7 7h10v10" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
                                          <path d="M7 17 17 7" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
                                        </svg>
                                      </button>
                                    </div>
                                    <div className="policy-summary-grid">
                                      <article className="policy-summary-section">
                                        <h5>Endpoint <span aria-hidden="true">✣</span></h5>
                                        <p><span>IP</span><strong>{policyIp || '-'}</strong></p>
                                        <p><span>SNI</span><strong>{sni || '-'}</strong></p>
                                        <p><span>Hostname</span><strong>{hostname || '-'}</strong></p>
                                        <p><span>Traffic Mirror</span><strong>{trafficMirror || '-'}</strong></p>
                                      </article>
                                      <article className="policy-summary-section">
                                        <h5>Certificate <span aria-hidden="true">✣</span></h5>
                                        <p><span>CN</span><strong>{certificateCn}</strong></p>
                                        <p><span>Issuer</span><strong>{certificateIssuer}</strong></p>
                                        <p><span>Expire Date</span><strong>{certificateExpireDate}</strong></p>
                                        <p><span>Days Left</span><strong>{certificateDaysLeft}</strong></p>
                                      </article>
                                      <article className="policy-summary-section">
                                        <h5>Network <span aria-hidden="true">✣</span></h5>
                                        <p><span>TLSv1.3</span><strong>{tlsV13 === null ? '-' : String(tlsV13)}</strong></p>
                                        <p><span>TLSv1.2</span><strong>{tlsV12 === null ? '-' : String(tlsV12)}</strong></p>
                                        <p><span>TLSv1.0-1.1</span><strong>{tlsV10V11}</strong></p>
                                        <p><span>HTTP/2</span><strong>{http2 === null ? '-' : String(http2)}</strong></p>
                                      </article>
                                    </div>
                                  </section>
                                )}
                              </article>
                              )
                            })}
                          </div>
                        )}
                      </>
                    )}
                  </>
                ) : (
                  <FullDetailsPage policy={activeWafTab?.policy} />
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
                  {loadingDevices && <p className="nav-desc">Loading devices...</p>}
                  {deviceError && <p className="error-box">{deviceError}</p>}
                  {filteredDevices.map((device) => (
                    <article className="device-card" key={device.id}>
                      <div>
                        <h3 className="device-card-name">{device.name} <span className={`status-pill ${device.status.toLowerCase()}`}>{device.status}</span></h3>
                        <div className="device-card-meta">{device.ip}</div>
                        <div className="device-card-meta">{device.model} · v{device.firmware}</div>
                      </div>
                      <div><p className="device-label">Environment</p><strong>{device.environment}</strong></div>
                      <div><p className="device-label">Region</p><strong>{device.region}</strong></div>
                      <div><p className="device-label">Last Sync</p><strong>{device.last_sync}</strong></div>
                      <div className="device-actions"><button type="button" onClick={() => viewDevice(device.id)}>View</button><button type="button" className="danger" onClick={() => deleteDevice(device.id)}>Delete</button></div>
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
                        <label>APIKEY<input value={newDevice.apikey} onChange={(e) => updateNewDeviceField('apikey', e.target.value)} /></label>
                      </div>
                      <div className="device-modal-actions">
                        <button type="button" onClick={() => setAddDeviceModalOpen(false)}>Cancel</button>
                        <button type="button" className="primary" onClick={saveNewDevice}>Save Device</button>
                      </div>
                    </div>
                  </div>
                )}

                {viewedDevice && (
                  <div className="device-modal-overlay" role="dialog" aria-modal="true">
                    <div className="device-modal">
                      <div className="device-modal-head">
                        <div>
                          <h3>{viewedDevice.name}</h3>
                          <p>Device details from database record.</p>
                        </div>
                        <button type="button" className="device-modal-close" onClick={() => setViewedDevice(null)}>×</button>
                      </div>
                      <div className="device-modal-grid">
                        <label>Management IP<input value={viewedDevice.ip} readOnly /></label>
                        <label>Status<input value={viewedDevice.status} readOnly /></label>
                        <label>Environment<input value={viewedDevice.environment} readOnly /></label>
                        <label>Region<input value={viewedDevice.region} readOnly /></label>
                        <label>Model<input value={viewedDevice.model} readOnly /></label>
                        <label>Firmware<input value={viewedDevice.firmware} readOnly /></label>
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
