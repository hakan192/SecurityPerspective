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
  const [loadingWaf, setLoadingWaf] = useState(false)
  const [wafError, setWafError] = useState('')
  const [selectedWafDevice, setSelectedWafDevice] = useState('')
  const [expandedPolicyCard, setExpandedPolicyCard] = useState('')
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
  const selectedWafDeviceData = useMemo(() => {
    if (!selectedWafDevice) return wafDevices[0] || null
    return wafDevices.find((device) => device.device_name === selectedWafDevice) || null
  }, [selectedWafDevice, wafDevices])
  const selectedWafDevicePolicies = useMemo(() => {
    if (!selectedWafDeviceData) return []
    if (selectedWafDeviceData.error) {
      return [{ server_policy_name: `Error: ${selectedWafDeviceData.error}` }]
    }
    return Array.isArray(selectedWafDeviceData.server_policies) ? selectedWafDeviceData.server_policies : []
  }, [selectedWafDeviceData])
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
    if (!wafDevices.length) {
      setSelectedWafDevice('')
      setExpandedPolicyCard('')
      return
    }
    if (!selectedWafDevice || !wafDevices.some((device) => device.device_name === selectedWafDevice)) {
      setSelectedWafDevice(wafDevices[0].device_name || '')
    }
  }, [wafDevices, selectedWafDevice])

  useEffect(() => {
    setExpandedPolicyCard('')
  }, [selectedWafDevice])

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
                    <div className="waf-device-picker">
                      <label htmlFor="waf-device-select">Device</label>
                      <select id="waf-device-select" value={selectedWafDevice} onChange={(e) => setSelectedWafDevice(e.target.value)}>
                        {wafDevices.map((device) => (
                          <option key={device.device_id} value={device.device_name}>
                            {device.device_name}
                          </option>
                        ))}
                      </select>
                    </div>
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
                    {selectedWafDevicePolicies.length === 0 ? (
                      <p className="nav-desc">No devices or server policies found.</p>
                    ) : (
                      <div className="waf-card-grid">
                        {selectedWafDevicePolicies.map((policy, index) => {
                          const policyName = typeof policy === 'string' ? policy : policy.server_policy_name
                          const policyIp = typeof policy === 'string' ? '' : policy.ip
                          const tls13CustomCipher = typeof policy === 'string' ? '' : policy.tls13_custom_cipher
                          const tlsV10 = typeof policy === 'string' ? null : policy.tls_v10
                          const tlsV11 = typeof policy === 'string' ? null : policy.tls_v11
                          const tlsV12 = typeof policy === 'string' ? null : policy.tls_v12
                          const tlsV13 = typeof policy === 'string' ? null : policy.tls_v13
                          const http2 = typeof policy === 'string' ? null : policy.http2
                          const trafficMirror = typeof policy === 'string' ? '' : (policy['traffic-mirror'] ?? policy.traffic_mirror ?? '')
                          const monitorMode = typeof policy === 'string' ? '' : (policy['monitor-mode'] ?? policy.monitor_mode ?? '')
                          const sni = typeof policy === 'string' ? '' : policy.sni
                          const sniCertificate = typeof policy === 'string' ? '' : (policy['sni-certificate'] ?? policy.sni_certificate ?? '')
                          const clientCertificate = typeof policy === 'string' ? '' : (policy['client-certificate'] ?? policy.client_certificate ?? '')
                          const allowHosts = typeof policy === 'string' ? '' : policy.allow_hosts
                          const webProtectionProfileName = typeof policy === 'string' ? '' : policy.web_protection_profile_name
                          const allowHostsEntries = typeof policy === 'string' ? [] : (policy.allow_hosts_entries || [])
                          const webProtectionDetails = typeof policy === 'string' ? {} : (policy.web_protection_profile_details || {})
                          const signatureRuleName = webProtectionDetails.signature_rule || ''
                          const httpProtocolParameterRestrictionName = webProtectionDetails.http_protocol_parameter_restriction || ''
                          const cookieSecurityPolicyName = webProtectionDetails.cookie_security_policy || ''
                          const syntaxBasedAttackDetectionName = webProtectionDetails.syntax_based_attack_detection || ''
                          const customAccessPolicyName = webProtectionDetails.custom_access_policy || ''
                          const allowMethodPolicyName = webProtectionDetails.allow_method_policy || ''
                          const ipListPolicyName = webProtectionDetails.ip_list_policy || ''
                          const geoIpPolicyName = webProtectionDetails.geo_block_list_policy || ''
                          const xmlValidationPolicyName = webProtectionDetails.xml_validation_policy || ''
                          const jsonValidationPolicyName = webProtectionDetails.json_validation_policy || ''
                          const applicationLayerDosPreventionPolicy = webProtectionDetails.application_layer_dos_prevention_policy || {}
                          const applicationLayerDosPreventionName = applicationLayerDosPreventionPolicy.name || webProtectionDetails.application_layer_dos_prevention || ''
                          const layer4AccessLimitRulePolicy = applicationLayerDosPreventionPolicy.layer4_access_limit_rule_policy || {}
                          const tcpFloodPreventionPolicy = applicationLayerDosPreventionPolicy.tcp_flood_prevention_policy || {}
                          const botMitigatePolicyDetail = applicationLayerDosPreventionPolicy.bot_mitigate_policy_detail || {}
                          const botMitigatePolicyName = botMitigatePolicyDetail.name || webProtectionDetails.bot_mitigate_policy || ''
                          const biometricBasedDetectionPolicyName = botMitigatePolicyDetail.biometrics_based_detection || ''
                          const thresholdBasedDetectionPolicyName = botMitigatePolicyDetail.threshold_based_detection || ''
                          const knownBotsPolicyName = botMitigatePolicyDetail.known_bots || ''
                          return (
                          <article
                            className={`policy-card ${expandedPolicyCard === `${policyName}-${index}` ? 'selected' : ''}`}
                            key={`${selectedWafDevice}-${policyName}-${index}`}
                            onClick={() => setExpandedPolicyCard((prev) => (prev === `${policyName}-${index}` ? '' : `${policyName}-${index}`))}
                          >
                            <p className="policy-label">Server Policy Name</p>
                            <p className="policy-name">{policyName}</p>
                            <p className="policy-meta">IP: {policyIp || '-'}</p>
                            <p className="policy-meta">TLS13 Custom Cipher: {tls13CustomCipher || '-'}</p>
                            <p className="policy-meta">TLS v1.0: {tlsV10 === null ? '-' : String(tlsV10)}</p>
                            <p className="policy-meta">TLS v1.1: {tlsV11 === null ? '-' : String(tlsV11)}</p>
                            <p className="policy-meta">TLS v1.2: {tlsV12 === null ? '-' : String(tlsV12)}</p>
                            <p className="policy-meta">TLS v1.3: {tlsV13 === null ? '-' : String(tlsV13)}</p>
                            <p className="policy-meta">HTTP2: {http2 === null ? '-' : String(http2)}</p>
                            <p className="policy-meta">Traffic Mirror: {trafficMirror || '-'}</p>
                            <p className="policy-meta">Monitor Mode: {monitorMode || '-'}</p>
                            <p className="policy-meta">SNI: {sni || '-'}</p>
                            <p className="policy-meta">SNI Certificate: {sniCertificate || '-'}</p>
                            <p className="policy-meta">Client Certificate: {clientCertificate || '-'}</p>
                            <p className="policy-meta">Web Protection Profile: {webProtectionProfileName || '-'}</p>
                            <p className="policy-meta">Custom Access Policy: {customAccessPolicyName || '-'}</p>
                            <p className="policy-meta">Allow Method Policy: {allowMethodPolicyName || '-'}</p>
                            <p className="policy-meta">IP List Policy: {ipListPolicyName || '-'}</p>
                            <p className="policy-meta">Geo-IP Policy: {geoIpPolicyName || '-'}</p>
                            <p className="policy-meta">XML Validation Policy: {xmlValidationPolicyName || '-'}</p>
                            <p className="policy-meta">JSON Validation Policy: {jsonValidationPolicyName || '-'}</p>
                            <p className="policy-meta">Bot Mitigate Policy: {botMitigatePolicyName || '-'}</p>
                            <p className="policy-meta">Known Bot Policy: {knownBotsPolicyName || '-'}</p>
                            <p className="policy-meta">Biometric Based Detection Policy: {biometricBasedDetectionPolicyName || '-'}</p>
                            <p className="policy-meta">Threshold Based Detection Policy: {thresholdBasedDetectionPolicyName || '-'}</p>
                            <p className="policy-meta">Application Layer DoS Prevention Policy: {applicationLayerDosPreventionName || '-'}</p>
                            <p className="policy-meta">HTTP Request Flood Prevention Rule: {applicationLayerDosPreventionPolicy.http_request_flood_prevention_rule || '-'}</p>
                            <p className="policy-meta">Access Limit in HTTP Session: {applicationLayerDosPreventionPolicy.access_limit_in_http_session || '-'}</p>
                            <p className="policy-meta">HTTP Request Flood Action: {applicationLayerDosPreventionPolicy.action || '-'}</p>
                            <p className="policy-meta">Bot Confirmation: {applicationLayerDosPreventionPolicy.bot_confirmation || '-'}</p>
                            <p className="policy-meta">Bot Recognition: {applicationLayerDosPreventionPolicy.bot_recognition || '-'}</p>
                            <p className="policy-meta">Enable Layer4 DoS Prevention: {applicationLayerDosPreventionPolicy.enable_layer4_dos_prevention || '-'}</p>
                            <p className="policy-meta">Layer4 Access Limit Rule: {applicationLayerDosPreventionPolicy.layer4_access_limit_rule || '-'}</p>
                            <p className="policy-meta">Layer4 Access Limit Standalone IP: {layer4AccessLimitRulePolicy.access_limit_standalone_ip || '-'}</p>
                            <p className="policy-meta">Layer4 Access Limit Share IP: {layer4AccessLimitRulePolicy.access_limit_share_ip || '-'}</p>
                            <p className="policy-meta">Layer4 Access Limit Bot Confirmation: {layer4AccessLimitRulePolicy.bot_confirmation || '-'}</p>
                            <p className="policy-meta">Layer4 Access Limit Bot Recognition: {layer4AccessLimitRulePolicy.bot_recognition || '-'}</p>
                            <p className="policy-meta">Layer4 Access Limit Action: {layer4AccessLimitRulePolicy.action || '-'}</p>
                            <p className="policy-meta">Layer4 Connection Flood Check Rule: {applicationLayerDosPreventionPolicy.layer4_connection_flood_check_rule || '-'}</p>
                            <p className="policy-meta">TCP Flood Prevention Threshold: {tcpFloodPreventionPolicy.layer4_connection_threshold || '-'}</p>
                            <p className="policy-meta">TCP Flood Prevention Action: {tcpFloodPreventionPolicy.action || '-'}</p>
                            <p className="policy-meta">Syntax Based Attack Detection: {syntaxBasedAttackDetectionName || '-'}</p>
                            <p className="policy-meta">Cookie Security Policy: {cookieSecurityPolicyName || '-'}</p>
                            <p className="policy-meta">HTTP Protocol Parameter Restriction: {httpProtocolParameterRestrictionName || '-'}</p>
                            <p className="policy-meta">Signature Rule: {signatureRuleName || '-'}</p>
                            <p className="policy-meta">Allow Hosts: {allowHosts || '-'}</p>
                            {allowHostsEntries.length > 0 && (
                              <ul className="policy-host-list policy-meta">
                                {allowHostsEntries.map((entry, hostIndex) => (
                                  <li key={`${selectedWafDevice}-${policyName}-${index}-host-${hostIndex}`}>{entry.host || '-'}</li>
                                ))}
                              </ul>
                            )}
                          </article>
                          )
                        })}
                      </div>
                    )}
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
