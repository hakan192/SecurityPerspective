import { useEffect, useId, useMemo, useRef, useState } from 'react'
import { AnimatePresence, motion } from 'framer-motion'
import './App.css'

const resolvedHost = window.location.hostname || 'localhost'
const configuredApiBase = import.meta.env.VITE_API_BASE_URL
const API_BASE =
  configuredApiBase && configuredApiBase.includes('localhost') && !['localhost', '127.0.0.1'].includes(resolvedHost)
    ? configuredApiBase.replace('localhost', resolvedHost)
    : configuredApiBase || `http://${resolvedHost}:8000`

const SERVER_POLICY_ENDPOINT = '/fortiweb/server-policy/latest'

const getCertificateCommonName = (subject) => {
  if (!subject) return ''
  const match = String(subject).trim().match(/(?:^|[,/]\s*)\s*CN\s*=\s*((?:\\.|[^,/])*)/i)
  return match ? match[1].replace(/\\(.)/g, '$1').trim() : ''
}

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
const MAIN_AUTOMATION_TAB_ID = 'automation-main-tab'

const automationCards = [
  {
    id: 'server-policy-disable',
    title: 'Server Policy Disable',
    definition: 'Disables configured server policy enforcement and bypasses the policy chain for matching traffic.',
    objective: 'Temporarily disable a selected server policy while preserving the current rule set for rollback.',
    fields: [
      { label: 'Target policy', value: 'Select FortiWeb server policy' },
      { label: 'Execution mode', value: 'Approval required' },
      { label: 'Rollback timer', value: '30 minutes' },
      { label: 'Change record', value: 'Required before execution' }
    ],
    steps: [
      'Validate the target policy and attached protected host.',
      'Capture the current enabled state for audit and rollback.',
      'Disable policy enforcement only after approval is recorded.',
      'Schedule an automatic verification and rollback check.'
    ]
  },
  {
    id: 'recaptcha-disable',
    title: 'Recaptcha Disable',
    definition: 'Turns off CAPTCHA challenge checks, allowing requests to pass without Recaptcha validation.',
    objective: 'Disable Recaptcha challenge enforcement for a controlled exception window.',
    fields: [
      { label: 'Protected host', value: 'Select host or application' },
      { label: 'Exception scope', value: 'Bot mitigation profile' },
      { label: 'Expiration window', value: '15 minutes' },
      { label: 'Notification channel', value: 'Security operations' }
    ],
    steps: [
      'Confirm the protected host and active bot mitigation profile.',
      'Record the exception reason and required expiration time.',
      'Disable Recaptcha checks for the scoped profile only.',
      'Notify operations and restore enforcement when the window ends.'
    ]
  }
]


const executiveMaturityCards = [
  {
    id: 'overall',
    title: 'Overall WAF Maturity Level',
    location: 'Enterprise aggregate',
    score: 90,
    series: [84, 87, 90],
    level: 'Optimized',
    tone: 'strong',
    summary: 'Protection is consistently enforced across core application tiers with mature policy coverage and response-ready controls.',
    trend: { direction: 'improved', value: '+6 pts', label: 'Improved this quarter' },
    signals: ['Policy coverage 91%', 'Attack signatures current', 'Bot controls aligned']
  },
  {
    id: 'pendik',
    title: 'Pendik WAF Maturity Level',
    location: 'Pendik data center',
    score: 90,
    series: [90, 90, 90],
    level: 'Optimized',
    tone: 'steady',
    summary: 'Pendik sustains a high-confidence blocking posture with stable controls and disciplined exception hygiene.',
    trend: { direction: 'stable', value: '0 pts', label: 'No maturity change' },
    signals: ['Blocking mode enabled', 'Exception review current', 'Certificate posture healthy']
  },
  {
    id: 'ankara',
    title: 'Ankara WAF Maturity Level',
    location: 'Ankara data center',
    score: 90,
    series: [92, 91, 90],
    level: 'Optimized',
    tone: 'strong',
    summary: 'Ankara maintains enterprise-grade coverage while final planned services move through monitoring-to-blocking readiness.',
    trend: { direction: 'decreased', value: '-2 pts', label: 'Normalized this quarter' },
    signals: ['Blocking migration active', 'Profiles normalized', 'High-priority apps covered']
  }
]

const timelineStatusOptions = ['Planned', 'In progress', 'Pending review', 'Moved to Blocking', 'Completed']

const executiveTimelineItems = [
  {
    id: 'timeline-1',
    date: '2026-05-15',
    domain: 'test1.garantibbva.com.tr',
    action: 'Move from Monitoring to Blocking',
    owner: 'WAF Operations',
    status: 'Planned'
  },
  {
    id: 'timeline-2',
    date: '2026-05-20',
    domain: 'integration.garanti.com.tr',
    action: 'Configure domain on WAF',
    owner: 'Security Engineering',
    status: 'In progress'
  },
  {
    id: 'timeline-3',
    date: '2026-05-27',
    domain: 'test3.garanti.com.tr',
    action: 'Complete missing WAF policy configuration',
    owner: 'Application Team',
    status: 'Pending review'
  }
]

const formatRecentChangeTime = (value) => {
  if (!value || value === '-') return '-'
  if (/^\d{2}\/\d{2}$/.test(value)) return value

  const parsed = new Date(value)
  if (Number.isNaN(parsed.getTime())) return value

  return `${String(parsed.getUTCDate()).padStart(2, '0')}/${String(parsed.getUTCMonth() + 1).padStart(2, '0')}`
}

function ShieldCheckIcon({ className = '', size = 14 }) {
  return (
    <svg className={className} width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M20 13c0 5-3.5 7.5-8 9-4.5-1.5-8-4-8-9V6l8-3 8 3z" />
      <path d="m9 12 2 2 4-4" />
    </svg>
  )
}

function ShieldAlertIcon({ className = '', size = 14 }) {
  return (
    <svg className={className} width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M20 13c0 5-3.5 7.5-8 9-4.5-1.5-8-4-8-9V6l8-3 8 3z" />
      <path d="M12 8v4" />
      <path d="M12 16h.01" />
    </svg>
  )
}

function ShieldXIcon({ className = '', size = 14 }) {
  return (
    <svg className={className} width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M20 13c0 5-3.5 7.5-8 9-4.5-1.5-8-4-8-9V6l8-3 8 3z" />
      <path d="m9 9 6 6" />
      <path d="m15 9-6 6" />
    </svg>
  )
}

function DeviceStackIcon({ className = '', size = 14 }) {
  return (
    <svg className={className} width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <rect width="20" height="8" x="2" y="3" rx="2" />
      <rect width="20" height="8" x="2" y="13" rx="2" />
      <path d="M6 7h.01" />
      <path d="M6 17h.01" />
    </svg>
  )
}

function InfoCircleIcon({ className = '', size = 14 }) {
  return (
    <svg className={className} width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <circle cx="12" cy="12" r="10" />
      <line x1="12" y1="10" x2="12" y2="16" />
      <circle cx="12" cy="7" r="1" fill="currentColor" stroke="none" />
    </svg>
  )
}

function getPolicyStatusVisual(status) {
  const normalized = String(status ?? '').trim().toLowerCase()
  if (normalized === 'blocking') {
    return { Icon: ShieldCheckIcon, toneClass: 'blocking' }
  }
  if (normalized === 'monitoring') {
    return { Icon: ShieldAlertIcon, toneClass: 'monitoring' }
  }
  return { Icon: ShieldXIcon, toneClass: 'not-protected' }
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

function FullDetailsPage({ policy }) {
  if (!policy) return null

  const [customAccessExpanded, setCustomAccessExpanded] = useState(false)
  const [httpFloodExpanded, setHttpFloodExpanded] = useState(false)
  const [httpAccessLimitExpanded, setHttpAccessLimitExpanded] = useState(false)
  const [tcpFloodExpanded, setTcpFloodExpanded] = useState(false)
  const [allowMethodExpanded, setAllowMethodExpanded] = useState(false)
  const [ipListExpanded, setIpListExpanded] = useState(false)
  const [geoLocationExpanded, setGeoLocationExpanded] = useState(false)
  const [biometricDetectionExpanded, setBiometricDetectionExpanded] = useState(false)
  const [thresholdDetectionExpanded, setThresholdDetectionExpanded] = useState(false)
  const [knownBotExpanded, setKnownBotExpanded] = useState(false)

  const parseCustomAccessRule = (rule) => {
    if (!rule || typeof rule !== 'object') return null
    const rawPayload = rule.raw_json_custom_rule
    let parsedRawPayload = rawPayload
    if (typeof rawPayload === 'string') {
      try {
        parsedRawPayload = JSON.parse(rawPayload)
      } catch {
        parsedRawPayload = {}
      }
    }
    if (!parsedRawPayload || typeof parsedRawPayload !== 'object') {
      parsedRawPayload = {}
    }
    const rawResult =
      parsedRawPayload?.results?.[0] ??
      parsedRawPayload?.result?.[0] ??
      parsedRawPayload?.results ??
      parsedRawPayload?.result ??
      {}
    return {
      name: rule.name || '-',
      action: rule.action || rawResult.action || '-',
      botConfirmation: rule.bot_confirmation || rawResult['bot-confirmation'] || rawResult.bot_confirmation || '-',
      botRecognition: rule.bot_recognition || rawResult['bot-recognition'] || rawResult.bot_recognition || '-',
      rawJsonCustomRule: parsedRawPayload,
      rawJsonCustomRuleText: JSON.stringify(parsedRawPayload, null, 2)
    }
  }

  const policyIp = (policy.ip || '').trim()
  const monitorMode = String(policy['monitor-mode'] ?? policy.monitor_mode ?? '').toLowerCase()
  const deviceName = policy._deviceName || policy.device_name || policy.deviceName || 'Unknown Device'
  const policyStatus = !policyIp ? 'Not Protected' : monitorMode === 'enable' ? 'Monitoring' : 'Blocking'
  const policyStatusClass = policyStatus.toLowerCase().replace(/\s+/g, '-')

  const normalizeFeatureStatus = (value) => {
    const normalized = String(value ?? '').trim().toLowerCase()
    if (['true', '1', 'yes', 'on', 'enable', 'enabled'].includes(normalized)) return 'Enabled'
    if (['false', '0', 'no', 'off', 'disable', 'disabled'].includes(normalized)) return 'Disabled'
    return 'Unknown'
  }
  const normalizePresenceStatus = (value) =>
    String(value ?? '').trim() ? 'Enabled' : 'Unknown'

  const { Icon: PolicyStatusIcon, toneClass: policyStatusTone } = getPolicyStatusVisual(policyStatus)
  const syntaxBasedDetectionStatusFields = [
    'xss_html_tag_based_status',
    'xss_html_attribute_based_status',
    'xss_javascript_function_based_status',
    'xss_javascript_variable_based_status',
    'sql_stacked_queries_status',
    'sql_embeded_queries_status',
    'sql_condition_based_status',
    'sql_arithmetic_operation_status',
    'sql_line_comments_status',
    'sql_function_based_status'
  ]

  const syntaxBasedDetectionDetails =
    policy.syntax_based_attack_detection_details ??
    policy.web_protection_profile_details?.syntax_based_attack_detection_details ??
    {}

  const syntaxEnabledCount = syntaxBasedDetectionStatusFields.reduce((enabledCount, fieldName) => {
    const normalizedValue = String(syntaxBasedDetectionDetails[fieldName] ?? '').trim().toLowerCase()
    return enabledCount + (['enable', 'enabled', 'on', 'true', '1', 'yes'].includes(normalizedValue) ? 1 : 0)
  }, 0)
  const syntaxBasedDetectionStatus = syntaxEnabledCount >= 2 ? 'Enabled' : 'Disabled'
  const customAccessRules = (
    policy.custom_access_rules ??
    policy.web_protection_profile_details?.custom_access_rules ??
    []
  )
    .map(parseCustomAccessRule)
    .filter(Boolean)
  const customAccessRuleStatus = customAccessRules.length > 0 ? 'Enabled' : 'Unknown'
  const applicationLayerDosPolicy =
    policy.application_layer_dos_prevention_policy ??
    policy.web_protection_profile_details?.application_layer_dos_prevention_policy ??
    {}
  const layer4AccessLimitRulePolicy =
    applicationLayerDosPolicy.layer4_access_limit_rule_policy ??
    applicationLayerDosPolicy['/layer4-access-limit-rule'] ??
    applicationLayerDosPolicy['layer4-access-limit-rule'] ??
    {}
  const layer4ConnectionFloodCheckRulePolicy =
    applicationLayerDosPolicy.tcp_flood_prevention_policy ??
    applicationLayerDosPolicy.layer4_connection_flood_check_rule_policy ??
    applicationLayerDosPolicy['/layer4-connection-flood-check-rule'] ??
    applicationLayerDosPolicy['layer4-connection-flood-check-rule'] ??
    {}

  const standardProtectionFeatures = [
    {
      name: 'Signature',
      status: normalizeFeatureStatus(
        policy.signature ??
          policy.web_protection_profile_details?.signature_set_status ??
          policy.signature_protection ??
          policy['signature-protection']
      )
    },
    {
      name: 'HTTP RFC',
      status: normalizeFeatureStatus(
        policy.http_rfc ??
          policy.web_protection_profile_details?.http_protocol_parameter_restriction ??
          policy.httpRfc ??
          policy['http-rfc']
      )
    },
    {
      name: 'HTTP/2 RFC control',
      status: normalizeFeatureStatus(
        policy.http2_rfc_control ??
          policy.http2RfcControl ??
          policy['http2-rfc-control']
      )
    }
  ]


  const advancedProtectionFeatures = [
    {
      name: 'Syntax Based Detection',
      status: syntaxBasedDetectionStatus
    },
    {
      name: 'Custom Access Rules',
      status: customAccessRuleStatus,
      customAccessRules
    }
  ]
  const applicationDosProtectionFeatures = [
    {
      name: 'HTTP Flood Prevention',
      status: normalizePresenceStatus(
        applicationLayerDosPolicy.http_request_flood_prevention_rule ??
          policy.http_flood_prevention ??
          policy.web_protection_profile_details?.http_flood_prevention ??
          policy['http-flood-prevention']
      ),
      details: {
        accessLimitInHttpSession: applicationLayerDosPolicy.access_limit_in_http_session ?? '-',
        action: applicationLayerDosPolicy.action ?? '-',
        botConfirmation: applicationLayerDosPolicy.bot_confirmation ?? '-',
        botRecognition: applicationLayerDosPolicy.bot_recognition ?? '-'
      }
    },
    {
      name: 'HTTP Access Limit',
      status: normalizePresenceStatus(
        applicationLayerDosPolicy.layer4_access_limit_rule ??
          policy.http_access_limit ??
          policy.web_protection_profile_details?.http_access_limit ??
          policy['http-access-limit']
      ),
      details: {
        accessLimitStandaloneIp:
          layer4AccessLimitRulePolicy.access_limit_standalone_ip ??
          layer4AccessLimitRulePolicy['access-limit-standalone-ip'] ??
          applicationLayerDosPolicy.access_limit_standalone_ip ??
          applicationLayerDosPolicy['access-limit-standalone-ip'] ??
          '-',
        accessLimitShareIp:
          layer4AccessLimitRulePolicy.access_limit_share_ip ??
          layer4AccessLimitRulePolicy['access-limit-share-ip'] ??
          applicationLayerDosPolicy.access_limit_share_ip ??
          applicationLayerDosPolicy['access-limit-share-ip'] ??
          '-',
        action:
          layer4AccessLimitRulePolicy.action ??
          applicationLayerDosPolicy.layer4_access_limit_action ??
          applicationLayerDosPolicy.action ??
          '-',
        botConfirmation:
          layer4AccessLimitRulePolicy.bot_confirmation ??
          applicationLayerDosPolicy.layer4_access_limit_bot_confirmation ??
          applicationLayerDosPolicy.bot_confirmation ??
          '-',
        botRecognition:
          layer4AccessLimitRulePolicy.bot_recognition ??
          applicationLayerDosPolicy.layer4_access_limit_bot_recognition ??
          applicationLayerDosPolicy.bot_recognition ??
          '-'
      }
    },
    {
      name: 'TCP Flood Prevention',
      status: normalizePresenceStatus(
        applicationLayerDosPolicy.layer4_connection_flood_check_rule ??
          policy.tcp_flood_prevention ??
          policy.web_protection_profile_details?.tcp_flood_prevention ??
          policy['tcp-flood-prevention']
      ),
      details: {
        layer4ConnectionThreshold:
          layer4ConnectionFloodCheckRulePolicy.layer4_connection_threshold ??
          layer4ConnectionFloodCheckRulePolicy['layer4-connection-threshold'] ??
          applicationLayerDosPolicy.layer4_connection_threshold ??
          applicationLayerDosPolicy['layer4-connection-threshold'] ??
          '-',
        action:
          layer4ConnectionFloodCheckRulePolicy.action ??
          applicationLayerDosPolicy.layer4_connection_flood_check_action ??
          '-'
      }
    }
  ]
  const biometricBasedDetectionDetails =
    policy.web_protection_profile_details?.application_layer_dos_prevention_policy?.bot_mitigate_policy_detail?.biometric_based_detection_details ??
    policy.web_protection_profile_details?.bot_mitigate_policy_detail?.biometric_based_detection_details ??
    policy.web_protection_profile_details?.biometric_based_detection_details ??
    policy.bot_mitigate_policy_detail?.biometric_based_detection_details ??
    policy.biometric_based_detection_details ??
    {}
  const resolveBiometricDetail = (...values) => {
    const resolved = values.find((value) => value !== null && value !== undefined && String(value).trim() !== '')
    return resolved ?? '-'
  }
  const biometricDetails = {
    action: resolveBiometricDetail(
      biometricBasedDetectionDetails.action,
      biometricBasedDetectionDetails['action']
    ),
    host: resolveBiometricDetail(
      biometricBasedDetectionDetails.host,
      biometricBasedDetectionDetails['host']
    ),
    mouseMovement: resolveBiometricDetail(
      biometricBasedDetectionDetails.mouse_movement,
      biometricBasedDetectionDetails['mouse-movement'],
      biometricBasedDetectionDetails.mouseMovement
    ),
    pageFocus: resolveBiometricDetail(
      biometricBasedDetectionDetails.page_focus,
      biometricBasedDetectionDetails['page-focus'],
      biometricBasedDetectionDetails.pageFocus
    ),
    keyboard: resolveBiometricDetail(
      biometricBasedDetectionDetails.keyboard
    ),
    screenTouch: resolveBiometricDetail(
      biometricBasedDetectionDetails.screen_touch,
      biometricBasedDetectionDetails['screen-touch'],
      biometricBasedDetectionDetails.screenTouch
    ),
    scroll: resolveBiometricDetail(
      biometricBasedDetectionDetails.scroll
    ),
    botTraits: resolveBiometricDetail(
      biometricBasedDetectionDetails.bot_traits,
      biometricBasedDetectionDetails['bot-traits'],
      biometricBasedDetectionDetails.botTraits
    ),
    botTraitsNum: resolveBiometricDetail(
      biometricBasedDetectionDetails.bot_traits_num,
      biometricBasedDetectionDetails['bot-traits-num'],
      biometricBasedDetectionDetails.botTraitsNum
    )
  }
  const biometricHasValues = Object.values(biometricDetails).some((value) => value !== '-')
  const thresholdBasedDetectionDetails =
    policy.web_protection_profile_details?.application_layer_dos_prevention_policy?.bot_mitigate_policy_detail?.threshold_based_detection_details ??
    policy.web_protection_profile_details?.bot_mitigate_policy_detail?.threshold_based_detection_details ??
    policy.web_protection_profile_details?.threshold_based_detection_details ??
    policy.bot_mitigate_policy_detail?.threshold_based_detection_details ??
    policy.threshold_based_detection_details ??
    {}
  const thresholdDetails = {
    botConfirmation: resolveBiometricDetail(
      thresholdBasedDetectionDetails.bot_confirmation,
      thresholdBasedDetectionDetails['bot-confirmation'],
      thresholdBasedDetectionDetails.botConfirmation
    ),
    botRecognition: resolveBiometricDetail(
      thresholdBasedDetectionDetails.bot_recognition,
      thresholdBasedDetectionDetails['bot-recognition'],
      thresholdBasedDetectionDetails.botRecognition
    ),
    crawlerDetection: resolveBiometricDetail(
      thresholdBasedDetectionDetails.crawler_detection,
      thresholdBasedDetectionDetails['crawler-detection'],
      thresholdBasedDetectionDetails.crawlerDetection
    ),
    crawlerAction: resolveBiometricDetail(
      thresholdBasedDetectionDetails.crawler_action,
      thresholdBasedDetectionDetails['crawler-action'],
      thresholdBasedDetectionDetails.crawlerAction
    ),
    crawlerOccurrenceNum: resolveBiometricDetail(
      thresholdBasedDetectionDetails.crawler_occurrence_num,
      thresholdBasedDetectionDetails['crawler-occurrence-num'],
      thresholdBasedDetectionDetails.crawlerOccurrenceNum
    ),
    crawlerWithin: resolveBiometricDetail(
      thresholdBasedDetectionDetails.crawler_within,
      thresholdBasedDetectionDetails['crawler-within'],
      thresholdBasedDetectionDetails.crawlerWithin
    ),
    slowAttackDetection: resolveBiometricDetail(
      thresholdBasedDetectionDetails.slow_attack_detection,
      thresholdBasedDetectionDetails['slow-attack-detection'],
      thresholdBasedDetectionDetails.slowAttackDetection
    ),
    slowAttackAction: resolveBiometricDetail(
      thresholdBasedDetectionDetails.slow_attack_action,
      thresholdBasedDetectionDetails['slow-attack-action'],
      thresholdBasedDetectionDetails.slowAttackAction
    ),
    slowAttackOccurrenceNum: resolveBiometricDetail(
      thresholdBasedDetectionDetails.slow_attack_occurrence_num,
      thresholdBasedDetectionDetails['slow-attack-occurrence-num'],
      thresholdBasedDetectionDetails.slowAttackOccurrenceNum
    ),
    slowAttackWithin: resolveBiometricDetail(
      thresholdBasedDetectionDetails.slow_attack_within,
      thresholdBasedDetectionDetails['slow-attack-within'],
      thresholdBasedDetectionDetails.slowAttackWithin
    )
  }
  const thresholdHasValues = Object.values(thresholdDetails).some((value) => value !== '-')
  const knownBotsDetailsPayload =
    policy.web_protection_profile_details?.application_layer_dos_prevention_policy?.bot_mitigate_policy_detail?.known_bots_details ??
    policy.web_protection_profile_details?.bot_mitigate_policy_detail?.known_bots_details ??
    policy.web_protection_profile_details?.known_bots_details ??
    policy.bot_mitigate_policy_detail?.known_bots_details ??
    policy.known_bots_details ??
    {}
  const knownBotsDetails = {
    dos: resolveBiometricDetail(
      knownBotsDetailsPayload.dos_status,
      knownBotsDetailsPayload['dos-status'],
      knownBotsDetailsPayload.dos
    ),
    dosAction: resolveBiometricDetail(
      knownBotsDetailsPayload.dos_action,
      knownBotsDetailsPayload['dos-action'],
      knownBotsDetailsPayload.dosAction
    ),
    spam: resolveBiometricDetail(
      knownBotsDetailsPayload.spam_status,
      knownBotsDetailsPayload['spam-status'],
      knownBotsDetailsPayload.spam
    ),
    spamAction: resolveBiometricDetail(
      knownBotsDetailsPayload.spam_action,
      knownBotsDetailsPayload['spam-action'],
      knownBotsDetailsPayload.spamAction
    ),
    trojan: resolveBiometricDetail(
      knownBotsDetailsPayload.trojan_status,
      knownBotsDetailsPayload['trojan-status'],
      knownBotsDetailsPayload.trojan
    ),
    trojanAction: resolveBiometricDetail(
      knownBotsDetailsPayload.trojan_action,
      knownBotsDetailsPayload['trojan-action'],
      knownBotsDetailsPayload.trojanAction
    ),
    scanner: resolveBiometricDetail(
      knownBotsDetailsPayload.scanner_status,
      knownBotsDetailsPayload['scanner-status'],
      knownBotsDetailsPayload.scanner
    ),
    scannerAction: resolveBiometricDetail(
      knownBotsDetailsPayload.scanner_action,
      knownBotsDetailsPayload['scanner-action'],
      knownBotsDetailsPayload.scannerAction
    ),
    crawler: resolveBiometricDetail(
      knownBotsDetailsPayload.crawler_status,
      knownBotsDetailsPayload['crawler-status'],
      knownBotsDetailsPayload.crawler
    ),
    crawlerAction: resolveBiometricDetail(
      knownBotsDetailsPayload.crawler_action,
      knownBotsDetailsPayload['crawler-action'],
      knownBotsDetailsPayload.crawlerAction
    ),
    knownEngines: resolveBiometricDetail(
      knownBotsDetailsPayload.known_engines_status,
      knownBotsDetailsPayload['known-engines-status'],
      knownBotsDetailsPayload.knownEngines
    ),
    knownEnginesAction: resolveBiometricDetail(
      knownBotsDetailsPayload.known_engines_action,
      knownBotsDetailsPayload['known-engines-action'],
      knownBotsDetailsPayload.knownEnginesAction
    )
  }
  const isEnabledValue = (value) =>
    ['true', '1', 'yes', 'on', 'enable', 'enabled'].includes(String(value ?? '').trim().toLowerCase())
  const knownBotsHasEnabledControl = [
    knownBotsDetails.dos,
    knownBotsDetails.spam,
    knownBotsDetails.trojan,
    knownBotsDetails.scanner,
    knownBotsDetails.crawler,
    knownBotsDetails.knownEngines
  ].some(isEnabledValue)
  const botMitigationFeatures = [
    {
      name: 'Biometric Based Detection',
      status: biometricHasValues ? 'Enabled' : 'Unknown',
      details: biometricDetails
    },
    {
      name: 'Threshold Based Detection',
      status: thresholdHasValues ? 'Enabled' : 'Unknown',
      details: thresholdDetails
    },
    {
      name: 'Known-Bot',
      status: knownBotsHasEnabledControl ? 'Enabled' : 'Unknown',
      details: knownBotsDetails
    }
  ]
  const accessFeatures = [
    {
      name: 'Allow method',
      status: normalizePresenceStatus(
        policy.allow_method ??
          policy.allow_method_display ??
          policy.allowMethod ??
          policy['allow-method'] ??
          policy.web_protection_profile_details?.allow_method ??
          policy.web_protection_profile_details?.allow_method_display ??
          policy.web_protection_profile_details?.allowMethod ??
          policy.web_protection_profile_details?.['allow-method']
      ),
      details: {
        method:
          policy.allow_method ??
          policy.allow_method_display ??
          policy.allowMethod ??
          policy['allow-method'] ??
          (Array.isArray(policy.allow_method_list) ? policy.allow_method_list.join(', ') : null) ??
          policy.web_protection_profile_details?.allow_method ??
          policy.web_protection_profile_details?.allow_method_display ??
          (Array.isArray(policy.web_protection_profile_details?.allow_method_list)
            ? policy.web_protection_profile_details.allow_method_list.join(', ')
            : null) ??
          policy.web_protection_profile_details?.allowMethod ??
          policy.web_protection_profile_details?.['allow-method'] ??
          '-'
      }
    }
  ]
  const ipListPolicyEntries = (
    policy.ip_list_policy_entries ??
    policy.web_protection_profile_details?.ip_list_policy_entries ??
    []
  ).filter((entry) => entry && typeof entry === 'object')
  const geoIpEntries = (
    policy.geo_ip_entries ??
    policy.web_protection_profile_details?.geo_ip_entries ??
    []
  ).filter((entry) => entry && typeof entry === 'object')
  const ipProtectionFeatures = [
    {
      name: 'IP List',
      status: normalizePresenceStatus(
        ipListPolicyEntries.length > 0
          ? 'enabled'
          :
        policy.ip_list ??
          policy.ipList ??
          policy['ip-list'] ??
          policy.web_protection_profile_details?.ip_list ??
          policy.web_protection_profile_details?.ipList ??
          policy.web_protection_profile_details?.['ip-list']
      ),
      details: {
        type:
          policy.ip_list_type ??
          policy.ipListType ??
          policy['ip-list-type'] ??
          policy.web_protection_profile_details?.ip_list_type ??
          policy.web_protection_profile_details?.ipListType ??
          policy.web_protection_profile_details?.['ip-list-type'] ??
          '-',
        groupType:
          policy.ip_list_group_type ??
          policy.ipListGroupType ??
          policy['ip-list-group-type'] ??
          policy.web_protection_profile_details?.ip_list_group_type ??
          policy.web_protection_profile_details?.ipListGroupType ??
          policy.web_protection_profile_details?.['ip-list-group-type'] ??
          '-',
        ip:
          policy.ip_list ??
          policy.ipList ??
          policy['ip-list'] ??
          (Array.isArray(policy.ip_list_entries) ? policy.ip_list_entries.join(', ') : null) ??
          policy.web_protection_profile_details?.ip_list ??
          policy.web_protection_profile_details?.ipList ??
          (Array.isArray(policy.web_protection_profile_details?.ip_list_entries)
            ? policy.web_protection_profile_details.ip_list_entries.join(', ')
            : null) ??
          policy.web_protection_profile_details?.['ip-list'] ??
          '-',
        ipGroup:
          policy.ip_group ??
          policy.ipGroup ??
          policy['ip-group'] ??
          (Array.isArray(policy.ip_group_list) ? policy.ip_group_list.join(', ') : null) ??
          policy.web_protection_profile_details?.ip_group ??
          policy.web_protection_profile_details?.ipGroup ??
          (Array.isArray(policy.web_protection_profile_details?.ip_group_list)
            ? policy.web_protection_profile_details.ip_group_list.join(', ')
            : null) ??
          policy.web_protection_profile_details?.['ip-group'] ??
          '-',
        ipExternal:
          policy.ip_external ??
          policy.ipExternal ??
          policy['ip-external'] ??
          (Array.isArray(policy.ip_external_list) ? policy.ip_external_list.join(', ') : null) ??
          policy.web_protection_profile_details?.ip_external ??
          policy.web_protection_profile_details?.ipExternal ??
          (Array.isArray(policy.web_protection_profile_details?.ip_external_list)
            ? policy.web_protection_profile_details.ip_external_list.join(', ')
            : null) ??
          policy.web_protection_profile_details?.['ip-external'] ??
          '-',
        entries: ipListPolicyEntries.map((entry) => ({
          type: entry.type || '-',
          groupType: entry.group_type || entry.groupType || '-',
          ip: entry.ip || '-',
          ipGroup: entry.ip_group || entry.ipGroup || '-',
          ipExternal: entry.ip_external || entry.ipExternal || '-'
        }))
      }
    },
    {
      name: 'Geo Location',
      status: normalizePresenceStatus(
        geoIpEntries.length > 0
          ? 'enabled'
          :
        policy.geo_location ??
          policy.geoLocation ??
          policy['geo-location'] ??
          policy.web_protection_profile_details?.geo_location ??
          policy.web_protection_profile_details?.geoLocation ??
          policy.web_protection_profile_details?.['geo-location']
      ),
      details: {
        action:
          policy.geo_location_action ??
          policy.geoLocationAction ??
          policy['geo-location-action'] ??
          policy.web_protection_profile_details?.geo_location_action ??
          policy.web_protection_profile_details?.geoLocationAction ??
          policy.web_protection_profile_details?.['geo-location-action'] ??
          '-',
        countryName:
          policy.geo_location ??
          policy.geoLocation ??
          policy['geo-location'] ??
          (Array.isArray(policy.geo_location_list) ? policy.geo_location_list.join(', ') : null) ??
          policy.web_protection_profile_details?.geo_location ??
          policy.web_protection_profile_details?.geoLocation ??
          (Array.isArray(policy.web_protection_profile_details?.geo_location_list)
            ? policy.web_protection_profile_details.geo_location_list.join(', ')
            : null) ??
          policy.web_protection_profile_details?.['geo-location'] ??
          '-',
        blockPeriod:
          policy.geo_location_block_period ??
          policy.geoLocationBlockPeriod ??
          policy['geo-location-block-period'] ??
          policy.web_protection_profile_details?.geo_location_block_period ??
          policy.web_protection_profile_details?.geoLocationBlockPeriod ??
          policy.web_protection_profile_details?.['geo-location-block-period'] ??
          '-',
        entries: geoIpEntries.map((entry) => ({
          action: entry.action || '-',
          blockPeriod: entry.block_period || entry.blockPeriod || '-',
          countryName: entry.country_name || entry.countryName || '-'
        }))
      }
    }
  ]
  const apiSecurityFeatures = [
    {
      name: 'XMLValidation Policy',
      status: normalizeFeatureStatus(
        policy.xml_validation_enable_signature_detection ??
          policy['xml-validation-enable-signature-detection'] ??
          policy.web_protection_profile_details?.xml_validation_enable_signature_detection ??
          policy.web_protection_profile_details?.['xml-validation-enable-signature-detection'] ??
          policy.xml_validation_policy ??
          policy.xmlValidationPolicy ??
          policy['xml-validation-policy'] ??
          policy.web_protection_profile_details?.xml_validation_policy ??
          policy.web_protection_profile_details?.xmlValidationPolicy ??
          policy.web_protection_profile_details?.['xml-validation-policy']
      )
    },
    {
      name: 'JSON Validation Policy',
      status: normalizeFeatureStatus(
        policy.json_validation_enable_attack_signatures ??
          policy['json-validation-enable-attack-signatures'] ??
          policy.web_protection_profile_details?.json_validation_enable_attack_signatures ??
          policy.web_protection_profile_details?.['json-validation-enable-attack-signatures'] ??
          policy.json_validation_enable_signature_detection ??
          policy['json-validation-enable-signature-detection'] ??
          policy.web_protection_profile_details?.json_validation_enable_signature_detection ??
          policy.web_protection_profile_details?.['json-validation-enable-signature-detection'] ??
          policy.json_validation_policy ??
          policy.jsonValidationPolicy ??
          policy['json-validation-policy'] ??
          policy.web_protection_profile_details?.json_validation_policy ??
          policy.web_protection_profile_details?.jsonValidationPolicy ??
          policy.web_protection_profile_details?.['json-validation-policy']
      )
    }
  ]
  const recentChanges = Array.isArray(policy.recent_changes) && policy.recent_changes.length > 0
    ? policy.recent_changes
    : [{
        id: 'no-critical-changes',
        title: 'No Critical Changes',
        summary: 'No server policy status changes were detected in the last 7 days of backups.',
        time: '-',
        type: 'Server Policy'
      }]
  const fullDetailsSectionMeta = {
    'Recent Changes': {
      summary: 'Latest server policy status changes detected from recent backups.',
      link: '#'
    },
    'Standard Protection': {
      summary: 'Baseline defenses for signatures, web attacks, and protocol validation to stop common threats.',
      link: '#'
    },
    'Advance Protection': {
      summary: 'Advanced controls for custom access, nuanced threat logic, and tighter policy hardening.',
      link: '#'
    },
    'Application Dos protection': {
      summary: 'Application-layer DoS controls for flood prevention, access limiting, and connection thresholds.',
      link: '#'
    },
    'Bot Mitigation': {
      summary: 'Behavioral and known-bot detection to identify, challenge, or block automated abuse.',
      link: '#'
    },
    Access: {
      summary: 'Request access controls such as method restrictions and policy enforcement for inbound traffic.',
      link: '#'
    },
    'IP Protection': {
      summary: 'Network-level controls for IP and geo-based allow/block lists to reduce malicious exposure.',
      link: '#'
    },
    'API Security': {
      summary: 'Schema and payload validation policies for XML/JSON API traffic and signature detection.',
      link: '#'
    }
  }

  const renderSectionHeader = (title) => {
    const meta = fullDetailsSectionMeta[title]
    return (
      <header className="details-section-head">
        <h4>{title}</h4>
        {meta ? (
          <a
            className="details-section-info-link"
            href={meta.link}
            aria-label={`${title} information`}
          >
            <span className="details-section-info-tooltip" role="tooltip">{meta.summary}</span>
            <InfoCircleIcon className="details-section-info-icon" size={16} />
          </a>
        ) : null}
      </header>
    )
  }

  return (
    <section className="full-details-page">
      <div className="full-details-head">
        <div className="full-details-title-block">
          <p className="full-details-eyebrow">Server Policy</p>
          <h3>{policy.server_policy_name || 'Policy Details'}</h3>
        </div>
        <span className={`policy-status-pill ${policyStatusClass} status-pill-modern ${policyStatusTone}`}>
          <span className="policy-status-dot" aria-hidden="true" />
          <PolicyStatusIcon className="policy-status-icon" />
          <span className="policy-status-text">{policyStatus}</span>
        </span>
        <div className="full-details-device-wrap">
          <span className="policy-status-pill status-pill-modern full-details-device-pill">
            <span className="policy-status-dot" aria-hidden="true" />
            <DeviceStackIcon className="policy-status-icon" />
            <span className="policy-status-text">Device: {deviceName}</span>
          </span>
        </div>
        <p>Detailed view of selected policy configuration.</p>
      </div>

      <div className="details-sections">
        <section className="details-section">
          {renderSectionHeader('Recent Changes')}
          <div className="details-feature-grid details-feature-grid-stacked">
            {recentChanges.map((change) => (
              <article key={change.id} className="details-feature-card details-recent-change-card">
                <div className="details-article-row">
                  <p>{change.title}</p>
                  <span className="details-recent-change-type">{change.type}</span>
                </div>
                <p className="details-recent-change-summary">{change.summary}</p>
                <p className="details-recent-change-time">{formatRecentChangeTime(change.time)}</p>
              </article>
            ))}
          </div>
        </section>

        <section className="details-section">
          {renderSectionHeader('Standard Protection')}
          <div className="details-feature-grid">
            {standardProtectionFeatures.map((feature) => (
              <article key={feature.name} className="details-feature-card">
                <div className="details-article-row">
                  <p>{feature.name}</p>
                  <span className={`details-feature-status ${feature.status.toLowerCase()}`}>
                    <span>{feature.status}</span>
                  </span>
                </div>
              </article>
            ))}
          </div>
        </section>


        <section className="details-section">
          {renderSectionHeader('Advance Protection')}
          <div className="details-feature-grid details-feature-grid-stacked">
            {advancedProtectionFeatures.map((feature) => (
              <article
                key={feature.name}
                className={`details-feature-card ${feature.name === 'Custom Access Rules' ? 'details-feature-card-clickable' : ''}`}
                onClick={feature.name === 'Custom Access Rules' ? () => setCustomAccessExpanded((current) => !current) : undefined}
                role={feature.name === 'Custom Access Rules' ? 'button' : undefined}
                tabIndex={feature.name === 'Custom Access Rules' ? 0 : undefined}
                onKeyDown={
                  feature.name === 'Custom Access Rules'
                    ? (event) => {
                        if (event.key === 'Enter' || event.key === ' ') {
                          event.preventDefault()
                          setCustomAccessExpanded((current) => !current)
                        }
                      }
                    : undefined
                }
              >
                <div className="details-article-row">
                  <p>{feature.name}</p>
                  <span className={`details-feature-status ${feature.status.toLowerCase()}`}>
                    <span>{feature.status}</span>
                  </span>
                </div>
                {feature.name === 'Custom Access Rules' && customAccessExpanded && feature.customAccessRules?.length > 0 ? (
                  <ul className="details-sub-list">
                    {feature.customAccessRules.map((rule) => (
                      <li key={rule.name}>
                        <strong>{rule.name}</strong>
                        <span><strong>Action:</strong> <strong>{rule.action}</strong></span>
                        <span><strong>Bot confirmation:</strong> <strong>{rule.botConfirmation}</strong></span>
                        <span><strong>Bot recognition:</strong> <strong>{rule.botRecognition}</strong></span>
                        <span className="details-sub-list-meta">Raw JSON custom rule</span>
                        <pre className="details-sub-list-json">{rule.rawJsonCustomRuleText}</pre>
                      </li>
                    ))}
                  </ul>
                ) : null}
              </article>
            ))}
          </div>
        </section>

        <section className="details-section">
          {renderSectionHeader('Application Dos protection')}
          <div className="details-feature-grid details-feature-grid-stacked">
            {applicationDosProtectionFeatures.map((feature) => (
              <article
                key={feature.name}
                className={`details-feature-card ${feature.name === 'HTTP Flood Prevention' || feature.name === 'HTTP Access Limit' || feature.name === 'TCP Flood Prevention' ? 'details-feature-card-clickable' : ''}`}
                onClick={
                  feature.name === 'HTTP Flood Prevention'
                    ? () => setHttpFloodExpanded((current) => !current)
                    : feature.name === 'HTTP Access Limit'
                      ? () => setHttpAccessLimitExpanded((current) => !current)
                      : feature.name === 'TCP Flood Prevention'
                        ? () => setTcpFloodExpanded((current) => !current)
                      : undefined
                }
                role={feature.name === 'HTTP Flood Prevention' || feature.name === 'HTTP Access Limit' || feature.name === 'TCP Flood Prevention' ? 'button' : undefined}
                tabIndex={feature.name === 'HTTP Flood Prevention' || feature.name === 'HTTP Access Limit' || feature.name === 'TCP Flood Prevention' ? 0 : undefined}
                onKeyDown={
                  feature.name === 'HTTP Flood Prevention' || feature.name === 'HTTP Access Limit' || feature.name === 'TCP Flood Prevention'
                    ? (event) => {
                        if (event.key === 'Enter' || event.key === ' ') {
                          event.preventDefault()
                          if (feature.name === 'HTTP Flood Prevention') {
                            setHttpFloodExpanded((current) => !current)
                          } else if (feature.name === 'TCP Flood Prevention') {
                            setTcpFloodExpanded((current) => !current)
                          } else {
                            setHttpAccessLimitExpanded((current) => !current)
                          }
                        }
                      }
                    : undefined
                }
              >
                <div className="details-article-row">
                  <p>{feature.name}</p>
                  <span className={`details-feature-status ${feature.status.toLowerCase()}`}>
                    <span>{feature.status}</span>
                  </span>
                </div>
                {feature.name === 'HTTP Flood Prevention' && httpFloodExpanded ? (
                  <div className="details-sub-table-wrap">
                    <table className="details-sub-table">
                      <tbody>
                        <tr>
                          <th scope="row">Access limit in HTTP session</th>
                          <td>{feature.details.accessLimitInHttpSession}</td>
                        </tr>
                        <tr>
                          <th scope="row">Action</th>
                          <td>{feature.details.action}</td>
                        </tr>
                        <tr>
                          <th scope="row">Bot confirmation</th>
                          <td>{feature.details.botConfirmation}</td>
                        </tr>
                        <tr>
                          <th scope="row">Bot recognition</th>
                          <td>{feature.details.botRecognition}</td>
                        </tr>
                      </tbody>
                    </table>
                  </div>
                ) : null}
                {feature.name === 'HTTP Access Limit' && httpAccessLimitExpanded ? (
                  <div className="details-sub-table-wrap">
                    <table className="details-sub-table">
                      <tbody>
                        <tr>
                          <th scope="row">Access limit standalone IP</th>
                          <td>{feature.details.accessLimitStandaloneIp}</td>
                        </tr>
                        <tr>
                          <th scope="row">Access limit share IP</th>
                          <td>{feature.details.accessLimitShareIp}</td>
                        </tr>
                        <tr>
                          <th scope="row">Action</th>
                          <td>{feature.details.action}</td>
                        </tr>
                        <tr>
                          <th scope="row">Bot confirmation</th>
                          <td>{feature.details.botConfirmation}</td>
                        </tr>
                        <tr>
                          <th scope="row">Bot recognition</th>
                          <td>{feature.details.botRecognition}</td>
                        </tr>
                      </tbody>
                    </table>
                  </div>
                ) : null}
                {feature.name === 'TCP Flood Prevention' && tcpFloodExpanded ? (
                  <div className="details-sub-table-wrap">
                    <table className="details-sub-table">
                      <tbody>
                        <tr>
                          <th scope="row">Layer4 connection threshold</th>
                          <td>{feature.details.layer4ConnectionThreshold}</td>
                        </tr>
                        <tr>
                          <th scope="row">Action</th>
                          <td>{feature.details.action}</td>
                        </tr>
                      </tbody>
                    </table>
                  </div>
                ) : null}
              </article>
            ))}
          </div>
        </section>

        <section className="details-section">
          {renderSectionHeader('Bot Mitigation')}
          <div className="details-feature-grid details-feature-grid-stacked">
            {botMitigationFeatures.map((feature) => (
              <article
                key={feature.name}
                className={`details-feature-card ${feature.name === 'Biometric Based Detection' || feature.name === 'Threshold Based Detection' || feature.name === 'Known-Bot' ? 'details-feature-card-clickable' : ''}`}
                onClick={
                  feature.name === 'Biometric Based Detection'
                    ? () => setBiometricDetectionExpanded((current) => !current)
                    : feature.name === 'Threshold Based Detection'
                      ? () => setThresholdDetectionExpanded((current) => !current)
                      : feature.name === 'Known-Bot'
                        ? () => setKnownBotExpanded((current) => !current)
                      : undefined
                }
                role={feature.name === 'Biometric Based Detection' || feature.name === 'Threshold Based Detection' || feature.name === 'Known-Bot' ? 'button' : undefined}
                tabIndex={feature.name === 'Biometric Based Detection' || feature.name === 'Threshold Based Detection' || feature.name === 'Known-Bot' ? 0 : undefined}
                onKeyDown={
                  feature.name === 'Biometric Based Detection' || feature.name === 'Threshold Based Detection' || feature.name === 'Known-Bot'
                    ? (event) => {
                        if (event.key === 'Enter' || event.key === ' ') {
                          event.preventDefault()
                          if (feature.name === 'Biometric Based Detection') {
                            setBiometricDetectionExpanded((current) => !current)
                          } else if (feature.name === 'Threshold Based Detection') {
                            setThresholdDetectionExpanded((current) => !current)
                          } else {
                            setKnownBotExpanded((current) => !current)
                          }
                        }
                      }
                    : undefined
                }
              >
                <div className="details-article-row">
                  <p>{feature.name}</p>
                  <span className={`details-feature-status ${feature.status.toLowerCase()}`}>
                    <span>{feature.status}</span>
                  </span>
                </div>
                {feature.name === 'Biometric Based Detection' && biometricDetectionExpanded ? (
                  <div className="details-sub-table-wrap">
                    <table className="details-sub-table">
                      <tbody>
                        <tr>
                          <th scope="row">Action</th>
                          <td>{feature.details.action}</td>
                        </tr>
                        <tr>
                          <th scope="row">Host</th>
                          <td>{feature.details.host}</td>
                        </tr>
                        <tr>
                          <th scope="row">Mouse movement</th>
                          <td>{feature.details.mouseMovement}</td>
                        </tr>
                        <tr>
                          <th scope="row">Page focus</th>
                          <td>{feature.details.pageFocus}</td>
                        </tr>
                        <tr>
                          <th scope="row">Keyboard</th>
                          <td>{feature.details.keyboard}</td>
                        </tr>
                        <tr>
                          <th scope="row">Screen touch</th>
                          <td>{feature.details.screenTouch}</td>
                        </tr>
                        <tr>
                          <th scope="row">Scroll</th>
                          <td>{feature.details.scroll}</td>
                        </tr>
                        <tr>
                          <th scope="row">Bot traits</th>
                          <td>{feature.details.botTraits}</td>
                        </tr>
                        <tr>
                          <th scope="row">Bot traits num</th>
                          <td>{feature.details.botTraitsNum}</td>
                        </tr>
                      </tbody>
                    </table>
                  </div>
                ) : null}
                {feature.name === 'Threshold Based Detection' && thresholdDetectionExpanded ? (
                  <div className="details-sub-table-wrap">
                    <table className="details-sub-table">
                      <tbody>
                        <tr>
                          <th scope="row">Bot confirmation</th>
                          <td>{feature.details.botConfirmation}</td>
                        </tr>
                        <tr>
                          <th scope="row">Bot recognition</th>
                          <td>{feature.details.botRecognition}</td>
                        </tr>
                        <tr>
                          <th scope="row">Crawler detection</th>
                          <td>{feature.details.crawlerDetection}</td>
                        </tr>
                        <tr>
                          <th scope="row">Crawler action</th>
                          <td>{feature.details.crawlerAction}</td>
                        </tr>
                        <tr>
                          <th scope="row">Crawler occurrence num</th>
                          <td>{feature.details.crawlerOccurrenceNum}</td>
                        </tr>
                        <tr>
                          <th scope="row">Crawler within</th>
                          <td>{feature.details.crawlerWithin}</td>
                        </tr>
                        <tr>
                          <th scope="row">Slow attack detection</th>
                          <td>{feature.details.slowAttackDetection}</td>
                        </tr>
                        <tr>
                          <th scope="row">Slow attack action</th>
                          <td>{feature.details.slowAttackAction}</td>
                        </tr>
                        <tr>
                          <th scope="row">Slow attack occurrence num</th>
                          <td>{feature.details.slowAttackOccurrenceNum}</td>
                        </tr>
                        <tr>
                          <th scope="row">Slow attack within</th>
                          <td>{feature.details.slowAttackWithin}</td>
                        </tr>
                      </tbody>
                    </table>
                  </div>
                ) : null}
                {feature.name === 'Known-Bot' && knownBotExpanded ? (
                  <div className="details-sub-table-wrap">
                    <table className="details-sub-table">
                      <tbody>
                        <tr>
                          <th scope="row">Dos</th>
                          <td>{feature.details.dos}</td>
                        </tr>
                        <tr>
                          <th scope="row">Dos action</th>
                          <td>{feature.details.dosAction}</td>
                        </tr>
                        <tr>
                          <th scope="row">Spam</th>
                          <td>{feature.details.spam}</td>
                        </tr>
                        <tr>
                          <th scope="row">Spam action</th>
                          <td>{feature.details.spamAction}</td>
                        </tr>
                        <tr>
                          <th scope="row">Trojan</th>
                          <td>{feature.details.trojan}</td>
                        </tr>
                        <tr>
                          <th scope="row">Trojan action</th>
                          <td>{feature.details.trojanAction}</td>
                        </tr>
                        <tr>
                          <th scope="row">Scanner</th>
                          <td>{feature.details.scanner}</td>
                        </tr>
                        <tr>
                          <th scope="row">Scanner action</th>
                          <td>{feature.details.scannerAction}</td>
                        </tr>
                        <tr>
                          <th scope="row">Crawler</th>
                          <td>{feature.details.crawler}</td>
                        </tr>
                        <tr>
                          <th scope="row">Crawler action</th>
                          <td>{feature.details.crawlerAction}</td>
                        </tr>
                        <tr>
                          <th scope="row">Known engines</th>
                          <td>{feature.details.knownEngines}</td>
                        </tr>
                        <tr>
                          <th scope="row">Known engines action</th>
                          <td>{feature.details.knownEnginesAction}</td>
                        </tr>
                      </tbody>
                    </table>
                  </div>
                ) : null}
              </article>
            ))}
          </div>
        </section>

        <section className="details-section">
          {renderSectionHeader('Access')}
          <div className="details-feature-grid details-feature-grid-stacked">
            {accessFeatures.map((feature) => (
              <article
                key={feature.name}
                className={`details-feature-card ${feature.name === 'Allow method' ? 'details-feature-card-clickable' : ''}`}
                onClick={feature.name === 'Allow method' ? () => setAllowMethodExpanded((current) => !current) : undefined}
                role={feature.name === 'Allow method' ? 'button' : undefined}
                tabIndex={feature.name === 'Allow method' ? 0 : undefined}
                onKeyDown={
                  feature.name === 'Allow method'
                    ? (event) => {
                        if (event.key === 'Enter' || event.key === ' ') {
                          event.preventDefault()
                          setAllowMethodExpanded((current) => !current)
                        }
                      }
                    : undefined
                }
              >
                <div className="details-article-row">
                  <p>{feature.name}</p>
                  <span className={`details-feature-status ${feature.status.toLowerCase()}`}>
                    <span>{feature.status}</span>
                  </span>
                </div>
                {feature.name === 'Allow method' && allowMethodExpanded ? (
                  <div className="details-sub-table-wrap">
                    <table className="details-sub-table">
                      <tbody>
                        <tr>
                          <th scope="row">Method</th>
                          <td>{feature.details.method}</td>
                        </tr>
                      </tbody>
                    </table>
                  </div>
                ) : null}
              </article>
            ))}
          </div>
        </section>

        <section className="details-section">
          {renderSectionHeader('IP Protection')}
          <div className="details-feature-grid details-feature-grid-stacked">
            {ipProtectionFeatures.map((feature) => (
              <article
                key={feature.name}
                className={`details-feature-card ${feature.name === 'IP List' || feature.name === 'Geo Location' ? 'details-feature-card-clickable' : ''}`}
                onClick={
                  feature.name === 'IP List'
                    ? () => setIpListExpanded((current) => !current)
                    : feature.name === 'Geo Location'
                      ? () => setGeoLocationExpanded((current) => !current)
                      : undefined
                }
                role={feature.name === 'IP List' || feature.name === 'Geo Location' ? 'button' : undefined}
                tabIndex={feature.name === 'IP List' || feature.name === 'Geo Location' ? 0 : undefined}
                onKeyDown={
                  feature.name === 'IP List' || feature.name === 'Geo Location'
                    ? (event) => {
                        if (event.key === 'Enter' || event.key === ' ') {
                          event.preventDefault()
                          if (feature.name === 'IP List') {
                            setIpListExpanded((current) => !current)
                          } else {
                            setGeoLocationExpanded((current) => !current)
                          }
                        }
                      }
                    : undefined
                }
              >
                <div className="details-article-row">
                  <p>{feature.name}</p>
                  <span className={`details-feature-status ${feature.status.toLowerCase()}`}>
                    <span>{feature.status}</span>
                  </span>
                </div>
                {feature.name === 'IP List' && ipListExpanded ? (
                  <div className="details-sub-table-wrap">
                    {feature.details.entries.length > 0 ? (
                      feature.details.entries.map((entry, entryIndex) => (
                        <table className="details-sub-table" key={`${entry.ip}-${entryIndex}`}>
                          <tbody>
                            <tr>
                              <th scope="row">Type</th>
                              <td>{entry.type}</td>
                            </tr>
                            <tr>
                              <th scope="row">Group type</th>
                              <td>{entry.groupType}</td>
                            </tr>
                            <tr>
                              <th scope="row">IP</th>
                              <td>{entry.ip}</td>
                            </tr>
                            <tr>
                              <th scope="row">IP group</th>
                              <td>{entry.ipGroup}</td>
                            </tr>
                            <tr>
                              <th scope="row">IP external</th>
                              <td>{entry.ipExternal}</td>
                            </tr>
                          </tbody>
                        </table>
                      ))
                    ) : (
                      <table className="details-sub-table">
                        <tbody>
                          <tr>
                            <th scope="row">Type</th>
                            <td>{feature.details.type}</td>
                          </tr>
                          <tr>
                            <th scope="row">Group type</th>
                            <td>{feature.details.groupType}</td>
                          </tr>
                          <tr>
                            <th scope="row">IP</th>
                            <td>{feature.details.ip}</td>
                          </tr>
                          <tr>
                            <th scope="row">IP group</th>
                            <td>{feature.details.ipGroup}</td>
                          </tr>
                          <tr>
                            <th scope="row">IP external</th>
                            <td>{feature.details.ipExternal}</td>
                          </tr>
                        </tbody>
                      </table>
                    )}
                  </div>
                ) : null}
                {feature.name === 'Geo Location' && geoLocationExpanded ? (
                  <div className="details-sub-table-wrap">
                    {feature.details.entries.length > 0 ? (
                      feature.details.entries.map((entry, entryIndex) => (
                        <table className="details-sub-table" key={`${entry.countryName}-${entryIndex}`}>
                          <tbody>
                            <tr>
                              <th scope="row">Action</th>
                              <td>{entry.action}</td>
                            </tr>
                            <tr>
                              <th scope="row">Country name</th>
                              <td>{entry.countryName}</td>
                            </tr>
                            <tr>
                              <th scope="row">Block period</th>
                              <td>{entry.blockPeriod}</td>
                            </tr>
                          </tbody>
                        </table>
                      ))
                    ) : (
                      <table className="details-sub-table">
                        <tbody>
                          <tr>
                            <th scope="row">Action</th>
                            <td>{feature.details.action}</td>
                          </tr>
                          <tr>
                            <th scope="row">Country name</th>
                            <td>{feature.details.countryName}</td>
                          </tr>
                          <tr>
                            <th scope="row">Block period</th>
                            <td>{feature.details.blockPeriod}</td>
                          </tr>
                        </tbody>
                      </table>
                    )}
                  </div>
                ) : null}
              </article>
            ))}
          </div>
        </section>

        <section className="details-section">
          {renderSectionHeader('API Security')}
          <div className="details-feature-grid details-feature-grid-stacked">
            {apiSecurityFeatures.map((feature) => (
              <article key={feature.name} className="details-feature-card">
                <div className="details-article-row">
                  <p>{feature.name}</p>
                  <span className={`details-feature-status ${feature.status.toLowerCase()}`}>
                    <span>{feature.status}</span>
                  </span>
                </div>
              </article>
            ))}
          </div>
        </section>
      </div>
    </section>
  )
}


function AutomationDetailsPage({ automation }) {
  if (!automation) {
    return <div className="hero-text muted">Select an automation to view configuration details.</div>
  }

  return (
    <section className="automation-detail-page" aria-label={`${automation.title} configuration details`}>
      <div className="automation-detail-hero">
        <div>
          <p className="policy-label">Automation Configuration</p>
          <h2>{automation.title}</h2>
          <p>{automation.objective}</p>
        </div>
        <span className="automation-detail-badge">Ready to configure</span>
      </div>

      <div className="automation-detail-grid">
        <article className="automation-config-card">
          <div className="automation-config-card-head">
            <h3>Configuration Detail</h3>
            <span>Guided setup</span>
          </div>
          <div className="automation-config-fields">
            {automation.fields.map((field) => (
              <label key={field.label} className="automation-config-field">
                <span>{field.label}</span>
                <input type="text" value={field.value} readOnly />
              </label>
            ))}
          </div>
        </article>

        <article className="automation-config-card">
          <div className="automation-config-card-head">
            <h3>Execution Plan</h3>
            <span>Controlled workflow</span>
          </div>
          <ol className="automation-step-list">
            {automation.steps.map((step) => (
              <li key={step}>{step}</li>
            ))}
          </ol>
        </article>
      </div>
    </section>
  )
}


const maturityStatusStrong = 'Strong'
const maturityStatusNeedsImprovement = 'Needs improvement'

const toMaturityText = (value) => String(value ?? '').trim().toLowerCase()

const isMaturityEnabled = (value) => {
  const normalized = toMaturityText(value)
  return ['enabled', 'enable', 'monitoring', 'true', '1', 'yes', 'on'].includes(normalized)
}

const isMaturityActionStrong = (value) => {
  const normalized = toMaturityText(value).replaceAll('-', '_')
  return ['enabled', 'enable', 'alert', 'alert_deny', 'block_period', 'block', 'monitoring'].includes(normalized)
}

const hasStrongMaturityValue = (value) => {
  if (Array.isArray(value)) return value.some(hasStrongMaturityValue)
  if (value && typeof value === 'object') return Object.values(value).some(hasStrongMaturityValue)
  return isMaturityEnabled(value) || isMaturityActionStrong(value)
}

const hasAnyMaturityValue = (...values) => values.some(hasStrongMaturityValue)

function getMaturityPoints(policy = {}) {
  const backendCategories = policy?.maturity_assessment?.categories
  if (Array.isArray(backendCategories) && backendCategories.length > 0) {
    return backendCategories.map((category) => ({
      title: category.title,
      description: category.description,
      status: category.status,
      points: Number(category.points ?? 0),
      maxPoints: Number(category.max_points ?? category.maxPoints ?? 0),
      components: category.components || {}
    }))
  }

  const webProtectionProfile = policy.web_protection_profile_details || {}
  const syntaxDetails = policy.syntax_based_attack_detection_details || webProtectionProfile.syntax_based_attack_detection_details || {}
  const customAccessRules = policy.custom_access_rules || webProtectionProfile.custom_access_rules || []
  const applicationDosPolicy = policy.application_layer_dos_prevention_policy || webProtectionProfile.application_layer_dos_prevention_policy || {}
  const tcpFloodPolicy =
    applicationDosPolicy.tcp_flood_prevention_policy ||
    applicationDosPolicy.layer4_connection_flood_check_rule_policy ||
    applicationDosPolicy['/layer4-connection-flood-check-rule'] ||
    applicationDosPolicy['layer4-connection-flood-check-rule'] ||
    {}
  const botMitigationPolicy =
    policy.bot_mitigation_details ||
    policy.bot_mitigation ||
    policy.bot_mitigate_policy_detail ||
    webProtectionProfile.bot_mitigation_details ||
    webProtectionProfile.bot_mitigate_policy_detail ||
    {}
  const apiSecurityPolicy = policy.api_security_details || policy.api_security || webProtectionProfile.api_security_details || {}
  const ipListPolicyEntries = policy.ip_list_policy_entries || webProtectionProfile.ip_list_policy_entries || []
  const geoIpEntries = policy.geo_ip_entries || webProtectionProfile.geo_ip_entries || []

  const signatureStrong = isMaturityEnabled(
    policy.signature ?? webProtectionProfile.signature_set_status ?? policy.signature_protection ?? policy['signature-protection']
  )
  const httpRfcStrong = isMaturityEnabled(
    policy.http_rfc ?? webProtectionProfile.http_rfc ?? webProtectionProfile.http_protocol_parameter_restriction ?? policy.httpRfc ?? policy['http-rfc']
  )
  const http2Enabled = isMaturityEnabled(policy.http2 ?? webProtectionProfile.http2)
  const http2RfcStrong = http2Enabled && isMaturityEnabled(
    policy.http2_rfc_control ?? webProtectionProfile.http2_rfc_control ?? policy.http2RfcControl ?? policy['http2-rfc-control']
  )
  const standardPoints = http2Enabled
    ? (signatureStrong ? 10 : 0) + (httpRfcStrong ? 10 : 0) + (http2RfcStrong ? 10 : 0)
    : (signatureStrong ? 15 : 0) + (httpRfcStrong ? 15 : 0)
  const standardStrong = standardPoints === 30

  const syntaxStrong = Object.values(syntaxDetails).some(isMaturityEnabled)
  const customAccessStrong = (Array.isArray(customAccessRules) ? customAccessRules.length > 0 : hasAnyMaturityValue(customAccessRules)) || isMaturityEnabled(policy.custom_access_policy)
  const advancedPoints = (syntaxStrong ? 10 : 0) + (customAccessStrong ? 10 : 0)
  const advancedStrong = advancedPoints === 20

  const httpFloodStrong = hasAnyMaturityValue(
    applicationDosPolicy.http_request_flood_prevention_rule,
    policy.http_flood_prevention,
    webProtectionProfile.http_flood_prevention,
    policy['http-flood-prevention']
  )
  const httpAccessLimitStrong = hasAnyMaturityValue(
    applicationDosPolicy.layer4_access_limit_rule,
    applicationDosPolicy.http_access_limit,
    policy.http_access_limit,
    webProtectionProfile.http_access_limit,
    policy['http-access-limit']
  )
  const tcpFloodStrong = hasAnyMaturityValue(
    tcpFloodPolicy.action,
    applicationDosPolicy.layer4_connection_flood_check_rule,
    applicationDosPolicy.tcp_flood_prevention,
    applicationDosPolicy.tcp_flood_action,
    policy.tcp_flood_prevention,
    policy.tcp_flood_prevention_action,
    webProtectionProfile.tcp_flood_prevention,
    policy['tcp-flood-prevention']
  )
  const applicationDosPoints = (httpFloodStrong ? 5 : 0) + (httpAccessLimitStrong ? 5 : 0) + (tcpFloodStrong ? 5 : 0)
  const applicationDosStrong = applicationDosPoints === 15

  const thresholdBasedDetectionStrong = hasAnyMaturityValue(
    botMitigationPolicy.threshold_based_detection,
    botMitigationPolicy.threshold_based_detection_details,
    policy.threshold_based_detection,
    policy.threshold_based_detection_details,
    policy.bot_confirmation,
    policy.bot_recognition,
    webProtectionProfile.threshold_based_detection,
    webProtectionProfile.threshold_based_detection_details
  )
  const knownBotStrong = hasAnyMaturityValue(
    botMitigationPolicy.known_bot,
    botMitigationPolicy.known_bots,
    botMitigationPolicy.known_bots_details,
    policy.known_bot,
    policy.known_bots,
    policy.known_bots_details,
    webProtectionProfile.known_bot,
    webProtectionProfile.known_bots,
    webProtectionProfile.known_bots_details
  )
  const botMitigationPoints = (thresholdBasedDetectionStrong ? 5 : 0) + (knownBotStrong ? 5 : 0)
  const botStrong = botMitigationPoints === 10

  const allowMethodStrong = hasAnyMaturityValue(
    policy.allow_method,
    policy.allow_method_display,
    policy.allowMethod,
    policy['allow-method'],
    policy.allow_method_list,
    webProtectionProfile.allow_method,
    webProtectionProfile.allow_method_display,
    webProtectionProfile.allowMethod,
    webProtectionProfile['allow-method'],
    webProtectionProfile.allow_method_list
  )
  const accessPoints = allowMethodStrong ? 5 : 0
  const accessStrong = accessPoints === 5

  const ipListStrong = hasAnyMaturityValue(
    Array.isArray(ipListPolicyEntries) ? ipListPolicyEntries : [],
    policy.ip_list,
    policy.ipList,
    policy['ip-list'],
    policy.ip_list_entries,
    webProtectionProfile.ip_list,
    webProtectionProfile.ipList,
    webProtectionProfile['ip-list'],
    webProtectionProfile.ip_list_entries
  )
  const geoLocationStrong = hasAnyMaturityValue(
    Array.isArray(geoIpEntries) ? geoIpEntries : [],
    policy.geo_location,
    policy.geoLocation,
    policy['geo-location'],
    webProtectionProfile.geo_location,
    webProtectionProfile.geoLocation,
    webProtectionProfile['geo-location']
  )
  const ipProtectionPoints = (ipListStrong ? 5 : 0) + (geoLocationStrong ? 5 : 0)
  const ipStrong = ipProtectionPoints === 10

  const xmlValidationStrong = hasAnyMaturityValue(
    apiSecurityPolicy.xml_validation_policy,
    apiSecurityPolicy.xml_validation,
    apiSecurityPolicy.xmlValidationPolicy,
    apiSecurityPolicy.enable_signature_detection,
    policy.xml_validation_enable_signature_detection,
    policy['xml-validation-enable-signature-detection'],
    policy.xml_validation_policy,
    policy.xmlValidationPolicy,
    policy['xml-validation-policy'],
    webProtectionProfile.xml_validation_enable_signature_detection,
    webProtectionProfile.xml_validation_policy,
    webProtectionProfile.xmlValidationPolicy,
    webProtectionProfile['xml-validation-policy']
  )
  const jsonValidationStrong = hasAnyMaturityValue(
    apiSecurityPolicy.json_validation_policy,
    apiSecurityPolicy.json_validation,
    apiSecurityPolicy.jsonValidationPolicy,
    apiSecurityPolicy.enable_attack_signatures,
    policy.json_validation_enable_attack_signatures,
    policy['json-validation-enable-attack-signatures'],
    policy.json_validation_policy,
    policy.jsonValidationPolicy,
    policy['json-validation-policy'],
    webProtectionProfile.json_validation_enable_attack_signatures,
    webProtectionProfile.json_validation_policy,
    webProtectionProfile.jsonValidationPolicy,
    webProtectionProfile['json-validation-policy']
  )
  const apiSecurityPoints = (xmlValidationStrong ? 5 : 0) + (jsonValidationStrong ? 5 : 0)
  const apiStrong = apiSecurityPoints === 10

  const createPoint = (strong, title, description, maxPoints, weakPoints) => ({
    title,
    description,
    status: strong ? maturityStatusStrong : maturityStatusNeedsImprovement,
    points: strong ? maxPoints : weakPoints,
    maxPoints
  })

  return [
    {
      title: 'Standart Protection',
      description: 'Signature, HTTP RFC, and HTTP/2 RFC controls provide the highest-weight baseline protection score.',
      status: standardStrong ? maturityStatusStrong : maturityStatusNeedsImprovement,
      points: standardPoints,
      maxPoints: 30
    },
    {
      title: 'Advance Protection',
      description: 'Syntax based attack detection and custom access controls raise advanced protection maturity.',
      status: advancedStrong ? maturityStatusStrong : maturityStatusNeedsImprovement,
      points: advancedPoints,
      maxPoints: 20,
      components: {
        syntax_based_detection: { status: syntaxStrong ? 'enabled' : 'disabled', points: syntaxStrong ? 10 : 0 },
        custom_access_rules: { status: customAccessStrong ? 'enabled' : 'disabled', points: customAccessStrong ? 10 : 0 }
      }
    },
    {
      title: 'Application DoS',
      description: 'HTTP flood prevention, HTTP access limit, and TCP flood prevention are assessed for application-layer DoS readiness.',
      status: applicationDosStrong ? maturityStatusStrong : maturityStatusNeedsImprovement,
      points: applicationDosPoints,
      maxPoints: 15,
      components: {
        http_flood_prevention: { status: httpFloodStrong ? 'enabled' : 'disabled', points: httpFloodStrong ? 5 : 0 },
        http_access_limit: { status: httpAccessLimitStrong ? 'enabled' : 'disabled', points: httpAccessLimitStrong ? 5 : 0 },
        tcp_flood_prevention: { status: tcpFloodStrong ? 'enabled' : 'disabled', points: tcpFloodStrong ? 5 : 0 }
      }
    },
    {
      title: 'Bot Mitigation',
      description: 'Bot mitigation maturity checks threshold based detection and known-bot controls.',
      status: botStrong ? maturityStatusStrong : maturityStatusNeedsImprovement,
      points: botMitigationPoints,
      maxPoints: 10,
      components: {
        threshold_based_detection: { status: thresholdBasedDetectionStrong ? 'enabled' : 'disabled', points: thresholdBasedDetectionStrong ? 5 : 0 },
        known_bot: { status: knownBotStrong ? 'enabled' : 'disabled', points: knownBotStrong ? 5 : 0 }
      }
    },
    {
      title: 'Access',
      description: 'Access maturity reflects the Allow method security feature.',
      status: accessStrong ? maturityStatusStrong : maturityStatusNeedsImprovement,
      points: accessPoints,
      maxPoints: 5,
      components: {
        allow_method: { status: allowMethodStrong ? 'enabled' : 'disabled', points: allowMethodStrong ? 5 : 0 }
      }
    },
    {
      title: 'IP Protection',
      description: 'IP list and geo-location controls contribute location and source protection maturity.',
      status: ipStrong ? maturityStatusStrong : maturityStatusNeedsImprovement,
      points: ipProtectionPoints,
      maxPoints: 10,
      components: {
        ip_list: { status: ipListStrong ? 'enabled' : 'disabled', points: ipListStrong ? 5 : 0 },
        geo_location: { status: geoLocationStrong ? 'enabled' : 'disabled', points: geoLocationStrong ? 5 : 0 }
      }
    },
    {
      title: 'API Security',
      description: 'XML validation policy and JSON validation policy improve API governance maturity.',
      status: apiStrong ? maturityStatusStrong : maturityStatusNeedsImprovement,
      points: apiSecurityPoints,
      maxPoints: 10,
      components: {
        xml_validation_policy: { status: xmlValidationStrong ? 'enabled' : 'disabled', points: xmlValidationStrong ? 5 : 0 },
        json_validation_policy: { status: jsonValidationStrong ? 'enabled' : 'disabled', points: jsonValidationStrong ? 5 : 0 }
      }
    }
  ]
}

function runMaturityPointAssertions() {
  const strongPolicyPoints = getMaturityPoints({
    signature: 'Enabled',
    http_rfc: 'Enabled',
    syntax_based_attack_detection_details: { xss_html_tag_based_status: 'enable' },
    custom_access_rules: [{ name: 'rule-a' }],
    application_layer_dos_prevention_policy: {
      http_request_flood_prevention_rule: 'Enabled',
      layer4_access_limit_rule: 'Enabled',
      tcp_flood_prevention_policy: { action: 'alert_deny' }
    },
    bot_mitigation_details: { threshold_based_detection: 'Enabled', known_bot: 'Enabled' },
    allow_method: 'Enabled',
    ip_list_policy_entries: [{ ip: '10.0.0.1' }],
    geo_ip_entries: [{ countryName: 'United States' }],
    xml_validation_enable_signature_detection: 'Enabled',
    json_validation_enable_attack_signatures: 'Enabled'
  })
  const strongPolicyScore = strongPolicyPoints.reduce((total, point) => total + point.points, 0)
  const weakPolicyPoints = getMaturityPoints({})
  const backendPolicyPoints = getMaturityPoints({
    maturity_assessment: {
      categories: [
        { title: 'Standart Protection', description: 'Backend score', status: 'Needs improvement', points: 15, max_points: 30 }
      ]
    }
  })
  const partialStandardPoints = getMaturityPoints({ signature: 'Enabled', http_rfc: 'Disabled', http2: 'disable' })[0]
  const partialAdvancedPoints = getMaturityPoints({
    syntax_based_attack_detection_details: { xss_html_tag_based_status: 'enable' },
    custom_access_rules: []
  })[1]
  const partialApplicationDosPoints = getMaturityPoints({
    application_layer_dos_prevention_policy: { http_request_flood_prevention_rule: 'rule-a' }
  })[2]
  const partialBotMitigationPoints = getMaturityPoints({ bot_mitigation_details: { threshold_based_detection: 'Enabled' } })[3]
  const enabledAccessPoints = getMaturityPoints({ allow_method: 'Enabled' })[4]
  const partialIpProtectionPoints = getMaturityPoints({ ip_list_policy_entries: [{ ip: '10.0.0.1' }] })[5]
  const partialApiSecurityPoints = getMaturityPoints({ xml_validation_enable_signature_detection: 'Enabled' })[6]

  console.assert(strongPolicyScore >= 80, 'strong policy should score at least 80')
  console.assert(weakPolicyPoints.length === 7, 'weak policy should still return 7 categories')
  console.assert(
    [...strongPolicyPoints, ...weakPolicyPoints].every((point) => point.points <= point.maxPoints),
    'every category should have points <= max'
  )
  console.assert(backendPolicyPoints[0].points === 15, 'backend maturity categories should be used when present')
  console.assert(partialStandardPoints.points === 15, 'standard protection without HTTP/2 gives 15 points for one enabled control')
  console.assert(partialAdvancedPoints.points === 10, 'advance protection gives 10 points for one enabled feature')
  console.assert(partialApplicationDosPoints.points === 5, 'application DoS gives 5 points for one enabled feature')
  console.assert(partialBotMitigationPoints.points === 5, 'bot mitigation gives 5 points for one enabled feature')
  console.assert(enabledAccessPoints.points === 5, 'access gives 5 points when Allow method is enabled')
  console.assert(partialIpProtectionPoints.points === 5, 'IP protection gives 5 points for one enabled feature')
  console.assert(partialApiSecurityPoints.points === 5, 'API security gives 5 points for one enabled feature')
}

runMaturityPointAssertions()


const maturityComponentLabels = {
  http2_enabled: 'Server-pool HTTP/2',
  signature: 'Signature',
  http_rfc: 'HTTP RFC',
  http2_rfc_control: 'HTTP/2 RFC control',
  syntax_based_detection: 'Syntax based detection',
  custom_access_rules: 'Custom access rules',
  http_flood_prevention: 'HTTP flood prevention',
  http_access_limit: 'HTTP access limit',
  tcp_flood_prevention: 'TCP flood prevention',
  threshold_based_detection: 'Threshold based detection',
  known_bot: 'Known-bot',
  allow_method: 'Allow method',
  ip_list: 'IP list',
  geo_location: 'Geo location',
  xml_validation_policy: 'XML validation policy',
  json_validation_policy: 'JSON validation policy'
}

const formatMaturityComponentLabel = (key) => {
  if (maturityComponentLabels[key]) return maturityComponentLabels[key]
  return String(key || '')
    .replaceAll('_', ' ')
    .replace(/\b\w/g, (letter) => letter.toUpperCase())
}

const formatMaturityComponentStatus = (value) => {
  if (typeof value === 'boolean') return value ? 'enabled' : 'disabled'
  const normalized = String(value ?? '').trim()
  return normalized || 'unknown'
}

const getCalculatedPointDetails = (point = {}) => {
  const components = point.components || {}
  return Object.entries(components)
    .filter(([key]) => key !== 'http2_enabled')
    .map(([key, component]) => {
      const label = formatMaturityComponentLabel(key)
      if (component && typeof component === 'object' && !Array.isArray(component)) {
        const counted = component.counted !== false
        const status = formatMaturityComponentStatus(component.status)
        const points = Number(component.points ?? 0)
        return {
          key,
          label,
          status,
          points,
          counted,
          displayPoints: counted ? `${points} pts` : 'Not counted'
        }
      }

      return {
        key,
        label,
        status: formatMaturityComponentStatus(component),
        points: null,
        counted: true,
        displayPoints: null
      }
    })
}

function ScoreBadge({ status }) {
  const strong = status === maturityStatusStrong
  return <span className={`score-status-badge ${strong ? 'strong' : 'needs-improvement'}`}>{status}</span>
}

function ScoringPolicyCard({ policy, onOpenDetails }) {
  const [expanded, setExpanded] = useState(false)
  const maturityPoints = getMaturityPoints(policy)
  const totalPoints = maturityPoints.reduce((total, point) => total + point.points, 0)
  const maxPoints = maturityPoints.reduce((total, point) => total + point.maxPoints, 0)
  const maturityPercentage = Math.round((totalPoints / maxPoints) * 100)
  const policyName = typeof policy === 'string' ? policy : policy.server_policy_name || 'Policy Details'
  const deviceName = typeof policy === 'string' ? 'Unknown Device' : policy._deviceName || policy.device_name || policy.deviceName || 'Unknown Device'
  const policyLocation = typeof policy === 'string' ? 'Unknown' : policy.location || policy._deviceLocation || policy.region || 'Unknown'

  return (
    <article className={`scoring-assessment-card ${expanded ? 'expanded' : ''}`}>
      <button
        type="button"
        className="scoring-assessment-toggle"
        onClick={() => setExpanded((current) => !current)}
        aria-expanded={expanded}
      >
        <div className="scoring-assessment-main">
          <p className="policy-label">Maturity Assessment</p>
          <h4>{policyName}</h4>
          <div className="scoring-assessment-pills">
            <span className="scoring-assessment-pill">
              <DeviceStackIcon />
              {deviceName}
            </span>
            <span className="scoring-assessment-pill location">{policyLocation}</span>
          </div>
        </div>
        <div className="scoring-assessment-score" aria-label={`${maturityPercentage}% total maturity score`}>
          <strong>{maturityPercentage}%</strong>
          <span>Total maturity score</span>
        </div>
        <span className={`scoring-chevron ${expanded ? 'expanded' : ''}`} aria-hidden="true">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
            <path d="m6 9 6 6 6-6" />
          </svg>
        </span>
      </button>

      <AnimatePresence initial={false}>
        {expanded && (
          <motion.div
            className="scoring-assessment-expanded"
            initial={{ opacity: 0, height: 0, y: -6 }}
            animate={{ opacity: 1, height: 'auto', y: 0 }}
            exit={{ opacity: 0, height: 0, y: -6 }}
            transition={{ duration: 0.18, ease: 'easeOut' }}
          >
            <div className="scoring-assessment-expanded-head">
              <h5>Assessment points</h5>
              <button
                type="button"
                className="policy-full-details-btn scoring-full-details-btn"
                onClick={() => onOpenDetails?.(policy)}
              >
                <span>Full Details</span>
                <svg className="policy-full-details-icon" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
                  <path d="M7 7h10v10" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
                  <path d="M7 17 17 7" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
                </svg>
              </button>
            </div>

            <div className="scoring-assessment-point-list">
              {maturityPoints.map((point) => {
                const strong = point.status === maturityStatusStrong
                const percentage = Math.round((point.points / point.maxPoints) * 100)
                const calculatedDetails = getCalculatedPointDetails(point)
                return (
                  <div className="scoring-assessment-point" key={point.title}>
                    <div className="scoring-assessment-point-copy">
                      <div>
                        <h6>{point.title}</h6>
                        <p>{point.description}</p>
                        <p className="scoring-calculated-total">Calculated points: {point.points}/{point.maxPoints} pts</p>
                      </div>
                      <div className="scoring-assessment-point-score">
                        <ScoreBadge status={point.status} />
                        <strong>{point.points}/{point.maxPoints} pts</strong>
                      </div>
                    </div>
                    {calculatedDetails.length > 0 ? (
                      <div className="scoring-calculated-breakdown" aria-label={`${point.title} calculated point breakdown`}>
                        {calculatedDetails.map((detail) => (
                          <span key={detail.key} className={!detail.counted ? 'not-counted' : ''}>
                            <b>{detail.label}</b>
                            <small>{detail.status}{detail.displayPoints ? ` · ${detail.displayPoints}` : ''}</small>
                          </span>
                        ))}
                      </div>
                    ) : null}
                    <div className={`scoring-progress-track ${strong ? 'strong' : 'needs-improvement'}`}>
                      <span style={{ width: `${percentage}%` }} />
                    </div>
                  </div>
                )
              })}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </article>
  )
}

function ScoringPage({ selectedScoreId, scoringLocation, onBack, onOpenDetails, policies = [] }) {
  const normalizedScoreId = toMaturityText(scoringLocation || selectedScoreId || 'overall')
  const selectedLocationName = normalizedScoreId === 'pendik' ? 'Pendik' : normalizedScoreId === 'ankara' ? 'Ankara' : 'Overall'
  const filteredPolicies = policies.filter((policy) => {
    if (normalizedScoreId === 'overall' || normalizedScoreId === 'all') return true
    const policyLocation = toMaturityText(policy?.location || policy?._deviceLocation || 'Unknown')
    return policyLocation === normalizedScoreId
  })
  const subtitle = normalizedScoreId === 'overall' || normalizedScoreId === 'all'
    ? 'Enterprise-wide policy maturity scoring across all WAF locations.'
    : `${selectedLocationName} policy maturity scoring and assessment points.`

  return (
    <section className="scoring-page waf-panel modern-waf" aria-label="Scoring workspace">
      <div className="workspace-tab-bar scoring-tab-bar" role="tablist" aria-label="Scoring workspace tabs">
        <button type="button" role="tab" aria-selected="true" className="workspace-tab active">
          <span className="workspace-tab-label">Scoring</span>
        </button>
      </div>

      <div className="scoring-hero">
        <button type="button" className="scoring-back-btn" onClick={onBack}>
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
            <path d="M19 12H5" />
            <path d="m12 19-7-7 7-7" />
          </svg>
          <span>Back</span>
        </button>
        <div>
          <p className="maturity-location">Workspace tab</p>
          <h2>Scoring</h2>
          <p>{subtitle}</p>
        </div>
      </div>

      <div className="scoring-policy-section">
        <div className="scoring-section-head">
          <div>
            <p className="maturity-location">Maturity Assessment</p>
            <h3>{selectedLocationName} policies</h3>
          </div>
          <span className="maturity-level-pill">{filteredPolicies.length} policies</span>
        </div>

        {filteredPolicies.length === 0 ? (
          <div className="waf-empty-state">
            <p className="nav-desc">No policies found for {selectedLocationName}.</p>
          </div>
        ) : (
          <div className="scoring-assessment-list">
            {filteredPolicies.map((policy, index) => (
              <ScoringPolicyCard
                key={typeof policy === 'string' ? `scoring-policy-${index}` : `${policy._deviceName || 'device'}::${policy.server_policy_name || index}::${policy.ip || 'no-ip'}`}
                policy={policy}
                onOpenDetails={(selectedPolicy) => onOpenDetails?.(selectedPolicy, index)}
              />
            ))}
          </div>
        )}
      </div>
    </section>
  )
}


const getPolicyMaturityScore = (policy = {}) => {
  const maturityPoints = getMaturityPoints(policy)
  const totalPoints = maturityPoints.reduce((total, point) => total + Number(point.points || 0), 0)
  const maxPoints = maturityPoints.reduce((total, point) => total + Number(point.maxPoints || 0), 0)
  return maxPoints > 0 ? Math.round((totalPoints / maxPoints) * 100) : 0
}

const averagePolicyMaturityScore = (policies = [], locationName = '') => {
  const normalizedLocation = toMaturityText(locationName)
  const matchingPolicies = policies.filter((policy) => {
    if (!policy || typeof policy === 'string') return false
    return toMaturityText(policy.location || policy._deviceLocation || policy.region || 'Unknown') === normalizedLocation
  })
  if (matchingPolicies.length === 0) return 0
  const totalScore = matchingPolicies.reduce((total, policy) => total + getPolicyMaturityScore(policy), 0)
  return Math.round(totalScore / matchingPolicies.length)
}

const getMaturityLevel = (score) => {
  if (score >= 85) return 'Optimized'
  if (score >= 70) return 'Managed'
  if (score >= 50) return 'Developing'
  return 'Needs Focus'
}

const getMaturityTone = (score) => {
  if (score >= 85) return 'strong'
  if (score >= 70) return 'steady'
  return 'decreased'
}

const getPolicyProtectionStatusLabel = (policy = {}) => {
  const ip = String(policy?.ip || '').trim()
  if (!ip) return 'Not Protected'
  const monitorMode = String(policy?.['monitor-mode'] ?? policy?.monitor_mode ?? '').toLowerCase()
  return monitorMode === 'enable' ? 'Monitoring' : 'Blocking'
}

const getPolicyHostnames = (policy = {}) => {
  const allowHostsEntries = Array.isArray(policy?.allow_hosts_entries) ? policy.allow_hosts_entries : []
  const hostnames = allowHostsEntries
    .map((entry) => String(entry?.host || '').trim())
    .filter(Boolean)
  if (hostnames.length > 0) return hostnames
  return [policy?.hostname, policy?.domainname, policy?.host]
    .map((hostname) => String(hostname || '').trim())
    .filter(Boolean)
}

const getHostStatusTotals = (policies = [], locationName = '') => {
  const normalizedLocation = toMaturityText(locationName)
  const totals = { Blocking: new Set(), Monitoring: new Set(), 'Not Protected': new Set() }

  policies.forEach((policy) => {
    if (!policy || typeof policy === 'string') return
    const policyLocation = toMaturityText(policy.location || policy._deviceLocation || policy.region || 'Unknown')
    if (policyLocation !== normalizedLocation) return
    const status = getPolicyProtectionStatusLabel(policy)
    getPolicyHostnames(policy).forEach((hostname) => totals[status]?.add(hostname))
  })

  return {
    blocking: totals.Blocking.size,
    monitoring: totals.Monitoring.size,
    notProtected: totals['Not Protected'].size
  }
}

const buildHostStatusMetrics = (totals = {}) => [
  { label: 'Blocking', value: totals.blocking || 0 },
  { label: 'Monitoring', value: totals.monitoring || 0 },
  { label: 'Not protected', value: totals.notProtected || 0 }
]

function ExecutiveOverviewPage({ onDeepDive, policies = [] }) {
  const pendikScore = averagePolicyMaturityScore(policies, 'Pendik')
  const ankaraScore = averagePolicyMaturityScore(policies, 'Ankara')
  const overallScore = Math.round((pendikScore + ankaraScore) / 2)
  const dynamicScores = { overall: overallScore, pendik: pendikScore, ankara: ankaraScore }
  const hostStatusTotals = {
    pendik: getHostStatusTotals(policies, 'Pendik'),
    ankara: getHostStatusTotals(policies, 'Ankara')
  }
  const [overallCard, ...siteCards] = executiveMaturityCards.map((card) => {
    const score = dynamicScores[card.id] ?? 0
    return {
      ...card,
      score,
      series: [score, score, score],
      level: getMaturityLevel(score),
      tone: getMaturityTone(score),
      trend: card.id === 'overall'
        ? null
        : {
            direction: 'stable',
            label: 'Host status totals',
            metrics: buildHostStatusMetrics(hostStatusTotals[card.id])
          }
    }
  })
  const [timelineItems, setTimelineItems] = useState(executiveTimelineItems)
  const [timelineEditMode, setTimelineEditMode] = useState(false)
  const [overviewTabs, setOverviewTabs] = useState([{ id: 'executive-overview-main', title: 'Executive Overview', type: 'main' }])
  const [activeOverviewTabId, setActiveOverviewTabId] = useState('executive-overview-main')

  const handleTimelineChange = (id, field, value) => {
    setTimelineItems((items) => (
      items.map((item) => (item.id === id ? { ...item, [field]: value } : item))
    ))
  }

  const handleAddTimelineRow = () => {
    setTimelineItems((items) => ([
      ...items,
      {
        id: `timeline-${Date.now()}`,
        date: '',
        domain: '',
        action: 'Configure domain on WAF',
        owner: '',
        status: 'Planned'
      }
    ]))
  }

  const handleDeleteTimelineRow = (id) => {
    setTimelineItems((items) => items.filter((item) => item.id !== id))
  }

  const openTimelineAdminTab = () => {
    setOverviewTabs((tabs) => (
      tabs.some((tab) => tab.id === 'timeline-admin')
        ? tabs
        : [...tabs, { id: 'timeline-admin', title: 'Timeline Admin', type: 'timeline-admin' }]
    ))
    setTimelineEditMode(true)
    setActiveOverviewTabId('timeline-admin')
  }

  const closeOverviewTab = (tabId) => {
    setOverviewTabs((tabs) => tabs.filter((tab) => tab.id !== tabId))
    if (tabId === 'timeline-admin') {
      setTimelineEditMode(false)
    }
    if (activeOverviewTabId === tabId) {
      setActiveOverviewTabId('executive-overview-main')
    }
  }

  const saveTimeline = () => {
    setTimelineEditMode(false)
  }

  const activeOverviewTab = overviewTabs.find((tab) => tab.id === activeOverviewTabId) || overviewTabs[0]

  return (
    <section className="executive-overview-page" aria-label="Executive WAF maturity overview">
      {overviewTabs.length > 1 && (
        <div className="workspace-tab-bar executive-tab-bar" role="tablist" aria-label="Executive overview tabs">
          {overviewTabs.map((tab) => (
            <button
              key={tab.id}
              type="button"
              role="tab"
              aria-selected={activeOverviewTabId === tab.id}
              className={`workspace-tab ${activeOverviewTabId === tab.id ? 'active' : ''}`}
              onClick={() => setActiveOverviewTabId(tab.id)}
            >
              <span className="workspace-tab-label">{tab.title}</span>
              {tab.id !== 'executive-overview-main' && (
                <span
                  className="workspace-tab-close"
                  role="button"
                  aria-label={`Close ${tab.title}`}
                  onClick={(event) => {
                    event.stopPropagation()
                    closeOverviewTab(tab.id)
                  }}
                >×</span>
              )}
            </button>
          ))}
        </div>
      )}

      {activeOverviewTab?.type === 'timeline-admin' ? (
        <ExecutiveTimelineCard
          items={timelineItems}
          editMode={timelineEditMode}
          adminTab
          onChange={handleTimelineChange}
          onAddRow={handleAddTimelineRow}
          onDeleteRow={handleDeleteTimelineRow}
          onToggleEdit={() => (timelineEditMode ? saveTimeline() : setTimelineEditMode(true))}
        />
      ) : (
        <div className="maturity-layout" aria-label="WAF protection maturity levels">
          <MaturityCard card={overallCard} featured />
          <div className="maturity-site-grid">
            {siteCards.map((card) => (
              <MaturityCard key={card.id} card={card} showDeepDive onDeepDive={onDeepDive} />
            ))}
          </div>
          <ExecutiveTimelineCard
            items={timelineItems}
            editMode={false}
            onChange={handleTimelineChange}
            onAddRow={handleAddTimelineRow}
            onDeleteRow={handleDeleteTimelineRow}
            onToggleEdit={openTimelineAdminTab}
          />
        </div>
      )}
    </section>
  )
}


function ExecutiveTimelineCard({ items, editMode, adminTab = false, onChange, onAddRow, onDeleteRow, onToggleEdit }) {
  return (
    <article className="executive-timeline-card" aria-label="Upcoming WAF configuration plan">
      <div className="timeline-card-aura" aria-hidden="true" />
      <div className="executive-timeline-head">
        <div>
          <p className="maturity-location">{adminTab ? 'Admin timeline workspace' : 'Executive timeline'}</p>
          <h3>Upcoming WAF Configuration Plan</h3>
          <p className="executive-timeline-description">
            Shows which domains will be configured on WAF and which policies will move from Monitoring to Blocking.
          </p>
        </div>
        <div className="timeline-admin-actions">
          {editMode && (
            <button type="button" className="timeline-add-row-btn" onClick={onAddRow} aria-label="Add new domain row">
              +
            </button>
          )}
          <button type="button" className="timeline-admin-btn" onClick={onToggleEdit}>
            {editMode ? 'Save Timeline' : 'Edit as Admin'}
          </button>
        </div>
      </div>

      <div className={`floating-timeline ${editMode ? 'editing' : ''}`}>
        {items.map((item, index) => (
          <TimelineItem
            key={item.id}
            item={item}
            index={index}
            editMode={editMode}
            onChange={onChange}
            onDelete={onDeleteRow}
          />
        ))}
      </div>
    </article>
  )
}

function TimelineItem({ item, index, editMode, onChange, onDelete }) {
  const renderField = (field, label, type = 'text') => (
    <label className="timeline-edit-field">
      <span>{label}</span>
      <input
        type={type}
        value={item[field]}
        onChange={(event) => onChange(item.id, field, event.target.value)}
      />
    </label>
  )

  return (
    <div className="timeline-row">
      <div className="timeline-marker" aria-hidden="true">
        <span>{index + 1}</span>
      </div>
      <div className="timeline-floating-item">
        {editMode ? (
          <div className="timeline-edit-shell">
            <div className="timeline-edit-grid">
              {renderField('date', 'Date', 'date')}
              {renderField('domain', 'Domain')}
              {renderField('action', 'Action')}
              {renderField('owner', 'Owner')}
              <label className="timeline-edit-field">
                <span>Status</span>
                <select value={item.status} onChange={(event) => onChange(item.id, 'status', event.target.value)}>
                  {timelineStatusOptions.map((status) => (
                    <option key={status} value={status}>{status}</option>
                  ))}
                </select>
              </label>
            </div>
            <button
              type="button"
              className="timeline-delete-row-btn"
              onClick={() => onDelete(item.id)}
              aria-label={`Delete timeline item ${index + 1}`}
            >
              Delete
            </button>
          </div>
        ) : (
          <>
            <div className="timeline-item-topline">
              <time dateTime={item.date}>{item.date}</time>
              <TimelineStatusBadge status={item.status} />
            </div>
            <h4>{item.domain}</h4>
            <p>{item.action}</p>
            <div className="timeline-owner-row">
              <span>Owner</span>
              <strong>{item.owner}</strong>
            </div>
          </>
        )}
      </div>
    </div>
  )
}

function TimelineStatusBadge({ status }) {
  const normalized = status.toLowerCase().replaceAll(' ', '-').replace('moved-to-blocking', 'blocking')
  return <span className={`timeline-status-badge ${normalized}`}>{status}</span>
}


function TrendArrowIcon({ direction }) {
  if (direction === 'improved') {
    return (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
        <path d="m5 15 6-6 4 4 4-4" />
        <path d="M15 9h4v4" />
      </svg>
    )
  }

  if (direction === 'decreased') {
    return (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
        <path d="m5 9 6 6 4-4 4 4" />
        <path d="M15 15h4v-4" />
      </svg>
    )
  }

  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M5 12h14" />
      <path d="m15 8 4 4-4 4" />
    </svg>
  )
}

function MaturityCard({ card, featured = false, showDeepDive = false, onDeepDive, contentWrapped = true }) {
  const cardContent = (
    <>
      <div className="maturity-card-head">
        <div>
          <p className="maturity-location">{card.location}</p>
          <h3>{card.title}</h3>
        </div>
        <span className="maturity-level-pill">{card.level}</span>
      </div>

      <div className="maturity-metrics-row">
        <div className="maturity-score-row">
          <div className="maturity-score-orb" aria-label={`${card.score}% maturity score`}>
            <span>{card.score}</span>
            <small>%</small>
          </div>
          <p>{card.summary}</p>
        </div>

        {card.trend && (
          <div className={`maturity-trend ${card.trend.direction}`}>
            <span className="maturity-trend-icon"><TrendArrowIcon direction={card.trend.direction} /></span>
            <span className={`maturity-trend-copy ${card.trend.metrics ? 'host-status-summary' : ''}`}>
              {card.trend.metrics ? (
                <span className="host-status-grid" aria-label={card.trend.label}>
                  {card.trend.metrics.map((metric) => (
                    <span className="host-status-item" key={metric.label}>
                      <strong>{metric.value}</strong>
                      <small>{metric.label}</small>
                    </span>
                  ))}
                </span>
              ) : (
                <strong>{card.trend.value}</strong>
              )}
              <small>{card.trend.label}</small>
            </span>
          </div>
        )}
      </div>
      {showDeepDive && (
        <div className="maturity-card-actions">
          <button type="button" className="deep-dive-btn" onClick={() => onDeepDive?.(card.id)}>
            <span>Deep dive policies</span>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
              <path d="M5 12h14" />
              <path d="m13 6 6 6-6 6" />
            </svg>
          </button>
        </div>
      )}
    </>
  )

  return (
    <article className={`maturity-card ${featured ? 'featured' : ''} ${card.tone}`}>
      {contentWrapped ? <div className="maturity-card-content">{cardContent}</div> : cardContent}
    </article>
  )
}

function AppShell({ session, onLogout, darkMode, onToggleTheme }) {
  const [sidebarOpen, setSidebarOpen] = useState(true)
  const [activeNav, setActiveNav] = useState('home')
  const [activePage, setActivePage] = useState('overview')
  const [selectedScoreId, setSelectedScoreId] = useState('overall')
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
  const [expandedAutomationCard, setExpandedAutomationCard] = useState('')
  const [automationTabs, setAutomationTabs] = useState([{ id: MAIN_AUTOMATION_TAB_ID, title: 'Automation', type: 'main' }])
  const [activeAutomationTabId, setActiveAutomationTabId] = useState(MAIN_AUTOMATION_TAB_ID)
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
  const collectionInFlightRef = useRef(false)

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

  const hasServerPolicies = (payload) => {
    const payloadDevices = Array.isArray(payload?.devices) ? payload.devices : []
    return payloadDevices.some((device) => Array.isArray(device.server_policies) && device.server_policies.length > 0)
  }

  const waitForWafCollectionPayload = async (initialPayload = null) => {
    let latestPayload = initialPayload
    for (let attempt = 0; attempt < 12; attempt += 1) {
      if (hasServerPolicies(latestPayload)) return latestPayload
      await new Promise((resolve) => window.setTimeout(resolve, 5000))
      try {
        const response = await fetch(`${API_BASE}${SERVER_POLICY_ENDPOINT}`)
        if (response.ok) {
          const data = await response.json()
          latestPayload = data.payload
        }
      } catch {
        // Keep polling until attempts are exhausted; the collect job may still be running.
      }
    }
    return latestPayload || { devices: [] }
  }

  const fetchCollectedWafResponse = async () => {
    let payload = wafResponse
    if (!collectionInFlightRef.current) {
      collectionInFlightRef.current = true
      const response = await fetch(`${API_BASE}/fortiweb/server-policy/collect`, {
        method: 'POST',
        headers: { 'X-Role': 'admin' }
      })
      if (!response.ok) {
        collectionInFlightRef.current = false
        throw new Error('Failed to start WAF data collection from FortiWeb')
      }
      const data = await response.json()
      payload = data.payload
    }

    try {
      return await waitForWafCollectionPayload(payload)
    } finally {
      collectionInFlightRef.current = false
    }
  }

  const loadWafResponse = async ({ collectIfEmpty = false, showErrors = true } = {}) => {
    setLoadingWaf(true)
    setWafError('')
    try {
      const res = await fetch(`${API_BASE}${SERVER_POLICY_ENDPOINT}`)
      let payload = null
      if (res.ok) {
        const data = await res.json()
        payload = data.payload
      }
      if (collectIfEmpty && !hasServerPolicies(payload)) {
        payload = await fetchCollectedWafResponse()
      }
      if (!payload && showErrors) throw new Error('No WAF API response found. Collect from WAF first.')
      setWafResponse(payload || { devices: [] })
    } catch (err) {
      if (showErrors) setWafError(err.message)
      setWafResponse((prev) => prev || { devices: [] })
    } finally {
      setLoadingWaf(false)
    }
  }

  const collectWafResponse = async () => {
    setLoadingWaf(true)
    setWafError('')
    try {
      const payload = await fetchCollectedWafResponse()
      setWafResponse(payload)
    } catch (err) {
      setWafError(err.message)
    } finally {
      setLoadingWaf(false)
    }
  }

  useEffect(() => {
    if (activeNav === 'waf') loadWafResponse()
    if (activeNav === 'home' || activePage === 'scoring') loadWafResponse({ collectIfEmpty: true, showErrors: false })
  }, [activeNav, activePage])

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
    const label = typeof policy === 'string' ? 'Not Protected' : getPolicyProtectionStatusLabel(policy)
    return { label, className: label.toLowerCase().replace(/\s+/g, '-') }
  }

  const getPolicyTabId = (policy) => {
    const policyName = policy?.server_policy_name || 'Policy Details'
    const deviceName = policy?._deviceName || 'Unknown Device'
    const policyIp = policy?.ip || 'no-ip'
    return `${deviceName}::${policyName}::${policyIp}`
  }

  const openPolicyTab = (policy, index) => {
    const policyName = policy?.server_policy_name || `Policy ${index + 1}`
    const tabId = getPolicyTabId(policy)

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

  const openAutomationTab = (automation) => {
    const tabId = `automation::${automation.id}`

    setAutomationTabs((prev) => {
      if (prev.some((tab) => tab.id === tabId)) return prev
      return [...prev, { id: tabId, title: automation.title, type: 'automation', automation }]
    })
    setActiveAutomationTabId(tabId)
  }

  const closeAutomationTab = (tabId) => {
    if (tabId === MAIN_AUTOMATION_TAB_ID) return
    setAutomationTabs((prev) => {
      const next = prev.filter((tab) => tab.id !== tabId)
      if (activeAutomationTabId === tabId) {
        const closedIndex = prev.findIndex((tab) => tab.id === tabId)
        const fallback = next[Math.max(0, closedIndex - 1)] || next[0] || { id: MAIN_AUTOMATION_TAB_ID }
        setActiveAutomationTabId(fallback.id)
      }
      return next
    })
  }

  const openScoringPage = (scoreId) => {
    setSelectedScoreId(scoreId)
    setActivePage('scoring')
    setActiveNav('overview')
  }

  const closeScoringPage = () => {
    setActivePage('overview')
    setActiveNav('overview')
  }

  const openScoringPolicyDetails = (policy, index) => {
    openPolicyTab(policy, index)
    setActivePage('overview')
    setActiveNav('waf')
  }

  const activeWafTab = wafTabs.find((tab) => tab.id === activeWafTabId) || wafTabs[0]
  const activeAutomationTab = automationTabs.find((tab) => tab.id === activeAutomationTabId) || automationTabs[0]

  return (
    <div className={`dashboard-page ${darkMode ? 'dark' : 'light'}`}>
      <div className="ambient-layer" />
      <div className={`dashboard-shell ${sidebarOpen ? 'sidebar-open' : 'sidebar-closed'}`}>
        <aside className={`sidebar ${sidebarOpen ? 'is-open' : 'is-closed'}`}>
          <div className="sidebar-top">
            <button onClick={() => { setActiveNav('home'); setActivePage('overview') }} className="home-link">
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
                      setActivePage('overview')
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
              <button type="button" className={`settings-subitem ${activeNav === 'device-config' ? 'active' : ''}`} onClick={() => { setActiveNav('device-config'); setActivePage('overview') }}>
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
                {activePage === 'scoring'
                  ? 'Scoring'
                  : activeNav === 'home'
                    ? 'Search'
                    : activeNav === 'waf'
                      ? 'WAF Configuration'
                      : activeNav === 'automation'
                        ? 'Automation'
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

          <section className={`body-content ${activeNav === 'home' && activePage !== 'scoring' ? 'home-centered' : ''}`}>
            {activePage === 'scoring' && (
              <ScoringPage
                selectedScoreId={selectedScoreId}
                scoringLocation={selectedScoreId}
                onBack={closeScoringPage}
                onOpenDetails={openScoringPolicyDetails}
                policies={wafPolicies}
              />
            )}

            {activePage !== 'scoring' && activeNav === 'home' && (
              <form className="search-wrap" onSubmit={submitSearch}>
                <div className="hero-text">How can I help you? :)</div>
                <div className="search-bar">
                  <div className="search-input-with-icon">
                    <span className="search-icon" aria-hidden="true">⌕</span>
                    <input type="text" value={prompt} onChange={(e) => setPrompt(e.target.value)} placeholder="Search..." />
                  </div>
                  <button type="submit">Search</button>
                </div>
                {searchResult && <p className="search-result">{searchResult}</p>}
              </form>
            )}

            {activePage !== 'scoring' && activeNav === 'waf' && (
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
                        <div className="search-input-with-icon">
                          <span className="search-icon" aria-hidden="true">⌕</span>
                          <input
                            type="text"
                            value={wafSearch}
                            onChange={(e) => setWafSearch(e.target.value)}
                            placeholder="Search by policy name, IP, or hostname"
                            aria-label="Search WAF policies"
                          />
                        </div>
                      </div>
                      <div className="waf-location-card">
                        <span className="waf-location-label">Location</span>
                        <select value={selectedLocation} onChange={(e) => setSelectedLocation(e.target.value)} aria-label="Filter by location">
                          {locationOptions.map((location) => (
                            <option key={location} value={location}>{location}</option>
                          ))}
                        </select>
                      </div>
                      <button type="button" className="theme-btn" onClick={loadWafResponse} disabled={loadingWaf}>Refresh</button>
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
                              const hostnames = allowHostsEntries
                                .map((entry) => entry.host || '')
                                .filter(Boolean)
                              const clientCertificateDetails = typeof policy === 'string' ? {} : (policy.client_certificate_details || {})
                              const certificateCn = clientCertificateDetails.cn || getCertificateCommonName(clientCertificateDetails.subject) || '-'
                              const certificateIssuer = clientCertificateDetails.issuer_cn || getCertificateCommonName(clientCertificateDetails.issuer) || '-'
                              const certificateExpireDate = clientCertificateDetails.expire_date || clientCertificateDetails.valid_to || '-'
                              const certificateDaysLeft = clientCertificateDetails.days_left ?? '-'
                              const tlsV10V11 = [tlsV10, tlsV11].map((value) => (value === null ? '-' : String(value))).join(' / ')
                              const { Icon: CardPolicyStatusIcon, toneClass: policyStatusTone } = getPolicyStatusVisual(policyStatusLabel)
                              return (
                              <article
                                className={`policy-card ${expandedPolicyCard === `${policyName}-${index}` ? 'selected' : ''}`}
                                key={typeof policy === 'string' ? `policy-${index}` : getPolicyTabId(policy)}
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
                                    <span className={`policy-status-pill ${policyStatusClass} status-pill-modern ${policyStatusTone}`}>
                                      <span className="policy-status-dot" aria-hidden="true" />
                                      <CardPolicyStatusIcon className="policy-status-icon" />
                                      <span className="policy-status-text">{policyStatusLabel}</span>
                                    </span>
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
                                        <p>
                                          <span>Hostnames</span>
                                          <strong className="policy-hostname-list">
                                            {hostnames.length
                                              ? hostnames.map((hostname, hostnameIndex) => (
                                                <span key={`${hostname}-${hostnameIndex}`} className="policy-hostname-item">{hostname}</span>
                                              ))
                                              : '-'}
                                          </strong>
                                        </p>
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

            {activePage !== 'scoring' && activeNav === 'automation' && (
              <section className="waf-panel modern-waf automation-workspace">
                <div className="workspace-tab-bar" role="tablist" aria-label="Automation workspace tabs">
                  {automationTabs.map((tab) => (
                    <button
                      key={tab.id}
                      type="button"
                      role="tab"
                      aria-selected={activeAutomationTabId === tab.id}
                      className={`workspace-tab ${activeAutomationTabId === tab.id ? 'active' : ''}`}
                      onClick={() => setActiveAutomationTabId(tab.id)}
                    >
                      <span className="workspace-tab-label">{tab.title}</span>
                      {tab.id !== MAIN_AUTOMATION_TAB_ID && (
                        <span
                          className="workspace-tab-close"
                          role="button"
                          aria-label={`Close ${tab.title}`}
                          onClick={(event) => {
                            event.stopPropagation()
                            closeAutomationTab(tab.id)
                          }}
                        >×</span>
                      )}
                    </button>
                  ))}
                </div>

                {activeAutomationTab?.type === 'main' ? (
                  <div className="waf-card-grid">
                    {automationCards.map((card) => (
                      <article
                        key={card.id}
                        className={`policy-card ${expandedAutomationCard === card.id ? 'selected' : ''}`}
                        onClick={() => setExpandedAutomationCard((prev) => (prev === card.id ? '' : card.id))}
                      >
                        <div className="policy-top-row">
                          <div>
                            <p className="policy-label">Automation</p>
                            <p className="policy-name">{card.title}</p>
                          </div>
                          <div className="policy-status-wrap">
                            <span className={`policy-expand-icon ${expandedAutomationCard === card.id ? 'expanded' : ''}`} aria-hidden="true">
                              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
                                <path d="m6 9 6 6 6-6" />
                              </svg>
                            </span>
                          </div>
                        </div>
                        {expandedAutomationCard === card.id && (
                          <section className="policy-summary automation-definition" aria-label={`${card.title} definition`}>
                            <div className="policy-summary-head automation-summary-head">
                              <div>
                                <h4>Definition</h4>
                              </div>
                              <button
                                type="button"
                                className="policy-full-details-btn automation-details-btn"
                                onClick={(event) => {
                                  event.stopPropagation()
                                  openAutomationTab(card)
                                }}
                              >
                                <span>Details</span>
                                <svg className="policy-full-details-icon" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
                                  <path d="M7 7h10v10" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
                                  <path d="M7 17 17 7" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
                                </svg>
                              </button>
                            </div>
                            <p>{card.definition}</p>
                          </section>
                        )}
                      </article>
                    ))}
                  </div>
                ) : (
                  <AutomationDetailsPage automation={activeAutomationTab?.automation} />
                )}
              </section>
            )}

            {activePage !== 'scoring' && activeNav === 'overview' && <ExecutiveOverviewPage onDeepDive={openScoringPage} policies={wafPolicies} />}
            {activePage !== 'scoring' && activeNav === 'device-config' && (
              <section className="device-page">
                <div className="device-topbar">
                  <div>
                    <span className="device-kicker">● Device Management</span>
                    <h2 className="device-title">Manage FortiWeb Devices</h2>
                    <p className="device-subtitle">Add, review, filter, and remove devices connected to your WAF configuration platform.</p>
                  </div>
                  <div className="device-topbar-actions">
                    <button type="button" className="add-device-btn" onClick={() => setAddDeviceModalOpen(true)}>+ Add Device</button>
                    <button type="button" className="add-device-btn" onClick={collectWafResponse} disabled={loadingWaf}>{loadingWaf ? 'Collecting...' : 'Collect From WAF'}</button>
                  </div>
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
